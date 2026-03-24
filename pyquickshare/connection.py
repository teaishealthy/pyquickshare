from __future__ import annotations

import asyncio
import contextlib
import io
import random
from logging import getLogger
from typing import TYPE_CHECKING

from .backend import ConnectionBackend, EncryptedBackend, UnencryptedBackend
from .common import (
    SILLY,
    create_task,
    payloadify,
)
from .protos import offline_wire_formats, wire_format

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Awaitable, Callable

logger = getLogger(__name__)

_PayloadHeader = offline_wire_formats.PayloadTransferFramePayloadHeader

def _frame_type_name(frame_type: int) -> str:
    try:
        name = offline_wire_formats.V1FrameFrameType(frame_type).name
    except ValueError:
        return f"UNKNOWN({frame_type})"
    else:
        return name if name is not None else f"UNKNOWN({frame_type})"


def _bw_event_name(event_type: int) -> str:
    try:
        name = offline_wire_formats.BandwidthUpgradeNegotiationFrameEventType(event_type).name
    except ValueError:
        return f"UNKNOWN({event_type})"
    else:
        return name if name is not None else f"UNKNOWN({event_type})"


class NearbyConnection:
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        endpoint_id: bytes,
    ) -> None:
        self._backend: ConnectionBackend = UnencryptedBackend(reader, writer)
        self._keep_alive_task: asyncio.Task[None] | None = None
        self._endpoint_id: bytes = endpoint_id

        self._v1_registry: dict[
            int, Callable[[offline_wire_formats.OfflineFrame], Awaitable[None]]
        ] = {}

        self.register_v1_handler(
            offline_wire_formats.V1FrameFrameType.DISCONNECTION,
            self._handle_disconnection,
        )
        self.register_v1_handler(
            offline_wire_formats.V1FrameFrameType.KEEP_ALIVE,
            self._handle_keep_alive,
        )

    @property
    def auth_string(self) -> bytes:
        assert isinstance(self._backend, EncryptedBackend)  # noqa: S101
        return self._backend.auth_string

    async def send_bytes(self, data: bytes) -> None:
        await self._backend.send(data)

    async def recv_bytes(self) -> bytes:
        return await self._backend.recv()

    async def _send_transport_frame(
        self,
        frame: offline_wire_formats.OfflineFrame,
    ) -> None:
        frame_type = frame.v1.type
        logger.log(SILLY, "Sending transport frame type=%s", _frame_type_name(frame_type))
        await self._backend.send(bytes(frame))

    async def _send_payload_frame(  # noqa: PLR0913
        self,
        data: bytes,
        *,
        id: int,
        flags: int,
        payload_type: offline_wire_formats.PayloadTransferFramePayloadHeaderPayloadType,
        file_name: str | None = None,
        offset: int = 0,
        total_size: int | None = None,
    ) -> None:
        """Wrap data in PAYLOAD_TRANSFER."""
        logger.log(
            SILLY,
            "PAYLOAD_TRANSFER: id=%d type=%s flags=%02x len=%d offset=%d total=%s file=%s",
            id,
            offline_wire_formats.PayloadTransferFramePayloadHeaderPayloadType(payload_type).name,
            flags,
            len(data),
            offset,
            total_size,
            file_name,
        )
        frame_bytes = payloadify(
            data,
            id=id,
            flags=flags,
            type=payload_type,
            file_name=file_name,
            offset=offset,
            total_size=total_size,
        )
        await self._backend.send(frame_bytes)

    async def send_frame(self, frame: wire_format.Frame) -> None:
        """Serialise a wire_format.Frame and send as a BYTES payload."""
        data = bytes(frame)
        id_ = random.randint(0, 2**31 - 1)  # noqa: S311
        total = len(data)
        await self._send_payload_frame(
            data,
            id=id_,
            flags=0,
            payload_type=offline_wire_formats.PayloadTransferFramePayloadHeaderPayloadType.BYTES,
            total_size=total,
        )
        await self._send_payload_frame(
            b"",
            id=id_,
            flags=1,
            payload_type=offline_wire_formats.PayloadTransferFramePayloadHeaderPayloadType.BYTES,
            total_size=total,
        )

    async def send_file_chunk(  # noqa: PLR0913
        self,
        chunk: bytes,
        *,
        id: int,
        offset: int,
        total_size: int,
        file_name: str,
        flags: int = 0,
    ) -> None:
        """Send one chunk of a file payload."""
        await self._send_payload_frame(
            chunk,
            id=id,
            flags=flags,
            payload_type=offline_wire_formats.PayloadTransferFramePayloadHeaderPayloadType.FILE,
            file_name=file_name,
            offset=offset,
            total_size=total_size,
        )

    async def _handle_disconnection(self, _frame: offline_wire_formats.OfflineFrame) -> None:
        logger.debug("Received DISCONNECTION frame, closing connection")
        await self.close()

    async def _handle_keep_alive(self, _frame: offline_wire_formats.OfflineFrame) -> None:
        logger.debug("Received KEEP_ALIVE frame, ignoring")

    def register_v1_handler(
        self,
        frame_type: offline_wire_formats.V1FrameFrameType,
        handler: Callable[[offline_wire_formats.OfflineFrame], Awaitable[None]],
    ) -> None:
        self._v1_registry[frame_type] = handler

    async def iter_payloads(
        self,
    ) -> AsyncIterator[tuple[_PayloadHeader, bytes]]:
        """Yield complete (PayloadHeader, bytes) payloads."""
        incomplete: dict[int, io.BytesIO] = {}
        headers: dict[int, _PayloadHeader] = {}

        while not self._backend.reader.at_eof():
            try:
                raw = await self._backend.recv()
            except asyncio.IncompleteReadError:
                break

            frame = offline_wire_formats.OfflineFrame().parse(raw)
            frame_type = frame.v1.type
            logger.log(SILLY, "Received transport frame type=%s", _frame_type_name(frame_type))

            if frame_type in self._v1_registry:
                handler = self._v1_registry[frame_type]
                await handler(frame)
                continue

            if frame_type != offline_wire_formats.V1FrameFrameType.PAYLOAD_TRANSFER:
                logger.debug(
                    "Received unexpected frame type=%s, skipping",
                    _frame_type_name(frame_type),
                )
                continue

            payload_header = frame.v1.payload_transfer.payload_header
            payload_chunk = frame.v1.payload_transfer.payload_chunk

            if payload_header.id not in incomplete:
                incomplete[payload_header.id] = io.BytesIO()
                headers[payload_header.id] = payload_header

            buf = incomplete[payload_header.id]

            if payload_chunk.offset is None:
                logger.warning("Received payload chunk with no offset, treating as offset 0")
                payload_chunk.offset = 0

            buf.seek(payload_chunk.offset)
            buf.write(payload_chunk.body)

            logger.log(SILLY, "Received payload chunk %d", payload_header.id)

            if payload_chunk.flags is None:
                logger.warning("Received payload chunk with no flags, treating as incomplete")
                continue

            if payload_chunk.flags & 0b00000001:
                buf.seek(0)
                payload = buf.read()
                buf.close()
                incomplete.pop(payload_header.id)
                original_header = headers.pop(payload_header.id)
                yield original_header, payload

    def start_keep_alive(self) -> None:
        """Start the background keep-alive task."""
        self._keep_alive_task = create_task(self._keep_alive_loop())

    async def stop_keep_alive(self) -> None:
        """Cancel and await the keep-alive task."""
        if self._keep_alive_task is not None:
            self._keep_alive_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._keep_alive_task
            self._keep_alive_task = None

    async def _keep_alive_loop(self) -> None:
        frame = offline_wire_formats.OfflineFrame(
            version=offline_wire_formats.OfflineFrameVersion.V1,
            v1=offline_wire_formats.V1Frame(
                type=offline_wire_formats.V1FrameFrameType.KEEP_ALIVE,
                keep_alive=offline_wire_formats.KeepAliveFrame(ack=False),
            ),
        )
        while True:
            await self._send_transport_frame(frame)
            await asyncio.sleep(10)

    async def _finalize_old_channel(self) -> None:
        # 1. send LAST_WRITE_TO_PRIOR_CHANNEL
        # 2. wait for LAST_WRITE_TO_PRIOR_CHANNEL from the peer
        # 3. write a SAFE_TO_CLOSE_PRIOR_CHANNEL frame to the old channel
        # 4. keep reading until we get SAFE_TO_CLOSE_PRIOR_CHANNEL

        # LAST_WRITE_TO_PRIOR_CHANNEL on the old channel.
        last_write = offline_wire_formats.OfflineFrame(
            version=offline_wire_formats.OfflineFrameVersion.V1,
            v1=offline_wire_formats.V1Frame(
                type=offline_wire_formats.V1FrameFrameType.BANDWIDTH_UPGRADE_NEGOTIATION,
                bandwidth_upgrade_negotiation=offline_wire_formats.BandwidthUpgradeNegotiationFrame(
                    event_type=offline_wire_formats.BandwidthUpgradeNegotiationFrameEventType.LAST_WRITE_TO_PRIOR_CHANNEL,
                ),
            ),
        )
        await self._send_transport_frame(last_write)

        # Wait for LAST_WRITE_TO_PRIOR_CHANNEL from the old transport
        try:
            while True:
                raw = await self._backend.recv()
                f = offline_wire_formats.OfflineFrame().parse(raw)
                if f.v1.type == offline_wire_formats.V1FrameFrameType.BANDWIDTH_UPGRADE_NEGOTIATION:
                    if f.v1.bandwidth_upgrade_negotiation.event_type == (
                        offline_wire_formats.BandwidthUpgradeNegotiationFrameEventType.LAST_WRITE_TO_PRIOR_CHANNEL
                    ):
                        break
                    logger.warning(
                        "Expected LAST_WRITE_TO_PRIOR_CHANNEL, got bw event=%s",
                        _bw_event_name(f.v1.bandwidth_upgrade_negotiation.event_type),
                    )
                else:
                    logger.debug(
                        "Skipping frame type=%s while waiting for LAST_WRITE_TO_PRIOR_CHANNEL",
                        _frame_type_name(f.v1.type),
                    )
        except Exception:
            logger.exception("Error waiting for LAST_WRITE_TO_PRIOR_CHANNEL")

        # SAFE_TO_CLOSE_PRIOR_CHANNEL on the old channel.
        safe = offline_wire_formats.OfflineFrame(
            version=offline_wire_formats.OfflineFrameVersion.V1,
            v1=offline_wire_formats.V1Frame(
                type=offline_wire_formats.V1FrameFrameType.BANDWIDTH_UPGRADE_NEGOTIATION,
                bandwidth_upgrade_negotiation=offline_wire_formats.BandwidthUpgradeNegotiationFrame(
                    event_type=offline_wire_formats.BandwidthUpgradeNegotiationFrameEventType.SAFE_TO_CLOSE_PRIOR_CHANNEL,
                ),
            ),
        )
        await self._send_transport_frame(safe)

        # Wait for SAFE_TO_CLOSE_PRIOR_CHANNEL from the old transport
        try:
            while True:
                raw = await self._backend.recv()
                f = offline_wire_formats.OfflineFrame().parse(raw)
                if f.v1.type == offline_wire_formats.V1FrameFrameType.BANDWIDTH_UPGRADE_NEGOTIATION:
                    if f.v1.bandwidth_upgrade_negotiation.event_type == (
                        offline_wire_formats.BandwidthUpgradeNegotiationFrameEventType.SAFE_TO_CLOSE_PRIOR_CHANNEL
                    ):
                        break
                    logger.warning(
                        "Expected SAFE_TO_CLOSE_PRIOR_CHANNEL, got bw event=%s",
                        _bw_event_name(f.v1.bandwidth_upgrade_negotiation.event_type),
                    )
                else:
                    logger.debug(
                        "Skipping frame type=%s while waiting for SAFE_TO_CLOSE_PRIOR_CHANNEL",
                        _frame_type_name(f.v1.type),
                    )
        except Exception:
            logger.exception("Error waiting for SAFE_TO_CLOSE_PRIOR_CHANNEL")

        # swap the old backend back to Unencrypted and send a DISCONNECTION frame,
        # then close it with a wait_closed()

        # we need to store the last backend because it contains the encryption keys
        last_backend = self._backend

        self._backend = UnencryptedBackend(self._backend.reader, self._backend.writer)

        with contextlib.suppress(Exception):
            frame = offline_wire_formats.OfflineFrame(
                version=offline_wire_formats.OfflineFrameVersion.V1,
                v1=offline_wire_formats.V1Frame(
                    type=offline_wire_formats.V1FrameFrameType.DISCONNECTION,
                ),
            )
            await self._send_transport_frame(frame)

        await self._backend.writer.drain()
        self._backend.writer.close()
        with contextlib.suppress(Exception):
            await self._backend.writer.wait_closed()

        self._backend = last_backend

    async def close(self) -> None:
        """Send DISCONNECTION and close the writer."""
        with contextlib.suppress(Exception):
            frame = offline_wire_formats.OfflineFrame(
                version=offline_wire_formats.OfflineFrameVersion.V1,
                v1=offline_wire_formats.V1Frame(
                    type=offline_wire_formats.V1FrameFrameType.DISCONNECTION,
                ),
            )
            await self._send_transport_frame(frame)

        self._backend.writer.close()
        with contextlib.suppress(Exception):
            await self._backend.writer.wait_closed()
