from __future__ import annotations

import asyncio
import contextlib
import io
import random
from logging import getLogger
from typing import TYPE_CHECKING

from .backend import ConnectionBackend, EncryptedBackend, UnencryptedBackend
from .common import (
    create_task,
    generate_connection_response,
    payloadify,
)
from .dbus.p2p import connect_p2p_group
from .protos import (
    offline_wire_formats_pb2,
    wire_format_pb2,
)
from .ukey2 import do_client_key_exchange, do_server_key_exchange

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Awaitable, Callable

logger = getLogger(__name__)

_PayloadHeader = offline_wire_formats_pb2.PayloadTransferFrame.PayloadHeader


async def _exchange_connection_response_client(backend: ConnectionBackend) -> None:
    """Send our CONNECTION_RESPONSE and consume the peer's."""
    connection_response = generate_connection_response()
    await backend.send(connection_response.SerializeToString())
    await backend.recv()  # consume the peer's CONNECTION_RESPONSE


async def _exchange_connection_response_server(backend: ConnectionBackend) -> None:
    """Read CONNECTION_RESPONSE, send ours."""
    data = await backend.recv()
    client_response = offline_wire_formats_pb2.OfflineFrame()
    client_response.ParseFromString(data)
    os_name = offline_wire_formats_pb2.OsInfo.OsType.Name(
        client_response.v1.connection_response.os_info.type,
    )
    logger.debug("Client OS: %s", os_name)
    connection_response = generate_connection_response()
    await backend.send(connection_response.SerializeToString())


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

        # Upgrade gate: set = sends allowed, clear = upgrade in progress.
        self._upgrade_gate = asyncio.Event()
        self._upgrade_gate.set()

        # Idle tracker: set = no active sends, clear = at least one in flight.
        self._sends_idle = asyncio.Event()
        self._sends_idle.set()
        self._active_sends = 0

        # Holds a callable to destroy the P2P group if we do a WiFi Direct upgrade
        self._p2p_destroy: Callable[[], Awaitable[None]] | None = None

    @property
    def auth_string(self) -> bytes:
        assert isinstance(self._backend, EncryptedBackend)  # noqa: S101
        return self._backend.auth_string

    async def upgrade_client(self) -> bool:
        keychain = await do_client_key_exchange(self._backend)
        if keychain is None:
            return False
        await _exchange_connection_response_client(self._backend)
        self._backend = EncryptedBackend(
            self._backend.reader,
            self._backend.writer,
            keychain,
        )
        return True

    async def upgrade_server(self) -> bool:
        keychain = await do_server_key_exchange(self._backend)
        if keychain is None:
            return False
        await _exchange_connection_response_server(self._backend)
        self._backend = EncryptedBackend(
            self._backend.reader,
            self._backend.writer,
            keychain,
        )
        return True

    async def send_bytes(self, data: bytes) -> None:
        await self._backend.send(data)

    async def recv_bytes(self) -> bytes:
        return await self._backend.recv()

    async def _send_transport_frame(
        self,
        frame: offline_wire_formats_pb2.OfflineFrame,
    ) -> None:
        await self._backend.send(frame.SerializeToString())

    async def _send_payload_frame(  # noqa: PLR0913
        self,
        data: bytes,
        *,
        id: int,
        flags: int,
        payload_type: offline_wire_formats_pb2.PayloadTransferFrame.PayloadHeader.PayloadType,
        file_name: str | None = None,
        offset: int = 0,
        total_size: int | None = None,
    ) -> None:
        """Wrap data in PAYLOAD_TRANSFER."""
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

    async def send_frame(self, frame: wire_format_pb2.Frame) -> None:
        """Serialise a wire_format_pb2.Frame and send as a BYTES payload."""
        data = frame.SerializeToString()
        id_ = random.randint(0, 2**31 - 1)  # noqa: S311
        total = len(data)
        await self._send_payload_frame(
            data,
            id=id_,
            flags=0,
            payload_type=offline_wire_formats_pb2.PayloadTransferFrame.PayloadHeader.BYTES,
            total_size=total,
        )
        await self._send_payload_frame(
            b"",
            id=id_,
            flags=1,
            payload_type=offline_wire_formats_pb2.PayloadTransferFrame.PayloadHeader.BYTES,
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
        await self._upgrade_gate.wait()
        self._active_sends += 1
        self._sends_idle.clear()

        try:
            await self._send_payload_frame(
                chunk,
                id=id,
                flags=flags,
                payload_type=offline_wire_formats_pb2.PayloadTransferFrame.PayloadHeader.FILE,
                file_name=file_name,
                offset=offset,
                total_size=total_size,
            )
        finally:
            self._active_sends -= 1
            if self._active_sends == 0:
                self._sends_idle.set()

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

            frame = offline_wire_formats_pb2.OfflineFrame()
            frame.ParseFromString(raw)
            frame_type = frame.v1.type

            if frame_type == offline_wire_formats_pb2.V1Frame.DISCONNECTION:
                logger.debug("Received DISCONNECTION")
                break

            if frame_type == offline_wire_formats_pb2.V1Frame.KEEP_ALIVE:
                logger.debug("Received KEEP_ALIVE")
                continue

            if frame_type == offline_wire_formats_pb2.V1Frame.BANDWIDTH_UPGRADE_NEGOTIATION:
                await self._handle_bandwidth_upgrade(frame.v1.bandwidth_upgrade_negotiation)
                continue

            if frame_type != offline_wire_formats_pb2.V1Frame.PAYLOAD_TRANSFER:
                logger.debug("Received unexpected frame type %d, skipping", frame_type)
                continue

            payload_header = frame.v1.payload_transfer.payload_header
            payload_chunk = frame.v1.payload_transfer.payload_chunk

            if payload_header.id not in incomplete:
                incomplete[payload_header.id] = io.BytesIO()
                headers[payload_header.id] = payload_header

            buf = incomplete[payload_header.id]
            buf.seek(payload_chunk.offset)
            buf.write(payload_chunk.body)

            logger.debug("Received payload chunk %d", payload_header.id)

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
        frame = offline_wire_formats_pb2.OfflineFrame()
        frame.version = offline_wire_formats_pb2.OfflineFrame.V1
        frame.v1.type = offline_wire_formats_pb2.V1Frame.KEEP_ALIVE
        frame.v1.keep_alive.ack = False
        while True:
            await self._send_transport_frame(frame)
            await asyncio.sleep(10)

    async def _resolve_upgrade_endpoint(
        self,
        path: offline_wire_formats_pb2.BandwidthUpgradeNegotiationFrame.UpgradePathInfo,
    ) -> tuple[str, int] | None:
        """Return (ip, port) for the upgrade medium, or None to abort."""
        Medium = offline_wire_formats_pb2.BandwidthUpgradeNegotiationFrame.UpgradePathInfo  # noqa: N806
        medium = path.medium

        if medium == Medium.WIFI_DIRECT:
            creds = path.wifi_direct_credentials
            ip = creds.gateway
            port = creds.port
            logger.debug(
                "WiFi Direct upgrade to %s:%d (SSID=%r freq=%d)",
                ip,
                port,
                creds.ssid,
                creds.frequency,
            )
            try:
                start_time = asyncio.get_event_loop().time()
                destroy = await connect_p2p_group(
                    creds.ssid, creds.password, creds.frequency, creds.gateway
                )
                elapsed = asyncio.get_event_loop().time() - start_time
                logger.debug("Connecting to P2P group took %.2f seconds", elapsed)
            except Exception:
                logger.exception("Failed to join P2P group %r", creds.ssid)
                return None
            self._p2p_destroy = destroy
            return ip, port

        logger.warning("Unsupported upgrade medium %d, ignoring", medium)
        return None

    async def _handle_bandwidth_upgrade(
        self,
        upgrade_frame: offline_wire_formats_pb2.BandwidthUpgradeNegotiationFrame,
    ) -> None:
        logger.debug("Received BANDWIDTH_UPGRADE_NEGOTIATION event %d", upgrade_frame.event_type)

        if upgrade_frame.event_type != (
            offline_wire_formats_pb2.BandwidthUpgradeNegotiationFrame.UPGRADE_PATH_AVAILABLE
        ):
            return

        result = await self._resolve_upgrade_endpoint(upgrade_frame.upgrade_path_info)
        if result is None:
            return
        ip, port = result

        # Pause outgoing file sends and wait for any in-flight chunk to finish.
        self._upgrade_gate.clear()
        await self._sends_idle.wait()

        # Connect to the new transport endpoint.
        try:
            new_reader, new_writer = await asyncio.open_connection(ip, port)
        except Exception:
            logger.exception("Failed to connect to upgraded endpoint %s:%d", ip, port)
            self._upgrade_gate.set()
            return

        new_channel = UnencryptedBackend(new_reader, new_writer)

        # CLIENT_INTRODUCTION on new channel
        intro = offline_wire_formats_pb2.OfflineFrame()
        intro.version = offline_wire_formats_pb2.OfflineFrame.V1
        intro.v1.type = offline_wire_formats_pb2.V1Frame.BANDWIDTH_UPGRADE_NEGOTIATION
        intro.v1.bandwidth_upgrade_negotiation.event_type = (
            offline_wire_formats_pb2.BandwidthUpgradeNegotiationFrame.CLIENT_INTRODUCTION
        )
        intro.v1.bandwidth_upgrade_negotiation.client_introduction.endpoint_id = (
            self._endpoint_id.decode("ascii") if self._endpoint_id else ""
        )
        intro.v1.bandwidth_upgrade_negotiation.client_introduction.supports_disabling_encryption = (
            False
        )
        await new_channel.send(intro.SerializeToString())

        if upgrade_frame.upgrade_path_info.supports_client_introduction_ack:
            try:
                raw = await new_channel.recv()
                ack = offline_wire_formats_pb2.OfflineFrame()
                ack.ParseFromString(raw)
                if ack.v1.bandwidth_upgrade_negotiation.event_type != (
                    offline_wire_formats_pb2.BandwidthUpgradeNegotiationFrame.CLIENT_INTRODUCTION_ACK
                ):
                    logger.warning(
                        "Expected CLIENT_INTRODUCTION_ACK, got event %d",
                        ack.v1.bandwidth_upgrade_negotiation.event_type,
                    )
            except Exception:
                logger.exception("Failed to receive CLIENT_INTRODUCTION_ACK")
                new_writer.close()
                self._upgrade_gate.set()
                return

        await self._finalize_old_channel()

        # Swap to the encrypted backend on the new channel, reusing existing keys.
        assert isinstance(self._backend, EncryptedBackend)  # noqa: S101
        self._backend.replace(new_reader, new_writer)
        logger.debug("Switched to upgraded transport channel %s:%d", ip, port)
        self._upgrade_gate.set()  # resume sends, now transparently routed through new backend

    async def _finalize_old_channel(self) -> None:
        # 1. send LAST_WRITE_TO_PRIOR_CHANNEL
        # 2. wait for LAST_WRITE_TO_PRIOR_CHANNEL from the peer
        # 3. write a SAFE_TO_CLOSE_PRIOR_CHANNEL frame to the old channel
        # 4. keep reading until we get SAFE_TO_CLOSE_PRIOR_CHANNEL

        # LAST_WRITE_TO_PRIOR_CHANNEL on the old channel.
        last_write = offline_wire_formats_pb2.OfflineFrame()
        last_write.version = offline_wire_formats_pb2.OfflineFrame.V1
        last_write.v1.type = offline_wire_formats_pb2.V1Frame.BANDWIDTH_UPGRADE_NEGOTIATION
        last_write.v1.bandwidth_upgrade_negotiation.event_type = (
            offline_wire_formats_pb2.BandwidthUpgradeNegotiationFrame.LAST_WRITE_TO_PRIOR_CHANNEL
        )
        await self._send_transport_frame(last_write)

        # Wait for LAST_WRITE_TO_PRIOR_CHANNEL from the old transport
        try:
            while True:
                raw = await self._backend.recv()
                f = offline_wire_formats_pb2.OfflineFrame()
                f.ParseFromString(raw)
                if f.v1.type == offline_wire_formats_pb2.V1Frame.BANDWIDTH_UPGRADE_NEGOTIATION:
                    if f.v1.bandwidth_upgrade_negotiation.event_type == (
                        offline_wire_formats_pb2.BandwidthUpgradeNegotiationFrame.LAST_WRITE_TO_PRIOR_CHANNEL
                    ):
                        break
                    logger.warning(
                        "Expected LAST_WRITE_TO_PRIOR_CHANNEL, got bw event %d",
                        f.v1.bandwidth_upgrade_negotiation.event_type,
                    )
                else:
                    logger.debug(
                        "Skipping frame type %d while waiting for LAST_WRITE_TO_PRIOR_CHANNEL",
                        f.v1.type,
                    )
        except Exception:
            logger.exception("Error waiting for LAST_WRITE_TO_PRIOR_CHANNEL")

        # SAFE_TO_CLOSE_PRIOR_CHANNEL on the old channel.
        safe = offline_wire_formats_pb2.OfflineFrame()
        safe.version = offline_wire_formats_pb2.OfflineFrame.V1
        safe.v1.type = offline_wire_formats_pb2.V1Frame.BANDWIDTH_UPGRADE_NEGOTIATION
        safe.v1.bandwidth_upgrade_negotiation.event_type = (
            offline_wire_formats_pb2.BandwidthUpgradeNegotiationFrame.SAFE_TO_CLOSE_PRIOR_CHANNEL
        )
        await self._send_transport_frame(safe)

        # Wait for SAFE_TO_CLOSE_PRIOR_CHANNEL from the old transport
        try:
            while True:
                raw = await self._backend.recv()
                f = offline_wire_formats_pb2.OfflineFrame()
                f.ParseFromString(raw)
                if f.v1.type == offline_wire_formats_pb2.V1Frame.BANDWIDTH_UPGRADE_NEGOTIATION:
                    if f.v1.bandwidth_upgrade_negotiation.event_type == (
                        offline_wire_formats_pb2.BandwidthUpgradeNegotiationFrame.SAFE_TO_CLOSE_PRIOR_CHANNEL
                    ):
                        break
                    logger.warning(
                        "Expected SAFE_TO_CLOSE_PRIOR_CHANNEL, got bw event %d",
                        f.v1.bandwidth_upgrade_negotiation.event_type,
                    )
                else:
                    logger.debug(
                        "Skipping frame type %d while waiting for SAFE_TO_CLOSE_PRIOR_CHANNEL",
                        f.v1.type,
                    )
        except Exception:
            logger.exception("Error waiting for SAFE_TO_CLOSE_PRIOR_CHANNEL")

        # swap the old backend back to Unencrypted and send a DISCONNECTION frame,
        # then close it with a wait_closed()

        # we need to store the last backend because it contains the encryption keys
        last_backend = self._backend

        self._backend = UnencryptedBackend(self._backend.reader, self._backend.writer)

        with contextlib.suppress(Exception):
            frame = offline_wire_formats_pb2.OfflineFrame()
            frame.version = offline_wire_formats_pb2.OfflineFrame.V1
            frame.v1.type = offline_wire_formats_pb2.V1Frame.DISCONNECTION
            await self._send_transport_frame(frame)

        await self._backend.writer.drain()
        self._backend.writer.close()
        with contextlib.suppress(Exception):
            await self._backend.writer.wait_closed()

        self._backend = last_backend

    async def close(self) -> None:
        """Send DISCONNECTION and close the writer."""
        with contextlib.suppress(Exception):
            frame = offline_wire_formats_pb2.OfflineFrame()
            frame.version = offline_wire_formats_pb2.OfflineFrame.V1
            frame.v1.type = offline_wire_formats_pb2.V1Frame.DISCONNECTION
            await self._send_transport_frame(frame)

        self._backend.writer.close()
        with contextlib.suppress(Exception):
            await self._backend.writer.wait_closed()

        if self._p2p_destroy is not None:
            with contextlib.suppress(Exception):
                await self._p2p_destroy()
            self._p2p_destroy = None
