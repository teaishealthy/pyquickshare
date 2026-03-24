from __future__ import annotations

import abc
import asyncio
import contextlib
import pathlib
import random
import socket
import string
import time
from logging import getLogger
from typing import TYPE_CHECKING

import aiofile
import betterproto
import magic

from pyquickshare.ukey2 import do_client_key_exchange

from .backend import EncryptedBackend, UnencryptedBackend
from .bluetooth import BluetoothDevice, connect_bluetooth_device, find_receiving_devices
from .common import (
    Type,
    create_task,
    derive_endpoint_id_from_mac,
    from_url64,
    generate_connection_response,
    generate_paired_key_encryption,
    pick_mac_deterministically,
)
from .connection import NearbyConnection, _bw_event_name
from .dbus.p2p import connect_p2p_group
from .facts import Facts, collect_facts
from .mdns.receive import (
    EndpointInfo,
    get_interfaces,
    make_n,
    parse_endpoint_info,
)
from .mdns.send import discover_services as _discover_services
from .protos import offline_wire_formats, wire_format
from .qrcode import QRCode, decrypt_qrcode_record, generate_qr

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from zeroconf.asyncio import AsyncServiceInfo

logger = getLogger(__name__)

NAME = "pyquickshare"
CHUNK_SIZE = 64 * 1024

UpgradeMedium = offline_wire_formats.BandwidthUpgradeNegotiationFrameUpgradePathInfoMedium


class Connectable(abc.ABC):
    facts: Facts

    def __init__(self, *, facts: Facts) -> None:
        self.facts = facts

    @abc.abstractmethod
    async def connect(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter] | None: ...

    @property
    @abc.abstractmethod
    def connectable(self) -> bool: ...

    @property
    @abc.abstractmethod
    def endpoint_info(self) -> EndpointInfo | None: ...

    async def send(self, file: str) -> None:
        """Send a file to a device.

        Args:
            device (Device): The device to send to
            file (str): The file to send
        """
        maybe = await self.connect()

        if maybe is None:
            logger.error("Failed to connect to the device")
            return None

        reader, writer = maybe

        qr_code = None
        if isinstance(self, WifiConnectable):
            qr_code = self.qr_code

        return await _handle_target(file, reader, writer, qrcode=qr_code, facts=self.facts)


class WifiConnectable(Connectable):
    def __init__(self, *, service_info: AsyncServiceInfo, qr_code: QRCode, facts: Facts) -> None:
        self.service_info = service_info
        self.qr_code = qr_code
        self._connectable = True

        name = self.service_info.name.split(".")[0].lstrip("_")
        decoded = from_url64(name)
        self.peer_endpoint_id = decoded[1:5].decode("ascii")

        logger.debug("Discovered endpoint %r", self.peer_endpoint_id)

        n_raw = self.service_info.properties.get(b"n")
        if n_raw is not None:
            self._endpoint_info: EndpointInfo | None = parse_endpoint_info(n_raw)

            if self._endpoint_info.visible is False:
                if 1 not in self._endpoint_info.records:
                    logger.debug("Can't parse a hidden endpoint without a QR code record, aborting")
                    self._connectable = False
                    return

                keychain = self.qr_code.keychain()
                name_ = decrypt_qrcode_record(self._endpoint_info.records[1], keychain).decode(
                    "utf-8"
                )
                self._endpoint_info = self._endpoint_info._replace(name=name_)

        super().__init__(facts=facts)

    @property
    def endpoint_info(self) -> EndpointInfo | None:
        return self._endpoint_info

    @property
    def connectable(self) -> bool:
        return self._endpoint_info is not None and self._connectable

    async def connect(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter] | None:
        if not self.connectable:
            logger.error("Endpoint %r is not connectable", self.peer_endpoint_id)
            return None

        assert self._endpoint_info is not None  # noqa: S101 - escape hatch for the type checker

        logger.debug(
            "Endpoint %r has name %r and type %r",
            self.peer_endpoint_id,
            self._endpoint_info.name,
            self._endpoint_info.type,
        )

        address: str | None = None
        for addr in self.service_info.addresses:
            try:
                address = socket.inet_ntoa(addr)
                socket.gethostbyaddr(address)
                break
            except socket.herror:
                logger.debug("Address %r is not resolvable", address)

        if address is None:
            logger.error("No resolvable addresses found, aborting")
            return None

        logger.debug("Connecting to %s:%d", address, self.service_info.port)

        return await asyncio.open_connection(address, self.service_info.port)


class BluetoothConnectable(Connectable):
    def __init__(self, device: BluetoothDevice, *, facts: Facts) -> None:
        self.device = device
        self._endpoint_info = device.endpoint_info

        super().__init__(facts=facts)

    @property
    def endpoint_info(self) -> EndpointInfo:
        return self._endpoint_info

    async def connect(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter] | None:
        logger.debug("Connecting to Bluetooth device %r", self.device)
        try:
            sock = await connect_bluetooth_device(self.device)
        except Exception:
            logger.exception("Failed to connect to Bluetooth device: %s")
            return None

        reader, writer = await asyncio.open_connection(sock=sock)
        return reader, writer

    @property
    def connectable(self) -> bool:
        return self.endpoint_info.visible is not False


def _mime_to_type(mime_type: str) -> wire_format.FileMetadataType:
    namespace = mime_type.split("/", maxsplit=1)[0]

    if namespace == "audio":
        return wire_format.FileMetadataType.AUDIO
    if namespace == "image":
        return wire_format.FileMetadataType.IMAGE
    if namespace == "video":
        return wire_format.FileMetadataType.VIDEO

    return wire_format.FileMetadataType.UNKNOWN


def _generate_file_metadata(fp: str, id: int) -> wire_format.FileMetadata:
    path = pathlib.Path(fp)

    mime = magic.from_file(  # pyright: ignore[reportUnknownMemberType]
        fp,
        mime=True,
    )
    size = path.stat().st_size
    name = path.name

    return wire_format.FileMetadata(
        name=name,
        type=_mime_to_type(mime),
        mime_type=mime,
        size=size,
        payload_id=id,
    )


def generate_endpoint_id() -> bytes:
    """Generate a random 4-byte endpoint ID.

    Example:
        .. code-block:: python

            endpoint_id = generate_endpoint_id()
            async for request in receive(endpoint_id=endpoint_id):
                ...

    Returns:
        bytes: The generated endpoint ID

    """
    # 4-byte alphanum
    return "".join(random.choices(string.ascii_letters + string.digits, k=4)).encode(  # noqa: S311
        "ascii",
    )


class _DiscoverIterator:
    def __init__(self, *, facts: Facts) -> None:
        self.facts = facts
        self.qr_code = generate_qr()
        self.queue: asyncio.Queue[Connectable] | None = None

    async def start(self) -> None:
        self.queue = asyncio.Queue()

        if self.facts.bluetooth:
            tasks = [self._lan(self.queue), self._bluetooth(self.queue)]
            logger.debug("Starting discovery over MDNS and Bluetooth")
        else:
            tasks = [self._lan(self.queue)]
            logger.debug("Starting discovery over MDNS only (Bluetooth not available)")

        for task in tasks:
            create_task(task)

    async def _lan(self, queue: asyncio.Queue[Connectable]) -> None:
        local_queue = await _discover_services(self.facts)
        while True:
            service_info = await local_queue.get()
            connectable = WifiConnectable(
                service_info=service_info,
                qr_code=self.qr_code,
                facts=self.facts,
            )
            await queue.put(connectable)

    async def _bluetooth(self, queue: asyncio.Queue[Connectable]) -> None:
        async for device in find_receiving_devices():
            connectable = BluetoothConnectable(device=device, facts=self.facts)
            await queue.put(connectable)

    async def __anext__(self) -> Connectable:
        assert self.queue is not None  # noqa: S101 - escape hatch for the type checker
        return await self.queue.get()

    def __aiter__(self) -> _DiscoverIterator:
        return self


async def discover_services() -> _DiscoverIterator:
    """Discover Quick Share devices.

    Example:
        .. code-block:: python

            async for service in discover_services():
                print(service)
    """
    facts = await collect_facts()

    iterator = _DiscoverIterator(facts=facts)
    await iterator.start()
    await asyncio.sleep(0)
    return iterator


async def _handle_target(
    file: str,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    facts: Facts,
    qrcode: QRCode | None = None,
) -> None:
    endpoint_id = generate_endpoint_id()
    conn = SendConnection(reader, writer, endpoint_id=endpoint_id)
    derive_endpoint_id_from_mac(pick_mac_deterministically(get_interfaces()))

    await conn.send_connection_request(endpoint_id, facts=facts)

    if not await conn.upgrade_client():
        return

    await conn.do_paired_key_handshake(qrcode)

    conn.start_keep_alive()

    id = random.randint(0, 2**31 - 1)  # noqa: S311 - random is fine here
    await conn.send_introduction(file, id)
    await conn.wait_for_accept(file, id)

    await conn.stop_keep_alive()
    await conn.close()
    with contextlib.suppress(Exception):
        writer.close()
        await writer.wait_closed()


class SendConnection(NearbyConnection):
    def __init__(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, *, endpoint_id: bytes
    ) -> None:
        super().__init__(reader, writer, endpoint_id=endpoint_id)

        # Upgrade gate: set = sends allowed, clear = upgrade in progress.
        self._upgrade_gate = asyncio.Event()
        self._upgrade_gate.set()

        # Idle tracker: set = no active sends, clear = at least one in flight.
        self._sends_idle = asyncio.Event()
        self._sends_idle.set()
        self._active_sends = 0

        # Holds a callable to destroy the P2P group if we do a WiFi Direct upgrade
        self._p2p_destroy: Callable[[], Awaitable[None]] | None = None

        self.register_v1_handler(
            offline_wire_formats.V1FrameFrameType.BANDWIDTH_UPGRADE_NEGOTIATION,
            self._handle_bandwidth_upgrade,
        )

    async def _exchange_connection_response_client(self) -> None:
        """Send our CONNECTION_RESPONSE and consume the peer's."""
        connection_response = generate_connection_response()
        await self._backend.send(bytes(connection_response))
        await self._backend.recv()  # consume the peer's CONNECTION_RESPONSE

    async def upgrade_client(self) -> bool:
        keychain = await do_client_key_exchange(self._backend)
        if keychain is None:
            return False
        await self._exchange_connection_response_client()
        self._backend = EncryptedBackend(
            self._backend.reader,
            self._backend.writer,
            keychain,
        )
        return True

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
            await super().send_file_chunk(
                chunk,
                id=id,
                offset=offset,
                total_size=total_size,
                file_name=file_name,
                flags=flags,
            )
        finally:
            self._active_sends -= 1
            if self._active_sends == 0:
                self._sends_idle.set()

    async def close(self) -> None:
        await super().close()

        if self._p2p_destroy is not None:
            with contextlib.suppress(Exception):
                await self._p2p_destroy()
            self._p2p_destroy = None

    async def _send_file(
        self,
        *,
        file: str,
        id: int,
    ) -> None:
        start_time = time.perf_counter()
        path = pathlib.Path(file)
        total_size = path.stat().st_size  # noqa: ASYNC240 - stat should be fine
        logger.debug("Sending file %r", file)
        file_name = path.name

        last_time = start_time

        async with aiofile.async_open(file, "rb") as f:
            for offset in range(0, total_size, CHUNK_SIZE):
                f.seek(offset)
                chunk = await f.read(CHUNK_SIZE)
                if not chunk:
                    break
                await self.send_file_chunk(
                    chunk,
                    id=id,
                    offset=offset,
                    total_size=total_size,
                    file_name=file_name,
                )
                # log progress at most once per second, to avoid spamming the logs for large files
                if time.perf_counter() - last_time > 1:
                    logger.debug("Sent %d/%d bytes", offset + len(chunk), total_size)
                    last_time = time.perf_counter()

            await self.send_file_chunk(
                b"",
                id=id,
                offset=total_size,
                total_size=total_size,
                file_name=file_name,
                flags=1,
            )

        end_time = time.perf_counter()
        megabytes_per_second = (total_size / 1024 / 1024) / (end_time - start_time)

        logger.debug(
            "Took %.2f seconds to send %d bytes (%.2f MB/s)",
            end_time - start_time,
            total_size,
            megabytes_per_second,
        )

    async def send_connection_request(self, endpoint_id: bytes, *, facts: Facts) -> None:
        # TODO: populate from system (iw, NetworkManager, etc.)

        mediums = [
            offline_wire_formats.ConnectionRequestFrameMedium.WIFI_LAN,
        ]

        meta = betterproto.PLACEHOLDER

        if facts.network_manager:
            wifi_channels = [36, 40, 44, 48, 149, 153, 157, 161]  # common 5GHz
            meta = offline_wire_formats.MediumMetadata(
                supports_5_ghz=True,
                supports_6_ghz=False,
                mobile_radio=False,
                ap_frequency=5180,  # placeholder
                available_channels=offline_wire_formats.AvailableChannels(channels=wifi_channels),
                wifi_lan_usable_channels=offline_wire_formats.WifiLanUsableChannels(
                    channels=wifi_channels
                ),
                wifi_direct_cli_usable_channels=offline_wire_formats.WifiDirectCliUsableChannels(
                    channels=wifi_channels
                ),
            )
            mediums.append(offline_wire_formats.ConnectionRequestFrameMedium.WIFI_DIRECT)

        connection_request = offline_wire_formats.OfflineFrame(
            version=offline_wire_formats.OfflineFrameVersion.V1,
            v1=offline_wire_formats.V1Frame(
                type=offline_wire_formats.V1FrameFrameType.CONNECTION_REQUEST,
                connection_request=offline_wire_formats.ConnectionRequestFrame(
                    endpoint_name=socket.gethostname(),
                    endpoint_id=endpoint_id.decode("ascii"),
                    endpoint_info=bytes(
                        make_n(visible=True, type=Type.laptop, name=NAME.encode("utf-8")),
                    ),
                    mediums=mediums,
                    medium_metadata=meta,
                ),
            ),
        )

        await self.send_bytes(bytes(connection_request))

    async def do_paired_key_handshake(
        self,
        qrcode: QRCode | None,
    ) -> None:
        """Exchange PAIRED_KEY_ENCRYPTION and PAIRED_KEY_RESULT (application layer)."""
        qr_code_handshake_data = None

        if qrcode:
            qr_code_handshake_data = qrcode.qr_code_handshake_data(self.auth_string)

        paired_key_encryption = generate_paired_key_encryption(qr_code_handshake_data)
        await self.send_frame(paired_key_encryption)

        await anext(self.iter_payloads())  # consume the peer's PAIRED_KEY_RESULT

        paired_key_result = wire_format.Frame(
            version=wire_format.FrameVersion.V1,
            v1=wire_format.V1Frame(
                type=wire_format.V1FrameFrameType.PAIRED_KEY_RESULT,
                paired_key_result=wire_format.PairedKeyResultFrame(
                    status=wire_format.PairedKeyResultFrameStatus.UNABLE,
                ),
            ),
        )
        await self.send_frame(paired_key_result)

    async def send_introduction(
        self,
        file: str,
        id: int,
    ) -> None:
        meta = _generate_file_metadata(file, id)
        introduction_frame = wire_format.Frame(
            version=wire_format.FrameVersion.V1,
            v1=wire_format.V1Frame(
                type=wire_format.V1FrameFrameType.INTRODUCTION,
                introduction=wire_format.IntroductionFrame(
                    file_metadata=[meta],
                ),
            ),
        )
        await self.send_frame(introduction_frame)

    async def wait_for_accept(
        self,
        file: str,
        id: int,
    ) -> None:
        send_task: asyncio.Task[None] | None = None

        async for payload_header, data in self.iter_payloads():
            wire_frame = wire_format.Frame().parse(data)

            if wire_frame.v1.type == wire_format.V1FrameFrameType.PAIRED_KEY_RESULT:
                # we know we failed this, and we can just ignore it
                ...
            elif wire_frame.v1.type == wire_format.V1FrameFrameType.RESPONSE:
                status = wire_frame.v1.connection_response.status

                if status == wire_format.ConnectionResponseFrameStatus.ACCEPT:
                    logger.debug("Peer accepted our introduction. Ready to send")
                    send_task = create_task(self._send_file(file=file, id=id))
                else:
                    logger.debug("Peer rejected our introduction. Aborting")
                    break
            else:
                logger.warning(
                    "Received unknown frame %d type %d", payload_header.id, wire_frame.v1.type
                )  # noqa: RUF100

        if send_task is not None:
            await send_task

    async def _resolve_upgrade_endpoint(
        self,
        path: offline_wire_formats.BandwidthUpgradeNegotiationFrameUpgradePathInfo,
    ) -> tuple[str, int] | None:
        """Return (ip, port) for the upgrade medium, or None to abort."""
        medium = path.medium
        if medium == UpgradeMedium.WIFI_DIRECT:
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
        frame: offline_wire_formats.OfflineFrame,
    ) -> None:
        upgrade_frame = frame.v1.bandwidth_upgrade_negotiation

        logger.debug(
            "Received BANDWIDTH_UPGRADE_NEGOTIATION event=%s",
            _bw_event_name(upgrade_frame.event_type),
        )

        if upgrade_frame.event_type != (
            offline_wire_formats.BandwidthUpgradeNegotiationFrameEventType.UPGRADE_PATH_AVAILABLE
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
        intro = offline_wire_formats.OfflineFrame(
            version=offline_wire_formats.OfflineFrameVersion.V1,
            v1=offline_wire_formats.V1Frame(
                type=offline_wire_formats.V1FrameFrameType.BANDWIDTH_UPGRADE_NEGOTIATION,
                bandwidth_upgrade_negotiation=offline_wire_formats.BandwidthUpgradeNegotiationFrame(
                    event_type=offline_wire_formats.BandwidthUpgradeNegotiationFrameEventType.CLIENT_INTRODUCTION,
                    client_introduction=offline_wire_formats.BandwidthUpgradeNegotiationFrameClientIntroduction(
                        endpoint_id=self._endpoint_id.decode("ascii") if self._endpoint_id else "",
                        supports_disabling_encryption=False,
                    ),
                ),
            ),
        )
        await new_channel.send(bytes(intro))

        if upgrade_frame.upgrade_path_info.supports_client_introduction_ack:
            try:
                raw = await new_channel.recv()
                ack = offline_wire_formats.OfflineFrame().parse(raw)
                if ack.v1.bandwidth_upgrade_negotiation.event_type != (
                    offline_wire_formats.BandwidthUpgradeNegotiationFrameEventType.CLIENT_INTRODUCTION_ACK
                ):
                    logger.warning(
                        "Expected CLIENT_INTRODUCTION_ACK, got event=%s",
                        _bw_event_name(ack.v1.bandwidth_upgrade_negotiation.event_type),
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
