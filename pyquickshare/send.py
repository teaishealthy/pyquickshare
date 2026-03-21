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
import magic

from .bluetooth import BluetoothDevice, connect_bluetooth_device, find_receiving_devices
from .common import (
    Type,
    create_task,
    derive_endpoint_id_from_mac,
    from_url64,
    generate_paired_key_encryption,
    pick_mac_deterministically,
)
from .connection import NearbyConnection
from .mdns.receive import (
    EndpointInfo,
    get_interfaces,
    make_n,
    parse_endpoint_info,
)
from .mdns.send import discover_services as _discover_services
from .protos import (
    offline_wire_formats_pb2,
    wire_format_pb2,
)
from .qrcode import QRCode, decrypt_qrcode_record, generate_qr

if TYPE_CHECKING:
    from zeroconf.asyncio import AsyncServiceInfo

logger = getLogger(__name__)

NAME = "pyquickshare"
CHUNK_SIZE = 64 * 1024


class Connectable(abc.ABC):
    @abc.abstractmethod
    async def connect(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter] | None: ...

    @property
    @abc.abstractmethod
    def connectable(self) -> bool: ...

    @property
    @abc.abstractmethod
    def endpoint_info(self) -> EndpointInfo | None: ...


class WifiConnectable(Connectable):
    def __init__(self, *, service_info: AsyncServiceInfo, qr_code: QRCode) -> None:
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
    def __init__(self, device: BluetoothDevice) -> None:
        self.device = device
        self._endpoint_info = device.endpoint_info

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


def _mime_to_type(mime_type: str) -> wire_format_pb2.FileMetadata.Type:
    namespace = mime_type.split("/", maxsplit=1)[0]

    if namespace == "audio":
        return wire_format_pb2.FileMetadata.AUDIO
    if namespace == "image":
        return wire_format_pb2.FileMetadata.IMAGE
    if namespace == "video":
        return wire_format_pb2.FileMetadata.VIDEO

    return wire_format_pb2.FileMetadata.UNKNOWN


def _generate_file_metadata(fp: str, id: int) -> wire_format_pb2.FileMetadata:
    path = pathlib.Path(fp)

    mime = magic.from_file(  # pyright: ignore[reportUnknownMemberType]
        fp,
        mime=True,
    )
    size = path.stat().st_size
    name = path.name

    return wire_format_pb2.FileMetadata(
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
    def __init__(self) -> None:
        self.qr_code = generate_qr()
        self.queue: asyncio.Queue[Connectable] | None = None

    async def start(self) -> None:
        self.queue = asyncio.Queue()

        for task in [self._wifi(self.queue), self._bluetooth(self.queue)]:
            create_task(task)

    async def _wifi(self, queue: asyncio.Queue[Connectable]) -> None:
        local_queue = await _discover_services()
        while True:
            service_info = await local_queue.get()
            connectable = WifiConnectable(service_info=service_info, qr_code=self.qr_code)
            await queue.put(connectable)

    async def _bluetooth(self, queue: asyncio.Queue[Connectable]) -> None:
        async for device in find_receiving_devices():
            connectable = BluetoothConnectable(device=device)
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
    iterator = _DiscoverIterator()
    await iterator.start()
    await asyncio.sleep(0)
    return iterator


async def _send_file(
    *,
    file: str,
    conn: NearbyConnection,
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
            await conn.send_file_chunk(
                chunk,
                id=id,
                offset=offset,
                total_size=total_size,
                file_name=file_name,
            )
            if time.perf_counter() - last_time > 1:
                # log progress at most once per second, to avoid spamming the logs for large files
                logger.debug("Sent %d/%d bytes", offset + len(chunk), total_size)
                last_time = time.perf_counter()

        await conn.send_file_chunk(
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


async def send_to(device: Connectable, *, file: str) -> None:
    """Send a file to a device.

    Args:
        device (Device): The device to send to
        file (str): The file to send
    """
    maybe = await device.connect()

    if maybe is None:
        logger.error("Failed to connect to the device")
        return None

    reader, writer = maybe

    qr_code = None
    if isinstance(device, WifiConnectable):
        qr_code = device.qr_code

    return await _handle_target(file, reader, writer, qrcode=qr_code)


async def _send_connection_request(conn: NearbyConnection, endpoint_id: bytes) -> None:
    connection_request = offline_wire_formats_pb2.OfflineFrame()
    connection_request.version = offline_wire_formats_pb2.OfflineFrame.V1
    connection_request.v1.type = offline_wire_formats_pb2.V1Frame.CONNECTION_REQUEST
    connection_request.v1.connection_request.endpoint_name = socket.gethostname()
    connection_request.v1.connection_request.endpoint_id = endpoint_id.decode("ascii")
    connection_request.v1.connection_request.endpoint_info = bytes(
        make_n(visible=True, type=Type.tablet, name=NAME.encode("utf-8")),
    )
    connection_request.v1.connection_request.mediums.append(
        offline_wire_formats_pb2.ConnectionRequestFrame.WIFI_LAN,
    )
    connection_request.v1.connection_request.mediums.append(
        offline_wire_formats_pb2.ConnectionRequestFrame.WIFI_DIRECT,
    )

    # TODO: populate from system (iw, NetworkManager, etc.)
    wifi_channels = [36, 40, 44, 48, 149, 153, 157, 161]  # common 5GHz
    meta = offline_wire_formats_pb2.MediumMetadata()
    meta.supports_5_ghz = True
    meta.supports_6_ghz = False
    meta.mobile_radio = False
    meta.ap_frequency = 5180  # placeholder
    meta.available_channels.channels.extend(wifi_channels)
    meta.wifi_lan_usable_channels.channels.extend(wifi_channels)
    meta.wifi_direct_cli_usable_channels.channels.extend(wifi_channels)
    connection_request.v1.connection_request.medium_metadata.CopyFrom(meta)

    await conn.send_bytes(connection_request.SerializeToString())


async def _do_paired_key_handshake(
    conn: NearbyConnection,
    qrcode: QRCode | None,
) -> None:
    """Exchange PAIRED_KEY_ENCRYPTION and PAIRED_KEY_RESULT (application layer)."""
    qr_code_handshake_data = None
    if qrcode:
        qr_code_handshake_data = qrcode.qr_code_handshake_data(conn.auth_string)
    paired_key_encryption = generate_paired_key_encryption(qr_code_handshake_data)
    await conn.send_frame(paired_key_encryption)

    await anext(conn.iter_payloads())  # consume the peer's PAIRED_KEY_RESULT

    paired_key_result = wire_format_pb2.Frame()
    paired_key_result.v1.type = wire_format_pb2.V1Frame.PAIRED_KEY_RESULT
    paired_key_result.version = wire_format_pb2.Frame.V1
    paired_key_result.v1.paired_key_result.status = wire_format_pb2.PairedKeyResultFrame.UNABLE
    await conn.send_frame(paired_key_result)


async def _send_introduction(
    conn: NearbyConnection,
    file: str,
    id: int,
) -> None:
    meta = _generate_file_metadata(file, id)
    introduction_frame = wire_format_pb2.Frame()
    introduction_frame.v1.type = wire_format_pb2.V1Frame.INTRODUCTION
    introduction_frame.version = wire_format_pb2.Frame.V1
    introduction_frame.v1.introduction.file_metadata.append(meta)
    await conn.send_frame(introduction_frame)


async def _wait_for_accept(
    conn: NearbyConnection,
    file: str,
    id: int,
) -> None:
    send_task: asyncio.Task[None] | None = None

    async for payload_header, data in conn.iter_payloads():
        wire_frame = wire_format_pb2.Frame()
        wire_frame.ParseFromString(data)

        if wire_frame.v1.type == wire_format_pb2.V1Frame.PAIRED_KEY_RESULT:
            # we know we failed this, and we can just ignore it
            ...
        elif wire_frame.v1.type == wire_format_pb2.V1Frame.RESPONSE:
            status = wire_frame.v1.connection_response.status

            if status == wire_format_pb2.ConnectionResponseFrame.ACCEPT:
                logger.debug("Peer accepted our introduction. Ready to send")
                send_task = create_task(
                    _send_file(
                        file=file,
                        conn=conn,
                        id=id,
                    )
                )
            else:
                logger.debug("Peer rejected our introduction. Aborting")
                break
        else:
            logger.warning(
                "Received unknown frame %d type %d", payload_header.id, wire_frame.v1.type
            )

    if send_task is not None:
        await send_task


# should go to receive.py
def _make_bandwidth_upgrade_frame(ip: str, port: int) -> offline_wire_formats_pb2.OfflineFrame:
    """Offer to upgrade the connection to a higher bandwidth transport (e.g. WIFI_DIRECT)."""
    offline_frame = offline_wire_formats_pb2.OfflineFrame()
    offline_frame.version = offline_wire_formats_pb2.OfflineFrame.V1
    offline_frame.v1.type = offline_wire_formats_pb2.V1Frame.BANDWIDTH_UPGRADE_NEGOTIATION
    offline_frame.v1.bandwidth_upgrade_negotiation.event_type = (
        offline_wire_formats_pb2.BandwidthUpgradeNegotiationFrame.UPGRADE_PATH_AVAILABLE
    )
    upgrade_path_info = offline_frame.v1.bandwidth_upgrade_negotiation.upgrade_path_info
    upgrade_path_info.medium = (
        offline_wire_formats_pb2.BandwidthUpgradeNegotiationFrame.UpgradePathInfo.WIFI_LAN
    )
    upgrade_path_info.supports_disabling_encryption = False
    upgrade_path_info.supports_client_introduction_ack = False

    # in network byte order
    upgrade_path_info.wifi_lan_socket.ip_address = socket.inet_aton(ip)
    upgrade_path_info.wifi_lan_socket.wifi_port = port

    return offline_frame


async def _handle_target(
    file: str,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    qrcode: QRCode | None = None,
) -> None:
    endpoint_id = generate_endpoint_id()
    conn = NearbyConnection(reader, writer, endpoint_id=endpoint_id)
    derive_endpoint_id_from_mac(pick_mac_deterministically(get_interfaces()))

    await _send_connection_request(conn, endpoint_id)

    if not await conn.upgrade_client():
        return

    await _do_paired_key_handshake(conn, qrcode)

    conn.start_keep_alive()

    id = random.randint(0, 2**31 - 1)  # noqa: S311 - random is fine here
    await _send_introduction(conn, file, id)
    await _wait_for_accept(conn, file, id)

    await conn.stop_keep_alive()
    await conn.close()
    with contextlib.suppress(Exception):
        writer.close()
        await writer.wait_closed()
