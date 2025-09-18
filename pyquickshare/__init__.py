"""Quick Share implementation in Python."""

from __future__ import annotations

import asyncio
import contextlib
import enum
import hashlib
import io
import math
import os
import pathlib
import random
import socket
import string
import struct
import time
from logging import getLogger
from typing import TYPE_CHECKING, cast

import magic
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .common import InterfaceInfo, Type, create_task, from_url64, read, safe_assert
from .mdns.receive import (
    IPV4Runner,
    get_interface_info,
    get_interface_mac,
    get_interfaces,
    make_n,
    make_service,
)
from .mdns.send import discover_services as _discover_services
from .protos import (
    device_to_device_messages_pb2,
    offline_wire_formats_pb2,
    securegcm_pb2,
    securemessage_pb2,
    wire_format_pb2,
)
from .results import FileResult, Result, TextResult, WifiResult
from .ukey2 import Keychain, do_client_key_exchange, do_server_key_exchange

NAME = "pyquickshare"

logger = getLogger(__name__)
nearby = logger.getChild("nearby")

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Awaitable, Callable

    from zeroconf.asyncio import AsyncServiceInfo


__all__ = (
    "ShareRequest",
    "discover_services",
    "generate_endpoint_id",
    "receive",
    "send_to",
)


def to_pin(bytes_: bytes) -> str:
    k_hash_modulo = 9973
    k_hash_base_multiplier = 31

    hash = 0
    multiplier = 1
    for byte in struct.unpack("b" * len(bytes_), bytes_):
        # % in python is real mod, not remainder, unlike in C++ (worst bug i ever had to debug)
        hash = int(math.fmod((hash + byte * multiplier), k_hash_modulo))
        multiplier = int(
            math.fmod((multiplier * k_hash_base_multiplier), k_hash_modulo),
        )

    return f"{abs(hash):04d}"


class ShareRequest:
    def __init__(
        self,
        header: offline_wire_formats_pb2.PayloadTransferFrame.PayloadHeader,
        pin: str,
    ) -> None:
        self.respond: asyncio.Future[bool] = asyncio.Future()
        self.done: asyncio.Future[list[Result]] = asyncio.Future()
        self.header: offline_wire_formats_pb2.PayloadTransferFrame.PayloadHeader = header
        self.pin: str = pin

    async def accept(self) -> list[Result]:
        self.respond.set_result(True)
        return await self.done

    async def reject(self) -> None:
        self.respond.set_result(False)
        await self.done


class ReceiveMode(enum.Enum):
    WIFI = 1
    FILES = 2
    TEXT = 3


def parse_n(n: bytes) -> tuple[bool, Type, str]:
    n = from_url64(n.decode("utf-8"))
    flags = n[0]
    visible = bool(flags & 0b00000001)
    type = Type(flags >> 1 & 0b00000111)
    name = n[18:].decode("utf-8")
    return visible, type, name


def _mime_to_type(mime_type: str) -> wire_format_pb2.FileMetadata.Type:
    namespace = mime_type.split("/")[0]

    if mime_type == "application/vnd.android.package-archive":
        return wire_format_pb2.FileMetadata.APP
    if namespace == "audio":
        return wire_format_pb2.FileMetadata.AUDIO
    if namespace == "image":
        return wire_format_pb2.FileMetadata.IMAGE
    if namespace == "video":
        return wire_format_pb2.FileMetadata.VIDEO

    return wire_format_pb2.FileMetadata.UNKNOWN


def _make_sequence_number() -> Callable[[], int]:
    sequence_number = 0

    def f() -> int:
        nonlocal sequence_number
        sequence_number += 1
        return sequence_number

    return f


def _make_send(
    writer: asyncio.StreamWriter,
    keychain: Keychain,
    sequence_number: Callable[[], int],
) -> Callable[[bytes], Awaitable[None]]:
    async def send(frame: bytes, *, id: int | None = None) -> None:
        total_size = len(frame)
        id = id or random.randint(0, 2**31 - 1)  # noqa: S311 - random is fine here
        payload = _payloadify(
            frame,
            keychain,
            flags=0,
            id=id,
            total_size=total_size,
            sequence_number=sequence_number,
            type=offline_wire_formats_pb2.PayloadTransferFrame.PayloadHeader.BYTES,
        )

        writer.write(struct.pack(">I", len(payload)))
        writer.write(payload)

        finished = _payloadify(
            b"",
            keychain,
            flags=1,
            id=id,
            total_size=total_size,
            sequence_number=sequence_number,
            type=offline_wire_formats_pb2.PayloadTransferFrame.PayloadHeader.BYTES,
        )
        writer.write(struct.pack(">I", len(finished)))
        writer.write(finished)
        await writer.drain()

    return send


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


def _derive_endpoint_id_from_mac(mac: bytes) -> bytes:
    return bytes(i & 0b0111111 for i in hashlib.blake2b(mac, digest_size=4).digest())


def _pick_mac_deterministically(interfaces: list[str]) -> bytes:
    interface = sorted(interfaces)[0]
    return get_interface_mac(interface)


def _generate_paired_key_encryption() -> wire_format_pb2.Frame:
    paired_key_encryption = wire_format_pb2.Frame()
    paired_key_encryption.v1.type = wire_format_pb2.V1Frame.PAIRED_KEY_ENCRYPTION
    paired_key_encryption.version = wire_format_pb2.Frame.V1
    paired_key_encryption.v1.paired_key_encryption.secret_id_hash = bytes(
        [0x00] * 6,
    )  # fmt: off
    paired_key_encryption.v1.paired_key_encryption.signed_data = bytes([0x00] * 72)
    return paired_key_encryption


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


def _generate_connection_response() -> offline_wire_formats_pb2.OfflineFrame:
    connection_response = offline_wire_formats_pb2.OfflineFrame()
    connection_response.version = offline_wire_formats_pb2.OfflineFrame.V1
    connection_response.v1.type = offline_wire_formats_pb2.V1Frame.CONNECTION_RESPONSE
    connection_response.v1.connection_response.status = 0
    connection_response.v1.connection_response.response = (
        offline_wire_formats_pb2.ConnectionResponseFrame.ACCEPT
    )
    connection_response.v1.connection_response.os_info.type = (
        offline_wire_formats_pb2.OsInfo.LINUX  # 🐧
    )
    connection_response.v1.connection_response.multiplex_socket_bitmask = 0
    return connection_response


def _generate_accept() -> bytes:
    accept = wire_format_pb2.Frame()
    accept.v1.type = wire_format_pb2.V1Frame.RESPONSE
    accept.version = wire_format_pb2.Frame.V1
    accept.v1.connection_response.status = wire_format_pb2.ConnectionResponseFrame.ACCEPT

    return accept.SerializeToString()


async def _keep_alive(
    send: Callable[[bytes], Awaitable[None]],
) -> None:
    keep_alive = offline_wire_formats_pb2.OfflineFrame()
    keep_alive.version = offline_wire_formats_pb2.OfflineFrame.V1
    keep_alive.v1.type = offline_wire_formats_pb2.V1Frame.KEEP_ALIVE
    keep_alive.v1.keep_alive.ack = False

    data = keep_alive.SerializeToString()

    while True:
        nearby.debug("Sending keep-alive")
        await send(data)
        await asyncio.sleep(10)


def _payloadify(  # noqa: PLR0913 - not a lot we can do about this
    frame: bytes,
    keychain: Keychain,
    *,
    id: int,
    flags: int,
    type: offline_wire_formats_pb2.PayloadTransferFrame.PayloadHeader.PayloadType,
    file_name: str | None = None,
    offset: int = 0,
    total_size: int | None = None,
    sequence_number: Callable[[], int],
) -> bytes:
    print(file_name)
    # We're working from the inside out here

    payload_frame = offline_wire_formats_pb2.OfflineFrame()
    payload_frame.v1.type = offline_wire_formats_pb2.V1Frame.PAYLOAD_TRANSFER
    payload_frame.version = offline_wire_formats_pb2.OfflineFrame.V1
    payload_frame.v1.payload_transfer.payload_header.id = id
    payload_frame.v1.payload_transfer.payload_header.type = type
    if file_name:
        payload_frame.v1.payload_transfer.payload_header.file_name = file_name
    payload_frame.v1.payload_transfer.payload_header.total_size = total_size or len(
        frame,
    )
    payload_frame.v1.payload_transfer.payload_header.is_sensitive = False
    payload_frame.v1.payload_transfer.packet_type = (
        offline_wire_formats_pb2.PayloadTransferFrame.DATA
    )
    payload_frame.v1.payload_transfer.payload_chunk.offset = offset
    payload_frame.v1.payload_transfer.payload_chunk.flags = flags
    payload_frame.v1.payload_transfer.payload_chunk.body = frame

    device_to_device_message = device_to_device_messages_pb2.DeviceToDeviceMessage()
    device_to_device_message.sequence_number = sequence_number()
    device_to_device_message.message = payload_frame.SerializeToString()

    padder = padding.PKCS7(128).padder()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(keychain.encrypt_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padded = padder.update(device_to_device_message.SerializeToString()) + padder.finalize()

    body = encryptor.update(padded) + encryptor.finalize()

    public_metadata = securegcm_pb2.GcmMetadata()
    public_metadata.version = 1
    public_metadata.type = securegcm_pb2.DEVICE_TO_DEVICE_MESSAGE

    header_and_body = securemessage_pb2.HeaderAndBody()
    header_and_body.header.encryption_scheme = securemessage_pb2.AES_256_CBC
    header_and_body.header.signature_scheme = securemessage_pb2.HMAC_SHA256
    header_and_body.header.iv = iv
    header_and_body.header.public_metadata = public_metadata.SerializeToString()

    header_and_body.body = body

    serialized_header_and_body = header_and_body.SerializeToString()

    secure_message = securemessage_pb2.SecureMessage()
    secure_message.header_and_body = serialized_header_and_body

    h = hmac.HMAC(keychain.send_hmac_key, hashes.SHA256())
    h.update(serialized_header_and_body)
    secure_message.signature = h.finalize()

    return secure_message.SerializeToString()


def _decrypt(
    frame: securemessage_pb2.SecureMessage,
    keychain: Keychain,
) -> offline_wire_formats_pb2.OfflineFrame:
    h = hmac.HMAC(keychain.receive_hmac_key, hashes.SHA256())
    h.update(frame.header_and_body)
    h.verify(frame.signature)

    header_and_body = securemessage_pb2.HeaderAndBody()
    header_and_body.ParseFromString(frame.header_and_body)

    iv = header_and_body.header.iv
    public_metadata = securegcm_pb2.GcmMetadata()
    public_metadata.ParseFromString(header_and_body.header.public_metadata)

    padder = padding.PKCS7(128).unpadder()
    cipher = Cipher(algorithms.AES(keychain.decrypt_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(header_and_body.body) + decryptor.finalize()
    unpadded = padder.update(padded) + padder.finalize()

    device_to_device_message = device_to_device_messages_pb2.DeviceToDeviceMessage()
    device_to_device_message.ParseFromString(unpadded)

    payload_frame = offline_wire_formats_pb2.OfflineFrame()
    payload_frame.ParseFromString(device_to_device_message.message)

    return payload_frame


async def _handle_client(  # noqa: C901 , PLR0912 , PLR0915 # TODO: refactor
    requests: asyncio.Queue[ShareRequest],
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    start = time.perf_counter()
    ip, port = writer.get_extra_info("peername")
    nearby.debug("Connection from %s:%d", ip, port)

    # 4-byte big-endian length
    data = await read(reader)

    connection_request = offline_wire_formats_pb2.OfflineFrame()
    connection_request.ParseFromString(data)

    safe_assert(
        connection_request.v1.type == offline_wire_formats_pb2.V1Frame.CONNECTION_REQUEST,
        "Expected first message to be of type CONNECTION_REQUEST",
    )

    device_info = connection_request.v1.connection_request.endpoint_info

    # like n, first byte are flags, then 16 bytes of ?, then length of name, then name
    name = device_info[18:].decode("utf-8")

    nearby.debug("Received CONNECTION_REQUEST from %r", name)

    keychain = await do_server_key_exchange(reader, writer)

    if keychain is None:  # the client failed the key exchange at some point
        return

    # We don't actually need to include all this data, an empty frame would be fine

    data = await read(reader)

    client_connection_response = offline_wire_formats_pb2.OfflineFrame()
    client_connection_response.ParseFromString(data)
    os = offline_wire_formats_pb2.OsInfo.OsType.Name(
        client_connection_response.v1.connection_response.os_info.type,
    )
    nearby.debug("Client %s is on OS %r", name, os)

    connection_response = _generate_connection_response()

    data = connection_response.SerializeToString()
    writer.write(struct.pack(">I", len(data)))
    writer.write(data)
    await writer.drain()

    # All messages on the wire are now encrypted

    sequence_number = _make_sequence_number()

    send = _make_send(writer, keychain, sequence_number)

    nearby.debug("Connection established with %r", name)

    # ¯\_(ツ)_/¯
    paired_key_encryption = _generate_paired_key_encryption()
    await send(paired_key_encryption.SerializeToString())

    await writer.drain()

    nearby.debug("Sent PAIRED_KEY_ENCRYPTION")

    keep_alive_task = asyncio.create_task(_keep_alive(send))

    receive_mode: ReceiveMode | None = None
    expected_payload_ids: dict[
        int,
        wire_format_pb2.WifiCredentialsMetadata
        | wire_format_pb2.FileMetadata
        | wire_format_pb2.TextMetadata,
    ] = {}

    request: ShareRequest | None = None
    results: list[Result] = []

    async for payload_header, data in _iter_payload_messages(reader, keychain):
        if payload_header.id in expected_payload_ids:
            metadata = expected_payload_ids.pop(payload_header.id)

            if receive_mode is ReceiveMode.FILES:
                metadata = cast(wire_format_pb2.FileMetadata, metadata)

                nearby.debug(
                    "Received full file, saving to downloads/%s",
                    payload_header.file_name,
                )
                with open(  # noqa: PTH123, ASYNC230 # TODO: refactor
                    f"downloads/{payload_header.file_name}", "wb"
                ) as f:
                    f.write(data)

                results.append(
                    FileResult(
                        name=payload_header.file_name,
                        path=f"downloads/{payload_header.file_name}",
                        size=payload_header.total_size,
                    ),
                )
            elif receive_mode is ReceiveMode.WIFI:
                metadata = cast(wire_format_pb2.WifiCredentialsMetadata, metadata)

                credentials = wire_format_pb2.WifiCredentials()
                credentials.ParseFromString(data)

                nearby.debug("Received wifi credentials %r", credentials.password)

                results.append(
                    WifiResult(
                        ssid=metadata.ssid,
                        password=credentials.password,
                        security_type=metadata.security_type,
                    ),
                )
            elif receive_mode is ReceiveMode.TEXT:
                metadata = cast(wire_format_pb2.TextMetadata, metadata)

                nearby.debug("Received text %d", payload_header.id)

                results.append(
                    TextResult(
                        title=metadata.text_title,
                        text=data.decode("utf-8"),
                    ),
                )

        else:
            wire_frame = wire_format_pb2.Frame()
            wire_frame.ParseFromString(data)

            if wire_frame.v1.type == wire_format_pb2.V1Frame.PAIRED_KEY_RESULT:
                # we know we failed this, and we just mirror the response
                await send(wire_frame.SerializeToString())
            elif wire_frame.v1.type == wire_format_pb2.V1Frame.PAIRED_KEY_ENCRYPTION:
                # we don't really care about this, but I just don't want to see it in the logs
                ...
            elif wire_frame.v1.type == wire_format_pb2.V1Frame.INTRODUCTION:
                if wire_frame.v1.introduction.wifi_credentials_metadata:
                    receive_mode = ReceiveMode.WIFI
                    request = ShareRequest(payload_header, to_pin(keychain.auth_string))
                    await requests.put(request)
                    nearby.debug(
                        "Receiving wifi credentials for ssids %r",
                        ", ".join(
                            m.ssid for m in wire_frame.v1.introduction.wifi_credentials_metadata
                        ),
                    )

                    expected_payload_ids.update(
                        {
                            m.payload_id: m
                            for m in wire_frame.v1.introduction.wifi_credentials_metadata
                        },
                    )

                    await send(_generate_accept())

                elif wire_frame.v1.introduction.file_metadata:
                    nearby.debug(
                        "%r wants to send %r",
                        name,
                        ", ".join(m.name for m in wire_frame.v1.introduction.file_metadata),
                    )

                    receive_mode = ReceiveMode.FILES
                    request = ShareRequest(payload_header, to_pin(keychain.auth_string))
                    await requests.put(request)
                    result = await request.respond

                    if result:
                        nearby.debug("Accepting introduction")
                        await send(_generate_accept())
                        expected_payload_ids.update(
                            {m.payload_id: m for m in wire_frame.v1.introduction.file_metadata},
                        )
                    else:
                        nearby.debug("Rejecting introduction")
                        # TODO: send a rejection

                    #await send(_generate_accept())
                elif wire_frame.v1.introduction.text_metadata:
                    receive_mode = ReceiveMode.TEXT
                    request = ShareRequest(payload_header, to_pin(keychain.auth_string))
                    await requests.put(request)
                    nearby.debug("Receiving text")
                    expected_payload_ids.update(
                        {m.payload_id: m for m in wire_frame.v1.introduction.text_metadata},
                    )

                    await send(_generate_accept())
                else:
                    nearby.debug("Received weird introduction %d", payload_header.id)
            else:
                nearby.debug("Received unknown frame %d", payload_header.id)

        if not expected_payload_ids and receive_mode is not None:
            # We've received all attachments we were expecting
            break

    duration = time.perf_counter() - start

    nearby.debug("Connection with %r closed after %f seconds", name, duration)

    if request:
        request.done.set_result(results)

    writer.close()
    await writer.wait_closed()

    keep_alive_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await keep_alive_task


async def _socket_server(
    requests: asyncio.Queue[ShareRequest], *, interface_info: InterfaceInfo
) -> None:
    print(interface_info)
    server = await asyncio.start_server(
        lambda reader, writer: _handle_client(requests, reader, writer),
        "0.0.0.0",
        interface_info.port,
    )

    await server.serve_forever()


async def _iter_payload_messages(
    reader: asyncio.StreamReader,
    keychain: Keychain,
) -> AsyncIterator[tuple[offline_wire_formats_pb2.PayloadTransferFrame.PayloadHeader, bytes]]:
    incomplete_payloads: dict[int, io.BytesIO] = {}
    original_headers: dict[
        int,
        offline_wire_formats_pb2.PayloadTransferFrame.PayloadHeader,
    ] = {}

    while not reader.at_eof():
        secure_message = securemessage_pb2.SecureMessage()
        try:
            secure_message.ParseFromString(await read(reader))
        except asyncio.IncompleteReadError:
            break

        original_frame = _decrypt(secure_message, keychain)

        if original_frame.v1.type == offline_wire_formats_pb2.V1Frame.DISCONNECTION:
            nearby.debug("Received DISCONNECTION")
            break

        elif original_frame.v1.type != offline_wire_formats_pb2.V1Frame.PAYLOAD_TRANSFER:
            continue

        payload_header = original_frame.v1.payload_transfer.payload_header
        payload_chunk = original_frame.v1.payload_transfer.payload_chunk

        if payload_header.id not in incomplete_payloads:
            incomplete_payloads[payload_header.id] = io.BytesIO()
            original_headers[payload_header.id] = payload_header

        buffer = incomplete_payloads[payload_header.id]

        offset = payload_chunk.offset
        buffer.seek(offset)
        buffer.write(payload_chunk.body)

        nearby.debug("Received payload chunk %d", payload_header.id)
        if payload_chunk.flags & 0b00000001:
            incomplete_payloads.pop(payload_header.id)
            original_header = original_headers.pop(payload_header.id)

            buffer.seek(0)
            payload = buffer.read()
            buffer.close()

            yield original_header, payload


async def _send_file(
    *,
    file: str,
    writer: asyncio.StreamWriter,
    keychain: Keychain,
    sequence_number: Callable[[], int],
    id: int,
) -> None:
    path = pathlib.Path(file)
    total_size = path.stat().st_size
    nearby.debug("Sending file %r", file)
    file_name = path.name

    with open(file, "rb") as f:  # noqa: PTH123, ASYNC230 # TODO: refactor
        while True:
            offset = f.tell()
            # 512KB chunks
            chunk = f.read(512 * 1024)

            if not chunk:
                break

            payload = _payloadify(
                chunk,
                keychain,
                flags=0,
                total_size=total_size,
                offset=offset,
                id=id,
                file_name=file_name,
                type=offline_wire_formats_pb2.PayloadTransferFrame.PayloadHeader.FILE,
                sequence_number=sequence_number,
            )
            writer.write(struct.pack(">I", len(payload)))
            writer.write(payload)
            await writer.drain()

        payload = _payloadify(
            b"",
            keychain,
            flags=1,
            total_size=total_size,
            offset=f.tell(),
            file_name=file_name,
            id=id,
            type=offline_wire_formats_pb2.PayloadTransferFrame.PayloadHeader.FILE,
            sequence_number=sequence_number,
        )

        writer.write(struct.pack(">I", len(payload)))
        writer.write(payload)
        await writer.drain()


async def send_to(service: AsyncServiceInfo, *, file: str) -> None:
    """Send a file to a service.

    Args:
        service (AsyncServiceInfo): The service to send the file to
        file (str): The file to send
    """
    name = service.name.split(".")[0].lstrip("_")

    decoded = from_url64(name)
    peer_endpoint_id = decoded[1:5].decode("ascii")

    nearby.debug("Discovered endpoint %r", peer_endpoint_id)

    n_raw = service.properties.get(b"n")

    if n_raw is None:
        nearby.debug("No n record found, aborting")
        return None

    n = from_url64(n_raw.decode("utf-8"))

    flags = n[0]
    _visible = bool(flags & 0b00000001)
    type = Type(flags >> 1 & 0b00000111)

    name = n[18:].decode("utf-8")

    nearby.debug("Endpoint %r has name %r and type %r", peer_endpoint_id, name, type)

    address: str | None = None
    for addr in service.addresses:
        try:
            address = socket.inet_ntoa(addr)
            socket.gethostbyaddr(address)
            break
        except socket.herror:
            nearby.debug("Address %r is not resolvable", address)

    if address is None:
        nearby.error("No resolvable addresses found, aborting")
        return None

    nearby.debug("Connecting to %s:%d", address, service.port)

    reader, writer = await asyncio.open_connection(address, service.port)

    return await _handle_target(file, reader, writer)


async def _handle_target(  # noqa: PLR0915 # TODO: refactor
    file: str,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    endpoint_id = generate_endpoint_id()

    _derive_endpoint_id_from_mac(
        _pick_mac_deterministically(get_interfaces()),
    )

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

    data = connection_request.SerializeToString()
    writer.write(struct.pack(">I", len(data)))
    writer.write(data)
    await writer.drain()

    keychain = await do_client_key_exchange(reader, writer)

    if not keychain:
        # the server failed the key exchange at some point
        return

    connection_response = _generate_connection_response()
    data = connection_response.SerializeToString()
    writer.write(struct.pack(">I", len(data)))
    writer.write(data)
    await writer.drain()

    data = await read(reader)

    peer_connection_response = offline_wire_formats_pb2.OfflineFrame()
    peer_connection_response.ParseFromString(data)

    # Everything on the wire is now encrypted
    sequence_number = _make_sequence_number()
    send = _make_send(writer, keychain, sequence_number)

    paired_key_encryption = _generate_paired_key_encryption()
    await send(paired_key_encryption.SerializeToString())

    data = await read(reader)

    secure_message = securemessage_pb2.SecureMessage()
    secure_message.ParseFromString(data)

    _peer_paired_key_encryption = _decrypt(secure_message, keychain)

    task = create_task(_keep_alive(send))

    paired_key_result = wire_format_pb2.Frame()
    paired_key_result.v1.type = wire_format_pb2.V1Frame.PAIRED_KEY_RESULT
    paired_key_result.version = wire_format_pb2.Frame.V1
    paired_key_result.v1.paired_key_result.status = wire_format_pb2.PairedKeyResultFrame.UNABLE

    await send(paired_key_result.SerializeToString())

    id = random.randint(0, 2**31 - 1)  # noqa: S311 - random is fine here
    meta = _generate_file_metadata(file, id)
    introduction_frame = wire_format_pb2.Frame()
    introduction_frame.v1.type = wire_format_pb2.V1Frame.INTRODUCTION
    introduction_frame.version = wire_format_pb2.Frame.V1

    introduction_frame.v1.introduction.file_metadata.append(meta)
    await send(introduction_frame.SerializeToString())

    async for payload_header, data in _iter_payload_messages(reader, keychain):
        wire_frame = wire_format_pb2.Frame()
        wire_frame.ParseFromString(data)

        if wire_frame.v1.type == wire_format_pb2.V1Frame.PAIRED_KEY_RESULT:
            # we know we failed this, and we can just ignore it
            ...
        elif wire_frame.v1.type == wire_format_pb2.V1Frame.RESPONSE:
            status = wire_frame.v1.connection_response.status

            if status == wire_format_pb2.ConnectionResponseFrame.ACCEPT:
                nearby.debug("Peer accepted our introduction. Ready to send")
                await _send_file(
                    file=file,
                    writer=writer,
                    keychain=keychain,
                    sequence_number=sequence_number,
                    id=id,
                )
            else:
                nearby.debug("Peer rejected our introduction. Aborting")
                break
        else:
            has_introduction = getattr(wire_frame.v1, "introduction", None)
            has_connection_response = getattr(wire_frame.v1, "connection_response", None)
            has_paired_key_encryption = getattr(wire_frame.v1, "paired_key_encryption", None)
            has_paired_key_result = getattr(wire_frame.v1, "paired_key_result", None)
            has_certificate_info = getattr(wire_frame.v1, "certificate_info", None)

            logger.warning("Received unknown frame %d type %d", payload_header.id, wire_frame.v1.type)

    task.cancel()

    with contextlib.suppress(asyncio.CancelledError):
        await task


async def receive(*, endpoint_id: bytes | None = None) -> AsyncIterator[ShareRequest]:
    """Receive something over Quick Share. Runs forever.

    This function registers an mDNS service and opens a socket server to receive data.
    If firewalld is available, it temporarily reconfigures firewalld to allow incoming connections on the port.

    Yields:
        ShareRequest: A request to share something

    Example:
        .. code-block:: python

            async for request in receive():
                results = await request.accept()
                print(results)

    """  # noqa: E501
    if endpoint_id and len(endpoint_id) != 4:  # noqa: PLR2004, this is not a magic number
        msg = "endpoint_id must be 4 bytes (and in ASCII)"
        raise ValueError(msg)

    interface_info = await get_interface_info()

    info = await make_service(
        endpoint_id=endpoint_id
        or _derive_endpoint_id_from_mac(_pick_mac_deterministically(get_interfaces())),
        visible=True,
        type_=Type.phone,
        name=NAME.encode("utf-8"),
        interface_info=interface_info,
    )
    services = [info]
    result: asyncio.Queue[ShareRequest] = asyncio.Queue()

    create_task(_socket_server( result, interface_info=interface_info))
    create_task(_start_mdns_service(services))

    while True:
        yield await result.get()


async def _start_mdns_service(services: list[AsyncServiceInfo]) -> None:
    runner = IPV4Runner()
    try:
        await runner.register_services(services)
    except asyncio.CancelledError:
        await runner.unregister_services(services)


async def discover_services() -> AsyncIterator[AsyncServiceInfo]:
    """Discover services on the network.

    Example:
        .. code-block:: python

            async for service in discover_services():
                print(service)
    """
    queue = await _discover_services()
    while True:
        yield await queue.get()
