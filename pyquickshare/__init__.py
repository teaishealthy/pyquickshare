from __future__ import annotations

import asyncio
import contextlib
import enum
import io
import os
import random
import socket
import string
import struct
import time
from logging import getLogger
from typing import TYPE_CHECKING, AsyncIterator, Awaitable, Callable

import magic
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .common import Type, from_url64, read, safe_assert
from .mdns.receive import IPV4Runner, make_n, make_service
from .mdns.send import discover_services
from .protos import (
    device_to_device_messages_pb2,
    offline_wire_formats_pb2,
    securegcm_pb2,
    securemessage_pb2,
    wire_format_pb2,
)
from .ukey2 import Keychain, do_client_key_exchange, do_server_key_exchange

NAME = "pyquickshare"

logger = getLogger(__name__)
nearby = logger.getChild("nearby")

if TYPE_CHECKING:
    from zeroconf.asyncio import AsyncServiceInfo


class ReceiveMode(enum.Enum):
    WIFI = 1
    FILES = 2


def sequence_number_f() -> Callable[[], int]:
    sequence_number = 0

    def f() -> int:
        nonlocal sequence_number
        sequence_number += 1
        return sequence_number

    return f


def make_enpoint_id() -> bytes:
    # 4-byte alphanum
    return "".join(random.choices(string.ascii_letters + string.digits, k=4)).encode(
        "ascii"
    )


async def keep_alive(
    send: Callable[[bytes], Awaitable[None]],
):
    keep_alive = offline_wire_formats_pb2.OfflineFrame()
    keep_alive.version = offline_wire_formats_pb2.OfflineFrame.V1
    keep_alive.v1.type = offline_wire_formats_pb2.V1Frame.KEEP_ALIVE
    keep_alive.v1.keep_alive.ack = False

    data = keep_alive.SerializeToString()

    while True:
        nearby.debug("Sending keep-alive")
        await send(data)
        await asyncio.sleep(10)


async def send_simple(
    frame: bytes,
    writer: asyncio.StreamWriter,
    keychain: Keychain,
    sequence_number: Callable[[], int],
    *,
    id: int | None = None,
):
    total_size = len(frame)
    id = id or random.randint(0, 2**31 - 1)
    payload = payloadify(
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

    finished = payloadify(
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


def payloadify(
    frame: bytes,
    keychain: Keychain,
    *,
    offset: int = 0,
    total_size: int | None = None,
    type: offline_wire_formats_pb2.PayloadTransferFrame.PayloadHeader.PayloadType,
    flags: int,
    id: int,
    sequence_number: Callable[[], int],
    file_name: str | None = None,
) -> bytes:
    # We're working from the inside out here

    payload_frame = offline_wire_formats_pb2.OfflineFrame()
    payload_frame.v1.type = offline_wire_formats_pb2.V1Frame.PAYLOAD_TRANSFER
    payload_frame.version = offline_wire_formats_pb2.OfflineFrame.V1
    payload_frame.v1.payload_transfer.payload_header.id = id
    payload_frame.v1.payload_transfer.payload_header.type = type
    if file_name:
        payload_frame.v1.payload_transfer.payload_header.file_name = file_name
    payload_frame.v1.payload_transfer.payload_header.total_size = total_size or len(
        frame
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
    padded = (
        padder.update(device_to_device_message.SerializeToString()) + padder.finalize()
    )

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


def decrypt(
    frame: securemessage_pb2.SecureMessage, keychain: Keychain
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


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    start = time.perf_counter()
    ip, port = writer.get_extra_info("peername")
    nearby.debug("Connection from %s:%d", ip, port)

    # 4-byte big-endian length
    data = await read(reader)

    connection_request = offline_wire_formats_pb2.OfflineFrame()
    connection_request.ParseFromString(data)

    safe_assert(
        connection_request.v1.type
        == offline_wire_formats_pb2.V1Frame.CONNECTION_REQUEST,
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
        client_connection_response.v1.connection_response.os_info.type
    )
    nearby.debug("Client %s is on OS %r", name, os)

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

    data = connection_response.SerializeToString()
    writer.write(struct.pack(">I", len(data)))
    writer.write(data)
    await writer.drain()

    # All messages on the wire are now encrypted

    sequence_number = sequence_number_f()

    async def send(payload: bytes) -> None:
        await send_simple(payload, writer, keychain, sequence_number)

    nearby.debug("Connection established with %r", name)

    # ¯\_(ツ)_/¯
    paired_key_encryption = make_paired_key_encryption()
    await send(paired_key_encryption.SerializeToString())

    await writer.drain()

    nearby.debug("Sent PAIRED_KEY_ENCRYPTION")

    keep_alive_task = asyncio.create_task(keep_alive(send))

    received_files = 0
    expected_files = -1
    receive_mode: ReceiveMode | None = None
    expected_payload_ids: list[int] = []

    async for payload_header, data in payload_messages(reader, keychain):
        if payload_header.id in expected_payload_ids:
            expected_payload_ids.remove(payload_header.id)

            if receive_mode is ReceiveMode.FILES:
                received_files += 1
                nearby.debug(
                    "Received full file, saving to downloads/%s",
                    payload_header.file_name,
                )
                with open(f"downloads/{payload_header.file_name}", "wb") as f:
                    f.write(data)
            elif receive_mode is ReceiveMode.WIFI:
                credentials = wire_format_pb2.WifiCredentials()
                credentials.ParseFromString(data)

                nearby.debug("Received wifi credentials %r", credentials.password)
                break
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
                    nearby.debug(
                        "Receiving wifi credentials for ssids %r",
                        ", ".join(
                            m.ssid
                            for m in wire_frame.v1.introduction.wifi_credentials_metadata
                        ),
                    )

                    expected_payload_ids.extend(
                        m.payload_id
                        for m in wire_frame.v1.introduction.wifi_credentials_metadata
                    )

                    accept = wire_format_pb2.Frame()
                    accept.v1.type = wire_format_pb2.V1Frame.RESPONSE
                    accept.version = wire_format_pb2.Frame.V1
                    accept.v1.connection_response.status = (
                        wire_format_pb2.ConnectionResponseFrame.ACCEPT
                    )

                    await send(accept.SerializeToString())
                elif wire_frame.v1.introduction.file_metadata:
                    receive_mode = ReceiveMode.FILES
                    expected_files = len(wire_frame.v1.introduction.file_metadata)
                    nearby.debug(
                        "%r wants to send %r. Accepting",
                        name,
                        ", ".join(
                            m.name for m in wire_frame.v1.introduction.file_metadata
                        ),
                    )
                    expected_payload_ids.extend(
                        m.payload_id for m in wire_frame.v1.introduction.file_metadata
                    )

                    accept = wire_format_pb2.Frame()
                    accept.v1.type = wire_format_pb2.V1Frame.RESPONSE
                    accept.version = wire_format_pb2.Frame.V1
                    accept.v1.connection_response.status = (
                        wire_format_pb2.ConnectionResponseFrame.ACCEPT
                    )

                    await send(accept.SerializeToString())
                else:
                    nearby.debug("Received unknown frame %d", payload_header.id)
            else:
                nearby.debug("Received unknown frame %d", payload_header.id)

        if len(expected_payload_ids) == 0 and receive_mode is not None:
            break

    duration = time.perf_counter() - start

    if expected_files == received_files:
        nearby.debug("Received all files")

    nearby.debug("Connection with %r closed after %f seconds", name, duration)

    writer.close()
    await writer.wait_closed()

    keep_alive_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await keep_alive_task


async def socket_server():
    # TODO: automatically pick a port, instead of hardcoding
    server = await asyncio.start_server(handle_client, "0.0.0.0", 12345)

    await server.serve_forever()


async def receive_entrypoint() -> None:
    """Receive something over QuickShare. Runs forever.

    This function registers an mDNS service and opens a socket server to receive data.
    """
    info = make_service(
        endpoint_id=make_enpoint_id(),
        visible=True,
        type=Type.phone,
        name=NAME.encode("utf-8"),
    )
    services = [info]

    task = asyncio.create_task(socket_server())

    runner = IPV4Runner()
    try:
        await runner.register_services(services)
    except KeyboardInterrupt:
        await runner.unregister_services(services)
        task.cancel()
        await task


async def send_entrypoint(file: str) -> None:
    """Send something over QuickShare. Picks the first discovered service and sends data to it."""
    services = await discover_services()

    first = await services.get()

    return await send_to(first, file=file)


async def payload_messages(
    reader: asyncio.StreamReader, keychain: Keychain
) -> AsyncIterator[
    tuple[offline_wire_formats_pb2.PayloadTransferFrame.PayloadHeader, bytes]
]:
    incomplete_payloads: dict[int, io.BytesIO] = {}
    original_headers: dict[
        int, offline_wire_formats_pb2.PayloadTransferFrame.PayloadHeader
    ] = {}

    while True:
        secure_message = securemessage_pb2.SecureMessage()
        secure_message.ParseFromString(await read(reader))

        original_frame = decrypt(secure_message, keychain)

        if original_frame.v1.type == offline_wire_formats_pb2.V1Frame.DISCONNECTION:
            nearby.debug("Received DISCONNECTION")
            break

        elif (
            original_frame.v1.type != offline_wire_formats_pb2.V1Frame.PAYLOAD_TRANSFER
        ):
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


def mime_to_type(mime_type: str) -> wire_format_pb2.FileMetadata.Type:
    namespace = mime_type.split("/")[0]

    if mime_type == "application/vnd.android.package-archive":
        return wire_format_pb2.FileMetadata.APP
    elif namespace == "audio":
        return wire_format_pb2.FileMetadata.AUDIO
    elif namespace == "image":
        return wire_format_pb2.FileMetadata.IMAGE
    elif namespace == "video":
        return wire_format_pb2.FileMetadata.VIDEO
    else:
        return wire_format_pb2.FileMetadata.UNKNOWN


def make_file_metadata(fp: str, id: int) -> wire_format_pb2.FileMetadata:
    mime = magic.from_file(  # type: ignore
        fp,
        mime=True,
    )
    size = os.path.getsize(fp)
    name = os.path.basename(fp)

    return wire_format_pb2.FileMetadata(
        name=name,
        type=mime_to_type(mime),
        mime_type=mime,
        size=size,
        payload_id=id,
    )


async def _send_file(
    *,
    file: str,
    writer: asyncio.StreamWriter,
    keychain: Keychain,
    sequence_number: Callable[[], int],
    id: int,
) -> None:
    total_size = os.path.getsize(file)
    nearby.debug("Sending file %r", file)
    file_name = os.path.basename(file)

    with open(file, "rb") as f:
        while True:
            offset = f.tell()
            # 512KB chunks
            chunk = f.read(512 * 1024)

            if not chunk:
                break

            payload = payloadify(
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

            file_name = None

        payload = payloadify(
            b"",
            keychain,
            flags=1,
            total_size=total_size,
            offset=f.tell(),
            id=id,
            type=offline_wire_formats_pb2.PayloadTransferFrame.PayloadHeader.FILE,
            sequence_number=sequence_number,
        )

        writer.write(struct.pack(">I", len(payload)))
        writer.write(payload)
        await writer.drain()


async def send_to(service: AsyncServiceInfo, *, file: str) -> None:
    name = service.name.split(".")[0].lstrip("_")

    decoded = from_url64(name)
    peer_endpoint_id = decoded[1:5].decode("ascii")

    nearby.debug("Discovered endpoint %r", peer_endpoint_id)

    n_raw = service.properties.get(b"n")

    if n_raw is None:
        nearby.debug("No n record found, aborting")
        return

    n = from_url64(n_raw.decode("utf-8"))

    flags = n[0]
    _visible = bool(flags & 0b00000001)
    type = Type(flags >> 1 & 0b00000111)

    name = n[18:].decode("utf-8")

    nearby.debug("Endpoint %r has name %r and type %r", peer_endpoint_id, name, type)

    address = socket.inet_ntoa(service.addresses[0])

    nearby.debug("Connecting to %s:%d", address, service.port)

    reader, writer = await asyncio.open_connection(address, service.port)

    endpoint_id = make_enpoint_id()

    connection_request = offline_wire_formats_pb2.OfflineFrame()
    connection_request.version = offline_wire_formats_pb2.OfflineFrame.V1
    connection_request.v1.type = offline_wire_formats_pb2.V1Frame.CONNECTION_REQUEST
    connection_request.v1.connection_request.endpoint_name = socket.gethostname()
    connection_request.v1.connection_request.endpoint_id = endpoint_id.decode("ascii")
    connection_request.v1.connection_response.os_info.type = (
        offline_wire_formats_pb2.OsInfo.LINUX  # 🐧 again
    )
    connection_request.v1.connection_request.endpoint_info = bytes(
        make_n(visible=True, type=Type.tablet, name="pyquickshare".encode("utf-8"))
    )
    connection_request.v1.connection_request.mediums.append(
        offline_wire_formats_pb2.ConnectionRequestFrame.WIFI_LAN
    )

    data = connection_request.SerializeToString()
    writer.write(struct.pack(">I", len(data)))
    writer.write(data)
    await writer.drain()

    keychain = await do_client_key_exchange(reader, writer)

    if not keychain:
        # the server failed the key exchange at some point
        return

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
    data = connection_response.SerializeToString()
    writer.write(struct.pack(">I", len(data)))
    writer.write(data)
    await writer.drain()

    data = await read(reader)

    peer_connection_response = offline_wire_formats_pb2.OfflineFrame()
    peer_connection_response.ParseFromString(data)

    # Everything on the wire is now encrypted
    sequence_number = sequence_number_f()

    async def send(payload: bytes, *, id: int | None = None) -> None:
        await send_simple(payload, writer, keychain, sequence_number, id=id)

    paired_key_encryption = make_paired_key_encryption()
    await send(paired_key_encryption.SerializeToString())

    data = await read(reader)

    secure_message = securemessage_pb2.SecureMessage()
    secure_message.ParseFromString(data)

    _peer_paired_key_encryption = decrypt(secure_message, keychain)

    task = asyncio.create_task(keep_alive(send))

    paired_key_result = wire_format_pb2.Frame()
    paired_key_result.v1.type = wire_format_pb2.V1Frame.PAIRED_KEY_RESULT
    paired_key_result.version = wire_format_pb2.Frame.V1
    paired_key_result.v1.paired_key_result.status = (
        wire_format_pb2.PairedKeyResultFrame.UNABLE
    )

    await send(paired_key_result.SerializeToString())

    id = random.randint(0, 2**31 - 1)
    meta = make_file_metadata(file, id)
    introduction_frame = wire_format_pb2.Frame()
    introduction_frame.v1.type = wire_format_pb2.V1Frame.INTRODUCTION
    introduction_frame.version = wire_format_pb2.Frame.V1

    introduction_frame.v1.introduction.file_metadata.append(meta)
    await send(introduction_frame.SerializeToString())

    async for payload_header, data in payload_messages(reader, keychain):
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
            logger.warning("Received unknown frame %d", payload_header.id)

    task.cancel()

    with contextlib.suppress(asyncio.CancelledError):
        await task


def make_paired_key_encryption():
    paired_key_encryption = wire_format_pb2.Frame()
    paired_key_encryption.v1.type = wire_format_pb2.V1Frame.PAIRED_KEY_ENCRYPTION
    paired_key_encryption.version = wire_format_pb2.Frame.V1
    paired_key_encryption.v1.paired_key_encryption.secret_id_hash = bytes([0x00] * 6)  # fmt: off
    paired_key_encryption.v1.paired_key_encryption.signed_data = bytes([0x00] * 72)
    return paired_key_encryption
