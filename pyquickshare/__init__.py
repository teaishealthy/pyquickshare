import asyncio
import enum
import io
import os
import random
import string
import struct
import time
from logging import getLogger
from typing import Awaitable, Callable

from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .common import Type, safe_assert
from .mdns import IPV4Runner, make_service
from .protos import (
    device_to_device_messages_pb2,
    offline_wire_formats_pb2,
    securegcm_pb2,
    securemessage_pb2,
    wire_format_pb2,
)
from .ukey2 import Keychain, do_key_exchange

NAME = "pyquickshare"

logger = getLogger(__name__)
nearby = logger.getChild("nearby")


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
):
    id = random.randint(0, 2**31 - 1)
    payload = payloadify(
        frame, keychain, flags=0, id=id, sequence_number=sequence_number
    )

    writer.write(struct.pack(">I", len(payload)))
    writer.write(payload)
    await writer.drain()

    finished = payloadify(
        b"", keychain, flags=1, id=id, sequence_number=sequence_number
    )
    writer.write(struct.pack(">I", len(finished)))
    writer.write(finished)


def payloadify(
    frame: bytes,
    keychain: Keychain,
    *,
    flags: int,
    id: int,
    sequence_number: Callable[[], int],
) -> bytes:
    # We're working from the inside out here

    payload_frame = offline_wire_formats_pb2.OfflineFrame()
    payload_frame.v1.type = offline_wire_formats_pb2.V1Frame.PAYLOAD_TRANSFER
    payload_frame.version = offline_wire_formats_pb2.OfflineFrame.V1
    payload_frame.v1.payload_transfer.payload_header.id = id
    payload_frame.v1.payload_transfer.payload_header.type = (
        offline_wire_formats_pb2.PayloadTransferFrame.PayloadHeader.BYTES
    )
    payload_frame.v1.payload_transfer.payload_header.total_size = len(frame)
    payload_frame.v1.payload_transfer.packet_type = (
        offline_wire_formats_pb2.PayloadTransferFrame.DATA
    )
    payload_frame.v1.payload_transfer.payload_chunk.offset = 0
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
    (length,) = struct.unpack(">I", await reader.readexactly(4))

    data = await reader.readexactly(length)

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

    keychain = await do_key_exchange(reader, writer)

    if keychain is None:  # the client failed the key exchange at some point
        return

    # We don't actually need to include all this data, an empty frame would be fine

    (length,) = struct.unpack(">I", await reader.readexactly(4))
    data = await reader.readexactly(length)
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
        offline_wire_formats_pb2.OsInfo.ANDROID  # 🐧
    )
    connection_response.v1.connection_response.multiplex_socket_bitmask = 0

    data = connection_response.SerializeToString()
    writer.write(struct.pack(">I", len(data)))
    writer.write(data)
    await writer.drain()

    # All messages on the wire are now encrypted

    sequence_number = sequence_number_f()

    nearby.debug("Connection established with %r", name)

    # ¯\_(ツ)_/¯
    paired_key_encryption = wire_format_pb2.Frame()
    paired_key_encryption.v1.type = wire_format_pb2.V1Frame.PAIRED_KEY_ENCRYPTION
    paired_key_encryption.version = wire_format_pb2.Frame.V1
    paired_key_encryption.v1.paired_key_encryption.secret_id_hash = bytes([0x00] * 6)  # fmt: off
    paired_key_encryption.v1.paired_key_encryption.signed_data = bytes([0x00] * 72)
    await send_simple(
        paired_key_encryption.SerializeToString(), writer, keychain, sequence_number
    )

    await writer.drain()

    nearby.debug("Sent PAIRED_KEY_ENCRYPTION")

    keep_alive_task = asyncio.create_task(
        keep_alive(lambda x: send_simple(x, writer, keychain, sequence_number))
    )

    # maps message IDs to buffers
    incomplete_payloads: dict[int, io.BytesIO] = {}
    file_infos: dict[
        int, offline_wire_formats_pb2.PayloadTransferFrame.PayloadHeader
    ] = {}

    received_files = 0
    expected_files = -1
    receive_mode: ReceiveMode | None = None

    while (expected_files != received_files) or receive_mode != ReceiveMode.FILES:
        (length,) = struct.unpack(">I", await reader.readexactly(4))
        data = await reader.readexactly(length)

        secure_message = securemessage_pb2.SecureMessage()
        secure_message.ParseFromString(data)

        original_frame = decrypt(secure_message, keychain)

        if original_frame.v1.type == offline_wire_formats_pb2.V1Frame.DISCONNECTION:
            nearby.debug("Received DISCONNECTION: %r", original_frame)
            break

        elif (
            original_frame.v1.type != offline_wire_formats_pb2.V1Frame.PAYLOAD_TRANSFER
        ):
            print(original_frame)
            continue

        payload_header = original_frame.v1.payload_transfer.payload_header
        payload_chunk = original_frame.v1.payload_transfer.payload_chunk

        if payload_header.id not in incomplete_payloads:
            incomplete_payloads[payload_header.id] = io.BytesIO()

            if (
                payload_header.type
                == offline_wire_formats_pb2.PayloadTransferFrame.PayloadHeader.FILE
            ):
                file_infos[payload_header.id] = payload_header

        buffer = incomplete_payloads[payload_header.id]

        offset = payload_chunk.offset
        buffer.seek(offset)
        buffer.write(payload_chunk.body)

        nearby.debug("Received payload chunk %d", payload_header.id)
        if payload_chunk.flags & 0b00000001:
            incomplete_payloads.pop(payload_header.id)

            buffer.seek(0)
            payload = buffer.read()
            buffer.close()

            if (
                original_frame.v1.payload_transfer.payload_header.type
                == offline_wire_formats_pb2.PayloadTransferFrame.PayloadHeader.FILE
            ):
                received_files += 1

                file_info = file_infos.pop(payload_header.id)
                file_path = f"downloads/{file_info.file_name}"
                nearby.debug("Received full file data")
                with open(file_path, "wb") as f:
                    f.write(payload)
                nearby.debug("Wrote file to %s", file_path)

                continue

            frame = wire_format_pb2.Frame()
            frame.ParseFromString(payload)

            if frame.v1.type == wire_format_pb2.V1Frame.PAIRED_KEY_RESULT:
                # we know we failed this, and we just mirror the response
                await send_simple(payload, writer, keychain, sequence_number)
            elif frame.v1.type == wire_format_pb2.V1Frame.PAIRED_KEY_ENCRYPTION:
                # we don't really care about this, but I just don't want to see it in the logs
                ...
            elif frame.v1.type == wire_format_pb2.V1Frame.INTRODUCTION:
                if frame.v1.introduction.wifi_credentials_metadata:
                    receive_mode = ReceiveMode.WIFI
                    nearby.debug(
                        "Receiving wifi credentials for ssids %r",
                        ", ".join(
                            m.ssid
                            for m in frame.v1.introduction.wifi_credentials_metadata
                        ),
                    )
                elif frame.v1.introduction.file_metadata:
                    receive_mode = ReceiveMode.FILES
                    expected_files = len(frame.v1.introduction.file_metadata)
                    nearby.debug(
                        "%r wants to send %r. Accepting",
                        name,
                        ", ".join(m.name for m in frame.v1.introduction.file_metadata),
                    )

                accept = wire_format_pb2.Frame()
                accept.v1.type = wire_format_pb2.V1Frame.RESPONSE
                accept.version = wire_format_pb2.Frame.V1
                accept.v1.connection_response.status = (
                    wire_format_pb2.ConnectionResponseFrame.ACCEPT
                )

                await send_simple(
                    accept.SerializeToString(), writer, keychain, sequence_number
                )
            else:
                nearby.debug("Received unknown frame %d", payload_header.id)

    duration = time.perf_counter() - start

    if expected_files == received_files:
        nearby.debug("Received all files")

    nearby.debug("Connection with %r closed after %f seconds", name, duration)

    writer.close()
    await writer.wait_closed()

    keep_alive_task.cancel()
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
