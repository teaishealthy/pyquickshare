import asyncio
import atexit
import base64
import hashlib
import os
import pathlib
import struct
import typing
from collections.abc import Awaitable, Callable
from contextlib import suppress
from enum import Enum
from logging import getLogger
from typing import Any, NamedTuple, TypeVar

from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .protos import (
    device_to_device_messages_pb2,
    offline_wire_formats_pb2,
    securegcm_pb2,
    securemessage_pb2,
    wire_format_pb2,
)

logger = getLogger(__name__)

tasks: list[asyncio.Task[Any]] = []

T = TypeVar("T")

NETWORK_BASE_PATH = pathlib.Path("/sys/class/net")


class Keychain(typing.NamedTuple):
    decrypt_key: bytes
    receive_hmac_key: bytes
    encrypt_key: bytes
    send_hmac_key: bytes
    auth_string: bytes


def get_interface_mac(interface: str) -> bytes:
    mac_path = NETWORK_BASE_PATH / interface / "address"

    return bytes.fromhex(mac_path.read_text().strip().replace(":", ""))


def to_url64(data: bytes | bytearray) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def from_url64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def create_task(*args: Any, **kwargs: Any) -> asyncio.Task[Any]:  # - Any is good enough for this
    task = asyncio.create_task(*args, **kwargs)
    tasks.append(task)
    return task


@atexit.register
def shutdown() -> None:
    for task in tasks:
        task.cancel()


async def clear_tasks() -> None:
    for task in tasks:
        with suppress(asyncio.CancelledError):
            await task


class Type(Enum):
    unknown = 0
    phone = 1
    tablet = 2
    laptop = 3


VERSION = 0b000


def safe_assert(condition: bool, message: str | None = None) -> None:  # noqa: FBT001 - this is an 'assert'
    if not condition:
        raise AssertionError(message or "Assertion failed")


async def read(reader: asyncio.StreamReader) -> bytes:
    (length,) = struct.unpack(">I", await reader.readexactly(4))
    return await reader.readexactly(length)


class InterfaceInfo(NamedTuple):
    ips: list[str]
    port: int


def encrypt_bytes(
    data: bytes,
    keychain: Keychain,
    sequence_number: int,
) -> bytes:
    device_to_device_message = device_to_device_messages_pb2.DeviceToDeviceMessage()
    device_to_device_message.sequence_number = sequence_number
    device_to_device_message.message = data

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


def encrypt_offline_frame(
    offline_frame: offline_wire_formats_pb2.OfflineFrame,
    keychain: Keychain,
    sequence_number: int,
) -> bytes:
    return encrypt_bytes(offline_frame.SerializeToString(), keychain, sequence_number)


def payloadify(  # noqa: PLR0913
    frame: bytes,
    *,
    id: int,
    flags: int,
    type: offline_wire_formats_pb2.PayloadTransferFrame.PayloadHeader.PayloadType,
    file_name: str | None = None,
    offset: int = 0,
    total_size: int | None = None,
) -> bytes:
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

    return payload_frame.SerializeToString()


def decrypt_to_bytes(raw: bytes, keychain: Keychain) -> bytes:
    secure_message = securemessage_pb2.SecureMessage()
    secure_message.ParseFromString(raw)

    h = hmac.HMAC(keychain.receive_hmac_key, hashes.SHA256())
    h.update(secure_message.header_and_body)
    h.verify(secure_message.signature)

    header_and_body = securemessage_pb2.HeaderAndBody()
    header_and_body.ParseFromString(secure_message.header_and_body)

    iv = header_and_body.header.iv

    padder = padding.PKCS7(128).unpadder()
    cipher = Cipher(algorithms.AES(keychain.decrypt_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(header_and_body.body) + decryptor.finalize()
    unpadded = padder.update(padded) + padder.finalize()

    device_to_device_message = device_to_device_messages_pb2.DeviceToDeviceMessage()
    device_to_device_message.ParseFromString(unpadded)

    return device_to_device_message.message


def decrypt(
    frame: securemessage_pb2.SecureMessage,
    keychain: Keychain,
) -> offline_wire_formats_pb2.OfflineFrame:
    raw_message = decrypt_to_bytes(frame.SerializeToString(), keychain)
    payload_frame = offline_wire_formats_pb2.OfflineFrame()
    payload_frame.ParseFromString(raw_message)
    return payload_frame


def generate_connection_response() -> offline_wire_formats_pb2.OfflineFrame:
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


def generate_paired_key_encryption(
    qr_code_handshake_data: bytes | None = None,
) -> wire_format_pb2.Frame:
    paired_key_encryption = wire_format_pb2.Frame()
    paired_key_encryption.v1.type = wire_format_pb2.V1Frame.PAIRED_KEY_ENCRYPTION
    paired_key_encryption.version = wire_format_pb2.Frame.V1
    paired_key_encryption.v1.paired_key_encryption.secret_id_hash = bytes(
        [0x00] * 6,
    )  # fmt: off
    if qr_code_handshake_data:
        paired_key_encryption.v1.paired_key_encryption.qr_code_handshake_data = (
            qr_code_handshake_data
        )

    paired_key_encryption.v1.paired_key_encryption.signed_data = bytes([0x00] * 72)
    return paired_key_encryption


def derive_endpoint_id_from_mac(mac: bytes) -> bytes:
    return bytes(i & 0b0111111 for i in hashlib.blake2b(mac, digest_size=4).digest())


def pick_mac_deterministically(interfaces: list[str]) -> bytes:
    interface = sorted(interfaces)[0]
    return get_interface_mac(interface)


def with_semaphore(
    sem: asyncio.Semaphore,
) -> Callable[[Callable[..., Awaitable[T]]], Callable[..., Awaitable[T]]]:
    def deco(corof: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        async def wrapper(*args: Any, **kwargs: Any) -> T:
            async with sem:
                return await corof(*args, **kwargs)

        return wrapper

    return deco
