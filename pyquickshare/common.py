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

from .protos import offline_wire_formats, securegcm, securemessage, wire_format

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
    device_to_device_message = securegcm.DeviceToDeviceMessage(
        sequence_number=sequence_number,
        message=data,
    )

    padder = padding.PKCS7(128).padder()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(keychain.encrypt_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padded = padder.update(bytes(device_to_device_message)) + padder.finalize()
    body = encryptor.update(padded) + encryptor.finalize()

    public_metadata = securegcm.GcmMetadata(
        version=1,
        type=securegcm.Type.DEVICE_TO_DEVICE_MESSAGE,
    )

    header_and_body = securemessage.HeaderAndBody(
        header=securemessage.Header(
            encryption_scheme=securemessage.EncScheme.AES_256_CBC,
            signature_scheme=securemessage.SigScheme.HMAC_SHA256,
            iv=iv,
            public_metadata=bytes(public_metadata),
        ),
        body=body,
    )

    serialized_header_and_body = bytes(header_and_body)

    h = hmac.HMAC(keychain.send_hmac_key, hashes.SHA256())
    h.update(serialized_header_and_body)

    secure_message = securemessage.SecureMessage(
        header_and_body=serialized_header_and_body,
        signature=h.finalize(),
    )

    return bytes(secure_message)


def encrypt_offline_frame(
    offline_frame: offline_wire_formats.OfflineFrame,
    keychain: Keychain,
    sequence_number: int,
) -> bytes:
    return encrypt_bytes(bytes(offline_frame), keychain, sequence_number)


def payloadify(  # noqa: PLR0913
    frame: bytes,
    *,
    id: int,
    flags: int,
    type: offline_wire_formats.PayloadTransferFramePayloadHeaderPayloadType,
    file_name: str | None = None,
    offset: int = 0,
    total_size: int | None = None,
) -> bytes:
    payload_header = offline_wire_formats.PayloadTransferFramePayloadHeader(
        id=id,
        type=type,
        total_size=total_size or len(frame),
        is_sensitive=False,
    )
    if file_name:
        payload_header.file_name = file_name

    payload_frame = offline_wire_formats.OfflineFrame(
        version=offline_wire_formats.OfflineFrameVersion.V1,
        v1=offline_wire_formats.V1Frame(
            type=offline_wire_formats.V1FrameFrameType.PAYLOAD_TRANSFER,
            payload_transfer=offline_wire_formats.PayloadTransferFrame(
                packet_type=offline_wire_formats.PayloadTransferFramePacketType.DATA,
                payload_header=payload_header,
                payload_chunk=offline_wire_formats.PayloadTransferFramePayloadChunk(
                    offset=offset,
                    flags=flags,
                    body=frame,
                ),
            ),
        ),
    )

    return bytes(payload_frame)


def decrypt_to_bytes(raw: bytes, keychain: Keychain) -> bytes:
    secure_message = securemessage.SecureMessage().parse(raw)

    h = hmac.HMAC(keychain.receive_hmac_key, hashes.SHA256())
    h.update(secure_message.header_and_body)
    h.verify(secure_message.signature)

    header_and_body = securemessage.HeaderAndBody().parse(secure_message.header_and_body)

    iv = header_and_body.header.iv

    padder = padding.PKCS7(128).unpadder()
    cipher = Cipher(algorithms.AES(keychain.decrypt_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(header_and_body.body) + decryptor.finalize()
    unpadded = padder.update(padded) + padder.finalize()

    device_to_device_message = securegcm.DeviceToDeviceMessage().parse(unpadded)

    return device_to_device_message.message


def decrypt(
    frame: securemessage.SecureMessage,
    keychain: Keychain,
) -> offline_wire_formats.OfflineFrame:
    raw_message = decrypt_to_bytes(bytes(frame), keychain)
    return offline_wire_formats.OfflineFrame().parse(raw_message)


def generate_connection_response() -> offline_wire_formats.OfflineFrame:
    return offline_wire_formats.OfflineFrame(
        version=offline_wire_formats.OfflineFrameVersion.V1,
        v1=offline_wire_formats.V1Frame(
            type=offline_wire_formats.V1FrameFrameType.CONNECTION_RESPONSE,
            connection_response=offline_wire_formats.ConnectionResponseFrame(
                response=offline_wire_formats.ConnectionResponseFrameResponseStatus.ACCEPT,
                os_info=offline_wire_formats.OsInfo(
                    type=offline_wire_formats.OsInfoOsType.LINUX,  # 🐧
                ),
                multiplex_socket_bitmask=0,
            ),
        ),
    )


def generate_paired_key_encryption(
    qr_code_handshake_data: bytes | None = None,
) -> wire_format.Frame:
    pke = wire_format.PairedKeyEncryptionFrame(
        secret_id_hash=bytes([0x00] * 6),
        signed_data=bytes([0x00] * 72),
    )
    if qr_code_handshake_data:
        pke.qr_code_handshake_data = qr_code_handshake_data

    return wire_format.Frame(
        version=wire_format.FrameVersion.V1,
        v1=wire_format.V1Frame(
            type=wire_format.V1FrameFrameType.PAIRED_KEY_ENCRYPTION,
            paired_key_encryption=pke,
        ),
    )


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
