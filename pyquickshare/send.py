from __future__ import annotations

import asyncio
import contextlib
import pathlib
import random
import socket
import string
import struct
import time
from collections.abc import AsyncIterator
from logging import getLogger
from typing import TYPE_CHECKING

import aiofile
import magic

from .common import (
    Type,
    create_task,
    decrypt,
    derive_endpoint_id_from_mac,
    from_url64,
    generate_connection_response,
    generate_paired_key_encryption,
    iter_payload_messages,
    keep_alive,
    make_send,
    make_sequence_number,
    payloadify,
    pick_mac_deterministically,
    read,
    with_semaphore,
)
from .mdns.receive import (
    get_interfaces,
    make_n,
)
from .mdns.send import discover_services as _discover_services
from .protos import (
    offline_wire_formats_pb2,
    securemessage_pb2,
    wire_format_pb2,
)
from .ukey2 import Keychain, do_client_key_exchange

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable

    from zeroconf.asyncio import AsyncServiceInfo

logger = getLogger(__name__)

NAME = "pyquickshare"
CHUNK_SIZE = 512 * 1024


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


async def _send_file(
    *,
    file: str,
    writer: asyncio.StreamWriter,
    keychain: Keychain,
    sequence_number: Callable[[], int],
    id: int,
) -> None:
    start_time = time.perf_counter()
    path = pathlib.Path(file)
    total_size = path.stat().st_size
    logger.debug("Sending file %r", file)
    file_name = path.name

    semaphore = asyncio.Semaphore(
        int((total_size // CHUNK_SIZE) * 0.9) if total_size >= CHUNK_SIZE else 1
    )

    @with_semaphore(semaphore)
    async def write_task(offset: int) -> None:
        f.seek(offset)
        # 512KB chunks
        chunk = await f.read(CHUNK_SIZE)

        if not chunk:
            return

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

    async with aiofile.async_open(file, "rb") as f:
        await asyncio.gather(*(write_task(offset) for offset in range(0, total_size, CHUNK_SIZE)))
        await writer.drain()

        payload = payloadify(
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

        await asyncio.get_event_loop().run_in_executor(
            None, lambda: writer.write(struct.pack(">I", len(payload)))
        )
        await asyncio.get_event_loop().run_in_executor(None, lambda: writer.write(payload))
        await writer.drain()

    end_time = time.perf_counter()
    megabytes_per_second = (total_size / 1024 / 1024) / (end_time - start_time)

    logger.debug(
        "Took %.2f seconds to send %d bytes (%.2f MB/s)",
        end_time - start_time,
        total_size,
        megabytes_per_second,
    )


async def send_to(service: AsyncServiceInfo, *, file: str) -> None:
    """Send a file to a service.

    Args:
        service (AsyncServiceInfo): The service to send the file to
        file (str): The file to send
    """
    name = service.name.split(".")[0].lstrip("_")

    decoded = from_url64(name)
    peer_endpoint_id = decoded[1:5].decode("ascii")

    logger.debug("Discovered endpoint %r", peer_endpoint_id)

    n_raw = service.properties.get(b"n")

    if n_raw is None:
        logger.debug("No n record found, aborting")
        return None

    n = from_url64(n_raw.decode("utf-8"))

    flags = n[0]
    _visible = bool(flags & 0b00000001)
    type = Type(flags >> 1 & 0b00000111)

    name = n[18:].decode("utf-8")

    logger.debug("Endpoint %r has name %r and type %r", peer_endpoint_id, name, type)

    address: str | None = None
    for addr in service.addresses:
        try:
            address = socket.inet_ntoa(addr)
            socket.gethostbyaddr(address)
            break
        except socket.herror:
            logger.debug("Address %r is not resolvable", address)

    if address is None:
        logger.error("No resolvable addresses found, aborting")
        return None

    logger.debug("Connecting to %s:%d", address, service.port)

    reader, writer = await asyncio.open_connection(address, service.port)

    return await _handle_target(file, reader, writer)


async def _handle_target(  # noqa: PLR0915 # TODO: refactor
    file: str,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    endpoint_id = generate_endpoint_id()

    derive_endpoint_id_from_mac(
        pick_mac_deterministically(get_interfaces()),
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

    connection_response = generate_connection_response()
    data = connection_response.SerializeToString()
    writer.write(struct.pack(">I", len(data)))
    writer.write(data)
    await writer.drain()

    data = await read(reader)

    peer_connection_response = offline_wire_formats_pb2.OfflineFrame()
    peer_connection_response.ParseFromString(data)

    # Everything on the wire is now encrypted
    sequence_number = make_sequence_number()
    send = make_send(writer, keychain, sequence_number)

    paired_key_encryption = generate_paired_key_encryption()
    await send(paired_key_encryption.SerializeToString())

    data = await read(reader)

    secure_message = securemessage_pb2.SecureMessage()
    secure_message.ParseFromString(data)

    _peer_paired_key_encryption = decrypt(secure_message, keychain)

    task = create_task(keep_alive(send))

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

    async for payload_header, data in iter_payload_messages(reader, keychain):
        wire_frame = wire_format_pb2.Frame()
        wire_frame.ParseFromString(data)

        if wire_frame.v1.type == wire_format_pb2.V1Frame.PAIRED_KEY_RESULT:
            # we know we failed this, and we can just ignore it
            ...
        elif wire_frame.v1.type == wire_format_pb2.V1Frame.RESPONSE:
            status = wire_frame.v1.connection_response.status

            if status == wire_format_pb2.ConnectionResponseFrame.ACCEPT:
                logger.debug("Peer accepted our introduction. Ready to send")
                await _send_file(
                    file=file,
                    writer=writer,
                    keychain=keychain,
                    sequence_number=sequence_number,
                    id=id,
                )
            else:
                logger.debug("Peer rejected our introduction. Aborting")
                break
        else:
            logger.warning(
                "Received unknown frame %d type %d", payload_header.id, wire_frame.v1.type
            )

    task.cancel()

    with contextlib.suppress(asyncio.CancelledError):
        await task
