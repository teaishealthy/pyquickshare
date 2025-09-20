"""Quick Share implementation in Python."""

from __future__ import annotations

import asyncio
import contextlib
import enum
import math
import struct
import time
from logging import getLogger
from typing import TYPE_CHECKING, cast

import aiofile

from .common import (
    InterfaceInfo,
    Type,
    create_task,
    derive_endpoint_id_from_mac,
    generate_connection_response,
    generate_paired_key_encryption,
    iter_payload_messages,
    keep_alive,
    make_send,
    make_sequence_number,
    pick_mac_deterministically,
    read,
    safe_assert,
)
from .mdns.receive import (
    IPV4Runner,
    get_interface_info,
    get_interfaces,
    make_service,
)
from .protos import (
    offline_wire_formats_pb2,
    wire_format_pb2,
)
from .results import FileResult, Result, TextResult, WifiResult
from .ukey2 import do_server_key_exchange

NAME = "pyquickshare"

logger = getLogger(__name__)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from zeroconf.asyncio import AsyncServiceInfo


__all__ = (
    "ShareRequest",
    "receive",
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


def _generate_accept() -> bytes:
    accept = wire_format_pb2.Frame()
    accept.v1.type = wire_format_pb2.V1Frame.RESPONSE
    accept.version = wire_format_pb2.Frame.V1
    accept.v1.connection_response.status = wire_format_pb2.ConnectionResponseFrame.ACCEPT

    return accept.SerializeToString()


async def _handle_client(  # noqa: C901 , PLR0912 , PLR0915 # TODO: refactor
    requests: asyncio.Queue[ShareRequest],
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    start = time.perf_counter()
    ip, port = writer.get_extra_info("peername")
    logger.debug("Connection from %s:%d", ip, port)

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

    logger.debug("Received CONNECTION_REQUEST from %r", name)

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
    logger.debug("Client %s is on OS %r", name, os)

    connection_response = generate_connection_response()

    data = connection_response.SerializeToString()
    writer.write(struct.pack(">I", len(data)))
    writer.write(data)
    await writer.drain()

    # All messages on the wire are now encrypted

    sequence_number = make_sequence_number()

    send = make_send(writer, keychain, sequence_number)

    logger.debug("Connection established with %r", name)

    # ¯\_(ツ)_/¯
    paired_key_encryption = generate_paired_key_encryption()
    await send(paired_key_encryption.SerializeToString())

    await writer.drain()

    logger.debug("Sent PAIRED_KEY_ENCRYPTION")

    keep_alive_task = asyncio.create_task(keep_alive(send))

    receive_mode: ReceiveMode | None = None
    expected_payload_ids: dict[
        int,
        wire_format_pb2.WifiCredentialsMetadata
        | wire_format_pb2.FileMetadata
        | wire_format_pb2.TextMetadata,
    ] = {}

    request: ShareRequest | None = None
    results: list[Result] = []

    async for payload_header, data in iter_payload_messages(reader, keychain):
        if payload_header.id in expected_payload_ids:
            metadata = expected_payload_ids.pop(payload_header.id)

            if receive_mode is ReceiveMode.FILES:
                metadata = cast(wire_format_pb2.FileMetadata, metadata)

                logger.debug(
                    "Received full file, saving to downloads/%s",
                    payload_header.file_name,
                )
                async with aiofile.async_open(f"downloads/{payload_header.file_name}", "wb") as f:
                    await f.write(data)

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

                logger.debug("Received wifi credentials %r", credentials.password)

                results.append(
                    WifiResult(
                        ssid=metadata.ssid,
                        password=credentials.password,
                        security_type=metadata.security_type,
                    ),
                )
            elif receive_mode is ReceiveMode.TEXT:
                metadata = cast(wire_format_pb2.TextMetadata, metadata)

                logger.debug("Received text %d", payload_header.id)

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
                    logger.debug(
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
                    logger.debug(
                        "%r wants to send %r",
                        name,
                        ", ".join(m.name for m in wire_frame.v1.introduction.file_metadata),
                    )

                    receive_mode = ReceiveMode.FILES
                    request = ShareRequest(payload_header, to_pin(keychain.auth_string))
                    await requests.put(request)
                    result = await request.respond

                    if result:
                        logger.debug("Accepting introduction")
                        await send(_generate_accept())
                        expected_payload_ids.update(
                            {m.payload_id: m for m in wire_frame.v1.introduction.file_metadata},
                        )
                    else:
                        logger.debug("Rejecting introduction")
                        # TODO: send a rejection

                elif wire_frame.v1.introduction.text_metadata:
                    receive_mode = ReceiveMode.TEXT
                    request = ShareRequest(payload_header, to_pin(keychain.auth_string))
                    await requests.put(request)
                    logger.debug("Receiving text")
                    expected_payload_ids.update(
                        {m.payload_id: m for m in wire_frame.v1.introduction.text_metadata},
                    )

                    await send(_generate_accept())
                else:
                    logger.debug("Received weird introduction %d", payload_header.id)
            else:
                logger.debug("Received unknown frame %d", payload_header.id)

        if not expected_payload_ids and receive_mode is not None:
            # We've received all attachments we were expecting
            break

    duration = time.perf_counter() - start

    logger.debug("Connection with %r closed after %f seconds", name, duration)

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
    server = await asyncio.start_server(
        lambda reader, writer: _handle_client(requests, reader, writer),
        interface_info.ips,
        interface_info.port,
    )

    await server.serve_forever()


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
        or derive_endpoint_id_from_mac(pick_mac_deterministically(get_interfaces())),
        visible=True,
        type_=Type.phone,
        name=NAME.encode("utf-8"),
        interface_info=interface_info,
    )
    services = [info]
    result: asyncio.Queue[ShareRequest] = asyncio.Queue()

    create_task(_socket_server(result, interface_info=interface_info))
    create_task(_start_mdns_service(services))

    while True:
        yield await result.get()


async def _start_mdns_service(services: list[AsyncServiceInfo]) -> None:
    runner = IPV4Runner()
    try:
        await runner.register_services(services)
    except asyncio.CancelledError:
        await runner.unregister_services(services)
