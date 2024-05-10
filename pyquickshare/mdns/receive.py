# the mDNS part of QuickShare
from __future__ import annotations

import asyncio
import random
import socket
from logging import getLogger

from zeroconf import IPVersion
from zeroconf.asyncio import AsyncServiceInfo, AsyncZeroconf

from ..common import VERSION, Type, to_url64

logger = getLogger(__name__)


class IPV4Runner:
    def __init__(self) -> None:
        self.aiozc: AsyncZeroconf | None = None

    async def register_services(self, infos: list[AsyncServiceInfo]) -> None:
        self.aiozc = AsyncZeroconf(ip_version=IPVersion.V4Only)
        tasks = [self.aiozc.async_register_service(info) for info in infos]  # type: ignore
        background_tasks = await asyncio.gather(*tasks)  # type: ignore
        await asyncio.gather(*background_tasks)  # type: ignore
        logger.debug("Registered %d services", len(infos))

        while True:
            await asyncio.sleep(1)

    async def unregister_services(self, infos: list[AsyncServiceInfo]) -> None:
        assert self.aiozc is not None
        tasks = [self.aiozc.async_unregister_service(info) for info in infos]  # type: ignore
        background_tasks = await asyncio.gather(*tasks)  # type: ignore
        await asyncio.gather(*background_tasks)  # type: ignore
        await self.aiozc.async_close()


def make_service_name(endpoint_id: bytes) -> bytearray:
    array = bytearray()

    array.append(0x23)  # PCP
    logger.debug("endpoint_id: %s", endpoint_id)
    array.extend(endpoint_id)
    array.extend((0xFC, 0x9F, 0x5E))  # Service ID
    array.extend((0x00, 0x00))  # ¯\_(ツ)_/¯

    return array


def make_n(*, visible: bool, type: Type, name: bytes) -> bytearray:
    n = bytearray()

    # n record:
    # one byte: flags (3) visibility (1) type (3) empty (1)
    # 16 zero bytes
    # one byte: length of name
    # name, utf-8 encoded

    n.append(2)  # FIXME: compute flags from visibility, type, and VERSION
    # add 16 0 bytes
    n.extend([random.randint(1, 8) for _ in range(16)])
    n.append(len(name))
    n.extend(name)
    return n


def make_service(
    *, visible: bool, type: Type, name: bytes, endpoint_id: bytes
) -> AsyncServiceInfo:
    _name = to_url64(make_service_name(endpoint_id))
    n = make_n(visible=visible, type=type, name=name)

    ip = "192.168.0.141"

    info = AsyncServiceInfo(
        "_FC9F5ED42C8A._tcp.local.",
        f"{_name}._FC9F5ED42C8A._tcp.local.",
        port=12345,
        properties={"n": to_url64(n)},
        addresses=[socket.inet_aton(ip)],
        server="",
    )

    return info
