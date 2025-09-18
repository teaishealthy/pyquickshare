# ruff: noqa: PGH003
# the mDNS part of Quick Share
from __future__ import annotations

import asyncio
import os
import pathlib
import random
import socket
from contextlib import closing, suppress
from logging import getLogger

import dbus_next
import ifaddr
from zeroconf import IPVersion
from zeroconf.asyncio import AsyncServiceInfo, AsyncZeroconf

from ..common import InterfaceInfo, Type, to_url64
from ..firewalld import temporarily_open_port

logger = getLogger(__name__)


BASE_PATH = pathlib.Path("/sys/class/net")


def get_interfaces() -> list[str]:
    interfaces: list[str] = []
    for ifa in BASE_PATH.iterdir():
        carrier = ifa.joinpath("carrier")
        with suppress(OSError):
            if (
                "/devices/virtual/net/" not in ifa.resolve().as_posix()
                and carrier.exists()
                and carrier.read_text().strip() == "1"
            ):
                interfaces.append(ifa.name)
    return interfaces


def get_interface_mac(interface: str) -> bytes:
    mac_path = BASE_PATH / interface / "address"

    return bytes.fromhex(mac_path.read_text().strip().replace(":", ""))


class IPV4Runner:
    def __init__(self) -> None:
        self.aiozc: AsyncZeroconf | None = None

    async def register_services(self, infos: list[AsyncServiceInfo]) -> None:
        self.aiozc = AsyncZeroconf(ip_version=IPVersion.V4Only)
        tasks = [self.aiozc.async_register_service(info) for info in infos]  # type: ignore
        background_tasks = await asyncio.gather(*tasks)  # type: ignore
        await asyncio.gather(*background_tasks)  # type: ignore
        logger.debug("Registered %d services", len(infos))

        await asyncio.Event().wait()

    async def unregister_services(self, infos: list[AsyncServiceInfo]) -> None:
        assert self.aiozc is not None  # noqa: S101 - escape hatch for the type checker
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


def make_n(*, visible: bool, type: Type, name: bytes) -> bytearray:  # noqa: ARG001 # TODO: fix this
    n = bytearray()

    # n record:
    # one byte: flags (3) visibility (1) type (3) empty (1)
    # 16 zero bytes
    # one byte: length of name
    # name, utf-8 encoded

    n.append(2)  # flags
    # add 16 0 bytes
    n.extend([random.randint(1, 8) for _ in range(16)])  # noqa: S311 - random is fine here
    n.append(len(name))
    n.extend(name)
    return n


async def make_service(
    *,
    visible: bool,
    type_: Type,
    name: bytes,
    endpoint_id: bytes,
    interface_info: InterfaceInfo,
) -> AsyncServiceInfo:
    _name = to_url64(make_service_name(endpoint_id))
    n = make_n(visible=visible, type=type_, name=name)


    info = AsyncServiceInfo(
        "_FC9F5ED42C8A._tcp.local.",
        f"{_name}._FC9F5ED42C8A._tcp.local.",
        port=interface_info.port,
        parsed_addresses=interface_info.ips,
        properties={"n": to_url64(n)},
    )

    return info


async def get_interface_info() -> InterfaceInfo:
    ips: list[str] = []

    ip = os.environ.get("QUICKSHARE_IP")
    used_interfaces: set[str] = set()

    if ip is None:
        interfaces = get_interfaces()
        for adapter in ifaddr.get_adapters():
            if adapter.name not in interfaces:
                continue

            used_interfaces.add(adapter.name)
            ips.extend(str(ip.ip) for ip in adapter.ips if isinstance(ip.ip, str))

        logger.debug("QUICKSHARE_IP not set, using: %s", ", ".join(ips))
    else:
        ips.append(ip)

    with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as sock:
        sock.bind(("0.0.0.0", 0))  # noqa: S104 - we only care about the port
        _, port = sock.getsockname()

    try:
        for interface in used_interfaces:
            await temporarily_open_port(interface, port)
    except dbus_next.errors.DBusError as e:
        if e.text == "The name is not activatable":
            logger.exception(
                "Failed to open port %d. Are you using firewalld? "
                "You may need to manually open the port on your firewall.",
                port,
            )
    except Exception:
        logger.exception("Failed to open port %d. Are you using firewalld?", port)

    logger.debug("Using port %d", port)

    return InterfaceInfo(ips=ips, port=port)
