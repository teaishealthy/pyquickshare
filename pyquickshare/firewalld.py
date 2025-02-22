"""Module to command firewalld to open a port to allow incoming connections temporarily."""

import logging
from typing import Any

from dbus_next.aio.message_bus import MessageBus
from dbus_next.constants import BusType

logger = logging.getLogger(__name__)


__all__ = ("temporarily_open_port",)


async def get_proxy_object(
    bus: MessageBus,
    name: str,
    path: str,
    introspection: Any = None,
) -> Any:
    if introspection is None:
        introspection = await bus.introspect(
            name,
            path,
        )

    return bus.get_proxy_object(
        name,
        path,
        introspection,
    )


async def temporarily_open_port(interface: str, port: int = 8080) -> None:
    logger.info("Opening port %d for 5 minutes", port)

    logger.debug("Connecting to the system bus")
    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
    logger.info("Connected to the system bus")

    firewalld_root = await get_proxy_object(
        bus,
        "org.fedoraproject.FirewallD1",
        "/org/fedoraproject/FirewallD1",
    )
    firewalld = firewalld_root.get_interface("org.fedoraproject.FirewallD1")
    await firewalld.call_authorize_all()
    logger.info("Authorized all")

    zone_obj = firewalld_root.get_interface("org.fedoraproject.FirewallD1.zone")
    # 1. Get all zones
    zones = await zone_obj.call_get_zones()
    logger.debug("Got zones: %s", zones)

    zone: str | None = None
    for zone in zones:
        # zone is a string of the path to the zone object
        interfaces_in_zone = await zone_obj.call_get_interfaces(zone)
        if interface in interfaces_in_zone:
            logger.debug("Interface %r found in zone %r", interface, zone)
            break

    if zone is None:
        logger.error("Interface %r not found in any zone", interface)
        logger.error("This is likely a bug in pyquickshare.")
        return

    await zone_obj.call_add_port(zone, str(port), "tcp", 300)
    logger.info("Added port %d to zone %r for 5 minutes", port, zone)
