import asyncio
import binascii
import logging
import random

from dbus_next.aio.message_bus import MessageBus
from dbus_next.constants import BusType

from .dbus import get_proxy_object
from .untyped import _FastInitAdvertisement

SERVICE_DATA = binascii.unhexlify("fc128e2000000000000000000000")

_ADV_PATH = "/de/pyquickshare/FastInitAdvertisement"
_BLUEZ = "org.bluez"

logger = logging.getLogger(__name__)


async def trigger_devices() -> None:
    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()

    root_obj = await get_proxy_object(bus, _BLUEZ, "/")
    om = root_obj.get_interface("org.freedesktop.DBus.ObjectManager")
    objects = await om.call_get_managed_objects()

    adapters = [path for path, ifaces in objects.items() if "org.bluez.Adapter1" in ifaces]
    logger.debug("Found Bluetooth adapters: %s", adapters)
    adapter_path = adapters[0] if adapters else None

    if adapter_path is None:
        error = "No Bluetooth adapter found"
        raise RuntimeError(error)

    logger.debug("Connected to BlueZ D-Bus")

    # salt (1) + secret_id_hash (8) + flags (1, 0x00 = not silent, no BT req)
    payload = SERVICE_DATA + random.randbytes(9) + b"\x00"  # noqa: S311
    adv = _FastInitAdvertisement(payload)
    bus.export(_ADV_PATH, adv)

    adapter_obj = await get_proxy_object(bus, _BLUEZ, adapter_path)
    adv_manager = adapter_obj.get_interface("org.bluez.LEAdvertisingManager1")
    await adv_manager.call_register_advertisement(_ADV_PATH, {})

    logger.debug("Advertising Quick Share service")
    # BlueZ keeps advertising for as long as our D-Bus connection is open
    await asyncio.Future()
