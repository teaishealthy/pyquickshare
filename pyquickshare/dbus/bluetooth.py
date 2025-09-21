import asyncio
import contextlib
import logging
from pprint import pprint
from typing import Any

from dbus_next.aio.message_bus import MessageBus
from dbus_next.constants import BusType
from dbus_next.signature import Variant

from .dbus import get_proxy_object
from .untyped import Profile

logger = logging.getLogger(__name__)


BLEUTOOTH_QUICKSHARE_UUID = "a82efa21-ae5c-3dde-9bbc-f16da7b16c5a"
BLEUTOOTH_QUICKSHARE_RECEIVE_UUID = "0000fef3-0000-1000-8000-00805f9b34fb"
BLUETOOTH_QUICKSHARE_NEW_UUID = "00001101-0000-1000-8000-00805f9b34fb"
UUIDS = [BLEUTOOTH_QUICKSHARE_UUID, BLEUTOOTH_QUICKSHARE_RECEIVE_UUID, BLUETOOTH_QUICKSHARE_NEW_UUID]
PROFILE_PATH = "/de/pyquickshare/bluetooth/profile"
OPTIONS = {uuid: {
        "Name": Variant("s", f"PyQuickShare {uuid[-4:]}"),
        "Channel": Variant("q", 0),
        "RequireAuthentication": Variant("b", False),
        "RequireAuthorization": Variant("b", False),
        "AutoConnect": Variant("b", True),
        "PSM": Variant("q", 0),
    } for uuid in UUIDS}
pprint(OPTIONS)


async def tinker():
    logger.debug("Connecting to the system bus")
    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
    logger.info("Connected to the system bus")

    bluez_root = await get_proxy_object(
        bus,
        "org.bluez",
        "/",
    )
    bluez = await get_proxy_object(
        bus,
        "org.bluez",
        "/org/bluez",
    )

    profile_manager = bluez.get_interface("org.bluez.ProfileManager1")
    for uuid, option in OPTIONS.items():
        profile = Profile()
        profile_path = f"{PROFILE_PATH}/{uuid.replace('-', '_')}"
        bus.export(profile_path, profile)
        logger.debug("Registering profile with uuid %s", uuid)
        await profile_manager.call_register_profile(profile_path, uuid, option)

    object_manager = bluez_root.get_interface("org.freedesktop.DBus.ObjectManager")
    objects = await object_manager.call_get_managed_objects()

    adapter_path = None
    for path, interfaces in objects.items():
        if "org.bluez.Adapter1" in interfaces:
            logger.debug("Found adapter at %s", path)
            adapter_path = path
            break

    if adapter_path is None:
        logger.error("No Bluetooth adapter found")
        return


    queue: asyncio.Queue[str] = asyncio.Queue()

    for path, interface in objects.items():
        if "org.bluez.Device1" in interface:
            await queue.put(path)

    register_new_devices(object_manager, queue)

    adapter_proxy = await get_proxy_object(bus, "org.bluez", adapter_path)
    adapter = adapter_proxy.get_interface("org.bluez.Adapter1")
    await adapter.call_start_discovery()


    while True:
        path = await queue.get()
        device_proxy = await get_proxy_object(bus, "org.bluez", path)
        device = device_proxy.get_interface("org.bluez.Device1")
        uuids = [u.casefold() for u in await device.get_uui_ds()]
        if BLEUTOOTH_QUICKSHARE_UUID in uuids:
            name = await device.get_name()
            address = await device.get_address()
            logger.info("Found QuickShare device: %s (%s) at %s", name, address, path)
            await device.set_trusted(True)
            print("Trusted?", await device.get_trusted())
            for uuid in UUIDS:
                if uuid in uuids:
                    logger.info("Connecting to profile %s", uuid)
                    #await device.call_connect_profile(uuid)
            logger.exception("No more profiles to connect")

def register_new_devices(object_manager: Any, queue: asyncio.Queue[str]) -> None:
    def on_interfaces_added(object_path: str, interfaces: dict[str, Any]) -> None:
        if "org.bluez.Device1" in interfaces:
            logger.debug("Found new device at %s", object_path)
            queue.put_nowait(object_path)

    object_manager.on_interfaces_added(on_interfaces_added)

if __name__ == "__main__":
    import asyncio

    logging.basicConfig(level=logging.DEBUG)

    asyncio.run(tinker())
