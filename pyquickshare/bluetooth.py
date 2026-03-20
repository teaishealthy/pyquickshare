import asyncio
import logging
import socket
from collections.abc import AsyncGenerator
from dataclasses import dataclass
from typing import Any, cast

from dbus_next.aio.message_bus import MessageBus
from dbus_next.constants import BusType

from . import rfcomm
from .dbus.dbus import get_proxy_object

logger = logging.getLogger(__name__)


BLEUTOOTH_QUICKSHARE_UUID = "a82efa21-ae5c-3dde-9bbc-f16da7b16c5a"
BLEUTOOTH_QUICKSHARE_RECEIVE_UUID = "0000fef3-0000-1000-8000-00805f9b34fb"
BLUETOOTH_QUICKSHARE_NEW_UUID = "00001101-0000-1000-8000-00805f9b34fb"
UUIDS = [
    BLEUTOOTH_QUICKSHARE_UUID,
    BLEUTOOTH_QUICKSHARE_RECEIVE_UUID,
    BLUETOOTH_QUICKSHARE_NEW_UUID,
]


@dataclass
class BluetoothDevice:
    name: str
    address: str
    channel: int


async def find_receiving_devices() -> AsyncGenerator[BluetoothDevice, None]:
    logger.debug("Connecting to the system bus")
    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
    logger.info("Connected to the system bus")

    bluez_root = await get_proxy_object(
        bus,
        "org.bluez",
        "/",
    )

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

            channel = cast(
                int,
                rfcomm.find_rfcomm_channel(address, BLEUTOOTH_QUICKSHARE_UUID),  # pyright: ignore[reportAttributeAccessIssue, reportUnknownMemberType]
            )

            yield BluetoothDevice(name, address, channel)


def register_new_devices(object_manager: Any, queue: asyncio.Queue[str]) -> None:
    def on_interfaces_added(object_path: str, interfaces: dict[str, Any]) -> None:
        if "org.bluez.Device1" in interfaces:
            logger.debug("Found new device at %s", object_path)
            queue.put_nowait(object_path)

    object_manager.on_interfaces_added(on_interfaces_added)


async def connect_bluetooth_device(device: BluetoothDevice) -> socket.socket:
    logger.info(
        "Connecting to device %s (%s) on channel %d", device.name, device.address, device.channel
    )

    sock = rfcomm.open_rfcomm_socket()
    rfcomm.connect_rfcomm(sock.fileno(), device.address, device.channel)  # pyright: ignore[reportAttributeAccessIssue, reportUnknownMemberType]
    logger.info(
        "Connected to device %s (%s) on channel %d", device.name, device.address, device.channel
    )

    return sock


async def tinker() -> None:
    async for device in find_receiving_devices():
        sock = await connect_bluetooth_device(device)
        sock.close()
        break


if __name__ == "__main__":
    import asyncio

    logging.basicConfig(level=logging.DEBUG)

    asyncio.run(tinker())
