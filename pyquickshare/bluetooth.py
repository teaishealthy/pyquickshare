import asyncio
import logging
import socket
from collections.abc import AsyncGenerator
from typing import Any, cast

from dbus_next.aio.message_bus import MessageBus
from dbus_next.constants import BusType

from pyquickshare.common import from_url64, to_url64

from . import rfcomm
from .dbus.dbus import get_proxy_object
from .mdns.receive import EndpointInfo, parse_endpoint_info

logger = logging.getLogger(__name__)


BLEUTOOTH_QUICKSHARE_UUID = "a82efa21-ae5c-3dde-9bbc-f16da7b16c5a"
BLEUTOOTH_QUICKSHARE_RECEIVE_UUID = "0000fef3-0000-1000-8000-00805f9b34fb"
BLUETOOTH_QUICKSHARE_NEW_UUID = "00001101-0000-1000-8000-00805f9b34fb"
UUIDS = [
    BLEUTOOTH_QUICKSHARE_UUID,
    BLEUTOOTH_QUICKSHARE_RECEIVE_UUID,
    BLUETOOTH_QUICKSHARE_NEW_UUID,
]


class BluetoothDevice:
    def __init__(self, name: str, address: str, channel: int) -> None:
        self.name = name
        self.address = address
        self.channel = channel
        self.endpoint_info = parse_bluetooth_device_name(name)

    def __repr__(self) -> str:  # noqa: D105
        return (
            f"BluetoothDevice(name={self.name!r}, "
            f"address={self.address!r}, "
            f"channel={self.channel!r} "
            f"endpoint_info={self.endpoint_info!r})"
        )


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


def parse_bluetooth_device_name(name: str) -> EndpointInfo:
    # Offset	Size	    Field	               Notes
    # 0	        1 byte	    version_and_pcp	       Upper 3 bits = version, lower 5 bits = PCP
    # 1	        4 bytes	    endpoint_id	           Raw ASCII chars
    # 5	        3 bytes	    service_id_hash	       SHA-256 of service ID, truncated
    # 8	        1 byte	    field_byte	           Bit 0 = WebRTC connectable flag
    # 9	        6 bytes	    (reserved)	           Skipped/ignored
    # 15	    1 byte	    endpoint_info_length   Length of the next field
    # 16	    N bytes	    endpoint_info	       Capped at 131 bytes
    # 16+N	    1 byte	    uwb_address_length	   Optional if bytes remain
    # 17+N	    M bytes	    uwb_address	Optional   UWB address (2 or 8 bytes)

    blob = from_url64(name)

    version_and_pcp = blob[0]
    _version = version_and_pcp >> 5
    _pcp = version_and_pcp & 0b00011111

    _endpoint_id = blob[1:5]
    _service_id_hash = blob[5:8]
    field_byte = blob[8]
    _webrtc_connectable = bool(field_byte & 0b00000001)

    endpoint_info_length = blob[15]
    endpoint_info = blob[16 : 16 + endpoint_info_length]

    return parse_endpoint_info(to_url64(endpoint_info).encode("utf-8"))
