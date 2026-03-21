from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import TYPE_CHECKING

from dbus_next.aio.message_bus import MessageBus
from dbus_next.constants import BusType
from dbus_next.signature import Variant

from .dbus import get_proxy_object

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

logger = logging.getLogger(__name__)

_NM = "org.freedesktop.NetworkManager"
_NM_PATH = "/org/freedesktop/NetworkManager"

_DEVICE_TYPE_WIFI = 2

_AC_STATE_ACTIVATED = 2
_AC_STATE_DEACTIVATING = 3

_WIFI_24GHZ_BAND_MIN_FREQ_MHZ = 2400
_WIFI_24GHZ_BAND_MAX_FREQ_MHZ = 2500
_WIFI_5GHZ_BAND_MIN_FREQ_MHZ = 5000
_WIFI_5GHZ_BAND_MAX_FREQ_MHZ = 6000

_WIFI_24GHZ_CHANNEL_OFFSET = 2407
_WIFI_24GHZ_MIN_FREQ_MHZ = 2412
_WIFI_24GHZ_MAX_FREQ_MHZ = 2484

_WIFI_5GHZ_CHANNEL_OFFSET = 5000
_WIFI_5GHZ_MIN_FREQ_MHZ = 5180
_WIFI_5GHZ_MAX_FREQ_MHZ = 5825


def freq_to_band(frequency: int) -> str:
    """Convert frequency (MHz) to band."""
    if _WIFI_24GHZ_BAND_MIN_FREQ_MHZ <= frequency <= _WIFI_24GHZ_BAND_MAX_FREQ_MHZ:
        return "bg"
    if _WIFI_5GHZ_BAND_MIN_FREQ_MHZ <= frequency <= _WIFI_5GHZ_BAND_MAX_FREQ_MHZ:
        return "a"
    return ""


def freq_to_channel(frequency: int) -> int:
    """Convert frequency (MHz) to channel number."""
    if _WIFI_24GHZ_MIN_FREQ_MHZ <= frequency <= _WIFI_24GHZ_MAX_FREQ_MHZ:
        return (frequency - _WIFI_24GHZ_CHANNEL_OFFSET) // 5

    if _WIFI_5GHZ_MIN_FREQ_MHZ <= frequency <= _WIFI_5GHZ_MAX_FREQ_MHZ:
        return (frequency - _WIFI_5GHZ_CHANNEL_OFFSET) // 5
    return 0


def static_ip_from_gateway(gateway: str) -> str:
    """Derive a static IP address from the gateway by picking a different last octet."""
    parts = gateway.split(".")
    last = int(parts[-1])
    last = (last + 1) % 255

    return ".".join([*parts[:-1], str(last)])


async def _find_wifi_device_path(bus: MessageBus) -> str:
    nm = await get_proxy_object(bus, _NM, _NM_PATH)
    nm_iface = nm.get_interface(_NM)
    for device_path in await nm_iface.call_get_all_devices():
        device = await get_proxy_object(bus, _NM, device_path)
        device_iface = device.get_interface(f"{_NM}.Device")
        if await device_iface.get_device_type() == _DEVICE_TYPE_WIFI:
            return device_path
    msg = "No WiFi device found"
    raise RuntimeError(msg)


async def _wait_for_activated(bus: MessageBus, ac_path: str, timeout: float) -> None:
    ac = await get_proxy_object(bus, _NM, ac_path)
    ac_iface = ac.get_interface(f"{_NM}.Connection.Active")

    # Check immediately to avoid missing a transition that already happened.
    state = await ac_iface.get_state()
    if state == _AC_STATE_ACTIVATED:
        return
    if state >= _AC_STATE_DEACTIVATING:
        msg = f"WiFi Direct connection failed (NM state={state})"
        raise RuntimeError(msg)

    queue: asyncio.Queue[int] = asyncio.Queue()

    def _on_state_changed(new_state: int, *_: object) -> None:
        queue.put_nowait(new_state)

    ac_iface.on_state_changed(_on_state_changed)
    try:
        deadline = asyncio.get_event_loop().time() + timeout
        while True:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                msg = "WiFi Direct connection timed out"
                raise TimeoutError(msg)
            try:
                new_state = await asyncio.wait_for(queue.get(), timeout=remaining)
            except asyncio.TimeoutError:
                msg = "WiFi Direct connection timed out"
                raise TimeoutError(msg) from None
            if new_state == _AC_STATE_ACTIVATED:
                return
            if new_state >= _AC_STATE_DEACTIVATING:
                msg = f"WiFi Direct connection failed (NM state={new_state})"
                raise RuntimeError(msg)
    finally:
        ac_iface.off_state_changed(_on_state_changed)


async def connect_p2p_group(
    ssid: str,
    password: str,
    frequency: int,
    gateway: str,
    *,
    timeout: float = 30.0,
) -> Callable[[], Awaitable[None]]:
    """Connect to a WiFi Direct group and return a cleanup callback to disconnect from it."""
    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
    wifi_device_path = await _find_wifi_device_path(bus)

    nm = await get_proxy_object(bus, _NM, _NM_PATH)
    nm_iface = nm.get_interface(_NM)

    settings = {
        "connection": {
            "id": Variant("s", f"pyquickshare-{ssid}"),
            "type": Variant("s", "802-11-wireless"),
        },
        "802-11-wireless": {
            "ssid": Variant("ay", ssid.encode()),
            "mode": Variant("s", "infrastructure"),
            "band": Variant("s", freq_to_band(frequency)),
            "channel": Variant("u", freq_to_channel(frequency)),
            "hidden": Variant("b", False),  # noqa: FBT003
            "powersave": Variant("u", 2),
        },
        "802-11-wireless-security": {
            "key-mgmt": Variant("s", "wpa-psk"),
            "psk": Variant("s", password),
        },
        "ipv4": {
            "method": Variant("s", "manual"),
            "address-data": Variant(
                "aa{sv}",
                [
                    {
                        "address": Variant("s", static_ip_from_gateway(gateway)),
                        "prefix": Variant("u", 24),
                    },
                ],
            ),
            "gateway": Variant("s", gateway),
        },
        "ipv6": {"method": Variant("s", "disabled")},
    }

    conn_path, ac_path, _result = await nm_iface.call_add_and_activate_connection2(
        settings,
        wifi_device_path,
        "/",
        {"persist": Variant("s", "volatile")},
    )
    logger.debug("Activating connection %s for P2P group %r", ac_path, ssid)

    await _wait_for_activated(bus, ac_path, timeout)
    logger.debug("Connected to P2P group %r", ssid)

    async def destroy_p2p_group() -> None:
        with contextlib.suppress(Exception):
            await nm_iface.call_deactivate_connection(ac_path)
        with contextlib.suppress(Exception):
            conn_obj = await get_proxy_object(bus, _NM, conn_path)
            conn_settings = conn_obj.get_interface(f"{_NM}.Settings.Connection")
            await conn_settings.call_delete()
        bus.disconnect()
        logger.debug("Disconnected from P2P group %r", ssid)

    return destroy_p2p_group
