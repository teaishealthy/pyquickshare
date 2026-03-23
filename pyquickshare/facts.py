import abc
import logging
from typing import NamedTuple

from dbus_next.aio.message_bus import MessageBus
from dbus_next.constants import BusType

from .dbus.bluez import BLUEZ, get_advertisement_manager, get_bluetooth_adapter
from .dbus.dbus import get_proxy_object

logger = logging.getLogger(__name__)

_ADVICE_BLE = (
    "Bluetooth Low Energy (BLE) is required for Quick Share. "
    "Without BLE, Quick Share will not be able to advertise itself to nearby devices."
)

_ADVICE_BLUETOOTH = (
    "Bluetooth is required for Quick Share. "
    "Please ensure Bluetooth is enabled and a compatible adapter is present."
)

_ADVICE_NETWORK_MANAGER = (
    "NetworkManager is required for switching to Wi-Fi Direct. "
    "If you want to use Wi-Fi Direct, please install NetworkManager and ensure it's running."
)


class Feature(abc.ABC):
    """A feature the system has, such as Bluetooth, Wi-Fi, etc."""

    def __init__(self, name: str, *, advice: str | None = None) -> None:
        self.name: str = name
        self.advice: str | None = advice
        self._state: bool | None = None

    @property
    def state(self) -> bool:
        """Whether the system has this feature."""
        if self._state is None:
            error = "Feature {} has not been checked yet."
            raise RuntimeError(error.format(self.name))
        return self._state

    async def collect(self) -> None:
        """Collect the fact about this feature."""
        self._state = await self.check()

    @abc.abstractmethod
    async def check(self) -> bool:
        """Check if the system has this feature."""


class BLE(Feature):
    def __init__(self) -> None:
        super().__init__("BLE", advice=_ADVICE_BLE)

    async def check(self) -> bool:
        try:
            result = await get_advertisement_manager()
        except Exception:
            logger.exception("Failed to connect to BlueZ or missing BLE support")
            return False
        else:
            return result is not None


class Bluetooth(Feature):
    def __init__(self) -> None:
        super().__init__("Bluetooth", advice=_ADVICE_BLUETOOTH)

    async def check(self) -> bool:
        try:
            bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
            root_obj = await get_proxy_object(bus, BLUEZ, "/")
            adapter_path = await get_bluetooth_adapter(root_obj)
        except Exception:
            logger.exception("Failed to connect to BlueZ or missing Bluetooth adapter")
            return False
        else:
            return adapter_path is not None


class NetworkManager(Feature):
    def __init__(self) -> None:
        super().__init__("NetworkManager", advice=_ADVICE_NETWORK_MANAGER)

    async def check(self) -> bool:
        try:
            bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
            await get_proxy_object(
                bus, "org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager"
            )
        except Exception:
            logger.exception("Failed to connect to NetworkManager via D-Bus")
            return False
        else:
            return True


class Facts(NamedTuple):
    ble: bool
    bluetooth: bool
    network_manager: bool


async def collect_facts() -> Facts:
    ble = BLE()
    bluetooth = Bluetooth()
    network_manager = NetworkManager()
    features = [ble, bluetooth, network_manager]

    logger.info("Collecting system facts for features: %s", [feature.name for feature in features])

    for feature in features:
        await feature.collect()

    facts = Facts(ble=ble.state, bluetooth=bluetooth.state, network_manager=network_manager.state)
    logger.info("Collected system facts: %s", facts)
    return facts
