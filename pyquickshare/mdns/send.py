import asyncio
import atexit
import binascii
import random
from logging import getLogger
from typing import Any

from bless.backends.bluezdbus.dbus.advertisement import BlueZLEAdvertisement, Type
from bless.backends.bluezdbus.server import BlessServerBlueZDBus
from dbus_next.signature import Variant
from zeroconf import IPVersion, ServiceStateChange, Zeroconf
from zeroconf.asyncio import (
    AsyncServiceBrowser,
    AsyncServiceInfo,
    AsyncZeroconf,
)

from ..common import create_task, tasks

SERVICE_UUID = "FE2C"
SERVICE_DATA = binascii.unhexlify("fc128e0142000000000000000000")

logger = getLogger(__name__)
bluetooth = logger.parent.getChild(  # pyright: ignore[reportOptionalMemberAccess]
    "bluetooth",
)


_tasks: list[asyncio.Task[Any]] = []


class AsyncRunner:
    def __init__(self) -> None:
        self.result: asyncio.Queue[AsyncServiceInfo] = asyncio.Queue()
        self.aiobrowser: AsyncServiceBrowser | None = None
        self.aiozc: AsyncZeroconf | None = None

    async def async_run(self) -> None:
        self.aiozc = AsyncZeroconf(ip_version=IPVersion.V4Only)

        services = ["_FC9F5ED42C8A._tcp.local."]
        self.aiobrowser = AsyncServiceBrowser(
            self.aiozc.zeroconf,
            services,
            handlers=[self.async_on_service_state_change],
        )
        await asyncio.Event().wait()

    async def async_close(self) -> None:
        assert self.aiozc is not None  # noqa: S101 - escape hatch for the type checker
        assert self.aiobrowser is not None  # noqa: S101 - escape hatch for the type checker
        await self.aiobrowser.async_cancel()
        await self.aiozc.async_close()

    def async_on_service_state_change(
        self,
        zeroconf: Zeroconf,
        service_type: str,
        name: str,
        state_change: ServiceStateChange,
    ) -> None:
        if state_change is not ServiceStateChange.Added:
            return
        logger.debug("Discovered Quick Share service: %s", name)

        # make sure this gets cleaned up properly
        tasks.append(
            asyncio.ensure_future(
                self.async_display_service_info(zeroconf, service_type, name),
            ),
        )

    async def async_display_service_info(
        self,
        zeroconf: Zeroconf,
        service_type: str,
        name: str,
    ) -> None:
        info = AsyncServiceInfo(service_type, name)
        await info.async_request(zeroconf, 3000)

        if info:
            await self.result.put(info)


async def trigger_devices() -> None:
    # I actually have zero clue what I'm doing here

    server = BlessServerBlueZDBus(name="pyquickshare")
    await server.setup_task  # pyright: ignore[reportUnknownMemberType]
    bluetooth.debug("Connected to BlueZ D-Bus")  # Hello :3

    advertisement = BlueZLEAdvertisement(Type.BROADCAST, 2, server.app)

    advertisement.ServiceUUIDs = [SERVICE_UUID]
    advertisement.ServiceData = {
        SERVICE_UUID: Variant("ay", SERVICE_DATA + random.randbytes(9)),  # noqa: S311 - random is fine here
    }

    server.app.advertisements = [advertisement]

    server.bus.export(advertisement.path, advertisement)

    iface = server.adapter.get_interface("org.bluez.LEAdvertisingManager1")

    await iface.call_register_advertisement(  # pyright: ignore[reportUnknownMemberType, reportAttributeAccessIssue]
        advertisement.path,
        {},
    )

    bluetooth.debug("Advertising Quick Share service")

    # Wait forever, BlueZ keeps advertising while the D-Bus connection is open
    await asyncio.Future()


async def discover_services(timeout: float = 10) -> asyncio.Queue[AsyncServiceInfo]:  # noqa: ARG001 # TODO: actually timeout
    task = create_task(trigger_devices())
    _tasks.append(task)

    runner = AsyncRunner()

    task = create_task(runner.async_run())
    _tasks.append(task)

    return runner.result


@atexit.register
def cleanup() -> None:
    if _tasks:
        logger.debug("Shutting advertiser and browser down")

    for task in _tasks:
        task.cancel()
