import asyncio
from logging import getLogger

from zeroconf import IPVersion, ServiceStateChange, Zeroconf
from zeroconf.asyncio import (
    AsyncServiceBrowser,
    AsyncServiceInfo,
    AsyncZeroconf,
)

from pyquickshare.dbus.bluez import trigger_devices

from ..common import create_task, tasks

logger = getLogger(__name__)


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


async def discover_services(timeout: float = 10) -> asyncio.Queue[AsyncServiceInfo]:  # noqa: ARG001 # TODO: actually timeout
    create_task(trigger_devices())

    runner = AsyncRunner()

    create_task(runner.async_run())

    return runner.result
