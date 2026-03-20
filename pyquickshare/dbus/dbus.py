from typing import Any

from dbus_next.aio.message_bus import MessageBus


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
