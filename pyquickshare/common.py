import asyncio
import atexit
import base64
import struct
from enum import Enum
from typing import Any, NamedTuple, TypeVar

tasks: list[asyncio.Task[Any]] = []

T = TypeVar("T")


def to_url64(data: bytes | bytearray) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def from_url64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def create_task(*args: Any, **kwargs: Any) -> asyncio.Task[Any]:  # - Any is good enough for this
    task = asyncio.create_task(*args, **kwargs)
    tasks.append(task)
    return task


@atexit.register
def shutdown() -> None:
    for task in tasks:
        task.cancel()


class Type(Enum):
    unknown = 0
    phone = 1
    tablet = 2
    laptop = 3


VERSION = 0b000


def safe_assert(condition: bool, message: str | None = None) -> None:  # noqa: FBT001 - this is an 'assert'
    if not condition:
        raise AssertionError(message or "Assertion failed")


async def read(reader: asyncio.StreamReader) -> bytes:
    (length,) = struct.unpack(">I", await reader.readexactly(4))
    return await reader.readexactly(length)

class InterfaceInfo(NamedTuple):
    ips: list[str]
    port: int
