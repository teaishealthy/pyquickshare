import base64
from enum import Enum


def to_url64(data: bytes | bytearray) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


class Type(Enum):
    unknown = 0
    phone = 1
    tablet = 2
    laptop = 3


VERSION = 0b000


def safe_assert(condition: bool, message: str | None = None) -> None:
    if not condition:
        raise AssertionError(message or "Assertion failed")
