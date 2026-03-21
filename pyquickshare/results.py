from __future__ import annotations

from typing import TYPE_CHECKING, NamedTuple, TypeAlias

if TYPE_CHECKING:
    from .protos.nearby.sharing.service.proto import WifiCredentialsMetadataSecurityType


class FileResult(NamedTuple):
    name: str
    path: str
    size: int


class TextResult(NamedTuple):
    title: str
    text: str


class WifiResult(NamedTuple):
    ssid: str
    password: str
    security_type: WifiCredentialsMetadataSecurityType


Result: TypeAlias = FileResult | TextResult | WifiResult
