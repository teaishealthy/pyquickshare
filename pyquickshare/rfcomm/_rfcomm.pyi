# pyright: reportIncompatibleMethodOverride=false
# ruff: noqa: N801
import typing

__all__: list[str] = [
    "AF_BLUETOOTH",
    "BTPROTO_RFCOMM",
    "BT_SECURITY",
    "BT_SECURITY_FIPS",
    "BT_SECURITY_HIGH",
    "BT_SECURITY_LOW",
    "BT_SECURITY_MEDIUM",
    "BT_SECURITY_SDP",
    "PF_BLUETOOTH",
    "RFCOMM_CONNINFO",
    "RFCOMM_DEFAULT_MTU",
    "RFCOMM_LM",
    "RFCOMM_LM_AUTH",
    "RFCOMM_LM_ENCRYPT",
    "RFCOMM_LM_MASTER",
    "RFCOMM_LM_RELIABLE",
    "RFCOMM_LM_SECURE",
    "RFCOMM_LM_TRUSTED",
    "RFCOMM_PSM",
    "SHUT_RD",
    "SHUT_RDWR",
    "SHUT_WR",
    "SOCK_SEQPACKET",
    "SOCK_STREAM",
    "SOL_BLUETOOTH",
    "SOL_RFCOMM",
    "ba2str",
    "bacmp",
    "bacpy",
    "bdaddr_t",
    "bind_rfcomm",
    "bt_security",
    "connect_rfcomm",
    "find_rfcomm_channel",
    "getsockopt_bytes",
    "make_rfcomm_socket",
    "rfcomm_conninfo",
    "setsockopt_bytes",
    "sockaddr_rc",
    "str2ba",
]

Int: typing.TypeAlias = typing.SupportsIndex | typing.SupportsInt

class bdaddr_t:
    __hash__: typing.ClassVar[None] = None
    b: bytes
    def __eq__(self, arg0: bdaddr_t) -> bool: ...
    def __init__(self) -> None: ...
    def __ne__(self, arg0: bdaddr_t) -> bool: ...

class bt_security:
    @typing.overload
    def __init__(self) -> None: ...
    @typing.overload
    def __init__(self, level: Int, key_size: Int = 0) -> None: ...
    def pack(self) -> bytes: ...
    @property
    def key_size(self) -> int: ...
    @key_size.setter
    def key_size(self, arg0: Int) -> None: ...
    @property
    def level(self) -> int: ...
    @level.setter
    def level(self, arg0: Int) -> None: ...

class rfcomm_conninfo:
    dev_class: bytes
    @staticmethod
    def unpack(raw: bytes) -> rfcomm_conninfo: ...
    def __init__(self) -> None: ...
    @property
    def hci_handle(self) -> int: ...
    @hci_handle.setter
    def hci_handle(self, arg0: Int) -> None: ...

class sockaddr_rc:
    rc_bdaddr: bdaddr_t
    def __init__(self) -> None: ...
    @property
    def rc_channel(self) -> int: ...
    @rc_channel.setter
    def rc_channel(self, arg0: Int) -> None: ...
    @property
    def rc_family(self) -> int: ...
    @rc_family.setter
    def rc_family(self, arg0: Int) -> None: ...

def ba2str(ba: bdaddr_t) -> str: ...
def bacmp(ba1: bdaddr_t, ba2: bdaddr_t) -> int: ...
def bacpy(dst: bdaddr_t, src: bdaddr_t) -> None: ...
def bind_rfcomm(fd: Int, bdaddr_str: str, channel: Int) -> None: ...
def connect_rfcomm(fd: Int, bdaddr_str: str, channel: Int) -> None: ...
def find_rfcomm_channel(remote_bdaddr: str, uuid: str) -> int: ...
def getsockopt_bytes(fd: Int, level: Int, optname: Int, buflen: Int) -> bytes: ...
def make_rfcomm_socket() -> int: ...
def setsockopt_bytes(fd: Int, level: Int, optname: Int, data: bytes) -> None: ...
def str2ba(str: str) -> bdaddr_t: ...

AF_BLUETOOTH: int = 31
BTPROTO_RFCOMM: int = 3
BT_SECURITY: int = 4
BT_SECURITY_FIPS: int = 4
BT_SECURITY_HIGH: int = 3
BT_SECURITY_LOW: int = 1
BT_SECURITY_MEDIUM: int = 2
BT_SECURITY_SDP: int = 0
PF_BLUETOOTH: int = 31
RFCOMM_CONNINFO: int = 2
RFCOMM_DEFAULT_MTU: int = 127
RFCOMM_LM: int = 3
RFCOMM_LM_AUTH: int = 2
RFCOMM_LM_ENCRYPT: int = 4
RFCOMM_LM_MASTER: int = 1
RFCOMM_LM_RELIABLE: int = 16
RFCOMM_LM_SECURE: int = 32
RFCOMM_LM_TRUSTED: int = 8
RFCOMM_PSM: int = 3
SHUT_RD: int = 0
SHUT_RDWR: int = 2
SHUT_WR: int = 1
SOCK_SEQPACKET: int = 5
SOCK_STREAM: int = 1
SOL_BLUETOOTH: int = 274
SOL_RFCOMM: int = 18
