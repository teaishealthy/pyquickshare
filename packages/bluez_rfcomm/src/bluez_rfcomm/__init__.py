"""BlueZ RFCOMM bindings via pybind11."""

import socket as _socket

from ._rfcomm import (
    # structs
    bdaddr_t,
    bt_security,
    rfcomm_conninfo,
    sockaddr_rc,
    # libbluetooth helpers
    ba2str,
    bacmp,
    bacpy,
    str2ba,
    # socket helpers
    bind_rfcomm,
    connect_rfcomm,
    getsockopt_bytes,
    make_rfcomm_socket,
    setsockopt_bytes,
    # SDP discovery
    find_rfcomm_channel,
    # constants — protocol family / socket type
    AF_BLUETOOTH,
    BTPROTO_RFCOMM,
    PF_BLUETOOTH,
    SOCK_SEQPACKET,
    SOCK_STREAM,
    # socket option levels
    SOL_BLUETOOTH,
    SOL_RFCOMM,
    # BT_SECURITY
    BT_SECURITY,
    BT_SECURITY_FIPS,
    BT_SECURITY_HIGH,
    BT_SECURITY_LOW,
    BT_SECURITY_MEDIUM,
    BT_SECURITY_SDP,
    # RFCOMM socket options
    RFCOMM_CONNINFO,
    RFCOMM_DEFAULT_MTU,
    RFCOMM_LM,
    RFCOMM_LM_AUTH,
    RFCOMM_LM_ENCRYPT,
    RFCOMM_LM_MASTER,
    RFCOMM_LM_RELIABLE,
    RFCOMM_LM_SECURE,
    RFCOMM_LM_TRUSTED,
    RFCOMM_PSM,
    # shutdown flags
    SHUT_RD,
    SHUT_RDWR,
    SHUT_WR,
)

__all__ = [
    # structs
    "bdaddr_t",
    "bt_security",
    "rfcomm_conninfo",
    "sockaddr_rc",
    # libbluetooth helpers
    "ba2str",
    "bacmp",
    "bacpy",
    "str2ba",
    # socket helpers
    "bind_rfcomm",
    "connect_rfcomm",
    "getsockopt_bytes",
    "make_rfcomm_socket",
    "find_rfcomm_channel",
    "open_rfcomm_socket",
    "setsockopt_bytes",
    # constants
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
]


def open_rfcomm_socket() -> _socket.socket:
    """Create an RFCOMM socket wrapped in a Python socket object.

    The returned socket is ready for asyncio use via loop.sock_connect(),
    loop.sock_sendall(), loop.sock_recv(), etc.

    socket.socket(fileno=fd) takes ownership of the fd — do not close it
    separately.
    """
    fd = make_rfcomm_socket()
    return _socket.socket(fileno=fd)
