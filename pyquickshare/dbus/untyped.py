# pyright: basic
# ruff: noqa: ANN204 ANN201 N802
from dbus_next.service import ServiceInterface, method


class Profile(ServiceInterface):
    def __init__(self):
        super().__init__("org.bluez.Profile1")

    @method()
    async def NewConnection(self, device: "o", fd: "h", fd_properties: "a{sv}"):
        print("NewConnection from device:", device)
        # Take ownership of fd
        print("File descriptor:", fd)

    @method()
    async def RequestDisconnection(self, device: "o"):
        print("RequestDisconnection from device:", device)

    @method()
    async def Release(self):
        print("Profile released")
