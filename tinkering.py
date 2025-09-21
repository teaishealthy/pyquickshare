# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "bluetooth",
# ]
# ///
import asyncio
import socket


async def main():
    
    bdaddr = "18:F0:E4:3C:07:8B"
    port = 1  # RFCOMM channel

    sock = socket.socket(   , socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
    sock.setblocking(False)

    loop = asyncio.get_running_loop()
    await loop.sock_connect(sock, (bdaddr, port))
    print("Connected!")

    # Example send/receive loop
    await loop.sock_sendall(sock, b"Hello Bluetooth!\n")
    data = await loop.sock_recv(sock, 1024)
    print("Got:", data.decode())

asyncio.run(main())