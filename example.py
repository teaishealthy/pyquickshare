import asyncio
import contextlib
import sys
from logging import DEBUG, basicConfig

import pyquickshare

basicConfig(level=DEBUG)


async def send(file: str) -> None:
    quickshare = await pyquickshare.discover_services()
    quickshare.qr_code.print()

    first = await anext(quickshare)

    return await pyquickshare.send_to(first, file=file)


async def main(argv: list[str]) -> None:
    if len(argv) < 2:
        print("Usage: example.py <mode> [args...]")
        return

    if argv[1] == "send":
        if len(argv) < 3:
            print("Usage: example.py send <file>")
            return
        await send(argv[2])
    elif argv[1] == "receive":
        # if you want to appear like different devices, you can change the endpoint_id like this:
        # asnyc for request in pyquickshare.receive(endpoint_id=b"1234"):
        # (the endpoint_id must be 4 bytes long, you can use pyquickshare.generate_enpoint_id())

        async for request in pyquickshare.receive(endpoint_id=pyquickshare.generate_endpoint_id()):
            results = await request.accept()
            print(results)

    else:
        print("Unknown mode:", argv[1])


if __name__ == "__main__":
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(main(sys.argv))
