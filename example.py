import asyncio
from logging import DEBUG, basicConfig

import pyquickshare

basicConfig(level=DEBUG)


async def main():
    await pyquickshare.receive_entrypoint()


if __name__ == "__main__":
    asyncio.run(main())
