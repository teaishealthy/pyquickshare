import asyncio
import logging
import tempfile
from typing import Any

import pytest

import pyquickshare
from pyquickshare.receive import _handle_client  # type: ignore
from pyquickshare.send import _handle_target  # type: ignore

logging.basicConfig(level=logging.DEBUG)


class PipeTransport(asyncio.WriteTransport):
    def __init__(self, reader: asyncio.StreamReader, close_event: asyncio.Event):
        self._reader: asyncio.StreamReader = reader
        self._close: asyncio.Event = close_event
        super().__init__(
            {
                "peername": ("192.168.0.1", 1234),
            }
        )

    def write(self, data: bytes):
        self._reader.feed_data(data)

    def is_closing(self):
        return self._close.is_set()

    def close(self):
        self._close.set()
        self._reader.feed_eof()


class ClientServerProtocol(asyncio.streams.FlowControlMixin, asyncio.Protocol):
    def __init__(
        self, close_event: asyncio.Event, loop: asyncio.AbstractEventLoop | None = None
    ):
        self._close: asyncio.Event = close_event
        super().__init__(loop)

    def _get_close_waiter(self, stream: Any):
        return self._close.wait()


async def _stream_pairs() -> (
    tuple[
        tuple[asyncio.StreamReader, asyncio.StreamWriter],
        tuple[asyncio.StreamReader, asyncio.StreamWriter],
    ]
):
    loop = asyncio.get_event_loop()
    server_reader = asyncio.StreamReader()
    client_reader = asyncio.StreamReader()

    server_close = asyncio.Event()
    server_writer = asyncio.StreamWriter(
        PipeTransport(client_reader, server_close),
        ClientServerProtocol(server_close),
        None,
        loop,
    )
    client_close = asyncio.Event()
    client_writer = asyncio.StreamWriter(
        PipeTransport(server_reader, client_close),
        ClientServerProtocol(client_close),
        None,
        loop,
    )

    return (server_reader, server_writer), (client_reader, client_writer)


@pytest.mark.asyncio
async def test_async_streaming():
    # 'smoke test' to make sure our setup is working
    (
        (server_reader, server_writer),
        (client_reader, client_writer),
    ) = await _stream_pairs()

    server_writer.write(b"Hello, client!")
    await server_writer.drain()

    client_writer.write(b"Hello, server!")
    await client_writer.drain()

    await asyncio.sleep(0)

    data = await client_reader.read(100)
    assert data == b"Hello, client!"

    data = await server_reader.read(100)
    assert data == b"Hello, server!"


@pytest.mark.asyncio
async def test_handle_client():
    (
        (server_reader, server_writer),
        (client_reader, client_writer),
    ) = await _stream_pairs()

    queue: asyncio.Queue[pyquickshare.ShareRequest] = asyncio.Queue()

    async def _helper() -> None:
        request = await queue.get()
        await request.accept()

    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as tmp:

        tmp.write("Hello, world!")
        tmp.flush()

        task1 = asyncio.create_task(_handle_client(queue, client_reader, client_writer))

        task2 = asyncio.create_task(
            _handle_target(tmp.name, server_reader, server_writer)
        )

        task3 = asyncio.create_task(_helper())

        await asyncio.sleep(0)

        await asyncio.gather(task1, task2, task3)
