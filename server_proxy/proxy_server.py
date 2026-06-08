#!/usr/bin/env python3
"""Minimal TCP proxy-layer stub for the DCF C-client.

Default behavior is a local tunnel:
  client -> 127.0.0.1:15000 -> 127.0.0.1:9000

The relay records traffic in the same frame wrapper used by the supplied
captures: [8B timestamp little-endian][1B direction][4B length LE][payload].
Direction 0 is client-to-server, direction 1 is server-to-client.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import struct
import sys
import time
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
PROTOCOL_DOCS_DIR = ROOT_DIR / "protocol_docs"
if str(PROTOCOL_DOCS_DIR) not in sys.path:
    sys.path.insert(0, str(PROTOCOL_DOCS_DIR))

try:
    from bs_crypto import INITIAL_STATE, decrypt_body, des_cfb64_decrypt, parse_initial_login_plain
except Exception as exc:  # pragma: no cover - runtime diagnostic only
    INITIAL_STATE = 0x42574954
    decrypt_body = None
    des_cfb64_decrypt = None
    parse_initial_login_plain = None
    print(f"proxy warning: BS decrypt helpers unavailable: {exc}", flush=True)


FIXED_CHALLENGE_KEY = bytes(range(8))


class BsFrameCounter:
    def __init__(self) -> None:
        self.buffer = bytearray()

    def feed(self, data: bytes) -> list[bytes]:
        self.buffer.extend(data)
        frames: list[bytes] = []
        while len(self.buffer) >= 4:
            if self.buffer[:2] != b"BS":
                next_magic = self.buffer.find(b"BS", 1)
                if next_magic == -1:
                    keep = 1 if self.buffer[-1:] == b"B" else 0
                    del self.buffer[: len(self.buffer) - keep]
                    break
                del self.buffer[:next_magic]
                if len(self.buffer) < 4:
                    break
            frame_len = int.from_bytes(self.buffer[2:4], "little")
            if frame_len < 4 or frame_len > 65535:
                del self.buffer[:2]
                continue
            if len(self.buffer) < frame_len:
                break
            frames.append(bytes(self.buffer[:frame_len]))
            del self.buffer[:frame_len]
        return frames


class ClientLoginInspector:
    def __init__(self) -> None:
        self.counter = BsFrameCounter()
        self.state = INITIAL_STATE
        self.seen = False

    def feed(self, data: bytes) -> None:
        if self.seen or decrypt_body is None or parse_initial_login_plain is None:
            return
        for frame in self.counter.feed(data):
            body = frame[4:]
            result = decrypt_body(body, self.state)
            self.state = result.state
            if len(frame) != 99:
                continue
            self.seen = True
            try:
                parsed = parse_initial_login_plain(result.data)
            except Exception as exc:
                print(f"proxy initial-login parse failed: {exc}", flush=True)
                return
            challenge_response = result.data[-8:]
            challenge_block_text = "unavailable"
            if des_cfb64_decrypt is not None:
                block = des_cfb64_decrypt(challenge_response, FIXED_CHALLENGE_KEY)
                challenge_block_text = (
                    f"{block.hex(' ')} "
                    f"send_state=0x{int.from_bytes(block[:4], 'little'):08x} "
                    f"recv_state=0x{int.from_bytes(block[4:], 'little'):08x}"
                )
            print(
                "proxy client initial login decrypted: "
                f"opcode=0x{int(parsed['opcode']):08x} "
                f"version={parsed['version']!r} "
                f"account={parsed['account']!r} "
                f"challenge={parsed['challenge_response_hex']} "
                f"challenge_block={challenge_block_text}",
                flush=True,
            )


class CaptureWriter:
    def __init__(self, path: Path | None):
        self.path = path
        self._file = None
        self.records = 0
        self.payload_bytes = 0

    def open(self) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._file = self.path.open("ab")

    def write(self, direction: int, payload: bytes) -> None:
        if not self._file or not payload:
            return
        timestamp_us = time.time_ns() // 1000
        self._file.write(struct.pack("<QB I", timestamp_us, direction, len(payload)))
        self._file.write(payload)
        self.records += 1
        self.payload_bytes += len(payload)
        self._file.flush()

    def close(self) -> None:
        if self._file:
            self._file.close()
            self._file = None


def hexdump(data: bytes, limit: int = 96) -> str:
    shown = data[:limit].hex(" ")
    if len(data) > limit:
        return f"{shown} ...(+{len(data) - limit} bytes)"
    return shown


async def relay_stream(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    direction: int,
    label: str,
    capture: CaptureWriter,
    inspector: ClientLoginInspector | None = None,
) -> None:
    first = True
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            capture.write(direction, data)
            if inspector is not None:
                inspector.feed(data)
            if first:
                print(f"{label} first {len(data)} bytes: {hexdump(data)}", flush=True)
                first = False
            else:
                print(f"{label} {len(data)} bytes", flush=True)
            writer.write(data)
            await writer.drain()
    except ConnectionError:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def handle_client(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    target_host: str,
    target_port: int,
    capture_dir: Path | None,
) -> None:
    peer = client_writer.get_extra_info("peername")
    stamp = time.strftime("%Y%m%d-%H%M%S")
    capture = CaptureWriter(capture_dir / f"proxy-{stamp}-{id(client_writer):x}.bin" if capture_dir else None)
    capture.open()
    print(f"proxy accepted {peer}; connecting to {target_host}:{target_port}", flush=True)
    if capture.path:
        print(f"proxy capture writing {capture.path}", flush=True)
    try:
        server_reader, server_writer = await asyncio.open_connection(target_host, target_port)
    except Exception as exc:
        print(f"proxy target connection failed: {exc}", flush=True)
        client_writer.close()
        await client_writer.wait_closed()
        capture.close()
        return

    try:
        client_inspector = ClientLoginInspector()
        await asyncio.gather(
            relay_stream(client_reader, server_writer, 0, "client->game", capture, client_inspector),
            relay_stream(server_reader, client_writer, 1, "game->client", capture),
        )
    finally:
        capture.close()
        print(
            f"proxy closed {peer}; capture records={capture.records} payload_bytes={capture.payload_bytes}",
            flush=True,
        )


async def amain() -> None:
    parser = argparse.ArgumentParser(description="DCF local TCP proxy stub")
    parser.add_argument("--host", default=os.environ.get("FC_PROXY_BIND", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("FC_PROXY_PORT", "15000")))
    parser.add_argument("--target-host", default=os.environ.get("FC_GAME_HOST", "127.0.0.1"))
    parser.add_argument("--target-port", type=int, default=int(os.environ.get("FC_GAME_PORT", "9000")))
    parser.add_argument(
        "--capture-dir",
        default=os.environ.get("FC_CAPTURE_DIR", str(Path("protocol_docs") / "captures")),
        help="set empty string to disable capture output",
    )
    args = parser.parse_args()

    capture_dir = Path(args.capture_dir) if args.capture_dir else None
    server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, args.target_host, args.target_port, capture_dir),
        args.host,
        args.port,
    )
    sockets = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
    print(f"proxy stub listening on {sockets}; target {args.target_host}:{args.target_port}", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        pass
