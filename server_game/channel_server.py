#!/usr/bin/env python3
"""Minimal channel/room TCP listener for protocol discovery."""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import struct
import sys
import time
from dataclasses import dataclass
from pathlib import Path


WRAPPER = struct.Struct("<QB I")
ROOT_DIR = Path(__file__).resolve().parents[1]
PROTOCOL_DOCS_DIR = ROOT_DIR / "protocol_docs"
if str(PROTOCOL_DOCS_DIR) not in sys.path:
    sys.path.insert(0, str(PROTOCOL_DOCS_DIR))

try:
    from bs_crypto import INITIAL_STATE, decrypt_body, encrypt_body, frame_body
except Exception as exc:  # pragma: no cover - runtime diagnostic only
    INITIAL_STATE = 0x42574954
    decrypt_body = None
    encrypt_body = None
    frame_body = None
    print(f"channel warning: BS crypto helpers unavailable: {exc}", flush=True)


@dataclass
class ChannelReplayPlan:
    groups: dict[int, list[bytes]]
    client_frames: list[bytes]
    client_frame_count: int
    server_frame_count: int
    description: str = "CRC plaintext replay"
    compare_client_frames: bool = False


@dataclass
class DirectReplayState:
    room_ready_sent: bool = False
    auto_start_pending: bool = False
    map_start_sent: bool = False
    preload_ack_sent: bool = False
    loadout_sent: bool = False
    spawn_sync_sent: bool = False
    spawn_ack_sent: bool = False
    exit_group_sent: bool = False
    tick_index: int = 0


INITIAL_SUPPRESSED_SERVER_TYPES = {0x08, 0x25}
PASSIVE_CLIENT_TYPES = {
    0x0A,
    0x12,
    0x66,
    0x67,
    0x68,
    0x69,
    0x73,
    0x75,
    0x77,
    0x7E,
    0x7F,
    0x82,
    0x84,
    0x8B,
    0xA7,
}


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
        self._file.flush()
        self.records += 1
        self.payload_bytes += len(payload)

    def close(self) -> None:
        if self._file:
            self._file.close()
            self._file = None


class BsFrameCounter:
    def __init__(self) -> None:
        self.buffer = bytearray()
        self.resync_bytes = 0

    def feed(self, data: bytes) -> list[bytes]:
        self.buffer.extend(data)
        frames: list[bytes] = []
        while len(self.buffer) >= 4:
            if self.buffer[:2] != b"BS":
                next_magic = self.buffer.find(b"BS", 1)
                if next_magic == -1:
                    keep = 1 if self.buffer[-1:] == b"B" else 0
                    drop = len(self.buffer) - keep
                    self.resync_bytes += drop
                    del self.buffer[:drop]
                    break
                self.resync_bytes += next_magic
                del self.buffer[:next_magic]
                if len(self.buffer) < 4:
                    break
            frame_len = int.from_bytes(self.buffer[2:4], "little")
            if frame_len < 4 or frame_len > 65535:
                self.resync_bytes += 2
                del self.buffer[:2]
                continue
            if len(self.buffer) < frame_len:
                break
            frames.append(bytes(self.buffer[:frame_len]))
            del self.buffer[:frame_len]
        return frames


class CrcStream:
    def __init__(self) -> None:
        self.state = INITIAL_STATE

    def decrypt_frame(self, frame: bytes) -> bytes:
        if decrypt_body is None or frame_body is None:
            raise RuntimeError("CRC decrypt helpers are unavailable")
        result = decrypt_body(frame[4:], self.state)
        self.state = result.state
        return frame_body(result.data)

    def encrypt_frame(self, plain_frame: bytes) -> bytes:
        if encrypt_body is None or frame_body is None:
            raise RuntimeError("CRC encrypt helpers are unavailable")
        result = encrypt_body(plain_frame[4:], self.state)
        self.state = result.state
        return frame_body(result.data)


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts if count)


def ascii_preview(data: bytes, limit: int = 80) -> str:
    chars = [chr(byte) if 32 <= byte < 127 else "." for byte in data[:limit]]
    suffix = "..." if len(data) > limit else ""
    return "".join(chars) + suffix


def inspect_payload(data: bytes) -> str:
    parts = [f"len={len(data)}", f"entropy={entropy(data):.2f}"]
    if len(data) >= 4 and data[:2] == b"BS":
        parts.append(f"bs_len={int.from_bytes(data[2:4], 'little')}")
    if len(data) >= 2:
        parts.append(f"u16le={int.from_bytes(data[:2], 'little')}")
    if len(data) >= 4:
        parts.append(f"u32le={int.from_bytes(data[:4], 'little')}")
    parts.append(f"ascii={ascii_preview(data)!r}")
    return " ".join(parts)


def iter_capture_records(path: Path) -> list[tuple[int, bytes]]:
    data = path.read_bytes()
    records: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(data):
        if offset + WRAPPER.size > len(data):
            raise ValueError(f"truncated capture wrapper at offset {offset}")
        _timestamp, direction, length = WRAPPER.unpack_from(data, offset)
        payload_offset = offset + WRAPPER.size
        end = payload_offset + length
        if end > len(data):
            raise ValueError(f"truncated capture payload at offset {payload_offset}")
        records.append((direction, data[payload_offset:end]))
        offset = end
    return records


def extract_bs_frames_from_records(records: list[tuple[int, bytes]]) -> list[tuple[int, bytes]]:
    buffers: dict[int, bytearray] = {}
    frames: list[tuple[int, bytes]] = []
    for direction, payload in records:
        buffer = buffers.setdefault(direction, bytearray())
        buffer.extend(payload)
        while len(buffer) >= 4:
            if buffer[:2] != b"BS":
                next_magic = buffer.find(b"BS", 1)
                if next_magic == -1:
                    keep = 1 if buffer[-1:] == b"B" else 0
                    del buffer[: len(buffer) - keep]
                    break
                del buffer[:next_magic]
                if len(buffer) < 4:
                    break
            frame_len = int.from_bytes(buffer[2:4], "little")
            if frame_len < 4 or frame_len > 65535:
                del buffer[:2]
                continue
            if len(buffer) < frame_len:
                break
            frames.append((direction, bytes(buffer[:frame_len])))
            del buffer[:frame_len]
    leftovers = {direction: len(buffer) for direction, buffer in buffers.items() if buffer}
    if leftovers:
        raise ValueError(f"capture has incomplete BS stream leftovers: {leftovers}")
    return frames


def load_crc_replay_plan(path: Path) -> ChannelReplayPlan:
    if decrypt_body is None or frame_body is None:
        raise RuntimeError("CRC replay helpers are unavailable")
    frames = extract_bs_frames_from_records(iter_capture_records(path))
    decryptors = {0: CrcStream(), 1: CrcStream()}
    groups: dict[int, list[bytes]] = {}
    client_frames: list[bytes] = []
    client_count = 0
    server_count = 0
    for direction, frame in frames:
        plain_frame = decryptors[direction].decrypt_frame(frame)
        if direction == 0:
            client_count += 1
            client_frames.append(plain_frame)
        elif direction == 1:
            groups.setdefault(client_count, []).append(plain_frame)
            server_count += 1
    return ChannelReplayPlan(
        groups=groups,
        client_frames=client_frames,
        client_frame_count=client_count,
        server_frame_count=server_count,
        description=f"CRC plaintext replay from {path.name}",
    )


def load_asset_template_groups(session_dir: Path) -> dict[int, list[bytes]]:
    groups: dict[int, list[bytes]] = {}
    template_root = session_dir / "templates"
    if not template_root.exists():
        raise FileNotFoundError(f"asset templates not found: {template_root}")

    for group_dir in sorted(template_root.glob("server_group_after_client_*")):
        try:
            client_count = int(group_dir.name.rsplit("_", 1)[1])
        except (IndexError, ValueError):
            continue
        frames = [path.read_bytes() for path in sorted(group_dir.glob("frame_*.bin"))]
        if frames:
            groups[client_count] = frames
    return groups


def load_channel_asset_replay_plan(asset_root: Path, session_name: str) -> ChannelReplayPlan:
    session_dir = asset_root / "sessions" / session_name
    manifest_path = session_dir / "manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"asset session manifest not found: {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    flow = manifest.get("flow")
    if flow != "channel":
        raise ValueError(f"asset session {session_name!r} is flow {flow!r}, expected 'channel'")

    groups = load_asset_template_groups(session_dir)
    counts = manifest.get("counts", {})
    client_frame_count = int(counts.get("client_frame_count", 0)) if isinstance(counts, dict) else 0
    server_frame_count = sum(len(group) for group in groups.values())
    return ChannelReplayPlan(
        groups=groups,
        client_frames=[],
        client_frame_count=client_frame_count,
        server_frame_count=server_frame_count,
        description=f"CRC plaintext asset session {session_name!r}",
        compare_client_frames=False,
    )


def first_diff_offset(left: bytes, right: bytes) -> int | None:
    for index, (left_byte, right_byte) in enumerate(zip(left, right)):
        if left_byte != right_byte:
            return index
    if len(left) != len(right):
        return min(len(left), len(right))
    return None


def should_log_frame(index: int) -> bool:
    return index <= 30 or index in {50, 100, 250, 500} or index % 1000 == 0


def frame_type(frame: bytes) -> int | None:
    return frame[4] if len(frame) > 4 else None


def is_direct_spawn_ack_request(frame: bytes) -> bool:
    body = frame[4:]
    return (
        len(body) >= 5
        and body[0] == 0x67
        and body[2] in {0x01, 0x03, 0x05}
        and body[3:5] == b"\x02\x00"
    )


def is_passive_client_frame(plain_frame: bytes) -> bool:
    body_type = frame_type(plain_frame)
    if body_type is None:
        return True
    if body_type in PASSIVE_CLIENT_TYPES:
        return True
    body_len = len(plain_frame) - 4
    return body_len <= 2 and body_type not in {0x03, 0x04, 0x05}


def group_for_client_frame(
    replay: ChannelReplayPlan,
    client_frame_count: int,
    plain_client_frame: bytes,
    replay_mode: str,
    direct_state: DirectReplayState | None = None,
) -> list[bytes]:
    group = replay.groups.get(client_frame_count, [])
    if replay_mode == "direct":
        body_type = frame_type(plain_client_frame)
        if client_frame_count == 1:
            bootstrap: list[bytes] = [
                frame
                for frame in replay.groups.get(1, [])
                if frame_type(frame) not in INITIAL_SUPPRESSED_SERVER_TYPES
            ]
            # Bypass the public room list, but do not send map-load packets in
            # the first TCP burst. The client can enter gameplay with those
            # packets early, but its UI loading overlay may never close.
            bootstrap.extend(replay.groups.get(2, []))
            return bootstrap
        if direct_state and body_type == 0x05 and not direct_state.room_ready_sent:
            direct_state.room_ready_sent = True
            direct_state.auto_start_pending = True
            return replay.groups.get(3, [])
        if direct_state and body_type in {0x0A, 0x12} and not direct_state.map_start_sent:
            direct_state.map_start_sent = True
            return replay.groups.get(4, [])
        if (
            direct_state
            and body_type == 0x12
            and direct_state.map_start_sent
            and not direct_state.preload_ack_sent
            and not direct_state.loadout_sent
        ):
            direct_state.preload_ack_sent = True
            return replay.groups.get(5, [])
        if direct_state and body_type == 0x66 and not direct_state.loadout_sent:
            direct_state.loadout_sent = True
            group: list[bytes] = []
            if not direct_state.map_start_sent:
                direct_state.map_start_sent = True
                group.extend(replay.groups.get(4, []))
            if not direct_state.preload_ack_sent:
                direct_state.preload_ack_sent = True
                group.extend(replay.groups.get(5, []))
            group.extend(replay.groups.get(6, []))
            return group
        if direct_state and body_type in {0x67, 0x87}:
            if not direct_state.spawn_sync_sent:
                direct_state.spawn_sync_sent = True
                return replay.groups.get(11, [])
            if (
                body_type == 0x67
                and not direct_state.spawn_ack_sent
                and is_direct_spawn_ack_request(plain_client_frame)
            ):
                direct_state.spawn_ack_sent = True
                return replay.groups.get(13, [])
        if direct_state and body_type == 0x74 and not direct_state.exit_group_sent:
            direct_state.exit_group_sent = True
            return replay.groups.get(33, [])
        if (
            direct_state
            and body_type == 0x12
            and direct_state.loadout_sent
            and direct_state.spawn_ack_sent
        ):
            # After the map starts loading, the client sends compact heartbeat
            # frames. Reuse captured tick groups only after the equipment block
            # has been requested, otherwise the client can remain stuck behind
            # the loading overlay with out-of-phase world-state packets.
            tick_sources = (14, 15, 16, 17, 18, 19, 20)
            for _attempt in range(len(tick_sources)):
                source_client_count = tick_sources[direct_state.tick_index % len(tick_sources)]
                direct_state.tick_index += 1
                tick_group = replay.groups.get(source_client_count, [])
                if tick_group:
                    return tick_group
        return []

    if replay_mode == "sequential":
        return group

    if client_frame_count == 1:
        # The captured first 9024 response contains public room/player list
        # entries. They make the local client display or join stale real rooms,
        # so keep only handshake/status style frames in the default safe mode.
        return [
            frame
            for frame in group
            if frame_type(frame) not in INITIAL_SUPPRESSED_SERVER_TYPES
        ]

    if is_passive_client_frame(plain_client_frame):
        return []
    return group


def log_plain_client_frame(
    frame_count: int,
    plain_frame: bytes,
    replay: ChannelReplayPlan | None,
) -> None:
    if should_log_frame(frame_count):
        print(
            f"channel client plain frame #{frame_count}: {inspect_payload(plain_frame)}",
            flush=True,
        )
    if not replay or not replay.compare_client_frames:
        return
    expected_index = frame_count - 1
    if expected_index >= len(replay.client_frames):
        print(f"channel replay warning: unexpected extra client frame #{frame_count}", flush=True)
        return
    expected = replay.client_frames[expected_index]
    diff = first_diff_offset(expected, plain_frame)
    if diff is not None:
        print(
            f"channel replay warning: client frame #{frame_count} differs from template at byte {diff}; "
            f"expected_head={expected[:24].hex(' ')} actual_head={plain_frame[:24].hex(' ')}",
            flush=True,
        )


async def send_replay_group(
    writer: asyncio.StreamWriter,
    capture: CaptureWriter,
    replay: ChannelReplayPlan,
    encryptor: CrcStream,
    client_frame_count: int,
    plain_client_frame: bytes,
    max_server_frames: int,
    sent_server_frames: int,
    replay_mode: str,
    direct_state: DirectReplayState | None,
    direct_auto_start_delay: float,
) -> int:
    group = group_for_client_frame(
        replay,
        client_frame_count,
        plain_client_frame,
        replay_mode,
        direct_state,
    )
    if replay_mode != "sequential" and replay.groups.get(client_frame_count) and not group:
        body_type = frame_type(plain_client_frame)
        print(
            f"channel replay gated group after client frame #{client_frame_count} "
            f"type=0x{body_type:02x} len={len(plain_client_frame) - 4}",
            flush=True,
        )
    for plain_frame in group:
        if max_server_frames and sent_server_frames >= max_server_frames:
            return sent_server_frames
        wire_frame = encryptor.encrypt_frame(plain_frame)
        capture.write(1, wire_frame)
        writer.write(wire_frame)
        await writer.drain()
        sent_server_frames += 1
        if should_log_frame(sent_server_frames):
            print(
                f"channel replay sent server frame #{sent_server_frames} "
                f"after client frame #{client_frame_count}: {inspect_payload(wire_frame)}",
                flush=True,
            )
    if (
        replay_mode == "direct"
        and direct_state
        and direct_state.auto_start_pending
        and not direct_state.map_start_sent
    ):
        direct_state.auto_start_pending = False
        delay = max(0.0, direct_auto_start_delay)
        if delay:
            print(
                f"channel direct auto-start waiting {delay:.1f}s after room-ready",
                flush=True,
            )
            await asyncio.sleep(delay)
        auto_group: list[bytes] = []
        direct_state.map_start_sent = True
        auto_group.extend(replay.groups.get(4, []))
        if not direct_state.preload_ack_sent:
            direct_state.preload_ack_sent = True
            auto_group.extend(replay.groups.get(5, []))
        for plain_frame in auto_group:
            if max_server_frames and sent_server_frames >= max_server_frames:
                return sent_server_frames
            wire_frame = encryptor.encrypt_frame(plain_frame)
            capture.write(1, wire_frame)
            writer.write(wire_frame)
            await writer.drain()
            sent_server_frames += 1
            if should_log_frame(sent_server_frames):
                print(
                    f"channel direct auto-start sent server frame #{sent_server_frames}: "
                    f"{inspect_payload(wire_frame)}",
                    flush=True,
                )
    return sent_server_frames


async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    capture_dir: Path | None,
    echo: bool,
    replay: ChannelReplayPlan | None,
    replay_max_server_frames: int,
    replay_mode: str,
    direct_auto_start_delay: float,
) -> None:
    peer = writer.get_extra_info("peername")
    stamp = time.strftime("%Y%m%d-%H%M%S")
    capture = CaptureWriter(capture_dir / f"channel-{stamp}-{id(writer):x}.bin" if capture_dir else None)
    capture.open()
    if capture.path:
        print(f"channel capture writing {capture.path}", flush=True)
    print(f"channel accepted {peer}", flush=True)
    frame_counter = BsFrameCounter()
    client_decryptor = CrcStream()
    server_encryptor = CrcStream()
    direct_state = DirectReplayState() if replay_mode == "direct" else None
    frame_count = 0
    sent_server_frames = 0
    try:
        if replay:
            sent_server_frames = await send_replay_group(
                writer,
                capture,
                replay,
                server_encryptor,
                0,
                b"",
                replay_max_server_frames,
                sent_server_frames,
                replay_mode,
                direct_state,
                direct_auto_start_delay,
            )
        while True:
            data = await reader.read(65536)
            if not data:
                break
            capture.write(0, data)
            print(f"channel recv {inspect_payload(data)}", flush=True)
            frames = frame_counter.feed(data)
            for frame in frames:
                frame_count += 1
                body = frame[4:]
                print(
                    f"channel BS frame #{frame_count}: body_len={len(body)} "
                    f"head={body[:32].hex(' ')} ascii={ascii_preview(body[:64])!r}",
                    flush=True,
                )
                if replay:
                    plain_frame = client_decryptor.decrypt_frame(frame)
                    log_plain_client_frame(frame_count, plain_frame, replay)
                    before = sent_server_frames
                    sent_server_frames = await send_replay_group(
                        writer,
                        capture,
                        replay,
                        server_encryptor,
                        frame_count,
                        plain_frame,
                        replay_max_server_frames,
                        sent_server_frames,
                        replay_mode,
                        direct_state,
                        direct_auto_start_delay,
                    )
                    if sent_server_frames != before:
                        print(
                            f"channel replay observed client frame #{frame_count}; "
                            f"server frames sent={sent_server_frames}",
                            flush=True,
                        )
            if echo:
                capture.write(1, data)
                writer.write(data)
                await writer.drain()
                print(f"channel echoed {len(data)} bytes", flush=True)
    except ConnectionError:
        pass
    finally:
        capture.close()
        writer.close()
        await writer.wait_closed()
        if frame_counter.resync_bytes:
            print(f"channel stream resync bytes={frame_counter.resync_bytes}", flush=True)
        print(
            f"channel closed {peer}; capture records={capture.records} "
            f"payload_bytes={capture.payload_bytes}",
            flush=True,
        )


async def amain() -> None:
    parser = argparse.ArgumentParser(description="DCF local channel/room listener")
    parser.add_argument("--host", default=os.environ.get("FC_CHANNEL_BIND", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("FC_CHANNEL_PORT", "9024")))
    parser.add_argument(
        "--replay-crc-capture",
        default=os.environ.get("FC_CHANNEL_REPLAY_CRC_CAPTURE", ""),
        help="experimental: replay server BS frames from a 9024 capture, reencrypted with CRC feedback",
    )
    parser.add_argument(
        "--asset-root",
        default=os.environ.get("FC_PROTOCOL_ASSET_ROOT", ""),
        help="load a fcdev protocol_assets root instead of a raw 9024 capture",
    )
    parser.add_argument(
        "--asset-session",
        default=os.environ.get("FC_CHANNEL_ASSET_SESSION", "singleplayer_9024"),
        help="fcdev channel session name under --asset-root",
    )
    parser.add_argument(
        "--replay-max-server-frames",
        type=int,
        default=int(os.environ.get("FC_CHANNEL_REPLAY_MAX_SERVER_FRAMES", "0")),
        help="0 means replay all server frames available in the channel capture",
    )
    parser.add_argument(
        "--replay-mode",
        choices=("gated", "direct", "sequential"),
        default=os.environ.get("FC_CHANNEL_REPLAY_MODE", "gated"),
        help=(
            "gated filters stale public room/player broadcasts and ignores passive "
            "client frames; direct fast-forwards into the captured local room/game; "
            "sequential replays the capture by client frame count"
        ),
    )
    parser.add_argument(
        "--direct-auto-start-delay",
        type=float,
        default=float(os.environ.get("FC_CHANNEL_DIRECT_AUTO_START_DELAY", "6.0")),
        help=(
            "direct mode only: seconds to wait after room-ready before auto-sending "
            "the captured map-start group; gives the 15000 lobby UI requests time to finish"
        ),
    )
    parser.add_argument(
        "--capture-dir",
        default=os.environ.get("FC_CAPTURE_DIR", str(Path("protocol_docs") / "captures")),
        help="set empty string to disable capture output",
    )
    parser.add_argument("--echo", action="store_true", help="echo incoming bytes for socket smoke tests only")
    args = parser.parse_args()

    if args.asset_root and args.replay_crc_capture:
        raise SystemExit("--asset-root and --replay-crc-capture are mutually exclusive")

    capture_dir = Path(args.capture_dir) if args.capture_dir else None
    if args.asset_root:
        replay = load_channel_asset_replay_plan(Path(args.asset_root), args.asset_session)
    elif args.replay_crc_capture:
        replay = load_crc_replay_plan(Path(args.replay_crc_capture))
    else:
        replay = None
    if replay:
        print(
            "loaded channel replay: "
            f"{replay.client_frame_count} client frame(s), "
            f"{replay.server_frame_count} server frame(s), "
            f"{len(replay.groups)} response group(s); {replay.description}",
            flush=True,
        )
    server = await asyncio.start_server(
        lambda r, w: handle_client(
            r,
            w,
            capture_dir,
            args.echo,
            replay,
            args.replay_max_server_frames,
            args.replay_mode,
            args.direct_auto_start_delay,
        ),
        args.host,
        args.port,
    )
    sockets = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
    print(f"channel stub listening on {sockets}", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        pass
