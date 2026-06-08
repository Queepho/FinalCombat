#!/usr/bin/env python3
"""Minimal game-layer TCP stub for DCF protocol discovery.

This server intentionally does not invent unverified lobby packets. It accepts
the local proxy connection, records all traffic, and exposes small hooks for
future canned responses once captures identify packet headers and message IDs.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import struct
import sys
import time
from dataclasses import dataclass, replace
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
PROTOCOL_DOCS_DIR = ROOT_DIR / "protocol_docs"
if str(PROTOCOL_DOCS_DIR) not in sys.path:
    sys.path.insert(0, str(PROTOCOL_DOCS_DIR))

try:
    from bs_crypto import (
        INITIAL_STATE,
        decrypt_body,
        des_cfb64_decrypt,
        des_cfb64_encrypt,
        frame_body,
        parse_initial_login_plain,
    )
except Exception as exc:  # pragma: no cover - runtime diagnostic only
    INITIAL_STATE = 0x42574954
    decrypt_body = None
    des_cfb64_decrypt = None
    des_cfb64_encrypt = None
    frame_body = None
    parse_initial_login_plain = None
    print(f"game warning: BS decrypt helpers unavailable: {exc}", flush=True)


EXPERIMENTAL_DMP_BS1_RESPONSE_HEX = (
    "42535f0168901f83423fba1e4f71394abe4df75735f3d5dcd47ccd317d7c5fdc"
    "0cfbc09e13e4e816cc431084050cfaca1467090829dcd47cce8b27fea55f9262"
    "c09e13e57fbafe367d342a6f1070456e239b7a90d8075895f14605733b6ece"
    "4617d5000419c5d6425d9de063e9"
)
REAL_15000_BANNER_HEX = "42530c003fd4c168994104d0"
REAL_15000_FIRST_RESPONSE_HEX = (
    "425330000332d657594947dbc684f79ef8b5b5c3a639b78456adcb138e407be4"
    "08b03c2a39cf2069bc2c25748cbaaf36"
)
WRAPPER = struct.Struct("<QB I")
FIXED_CHALLENGE_KEY = bytes(range(8))


@dataclass
class ReplayPlan:
    groups: dict[int, list[bytes]]
    client_frames: list[bytes]
    client_frame_count: int
    server_frame_count: int
    rpc_response_groups: dict[str, list[bytes]] | None = None
    rpc_response_variants: dict[str, list[list[bytes]]] | None = None
    rpc_response_cursors: dict[str, int] | None = None
    rpc_signature_variants: dict[str, list[list[bytes]]] | None = None
    rpc_signature_cursors: dict[str, int] | None = None
    description: str = "cipher capture replay"
    compare_client_frames: bool = True
    cfb_plain_template: bool = False
    cfb_key: bytes | None = None
    cfb_auto_key: bool = False
    cfb_process_name: str = "FinalCombat.exe"
    replay_patch_host: str = ""
    binary_response_groups: list[tuple[int, list[bytes]]] | None = None
    binary_fallback_cursor: int = 0


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


class ClientFrameInspector:
    def __init__(self) -> None:
        self.state = INITIAL_STATE
        self.initial_login_seen = False

    def inspect(self, frame_index: int, frame: bytes) -> bytes | None:
        if decrypt_body is None or len(frame) < 4 or frame[:2] != b"BS":
            return None
        body = frame[4:]
        state_before = self.state
        result = decrypt_body(body, self.state)
        self.state = result.state

        if not self.initial_login_seen and len(frame) == 99 and parse_initial_login_plain is not None:
            self.initial_login_seen = True
            try:
                parsed = parse_initial_login_plain(result.data)
            except Exception as exc:
                print(
                    f"game client frame #{frame_index} initial-login parse failed: {exc}; "
                    f"plain_head={result.data[:64].hex(' ')}",
                    flush=True,
                )
                return None
            challenge_response = result.data[-8:]
            challenge_block_text = "unavailable"
            if des_cfb64_decrypt is not None and len(challenge_response) == 8:
                challenge_block = des_cfb64_decrypt(challenge_response, FIXED_CHALLENGE_KEY)
                challenge_block_text = (
                    f"{challenge_block.hex(' ')} "
                    f"send_state=0x{int.from_bytes(challenge_block[:4], 'little'):08x} "
                    f"recv_state=0x{int.from_bytes(challenge_block[4:], 'little'):08x}"
                )
            print(
                "game client initial login decrypted: "
                f"opcode=0x{int(parsed['opcode']):08x} "
                f"version={parsed['version']!r} "
                f"account={parsed['account']!r} "
                f"ticket={parsed['ticket']!r} "
                f"challenge={parsed['challenge_response_hex']} "
                f"challenge_block={challenge_block_text} "
                f"state=0x{state_before:08x}->0x{result.state:08x}",
                flush=True,
            )
            return challenge_response

        if frame_index <= 4:
            print(
                f"game client frame #{frame_index} decrypted prefix: "
                f"state=0x{state_before:08x}->0x{result.state:08x} "
                f"plain={result.data[:32].hex(' ')} ascii={ascii_preview(result.data[:32])!r}",
                flush=True,
            )
        return None


class CaptureWriter:
    def __init__(self, path: Path | None):
        self.path = path
        self._file = None

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

    def close(self) -> None:
        if self._file:
            self._file.close()
            self._file = None


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts if count)


def ascii_preview(data: bytes, limit: int = 80) -> str:
    out = []
    for byte in data[:limit]:
        out.append(chr(byte) if 32 <= byte < 127 else ".")
    suffix = "..." if len(data) > limit else ""
    return "".join(out) + suffix


def parse_hex_bytes(text: str) -> bytes:
    cleaned = "".join(ch for ch in text if ch in "0123456789abcdefABCDEF")
    if len(cleaned) % 2:
        raise ValueError(f"odd-length hex string: {text}")
    return bytes.fromhex(cleaned)


def env_flag(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def recover_cfb_key_from_process(
    challenge_response: bytes,
    process_name: str,
    max_address: int = 0xFFFFFFFF,
) -> bytes | None:
    try:
        from find_transform_instances import scan_instances
        from live_process_scan import find_pid_by_name
    except Exception as exc:
        print(f"game CFB auto-key unavailable: {exc}", flush=True)
        return None

    pid = find_pid_by_name(process_name)
    if pid is None:
        print(f"game CFB auto-key process not found: {process_name}", flush=True)
        return None

    wanted = challenge_response.hex(" ").lower()
    try:
        report = scan_instances(pid, max_address)
    except Exception as exc:
        print(f"game CFB auto-key scan failed: {exc}", flush=True)
        return None

    candidates = [item.get("cfb_subobject") for item in report.get("instances", [])]
    candidates = [item for item in candidates if item]
    for item in candidates:
        response = str(item.get("response_from_block_04_0b", "")).lower()
        if response == wanted:
            try:
                key = parse_hex_bytes(str(item["stream_key_1c_23"]))
            except (KeyError, ValueError) as exc:
                print(f"game CFB auto-key matched but key parse failed: {exc}", flush=True)
                return None
            print(
                "game CFB auto-key matched "
                f"pid={pid} subobject={item.get('va')} response={wanted} key={key.hex(' ')}",
                flush=True,
            )
            return key

    seen = ", ".join(str(item.get("response_from_block_04_0b", "")) for item in candidates[:4])
    print(
        "game CFB auto-key found no matching subobject: "
        f"wanted={wanted} candidates={len(candidates)} responses=[{seen}]",
        flush=True,
    )
    return None


def inspect_payload(data: bytes) -> str:
    parts = [f"len={len(data)}", f"entropy={entropy(data):.2f}"]
    if len(data) >= 4 and data[:2] == b"BS":
        parts.append(f"bs_len={int.from_bytes(data[2:4], 'little')}")
    if len(data) >= 2:
        parts.append(f"u16le={int.from_bytes(data[:2], 'little')}")
        parts.append(f"u16be={int.from_bytes(data[:2], 'big')}")
    if len(data) >= 4:
        parts.append(f"u32le={int.from_bytes(data[:4], 'little')}")
        parts.append(f"u32be={int.from_bytes(data[:4], 'big')}")
    if len(data) % 16 == 0:
        parts.append("block16=yes")
    parts.append(f"ascii={ascii_preview(data)!r}")
    return " ".join(parts)


def parse_rpc_name(body: bytes) -> str | None:
    if len(body) < 9:
        return None
    name_len = struct.unpack_from("<I", body, 5)[0]
    if name_len <= 0 or name_len > 64 or 9 + name_len > len(body):
        return None
    raw = body[9 : 9 + name_len]
    if any(byte < 32 or byte >= 127 for byte in raw):
        return None
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError:
        return None


def parse_rpc_params(body: bytes) -> dict[str, str]:
    if len(body) < 9:
        return {}
    name_len = struct.unpack_from("<I", body, 5)[0]
    pos = 9 + name_len
    if name_len <= 0 or pos > len(body):
        return {}
    params: dict[str, str] = {}
    while pos + 4 <= len(body):
        key_len = struct.unpack_from("<I", body, pos)[0]
        pos += 4
        if key_len <= 0 or key_len > 64 or pos + key_len > len(body):
            break
        key_raw = body[pos : pos + key_len]
        pos += key_len
        if pos + 4 > len(body):
            break
        value_len = struct.unpack_from("<I", body, pos)[0]
        pos += 4
        if value_len < 0 or value_len > 4096 or pos + value_len > len(body):
            break
        value_raw = body[pos : pos + value_len]
        pos += value_len
        if any(byte < 32 or byte >= 127 for byte in key_raw):
            continue
        try:
            key = key_raw.decode("ascii")
        except UnicodeDecodeError:
            continue
        if all(32 <= byte < 127 for byte in value_raw):
            value = value_raw.decode("ascii", errors="replace")
        else:
            value = "0x" + value_raw.hex()
        params[key] = value
    return params


def rpc_request_signature(body: bytes) -> str | None:
    rpc_name = parse_rpc_name(body)
    if not rpc_name:
        return None
    params = parse_rpc_params(body)
    dynamic_keys = {"pid", "uid", "fcm_online_time"}
    stable_items = [
        (key, value)
        for key, value in sorted(params.items())
        if key not in dynamic_keys
    ]
    if not stable_items:
        return rpc_name
    encoded = "&".join(f"{key}={value}" for key, value in stable_items)
    return f"{rpc_name}?{encoded}"


def printable_runs(data: bytes, min_len: int = 4, limit: int = 5) -> list[str]:
    runs: list[str] = []
    current = bytearray()
    for byte in data:
        if 32 <= byte < 127:
            current.append(byte)
            continue
        if len(current) >= min_len:
            runs.append(current.decode("ascii", errors="replace"))
            if len(runs) >= limit:
                return runs
        current.clear()
    if len(current) >= min_len and len(runs) < limit:
        runs.append(current.decode("ascii", errors="replace"))
    return runs


def describe_plain_body(body: bytes) -> str:
    if not body:
        return "empty"
    parts = [
        f"type=0x{body[0]:02x}",
        f"body_len={len(body)}",
        f"head={body[:16].hex(' ')}",
    ]
    if len(body) >= 5:
        field32 = struct.unpack_from("<I", body, 1)[0]
        parts.append(f"field32={field32}")
        if body[0] == 0x1E:
            parts.append(f"payload_len={field32}")
        elif body[0] == 0x0F:
            parts.append("heartbeat=yes")
    if len(body) >= 9:
        parts.append(f"field32b={struct.unpack_from('<I', body, 5)[0]}")
    strings = printable_runs(body)
    if strings:
        parts.append("strings=" + repr(strings))
    return " ".join(parts)


def should_log_plain_body(body: bytes, seen_counts: dict[str, int]) -> bool:
    if not body:
        return True
    if body == b"\x0f\x05\x00\x00\x00":
        key = "heartbeat-0f05"
    else:
        key = f"{body[0]:02x}:{len(body)}:{body[1:9].hex() if len(body) > 1 else ''}"
    count = seen_counts.get(key, 0) + 1
    seen_counts[key] = count
    return count <= 8 or count in {16, 32, 64, 128, 256}


def patch_rpc_response_header(response_frame: bytes, request_body: bytes) -> bytes:
    if len(response_frame) < 9 or len(request_body) < 5:
        return response_frame
    body = request_body[:5] + response_frame[9:]
    return frame_body(body) if frame_body is not None else response_frame


def find_len_prefixed_ascii_container(
    data: bytearray,
    index: int,
    length: int,
    max_scan_back: int = 512,
) -> tuple[int, int, int] | None:
    best: tuple[int, int, int] | None = None
    start_scan = max(0, index - max_scan_back)
    for prefix_offset in range(start_scan, max(0, index - 3)):
        field_len = struct.unpack_from("<I", data, prefix_offset)[0]
        if field_len <= 0 or field_len > 4096:
            continue
        value_start = prefix_offset + 4
        value_end = value_start + field_len
        if value_start <= index and index + length <= value_end <= len(data):
            value = data[value_start:value_end]
            if all(byte in (9, 10, 13) or 32 <= byte < 127 for byte in value):
                best = (prefix_offset, value_start, value_end)
    return best


def replace_len_prefixed_ascii(body: bytes, old: bytes, new: bytes) -> tuple[bytes, int]:
    if not old or old == new:
        return body, 0
    patched = bytearray(body)
    offset = 0
    count = 0
    while True:
        index = patched.find(old, offset)
        if index < 0:
            break
        container = find_len_prefixed_ascii_container(patched, index, len(old))
        if container:
            prefix_offset, value_start, value_end = container
            value = bytes(patched[value_start:value_end])
            new_value = value.replace(old, new, 1)
            patched[prefix_offset : prefix_offset + 4] = struct.pack("<I", len(new_value))
            patched[value_start:value_end] = new_value
            offset = value_start + len(new_value)
            count += 1
        elif len(old) == len(new):
            patched[index : index + len(old)] = new
            offset = index + len(new)
            count += 1
        else:
            offset = index + len(old)
    return bytes(patched), count


def patch_template_frame_host(frame: bytes, host: str) -> tuple[bytes, int]:
    if not host or len(frame) < 5 or frame[:2] != b"BS" or frame_body is None:
        return frame, 0
    body = frame[4:]
    patched_body, count = replace_len_prefixed_ascii(
        body,
        b"127.0.0.1",
        host.encode("ascii"),
    )
    if count:
        return frame_body(patched_body), count
    return frame, 0


def is_room_binary_server_group(frames: list[bytes]) -> bool:
    if not frames:
        return False
    # 0x24 frames in the first room-flow capture contained /InvitePlayer
    # broadcasts from live players. They are not required for local room create.
    room_types = {0x03, 0x18, 0x1C}
    for frame in frames:
        if len(frame) < 5 or frame[:2] != b"BS":
            return False
        if frame[4] not in room_types:
            return False
    return True


def is_room_binary_client_body(body: bytes) -> bool:
    return bool(body) and body[0] in {0x1E, 0x0F, 0x03}


def response_for_payload(data: bytes) -> bytes:
    """Return a canned response for a known request.

    TODO: Fill this dispatch table after capture analysis identifies game-layer
    message IDs and serialization. Returning no bytes keeps the socket alive
    without corrupting an unknown encrypted or length-prefixed stream.
    """

    return b""


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


def load_replay_plan(path: Path) -> ReplayPlan:
    frames = extract_bs_frames_from_records(iter_capture_records(path))
    groups: dict[int, list[bytes]] = {}
    client_frames: list[bytes] = []
    client_count = 0
    server_count = 0
    for direction, frame in frames:
        if direction == 0:
            client_count += 1
            client_frames.append(frame)
        elif direction == 1:
            groups.setdefault(client_count, []).append(frame)
            server_count += 1
    return ReplayPlan(
        groups=groups,
        client_frames=client_frames,
        client_frame_count=client_count,
        server_frame_count=server_count,
    )


def load_cfb_plain_replay_plan(
    path: Path,
    cfb_key: bytes | None,
    cfb_auto_key: bool,
    cfb_process_name: str,
    replay_patch_host: str,
) -> ReplayPlan:
    if des_cfb64_encrypt is None or frame_body is None:
        raise RuntimeError("DES-CFB64 helpers are unavailable")
    if cfb_key is not None and len(cfb_key) != 8:
        raise ValueError("CFB replay key must be exactly 8 bytes")

    frames = extract_bs_frames_from_records(iter_capture_records(path))
    groups: dict[int, list[bytes]] = {}
    rpc_response_groups: dict[str, list[bytes]] = {}
    client_frames: list[bytes] = []
    client_rpc_names: dict[int, str] = {}
    client_count = 0
    server_count = 0
    templated_count = 0
    for direction, frame in frames:
        if direction == 0:
            client_count += 1
            client_frames.append(frame)
            rpc_name = parse_rpc_name(frame[4:])
            if rpc_name:
                client_rpc_names[client_count] = rpc_name
        elif direction == 1:
            replay_frame = frame
            if replay_patch_host:
                replay_frame, patch_count = patch_template_frame_host(replay_frame, replay_patch_host)
                if patch_count:
                    print(
                        f"game replay patched service host in server template frame #{server_count + 1}: "
                        f"host={replay_patch_host!r} replacements={patch_count}",
                        flush=True,
                    )
            if client_count > 0:
                templated_count += 1
            groups.setdefault(client_count, []).append(replay_frame)
            rpc_name = client_rpc_names.get(client_count)
            if rpc_name:
                rpc_response_groups.setdefault(rpc_name, []).append(replay_frame)
            server_count += 1
    binary_response_groups = [
        (client_index, group)
        for client_index, group in sorted(groups.items())
        if client_index > 2 and is_room_binary_server_group(group)
    ]
    key_text = cfb_key.hex(" ") if cfb_key is not None else "auto"
    return ReplayPlan(
        groups=groups,
        client_frames=client_frames,
        client_frame_count=client_count,
        server_frame_count=server_count,
        rpc_response_groups=rpc_response_groups,
        description=(
            "CFB plaintext replay "
            f"(template {templated_count} server frame(s), "
            f"rpc fallback {len(rpc_response_groups)} method(s), "
            f"binary fallback {len(binary_response_groups)} group(s), key={key_text})"
        ),
        compare_client_frames=False,
        cfb_plain_template=True,
        cfb_key=cfb_key,
        cfb_auto_key=cfb_auto_key,
        cfb_process_name=cfb_process_name,
        replay_patch_host=replay_patch_host,
        binary_response_groups=binary_response_groups,
    )


def load_asset_template_groups(session_dir: Path, replay_patch_host: str = "") -> dict[int, list[bytes]]:
    groups: dict[int, list[bytes]] = {}
    template_root = session_dir / "templates"
    if not template_root.exists():
        raise FileNotFoundError(f"asset templates not found: {template_root}")

    for group_dir in sorted(template_root.glob("server_group_after_client_*")):
        try:
            client_count = int(group_dir.name.rsplit("_", 1)[1])
        except (IndexError, ValueError):
            continue
        frames: list[bytes] = []
        for frame_path in sorted(group_dir.glob("frame_*.bin")):
            frame = frame_path.read_bytes()
            if replay_patch_host:
                frame, patch_count = patch_template_frame_host(frame, replay_patch_host)
                if patch_count:
                    print(
                        f"game asset patched service host in {frame_path.name}: "
                        f"host={replay_patch_host!r} replacements={patch_count}",
                        flush=True,
                    )
            frames.append(frame)
        if frames:
            groups[client_count] = frames
    return groups


def load_asset_events(session_dir: Path) -> list[dict[str, object]]:
    events_path = session_dir / "events.jsonl"
    if not events_path.exists():
        return []
    events: list[dict[str, object]] = []
    with events_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def load_asset_rpc_signatures(session_dir: Path, manifest: dict[str, object]) -> dict[int, str]:
    raw_capture = manifest.get("raw_capture_copy")
    raw_path = None
    if isinstance(raw_capture, str) and raw_capture:
        raw_path = session_dir / raw_capture
    if raw_path is None or not raw_path.exists():
        raw_files = sorted((session_dir / "raw").glob("*.bin"))
        raw_path = raw_files[0] if raw_files else None
    if raw_path is None or not raw_path.exists():
        return {}

    signatures: dict[int, str] = {}
    client_count = 0
    try:
        frames = extract_bs_frames_from_records(iter_capture_records(raw_path))
    except Exception as exc:
        print(f"game asset signature scan failed for {raw_path}: {exc}", flush=True)
        return signatures
    for direction, frame in frames:
        if direction != 0:
            continue
        client_count += 1
        signature = rpc_request_signature(frame[4:])
        if signature:
            signatures[client_count] = signature
    return signatures


def split_asset_session_names(session_names: str) -> list[str]:
    names = [item.strip() for item in session_names.split(",")]
    return [item for item in names if item]


def load_cfb_asset_replay_plan(
    asset_root: Path,
    session_name: str,
    cfb_key: bytes | None,
    cfb_auto_key: bool,
    cfb_process_name: str,
    replay_patch_host: str,
) -> ReplayPlan:
    if des_cfb64_encrypt is None or frame_body is None:
        raise RuntimeError("DES-CFB64 helpers are unavailable")
    if cfb_key is not None and len(cfb_key) != 8:
        raise ValueError("CFB replay key must be exactly 8 bytes")

    session_names = split_asset_session_names(session_name)
    if not session_names:
        raise ValueError("at least one asset session is required")

    primary_groups: dict[int, list[bytes]] = {}
    rpc_response_groups: dict[str, list[bytes]] = {}
    rpc_response_variants: dict[str, list[list[bytes]]] = {}
    rpc_signature_variants: dict[str, list[list[bytes]]] = {}
    total_template_frames = 0
    client_frame_count = 0
    for index, name in enumerate(session_names):
        session_dir = asset_root / "sessions" / name
        manifest_path = session_dir / "manifest.json"
        if not manifest_path.exists():
            raise FileNotFoundError(f"asset session manifest not found: {manifest_path}")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        flow = manifest.get("flow")
        if flow != "game-cfb-plain":
            raise ValueError(f"asset session {name!r} is flow {flow!r}, expected 'game-cfb-plain'")

        groups = load_asset_template_groups(session_dir, replay_patch_host)
        signatures = load_asset_rpc_signatures(session_dir, manifest)
        total_template_frames += sum(len(group) for group in groups.values())
        if index == 0:
            primary_groups = groups
            counts = manifest.get("counts", {})
            client_frame_count = int(counts.get("client_frame_count", 0)) if isinstance(counts, dict) else 0

        events = load_asset_events(session_dir)
        for event in events:
            if event.get("direction") != "C2S":
                continue
            rpc_name = event.get("rpc")
            client_count = event.get("client_frame")
            if not rpc_name or not isinstance(client_count, int):
                continue
            frames = groups.get(client_count)
            if not frames:
                continue
            rpc_key = str(rpc_name)
            rpc_response_variants.setdefault(rpc_key, []).append(list(frames))
            rpc_response_groups.setdefault(rpc_key, list(frames))
            signature = signatures.get(client_count)
            if signature:
                rpc_signature_variants.setdefault(signature, []).append(list(frames))

    binary_response_groups = [
        (client_index, group)
        for client_index, group in sorted(primary_groups.items())
        if client_index > 2 and is_room_binary_server_group(group)
    ]
    server_frame_count = sum(len(group) for group in primary_groups.values())
    key_text = cfb_key.hex(" ") if cfb_key is not None else "auto"
    multi_variant_rpcs = [
        rpc_name
        for rpc_name, variants in sorted(rpc_response_variants.items())
        if len(variants) > 1
    ]
    if multi_variant_rpcs:
        print(
            "game asset loaded multi-variant RPC template(s): "
            + ", ".join(multi_variant_rpcs[:20]),
            flush=True,
        )
    return ReplayPlan(
        groups=primary_groups,
        client_frames=[],
        client_frame_count=client_frame_count,
        server_frame_count=server_frame_count,
        rpc_response_groups=rpc_response_groups,
        rpc_response_variants=rpc_response_variants,
        rpc_response_cursors={},
        rpc_signature_variants=rpc_signature_variants,
        rpc_signature_cursors={},
        description=(
            f"CFB plaintext asset session(s) {session_names!r} "
            f"(primary {server_frame_count} server frame(s), "
            f"templates available {total_template_frames}, "
            f"rpc fallback {len(rpc_response_groups)} method(s), "
            f"variants {sum(len(items) for items in rpc_response_variants.values())}, "
            f"signature variants {sum(len(items) for items in rpc_signature_variants.values())}, "
            f"binary fallback {len(binary_response_groups)} group(s), key={key_text})"
        ),
        compare_client_frames=False,
        cfb_plain_template=True,
        cfb_key=cfb_key,
        cfb_auto_key=cfb_auto_key,
        cfb_process_name=cfb_process_name,
        replay_patch_host=replay_patch_host,
        binary_response_groups=binary_response_groups,
    )


def first_diff_offset(left: bytes, right: bytes) -> int | None:
    for index, (left_byte, right_byte) in enumerate(zip(left, right)):
        if left_byte != right_byte:
            return index
    if len(left) != len(right):
        return min(len(left), len(right))
    return None


def log_replay_client_compare(replay: ReplayPlan, client_frame_count: int, frame: bytes) -> None:
    if not replay.compare_client_frames:
        return
    expected_index = client_frame_count - 1
    if expected_index >= len(replay.client_frames):
        print(f"game replay warning: unexpected extra client frame #{client_frame_count}", flush=True)
        return
    expected = replay.client_frames[expected_index]
    diff = first_diff_offset(expected, frame)
    if diff is None:
        return
    print(
        f"game replay warning: client frame #{client_frame_count} differs from capture at byte {diff}; "
        f"expected_tail={expected[-16:].hex(' ')} actual_tail={frame[-16:].hex(' ')}",
        flush=True,
    )


def replay_wire_frame(replay: ReplayPlan, client_frame_count: int, frame: bytes) -> bytes | None:
    if not replay.cfb_plain_template or client_frame_count == 0:
        return frame
    if replay.cfb_key is None:
        return None
    if des_cfb64_encrypt is None or frame_body is None:
        raise RuntimeError("DES-CFB64 helpers are unavailable")
    return frame_body(des_cfb64_encrypt(frame[4:], replay.cfb_key))


async def send_replay_group(
    writer: asyncio.StreamWriter,
    capture: CaptureWriter,
    replay: ReplayPlan,
    client_frame_count: int,
    max_server_frames: int,
    sent_server_frames: int,
) -> int:
    for frame in replay.groups.get(client_frame_count, []):
        if max_server_frames and sent_server_frames >= max_server_frames:
            return sent_server_frames
        wire_frame = replay_wire_frame(replay, client_frame_count, frame)
        if wire_frame is None:
            print(
                f"game replay waiting for CFB key before sending group after client frame #{client_frame_count}",
                flush=True,
            )
            return sent_server_frames
        capture.write(1, wire_frame)
        writer.write(wire_frame)
        await writer.drain()
        sent_server_frames += 1
        print(
            f"game replay sent server frame #{sent_server_frames} after client frame #{client_frame_count}: "
            f"{inspect_payload(wire_frame)}",
            flush=True,
        )
    return sent_server_frames


async def send_rpc_fallback_group(
    writer: asyncio.StreamWriter,
    capture: CaptureWriter,
    replay: ReplayPlan,
    rpc_name: str,
    request_body: bytes,
    sent_server_frames: int,
) -> int:
    signature = rpc_request_signature(request_body)
    if signature and replay.rpc_signature_variants and signature in replay.rpc_signature_variants:
        variants = replay.rpc_signature_variants[signature]
        if not variants:
            return sent_server_frames
        if replay.rpc_signature_cursors is None:
            replay.rpc_signature_cursors = {}
        cursor = replay.rpc_signature_cursors.get(signature, 0)
        variant_index = min(cursor, len(variants) - 1)
        frames = variants[variant_index]
        if cursor < len(variants) - 1:
            replay.rpc_signature_cursors[signature] = cursor + 1
        else:
            replay.rpc_signature_cursors[signature] = cursor
        print(
            f"game rpc fallback selected signature {signature!r} variant "
            f"{variant_index + 1}/{len(variants)}",
            flush=True,
        )
    elif replay.rpc_response_variants and rpc_name in replay.rpc_response_variants:
        variants = replay.rpc_response_variants[rpc_name]
        if not variants:
            return sent_server_frames
        if replay.rpc_response_cursors is None:
            replay.rpc_response_cursors = {}
        cursor = replay.rpc_response_cursors.get(rpc_name, 0)
        variant_index = min(cursor, len(variants) - 1)
        frames = variants[variant_index]
        if cursor < len(variants) - 1:
            replay.rpc_response_cursors[rpc_name] = cursor + 1
        else:
            replay.rpc_response_cursors[rpc_name] = cursor
        print(
            f"game rpc fallback selected {rpc_name!r} variant "
            f"{variant_index + 1}/{len(variants)}",
            flush=True,
        )
    elif replay.rpc_response_groups:
        frames = replay.rpc_response_groups.get(rpc_name)
        if not frames:
            return sent_server_frames
    else:
        return sent_server_frames
    for template_frame in frames:
        patched_frame = patch_rpc_response_header(template_frame, request_body)
        wire_frame = replay_wire_frame(replay, 1, patched_frame)
        if wire_frame is None:
            print(f"game rpc fallback waiting for CFB key before responding to {rpc_name!r}", flush=True)
            return sent_server_frames
        capture.write(1, wire_frame)
        writer.write(wire_frame)
        await writer.drain()
        sent_server_frames += 1
        print(
            f"game rpc fallback sent {rpc_name!r} response frame #{sent_server_frames}: "
            f"{inspect_payload(wire_frame)}",
            flush=True,
        )
    return sent_server_frames


def consume_binary_fallback_for_client_count(replay: ReplayPlan, client_frame_count: int) -> None:
    groups = replay.binary_response_groups or []
    if replay.binary_fallback_cursor >= len(groups):
        return
    original_client_count, _frames = groups[replay.binary_fallback_cursor]
    if original_client_count == client_frame_count:
        replay.binary_fallback_cursor += 1


async def send_binary_fallback_group(
    writer: asyncio.StreamWriter,
    capture: CaptureWriter,
    replay: ReplayPlan,
    sent_server_frames: int,
) -> int:
    groups = replay.binary_response_groups or []
    if replay.binary_fallback_cursor >= len(groups):
        return sent_server_frames
    original_client_count, frames = groups[replay.binary_fallback_cursor]
    for template_frame in frames:
        wire_frame = replay_wire_frame(replay, 1, template_frame)
        if wire_frame is None:
            print("game binary fallback waiting for CFB key before responding", flush=True)
            return sent_server_frames
        capture.write(1, wire_frame)
        writer.write(wire_frame)
        await writer.drain()
        sent_server_frames += 1
        print(
            f"game binary fallback sent template group from client frame #{original_client_count} "
            f"as server frame #{sent_server_frames}: {inspect_payload(wire_frame)}",
            flush=True,
        )
    replay.binary_fallback_cursor += 1
    return sent_server_frames


async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    capture_dir: Path | None,
    banner: bytes,
    first_response: bytes,
    echo: bool,
    replay: ReplayPlan | None,
    replay_max_server_frames: int,
) -> None:
    peer = writer.get_extra_info("peername")
    if replay is not None:
        replay = replace(replay)
        if replay.rpc_response_variants is not None:
            replay.rpc_response_cursors = {}
        if replay.rpc_signature_variants is not None:
            replay.rpc_signature_cursors = {}
    stamp = time.strftime("%Y%m%d-%H%M%S")
    capture = CaptureWriter(capture_dir / f"game-{stamp}-{id(writer):x}.bin" if capture_dir else None)
    capture.open()
    print(f"game accepted {peer}", flush=True)
    first_response_sent = False
    client_frame_count = 0
    sent_server_frames = 0
    frame_counter = BsFrameCounter()
    frame_inspector = ClientFrameInspector()
    plain_body_seen_counts: dict[str, int] = {}
    room_binary_request_count = 0
    try:
        if replay:
            sent_server_frames = await send_replay_group(
                writer,
                capture,
                replay,
                client_frame_count,
                replay_max_server_frames,
                sent_server_frames,
            )
        elif banner:
            capture.write(1, banner)
            writer.write(banner)
            await writer.drain()
            print(f"game sent banner {len(banner)} bytes", flush=True)

        while True:
            data = await reader.read(65536)
            if not data:
                break
            capture.write(0, data)
            print(f"game recv {inspect_payload(data)}", flush=True)

            completed_frames = frame_counter.feed(data)
            for completed_frame in completed_frames:
                client_frame_count += 1
                challenge_response = frame_inspector.inspect(client_frame_count, completed_frame)
                rpc_name = None
                cfb_plain_body = None
                binary_client_body = False
                if replay:
                    if (
                        challenge_response is not None
                        and replay.cfb_plain_template
                        and replay.cfb_key is None
                        and replay.cfb_auto_key
                    ):
                        replay.cfb_key = recover_cfb_key_from_process(
                            challenge_response,
                            replay.cfb_process_name,
                        )
                    if (
                        replay.cfb_plain_template
                        and replay.cfb_key is not None
                        and client_frame_count > 1
                        and des_cfb64_decrypt is not None
                    ):
                        cfb_plain_body = des_cfb64_decrypt(completed_frame[4:], replay.cfb_key)
                        rpc_name = parse_rpc_name(cfb_plain_body)
                        binary_client_body = is_room_binary_client_body(cfb_plain_body)
                        if cfb_plain_body and cfb_plain_body[0] == 0x1E:
                            room_binary_request_count += 1
                        if rpc_name:
                            print(
                                f"game client RPC #{client_frame_count}: "
                                f"{rpc_name!r} request_id={cfb_plain_body[:5].hex(' ')}",
                                flush=True,
                            )
                        elif should_log_plain_body(cfb_plain_body, plain_body_seen_counts):
                            print(
                                f"game client plain #{client_frame_count}: "
                                f"{describe_plain_body(cfb_plain_body)}",
                                flush=True,
                            )
                    log_replay_client_compare(replay, client_frame_count, completed_frame)
                    before_replay_send = sent_server_frames
                    sent_server_frames = await send_replay_group(
                        writer,
                        capture,
                        replay,
                        client_frame_count,
                        replay_max_server_frames,
                        sent_server_frames,
                    )
                    if sent_server_frames != before_replay_send:
                        consume_binary_fallback_for_client_count(replay, client_frame_count)
                    if (
                        sent_server_frames == before_replay_send
                        and rpc_name
                        and cfb_plain_body is not None
                    ):
                        sent_server_frames = await send_rpc_fallback_group(
                            writer,
                            capture,
                            replay,
                            rpc_name,
                            cfb_plain_body,
                            sent_server_frames,
                        )
                    if (
                        sent_server_frames == before_replay_send
                        and binary_client_body
                        and cfb_plain_body is not None
                    ):
                        should_send_binary = False
                        if cfb_plain_body[0] == 0x1E:
                            should_send_binary = (
                                replay.binary_fallback_cursor > 0
                                or room_binary_request_count >= 2
                            )
                        elif replay.binary_fallback_cursor > 0:
                            should_send_binary = True
                        if should_send_binary:
                            sent_server_frames = await send_binary_fallback_group(
                                writer,
                                capture,
                                replay,
                                sent_server_frames,
                            )
            if replay and completed_frames:
                print(
                    f"game replay observed {len(completed_frames)} complete client BS frame(s); "
                    f"total={client_frame_count}",
                    flush=True,
                )

            response = b""
            if replay:
                pass
            elif echo:
                response = data
            elif first_response and not first_response_sent and data.startswith(b"BS"):
                response = first_response
                first_response_sent = True
                print("game using configured first BS response", flush=True)
            else:
                response = response_for_payload(data)
            if response:
                capture.write(1, response)
                writer.write(response)
                await writer.drain()
                print(f"game sent {len(response)} bytes", flush=True)
    except ConnectionError:
        pass
    finally:
        capture.close()
        writer.close()
        await writer.wait_closed()
        if frame_counter.resync_bytes:
            print(f"game replay client stream resync bytes={frame_counter.resync_bytes}", flush=True)
        print(f"game closed {peer}", flush=True)


async def amain() -> None:
    parser = argparse.ArgumentParser(description="DCF local game-layer stub")
    parser.add_argument("--host", default=os.environ.get("FC_GAME_BIND", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("FC_GAME_PORT", "9000")))
    parser.add_argument(
        "--capture-dir",
        default=os.environ.get("FC_CAPTURE_DIR", str(Path("protocol_docs") / "captures")),
        help="set empty string to disable capture output",
    )
    parser.add_argument("--banner-hex", default=os.environ.get("FC_GAME_BANNER_HEX", ""))
    parser.add_argument(
        "--first-response-hex",
        default=os.environ.get("FC_GAME_FIRST_RESPONSE_HEX", ""),
        help="send this hex payload after the first client BS_ frame",
    )
    parser.add_argument(
        "--experimental-dmp-response",
        action="store_true",
        help="try the 109-byte BS_01 response fragment found in the 20180303 dump",
    )
    parser.add_argument(
        "--experimental-real-handshake",
        action="store_true",
        help="replay the real 15000 12-byte banner and 48-byte first response captured via MITM",
    )
    parser.add_argument(
        "--replay-capture",
        default=os.environ.get("FC_GAME_REPLAY_CAPTURE", ""),
        help="experimental: replay server BS frames from this MITM capture, gated by observed client BS frame count",
    )
    parser.add_argument(
        "--replay-cfb-plain-capture",
        default=os.environ.get("FC_GAME_REPLAY_CFB_PLAIN_CAPTURE", ""),
        help=(
            "experimental: replay server BS bodies from a DES-CFB64 plaintext capture, "
            "reencrypting post-login server frames with --replay-cfb-key or --replay-cfb-auto-key"
        ),
    )
    parser.add_argument(
        "--asset-root",
        default=os.environ.get("FC_PROTOCOL_ASSET_ROOT", ""),
        help="load a fcdev protocol_assets root instead of a raw 15000 capture",
    )
    parser.add_argument(
        "--asset-session",
        default=os.environ.get("FC_GAME_ASSET_SESSION", "singleplayer_15000"),
        help="fcdev game-cfb-plain session name under --asset-root; comma-separated sessions are allowed",
    )
    parser.add_argument(
        "--replay-cfb-key",
        default=os.environ.get("FC_GAME_REPLAY_CFB_KEY", ""),
        help="8-byte DES-CFB64 key for --replay-cfb-plain-capture, as hex bytes",
    )
    parser.add_argument(
        "--replay-cfb-auto-key",
        action="store_true",
        default=env_flag("FC_GAME_REPLAY_CFB_AUTO_KEY"),
        help="recover the DES-CFB64 key from the running client after the initial login frame",
    )
    parser.add_argument(
        "--replay-cfb-process-name",
        default=os.environ.get("FC_GAME_REPLAY_CFB_PROCESS_NAME", "FinalCombat.exe"),
        help="process name used by --replay-cfb-auto-key",
    )
    parser.add_argument(
        "--replay-max-server-frames",
        type=int,
        default=int(os.environ.get("FC_GAME_REPLAY_MAX_SERVER_FRAMES", "0")),
        help="0 means replay all server frames available in the capture",
    )
    parser.add_argument(
        "--replay-patch-host",
        default=os.environ.get("FC_GAME_REPLAY_PATCH_HOST", ""),
        help=(
            "experimental: replace length-prefixed 127.0.0.1 strings in "
            "plaintext replay server templates with this host"
        ),
    )
    parser.add_argument("--echo", action="store_true", help="echo incoming data for socket smoke tests only")
    args = parser.parse_args()

    banner = bytes.fromhex(args.banner_hex) if args.banner_hex else b""
    first_response_hex = args.first_response_hex
    if args.experimental_dmp_response and not first_response_hex:
        first_response_hex = EXPERIMENTAL_DMP_BS1_RESPONSE_HEX
    if args.experimental_real_handshake:
        if not banner:
            banner = bytes.fromhex(REAL_15000_BANNER_HEX)
        if not first_response_hex:
            first_response_hex = REAL_15000_FIRST_RESPONSE_HEX
    first_response = bytes.fromhex(first_response_hex) if first_response_hex else b""

    replay_sources = [
        bool(args.asset_root),
        bool(args.replay_capture),
        bool(args.replay_cfb_plain_capture),
    ]
    if sum(1 for item in replay_sources if item) > 1:
        raise SystemExit("--asset-root, --replay-capture, and --replay-cfb-plain-capture are mutually exclusive")
    replay = None
    if args.asset_root or args.replay_cfb_plain_capture:
        if not args.replay_cfb_key and not args.replay_cfb_auto_key:
            raise SystemExit(
                "--asset-root/--replay-cfb-plain-capture requires --replay-cfb-key or --replay-cfb-auto-key"
            )
        cfb_key = None
        if args.replay_cfb_key:
            try:
                cfb_key = parse_hex_bytes(args.replay_cfb_key)
            except ValueError as exc:
                raise SystemExit(str(exc)) from exc
            if len(cfb_key) != 8:
                raise SystemExit("--replay-cfb-key must decode to exactly 8 bytes")
        if args.asset_root:
            replay = load_cfb_asset_replay_plan(
                Path(args.asset_root),
                args.asset_session,
                cfb_key,
                args.replay_cfb_auto_key,
                args.replay_cfb_process_name,
                args.replay_patch_host,
            )
        else:
            replay = load_cfb_plain_replay_plan(
                Path(args.replay_cfb_plain_capture),
                cfb_key,
                args.replay_cfb_auto_key,
                args.replay_cfb_process_name,
                args.replay_patch_host,
            )
    elif args.replay_capture:
        replay = load_replay_plan(Path(args.replay_capture))
    if replay:
        print(
            "loaded replay capture: "
            f"{replay.client_frame_count} client frame(s), {replay.server_frame_count} server frame(s), "
            f"{len(replay.groups)} response group(s); {replay.description}",
            flush=True,
        )
    capture_dir = Path(args.capture_dir) if args.capture_dir else None
    server = await asyncio.start_server(
        lambda r, w: handle_client(
            r,
            w,
            capture_dir,
            banner,
            first_response,
            args.echo,
            replay,
            args.replay_max_server_frames,
        ),
        args.host,
        args.port,
    )
    sockets = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
    print(f"game stub listening on {sockets}", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        pass
