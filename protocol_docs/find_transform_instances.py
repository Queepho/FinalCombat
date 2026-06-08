#!/usr/bin/env python3
"""Find live DCF transform objects in a running FinalCombat.exe process."""

from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from live_process_scan import (  # noqa: E402
    PROCESS_QUERY_INFORMATION,
    PROCESS_VM_READ,
    close_handle,
    find_pid_by_name,
    is_readable,
    kernel32,
    list_modules,
    list_processes,
    module_for_va,
    protect_name,
    read_memory,
    type_name,
    iter_regions,
)
from bs_crypto import des_cfb64_encrypt  # noqa: E402


TRANSFORM_VTABLE = 0x00D33FDC
CFB_SUB_VTABLE = 0x00D33FEC
FIXED_CHALLENGE_KEY = bytes(range(8))


def dword(data: bytes, offset: int) -> int | None:
    if offset + 4 > len(data):
        return None
    return struct.unpack_from("<I", data, offset)[0]


def find_pattern(data: bytes, pattern: bytes) -> list[int]:
    hits: list[int] = []
    start = 0
    while True:
        pos = data.find(pattern, start)
        if pos < 0:
            return hits
        hits.append(pos)
        start = pos + 1


def ascii_preview(data: bytes) -> str:
    return "".join(chr(byte) if 32 <= byte < 127 else "." for byte in data)


def scan_instances(pid: int, max_address: int) -> dict[str, Any]:
    handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        raise OSError("OpenProcess failed")

    try:
        modules = list_modules(pid)
        regions = iter_regions(handle, max_address)
        pattern = struct.pack("<I", TRANSFORM_VTABLE)
        instances: list[dict[str, Any]] = []

        for region in regions:
            if not is_readable(region):
                continue
            data = read_memory(handle, region.base, region.size)
            if not data:
                continue
            for pos in find_pattern(data, pattern):
                va = region.base + pos
                context = read_memory(handle, va, 0x120)
                if len(context) < 0x30:
                    continue
                module = module_for_va(modules, va)
                item = {
                    "va": va,
                    "region_base": region.base,
                    "region_size": region.size,
                    "protect": protect_name(region.protect),
                    "type": type_name(region.type),
                    "module": module.name if module else None,
                    "module_offset": va - module.base if module else None,
                    "send_state_or_block0_le": f"0x{dword(context, 0x04) or 0:08x}",
                    "recv_state_or_block1_le": f"0x{dword(context, 0x08) or 0:08x}",
                    "block_04_0b": context[0x04:0x0C].hex(" "),
                    "block_0c_13": context[0x0C:0x14].hex(" "),
                    "key_14_1b": context[0x14:0x1C].hex(" "),
                    "block_1c_23": context[0x1C:0x24].hex(" "),
                    "block_24_2b": context[0x24:0x2C].hex(" "),
                    "ptr_2c": f"0x{dword(context, 0x2C) or 0:08x}",
                    "crypto_context_prefix": context[0x30:0x80].hex(" "),
                    "ascii": ascii_preview(context[:0x80]),
                }
                if dword(context, 0x14) == CFB_SUB_VTABLE and len(context) >= 0x60:
                    sub_block = context[0x18:0x20]
                    item["cfb_subobject"] = {
                        "va": va + 0x14,
                        "vtable": f"0x{CFB_SUB_VTABLE:08x}",
                        "block_04_0b": sub_block.hex(" "),
                        "response_from_block_04_0b": des_cfb64_encrypt(
                            sub_block, FIXED_CHALLENGE_KEY
                        ).hex(" "),
                        "block_0c_13": context[0x20:0x28].hex(" "),
                        "fixed_key_14_1b": context[0x28:0x30].hex(" "),
                        "stream_key_1c_23": context[0x30:0x38].hex(" "),
                        "cfb_iv_24_2b": context[0x38:0x40].hex(" "),
                        "des_context_prefix": context[0x44:0x84].hex(" "),
                    }
                instances.append(item)

        proc_name = next((proc.name for proc in list_processes() if proc.pid == pid), "unknown")
        return {
            "pid": pid,
            "process_name": proc_name,
            "vtable": f"0x{TRANSFORM_VTABLE:08x}",
            "instances": instances,
        }
    finally:
        close_handle(handle)


def write_markdown(path: Path, report: dict[str, Any]) -> None:
    lines = [
        "# Transform Instance Scan",
        "",
        f"- pid: `{report['pid']}`",
        f"- process: `{report['process_name']}`",
        f"- vtable: `{report['vtable']}`",
        f"- instances: `{len(report['instances'])}`",
        "",
        "| va | protect | type | module | +4..+b | +c..+13 | +14..+1b | +1c..+23 | +24..+2b |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for item in report["instances"]:
        module = item["module"] or ""
        lines.append(
            f"| `0x{item['va']:08x}` | `{item['protect']}` | `{item['type']}` | `{module}` | "
            f"`{item['block_04_0b']}` | `{item['block_0c_13']}` | `{item['key_14_1b']}` | "
            f"`{item['block_1c_23']}` | `{item['block_24_2b']}` |"
        )
        sub = item.get("cfb_subobject")
        if sub:
            lines.append(
                f"  - CFB subobject `0x{sub['va']:08x}` response `{sub['response_from_block_04_0b']}` "
                f"stream key `{sub['stream_key_1c_23']}`"
            )
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Find live transform objects")
    parser.add_argument("--pid", type=int)
    parser.add_argument("--name", default="FinalCombat.exe")
    parser.add_argument("--max-address", type=lambda value: int(value, 0), default=0xFFFFFFFF)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--markdown-out", type=Path)
    args = parser.parse_args()

    pid = args.pid if args.pid is not None else find_pid_by_name(args.name)
    if pid is None:
        raise SystemExit(f"process not found: {args.name}")

    report = scan_instances(pid, args.max_address)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    if args.json_out:
        args.json_out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    if args.markdown_out:
        write_markdown(args.markdown_out, report)


if __name__ == "__main__":
    main()
