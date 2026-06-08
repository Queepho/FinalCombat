#!/usr/bin/env python3
"""Read-only scanner for a running Windows process."""

from __future__ import annotations

import argparse
import ctypes
import json
import re
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import Any


TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
MEM_MAPPED = 0x40000
MEM_IMAGE = 0x1000000

PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80

MAX_PATH = 260


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * MAX_PATH),
    ]


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.c_void_p),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", ctypes.c_void_p),
        ("szModule", wintypes.WCHAR * 256),
        ("szExePath", wintypes.WCHAR * MAX_PATH),
    ]


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
kernel32.Process32FirstW.argtypes = [ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Process32FirstW.restype = wintypes.BOOL
kernel32.Process32NextW.argtypes = [ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Process32NextW.restype = wintypes.BOOL
kernel32.Module32FirstW.argtypes = [ctypes.c_void_p, ctypes.POINTER(MODULEENTRY32W)]
kernel32.Module32FirstW.restype = wintypes.BOOL
kernel32.Module32NextW.argtypes = [ctypes.c_void_p, ctypes.POINTER(MODULEENTRY32W)]
kernel32.Module32NextW.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = ctypes.c_void_p
kernel32.VirtualQueryEx.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.POINTER(MEMORY_BASIC_INFORMATION),
    ctypes.c_size_t,
]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t
kernel32.ReadProcessMemory.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
kernel32.ReadProcessMemory.restype = wintypes.BOOL


@dataclass
class ProcessInfo:
    pid: int
    name: str


@dataclass
class ModuleInfo:
    base: int
    size: int
    name: str
    path: str

    @property
    def end(self) -> int:
        return self.base + self.size


@dataclass
class RegionInfo:
    base: int
    size: int
    state: int
    protect: int
    type: int
    allocation_base: int

    @property
    def end(self) -> int:
        return self.base + self.size


PROTECT_NAMES = {
    0x01: "NOACCESS",
    0x02: "READONLY",
    0x04: "READWRITE",
    0x08: "WRITECOPY",
    0x10: "EXECUTE",
    0x20: "EXECUTE_READ",
    0x40: "EXECUTE_READWRITE",
    0x80: "EXECUTE_WRITECOPY",
}

TYPE_NAMES = {
    MEM_PRIVATE: "MEM_PRIVATE",
    MEM_MAPPED: "MEM_MAPPED",
    MEM_IMAGE: "MEM_IMAGE",
}


def win_error() -> OSError:
    return ctypes.WinError(ctypes.get_last_error())


def close_handle(handle: int) -> None:
    if handle:
        kernel32.CloseHandle(handle)


def list_processes() -> list[ProcessInfo]:
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == ctypes.c_void_p(-1).value:
        raise win_error()
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        processes: list[ProcessInfo] = []
        if not kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
            return processes
        while True:
            processes.append(ProcessInfo(pid=int(entry.th32ProcessID), name=entry.szExeFile))
            if not kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                break
        return processes
    finally:
        close_handle(snapshot)


def find_pid_by_name(name: str) -> int | None:
    wanted = name.lower()
    for proc in list_processes():
        if proc.name.lower() == wanted:
            return proc.pid
    return None


def list_modules(pid: int) -> list[ModuleInfo]:
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snapshot == ctypes.c_void_p(-1).value:
        return []
    try:
        entry = MODULEENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        modules: list[ModuleInfo] = []
        if not kernel32.Module32FirstW(snapshot, ctypes.byref(entry)):
            return modules
        while True:
            modules.append(
                ModuleInfo(
                    base=int(entry.modBaseAddr or 0),
                    size=int(entry.modBaseSize),
                    name=entry.szModule,
                    path=entry.szExePath,
                )
            )
            if not kernel32.Module32NextW(snapshot, ctypes.byref(entry)):
                break
        return modules
    finally:
        close_handle(snapshot)


def module_for_va(modules: list[ModuleInfo], va: int) -> ModuleInfo | None:
    for module in modules:
        if module.base <= va < module.end:
            return module
    return None


def protect_name(protect: int) -> str:
    base = protect & 0xFF
    name = PROTECT_NAMES.get(base, f"0x{base:x}")
    suffix = []
    if protect & PAGE_GUARD:
        suffix.append("GUARD")
    return "|".join([name, *suffix])


def type_name(mem_type: int) -> str:
    return TYPE_NAMES.get(mem_type, f"0x{mem_type:x}")


def is_readable(region: RegionInfo) -> bool:
    if region.state != MEM_COMMIT:
        return False
    if region.protect & PAGE_GUARD:
        return False
    return (region.protect & 0xFF) != PAGE_NOACCESS


def is_executable(region: RegionInfo) -> bool:
    return (region.protect & 0xFF) in {
        PAGE_EXECUTE,
        PAGE_EXECUTE_READ,
        PAGE_EXECUTE_READWRITE,
        PAGE_EXECUTE_WRITECOPY,
    }


def iter_regions(handle: int, max_address: int = 0x7FFFFFFF_FFFFFFFF) -> list[RegionInfo]:
    regions: list[RegionInfo] = []
    address = 0
    mbi = MEMORY_BASIC_INFORMATION()
    mbi_size = ctypes.sizeof(mbi)
    while address < max_address:
        result = kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), mbi_size)
        if not result:
            break
        base = int(mbi.BaseAddress or 0)
        size = int(mbi.RegionSize)
        if size <= 0:
            address += 0x1000
            continue
        regions.append(
            RegionInfo(
                base=base,
                size=size,
                state=int(mbi.State),
                protect=int(mbi.Protect),
                type=int(mbi.Type),
                allocation_base=int(mbi.AllocationBase or 0),
            )
        )
        next_address = base + size
        if next_address <= address:
            break
        address = next_address
    return regions


def read_memory(handle: int, address: int, size: int) -> bytes:
    buf = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t()
    if not kernel32.ReadProcessMemory(handle, ctypes.c_void_p(address), buf, size, ctypes.byref(read)):
        return b""
    return bytes(buf.raw[: read.value])


def ascii_preview(data: bytes) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)


def parse_hex_pattern(text: str) -> bytes:
    cleaned = re.sub(r"[^0-9a-fA-F]", "", text)
    if len(cleaned) % 2:
        raise argparse.ArgumentTypeError(f"odd-length hex pattern: {text}")
    return bytes.fromhex(cleaned)


def scan_region(
    handle: int,
    region: RegionInfo,
    modules: list[ModuleInfo],
    patterns: list[tuple[str, bytes]],
    chunk_size: int,
    max_hits: int,
) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    overlap = max((len(pattern) for _name, pattern in patterns), default=1) - 1
    offset = 0
    carry = b""
    while offset < region.size and len(hits) < max_hits:
        to_read = min(chunk_size, region.size - offset)
        chunk = read_memory(handle, region.base + offset, to_read)
        if not chunk:
            break
        haystack = carry + chunk
        haystack_lower = haystack.lower()
        for name, pattern in patterns:
            start = 0
            pattern_lower = pattern.lower()
            while len(hits) < max_hits:
                pos = haystack_lower.find(pattern_lower, start)
                if pos < 0:
                    break
                absolute = region.base + offset - len(carry) + pos
                module = module_for_va(modules, absolute)
                context = read_memory(handle, max(region.base, absolute - 16), 80)
                hits.append(
                    {
                        "pattern": name,
                        "va": absolute,
                        "region_base": region.base,
                        "region_size": region.size,
                        "protect": protect_name(region.protect),
                        "type": type_name(region.type),
                        "module": module.name if module else None,
                        "module_offset": absolute - module.base if module else None,
                        "hex": context.hex(" "),
                        "ascii": ascii_preview(context),
                    }
                )
                start = pos + 1
        carry = haystack[-overlap:] if overlap else b""
        offset += len(chunk)
    return hits


def dump_private_executable_regions(
    handle: int,
    regions: list[RegionInfo],
    modules: list[ModuleInfo],
    out_dir: Path,
    max_region_size: int,
) -> list[dict[str, Any]]:
    out_dir.mkdir(parents=True, exist_ok=True)
    dumped: list[dict[str, Any]] = []
    for region in regions:
        if not is_readable(region) or not is_executable(region):
            continue
        if module_for_va(modules, region.base):
            continue
        if region.type != MEM_PRIVATE:
            continue
        if region.size > max_region_size:
            continue
        data = read_memory(handle, region.base, region.size)
        if not data:
            continue
        path = out_dir / f"region_{region.base:08x}_{region.size:x}_{protect_name(region.protect)}.bin"
        path.write_bytes(data)
        dumped.append(
            {
                "path": str(path),
                "base": region.base,
                "size": region.size,
                "protect": protect_name(region.protect),
                "type": type_name(region.type),
            }
        )
    return dumped


def dump_selected_windows(
    handle: int,
    regions: list[RegionInfo],
    modules: list[ModuleInfo],
    addresses: list[int],
    size: int,
    out_dir: Path,
) -> list[dict[str, Any]]:
    out_dir.mkdir(parents=True, exist_ok=True)
    dumped: list[dict[str, Any]] = []
    half = size // 2
    for address in addresses:
        region = next((item for item in regions if item.base <= address < item.end), None)
        if region is None or not is_readable(region):
            dumped.append({"address": address, "error": "address is not readable"})
            continue
        start = max(region.base, address - half)
        end = min(region.end, start + size)
        data = read_memory(handle, start, end - start)
        if not data:
            dumped.append({"address": address, "error": "ReadProcessMemory failed"})
            continue
        module = module_for_va(modules, address)
        module_name = module.name if module else "nomodule"
        safe_module = re.sub(r"[^A-Za-z0-9_.-]+", "_", module_name)
        path = out_dir / f"window_{address:08x}_{start:08x}_{len(data):x}_{safe_module}.bin"
        path.write_bytes(data)
        dumped.append(
            {
                "path": str(path),
                "address": address,
                "base": start,
                "size": len(data),
                "protect": protect_name(region.protect),
                "type": type_name(region.type),
                "module": module.name if module else None,
                "module_offset": address - module.base if module else None,
            }
        )
    return dumped


def write_markdown(path: Path, payload: dict[str, Any]) -> None:
    lines = [
        "# Live Process Scan",
        "",
        f"- pid: `{payload['pid']}`",
        f"- process: `{payload['process_name']}`",
        f"- modules: `{len(payload['modules'])}`",
        f"- regions: `{payload['region_count']}`",
        "",
        "## Interesting Modules",
        "",
    ]
    interesting = [
        module
        for module in payload["modules"]
        if re.search(r"(?i)(finalcombat|xllogin|xlaccount|xlcrypto|utility|ws2_32)", module["name"])
    ]
    if interesting:
        for module in interesting:
            lines.append(f"- `0x{module['base']:x}` size `0x{module['size']:x}` `{module['path']}`")
    else:
        lines.append("- none")

    lines.extend(["", "## Pattern Hits", ""])
    if payload["hits"]:
        for hit in payload["hits"]:
            module = hit["module"] or "no module"
            module_offset = f"+0x{hit['module_offset']:x}" if hit["module_offset"] is not None else ""
            lines.append(
                f"- `{hit['pattern']}` VA `0x{hit['va']:x}` `{hit['protect']}` `{hit['type']}` `{module}`{module_offset}"
            )
            lines.append(f"  - ascii: `{hit['ascii']}`")
            lines.append(f"  - hex: `{hit['hex']}`")
    else:
        lines.append("- none")

    if payload.get("dumped_regions"):
        lines.extend(["", "## Dumped Regions", ""])
        for item in payload["dumped_regions"]:
            if "error" in item:
                lines.append(f"- VA `0x{item['address']:x}` error `{item['error']}`")
            else:
                lines.append(
                    f"- `{item['path']}` base `0x{item['base']:x}` size `0x{item['size']:x}` `{item['protect']}` `{item['type']}`"
                )

    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan a running process for protocol clues")
    parser.add_argument("--pid", type=int)
    parser.add_argument("--name", default="FinalCombat.exe")
    parser.add_argument("--pattern", action="append", default=["BS", "proxysvr", "Utility2.0", "XLCrypto"])
    parser.add_argument("--hex-pattern", action="append", default=[])
    parser.add_argument("--max-hits", type=int, default=80)
    parser.add_argument("--chunk-size", type=int, default=1024 * 1024)
    parser.add_argument("--max-address", type=lambda value: int(value, 0), default=0xFFFFFFFF)
    parser.add_argument("--dump-executable-private", type=Path)
    parser.add_argument("--dump-va", type=lambda value: int(value, 0), action="append", default=[])
    parser.add_argument("--dump-va-dir", type=Path)
    parser.add_argument("--dump-va-size", type=lambda value: int(value, 0), default=0x2000)
    parser.add_argument("--max-dump-region-size", type=int, default=8 * 1024 * 1024)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--markdown-out", type=Path)
    args = parser.parse_args()

    pid = args.pid if args.pid is not None else find_pid_by_name(args.name)
    if pid is None:
        raise SystemExit(f"process not found: {args.name}")

    handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        raise win_error()
    try:
        modules = list_modules(pid)
        regions = iter_regions(handle, args.max_address)
        patterns = [(pattern, pattern.encode("ascii")) for pattern in args.pattern]
        patterns.extend((f"hex:{text}", parse_hex_pattern(text)) for text in args.hex_pattern)

        hits: list[dict[str, Any]] = []
        for region in regions:
            if len(hits) >= args.max_hits:
                break
            if not is_readable(region):
                continue
            hits.extend(
                scan_region(
                    handle=handle,
                    region=region,
                    modules=modules,
                    patterns=patterns,
                    chunk_size=args.chunk_size,
                    max_hits=args.max_hits - len(hits),
                )
            )

        dumped_regions = []
        if args.dump_executable_private:
            dumped_regions = dump_private_executable_regions(
                handle=handle,
                regions=regions,
                modules=modules,
                out_dir=args.dump_executable_private,
                max_region_size=args.max_dump_region_size,
            )
        if args.dump_va:
            out_dir = args.dump_va_dir or Path("protocol_docs") / "runtime_windows"
            dumped_regions.extend(
                dump_selected_windows(
                    handle=handle,
                    regions=regions,
                    modules=modules,
                    addresses=args.dump_va,
                    size=args.dump_va_size,
                    out_dir=out_dir,
                )
            )

        proc_name = next((proc.name for proc in list_processes() if proc.pid == pid), args.name)
        payload = {
            "pid": pid,
            "process_name": proc_name,
            "modules": [module.__dict__ for module in modules],
            "region_count": len(regions),
            "hits": hits[: args.max_hits],
            "dumped_regions": dumped_regions,
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        if args.json_out:
            args.json_out.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        if args.markdown_out:
            write_markdown(args.markdown_out, payload)
    finally:
        close_handle(handle)


if __name__ == "__main__":
    main()
