#!/usr/bin/env python3
"""Minimal DCF C-client compatible HTTP auth stub.

The community launcher strings show JSON POSTs to:
  /auth/login
  /auth/register

Observed response field names:
  username, password, display_name, auth_ticket, login

This server deliberately keeps the response small and close to those strings.
Unknown fields can be added later if captures show the launcher expects them.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import os
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlsplit


DEFAULT_TICKET = "AAAAILocalOfflineTicket0000000000000000000000000"


@dataclass
class HttpRequest:
    method: str
    path: str
    query: str
    version: str
    headers: dict[str, str]
    body: bytes


def make_local_ticket(username: str) -> str:
    """Generate a deterministic 36-byte placeholder ticket.

    The captured ticket decodes to 36 bytes and starts with 00 00 00 11.
    The remaining 32 bytes are opaque. Until the cipher/signature is confirmed
    from captures or code, we preserve that shape and fill it with SHA-256.
    """

    seed = username.encode("utf-8", "replace") + b"|dcf-local-stub"
    raw = b"\x00\x00\x00\x11" + hashlib.sha256(seed).digest()
    return base64.b64encode(raw).decode("ascii")


def configured_ticket(username: str) -> str:
    value = os.environ.get("FC_AUTH_TICKET", DEFAULT_TICKET).strip()
    if value.lower() == "auto":
        return make_local_ticket(username)
    return value


async def read_http_request(reader: asyncio.StreamReader) -> HttpRequest | None:
    try:
        header_blob = await reader.readuntil(b"\r\n\r\n")
    except asyncio.IncompleteReadError:
        return None
    except asyncio.LimitOverrunError:
        return None

    header_text = header_blob.decode("iso-8859-1", "replace")
    lines = header_text.split("\r\n")
    request_line = lines[0].strip()
    if not request_line:
        return None

    parts = request_line.split()
    if len(parts) != 3:
        raise ValueError(f"bad request line: {request_line!r}")
    method, target, version = parts

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()

    length = int(headers.get("content-length", "0") or "0")
    if length < 0 or length > 1024 * 1024:
        raise ValueError(f"bad content length: {length}")
    body = await reader.readexactly(length) if length else b""

    split = urlsplit(target)
    return HttpRequest(
        method=method.upper(),
        path=split.path or "/",
        query=split.query,
        version=version,
        headers=headers,
        body=body,
    )


def parse_body(req: HttpRequest) -> dict[str, Any]:
    if not req.body:
        query = parse_qs(req.query, keep_blank_values=True)
        return {k: v[-1] for k, v in query.items()}

    content_type = req.headers.get("content-type", "")
    text = req.body.decode("utf-8", "replace")
    if "json" in content_type.lower() or text.lstrip().startswith(("{", "[")):
        try:
            value = json.loads(text)
            if isinstance(value, dict):
                return value
        except json.JSONDecodeError:
            pass

    form = parse_qs(text, keep_blank_values=True)
    return {k: v[-1] for k, v in form.items()}


def json_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def build_response(req: HttpRequest) -> tuple[int, dict[str, Any]]:
    path = req.path.lower().rstrip("/")
    data = parse_body(req)

    username = str(data.get("username") or data.get("account") or "100000001")
    password = str(data.get("password") or "")
    display_name = str(data.get("display_name") or data.get("nickname") or username)
    ticket = configured_ticket(username)

    if req.method == "GET" and path in {"", "/", "/health", "/status"}:
        return 200, {
            "ok": True,
            "service": "dcf-auth-stub",
            "auth_ticket": ticket,
            "launch_args": {
                "info": username,
                "login": ticket,
                "proxysvrip": os.environ.get("FC_PROXY_HOST", "127.0.0.1"),
                "proxysvrport": int(os.environ.get("FC_PROXY_PORT", "15000")),
                "servername": os.environ.get("FC_SERVER_NAME", "local"),
                "serverid": int(os.environ.get("FC_SERVER_ID", "1")),
            },
        }

    if path.endswith("/auth/login") or path.endswith("/login"):
        return 200, {
            "username": username,
            "password": password,
            "auth_ticket": ticket,
        }

    if path.endswith("/auth/register") or path.endswith("/register"):
        return 200, {
            "username": username,
            "password": password,
            "display_name": display_name,
            "auth_ticket": ticket,
            "login": True,
        }

    # Keep unknown auth endpoints non-fatal during protocol discovery.
    return 200, {
        "ok": True,
        "username": username,
        "password": password,
        "display_name": display_name,
        "auth_ticket": ticket,
        "login": True,
        "todo": f"unclassified endpoint {req.path}",
    }


async def write_http_response(
    writer: asyncio.StreamWriter,
    status: int,
    body: bytes,
    content_type: str = "application/json; charset=utf-8",
) -> None:
    reason = {
        200: "OK",
        400: "Bad Request",
        404: "Not Found",
        500: "Internal Server Error",
    }.get(status, "OK")
    header = (
        f"HTTP/1.1 {status} {reason}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Headers: content-type\r\n"
        "\r\n"
    ).encode("ascii")
    writer.write(header + body)
    await writer.drain()


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername")
    try:
        req = await read_http_request(reader)
        if req is None:
            return
        status, payload = build_response(req)
        body = json_bytes(payload)
        print(
            time.strftime("%H:%M:%S"),
            f"{peer} {req.method} {req.path} -> {status} {body.decode('utf-8', 'replace')}",
            flush=True,
        )
        await write_http_response(writer, status, body)
    except Exception as exc:
        body = json_bytes({"ok": False, "error": str(exc)})
        print(time.strftime("%H:%M:%S"), f"{peer} error: {exc}", flush=True)
        await write_http_response(writer, 400, body)
    finally:
        writer.close()
        await writer.wait_closed()


async def amain() -> None:
    parser = argparse.ArgumentParser(description="DCF local HTTP auth stub")
    parser.add_argument("--host", default=os.environ.get("FC_AUTH_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("FC_AUTH_PORT", "18090")))
    args = parser.parse_args()

    server = await asyncio.start_server(handle_client, args.host, args.port, limit=2 * 1024 * 1024)
    sockets = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
    print(f"auth stub listening on {sockets}", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        pass
