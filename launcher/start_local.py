#!/usr/bin/env python3
"""Start all local DCF stub services and print launch arguments."""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TICKET = "AAAAILocalOfflineTicket0000000000000000000000000"
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


def env_flag(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def start(name: str, args: list[str], env: dict[str, str]) -> subprocess.Popen:
    print(f"starting {name}: {' '.join(args)}", flush=True)
    return subprocess.Popen(args, cwd=ROOT, env=env)


def option_provided(argv: list[str], *names: str) -> bool:
    for item in argv:
        for name in names:
            if item == name or item.startswith(name + "="):
                return True
    return False


def resolve_asset_profile(asset_root: Path, profile: str) -> Path:
    candidate = Path(profile)
    if candidate.exists():
        return candidate
    name = profile if profile.endswith(".json") else f"{profile}.json"
    return asset_root / "profiles" / name


def session_value_to_arg(value: object) -> str:
    if isinstance(value, list):
        return ",".join(str(item) for item in value if str(item).strip())
    return str(value)


def apply_asset_profile(args: argparse.Namespace, argv: list[str], parser: argparse.ArgumentParser) -> None:
    if not args.asset_profile:
        return
    if not args.asset_root:
        args.asset_root = str(ROOT / "protocol_assets")

    asset_root = Path(args.asset_root)
    profile_path = resolve_asset_profile(asset_root, args.asset_profile)
    if not profile_path.exists():
        parser.error(f"asset profile not found: {profile_path}")

    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    sessions = profile.get("sessions", {})
    launch = profile.get("launch", {})
    if not isinstance(sessions, dict) or not isinstance(launch, dict):
        parser.error(f"invalid asset profile: {profile_path}")

    if sessions.get("game") and not option_provided(argv, "--game-asset-session"):
        args.game_asset_session = session_value_to_arg(sessions["game"])
    if sessions.get("channel") and not option_provided(argv, "--channel-asset-session"):
        args.channel_asset_session = str(sessions["channel"])

    field_map = {
        "channel_replay_mode": ("channel_replay_mode", "--channel-replay-mode"),
        "channel_direct_auto_start_delay": (
            "channel_direct_auto_start_delay",
            "--channel-direct-auto-start-delay",
        ),
        "game_replay_patch_host": ("game_replay_patch_host", "--game-replay-patch-host"),
        "game_replay_cfb_auto_key": ("game_replay_cfb_auto_key", "--game-replay-cfb-auto-key"),
        "start_channel": ("start_channel", "--start-channel"),
        "server_name": ("server_name", "--server-name"),
        "server_id": ("server_id", "--server-id"),
    }
    for key, (attr, option_name) in field_map.items():
        if key in launch and not option_provided(argv, option_name):
            setattr(args, attr, launch[key])

    print(f"loaded asset profile: {profile_path}", flush=True)


def main() -> int:
    argv = sys.argv[1:]
    parser = argparse.ArgumentParser(description="Start DCF local compatibility stubs")
    parser.add_argument("--account", default=os.environ.get("FC_ACCOUNT", "100000001"))
    parser.add_argument("--ticket", default=os.environ.get("FC_AUTH_TICKET", DEFAULT_TICKET))
    parser.add_argument("--host", default=os.environ.get("FC_LOCAL_HOST", "127.0.0.1"))
    parser.add_argument("--auth-port", type=int, default=int(os.environ.get("FC_AUTH_PORT", "18090")))
    parser.add_argument("--proxy-port", type=int, default=int(os.environ.get("FC_PROXY_PORT", "15000")))
    parser.add_argument("--game-port", type=int, default=int(os.environ.get("FC_GAME_PORT", "9000")))
    parser.add_argument("--channel-port", type=int, default=int(os.environ.get("FC_CHANNEL_PORT", "9024")))
    parser.add_argument(
        "--start-channel",
        action="store_true",
        default=env_flag("FC_START_CHANNEL"),
        help="start the experimental local channel/room listener",
    )
    parser.add_argument(
        "--channel-replay-crc-capture",
        default=os.environ.get("FC_CHANNEL_REPLAY_CRC_CAPTURE", ""),
        help=(
            "experimental: replay a 9024 room/game capture reencrypted with "
            "the CRC feedback transform"
        ),
    )
    parser.add_argument(
        "--channel-replay-max-server-frames",
        type=int,
        default=int(os.environ.get("FC_CHANNEL_REPLAY_MAX_SERVER_FRAMES", "0")),
        help="0 means replay all server frames available in the channel capture",
    )
    parser.add_argument(
        "--channel-replay-mode",
        choices=("gated", "direct", "sequential"),
        default=os.environ.get("FC_CHANNEL_REPLAY_MODE", "gated"),
        help=(
            "gated filters stale public room/player broadcasts and ignores passive "
            "client frames; direct fast-forwards into the captured local room/game; "
            "sequential replays the capture by client frame count"
        ),
    )
    parser.add_argument(
        "--channel-direct-auto-start-delay",
        type=float,
        default=float(os.environ.get("FC_CHANNEL_DIRECT_AUTO_START_DELAY", "6.0")),
        help=(
            "direct channel mode only: seconds to wait after entering the room "
            "before auto-sending the map-start group"
        ),
    )
    parser.add_argument("--server-name", default=os.environ.get("FC_SERVER_NAME", "local"))
    parser.add_argument("--server-id", default=os.environ.get("FC_SERVER_ID", "1"))
    parser.add_argument(
        "--capture-dir",
        default=os.environ.get("FC_CAPTURE_DIR", str(ROOT / "protocol_docs" / "captures")),
        help="runtime capture output directory; use an empty value to disable capture output",
    )
    parser.add_argument("--game-banner-hex", default=os.environ.get("FC_GAME_BANNER_HEX", ""))
    parser.add_argument("--game-first-response-hex", default=os.environ.get("FC_GAME_FIRST_RESPONSE_HEX", ""))
    parser.add_argument(
        "--asset-root",
        default=os.environ.get("FC_PROTOCOL_ASSET_ROOT", ""),
        help="fcdev protocol_assets root; starts game/channel replay from imported sessions",
    )
    parser.add_argument(
        "--asset-profile",
        default=os.environ.get("FC_ASSET_PROFILE", ""),
        help="profile name or JSON path under <asset-root>\\profiles",
    )
    parser.add_argument(
        "--game-asset-session",
        default=os.environ.get("FC_GAME_ASSET_SESSION", "singleplayer_15000"),
        help="fcdev game-cfb-plain session used with --asset-root; comma-separated sessions are allowed",
    )
    parser.add_argument(
        "--channel-asset-session",
        default=os.environ.get("FC_CHANNEL_ASSET_SESSION", "singleplayer_9024"),
        help="fcdev channel session used with --asset-root",
    )
    parser.add_argument("--game-replay-capture", default=os.environ.get("FC_GAME_REPLAY_CAPTURE", ""))
    parser.add_argument(
        "--game-replay-cfb-plain-capture",
        default=os.environ.get("FC_GAME_REPLAY_CFB_PLAIN_CAPTURE", ""),
        help=(
            "experimental: replay a DES-CFB64 plaintext BS capture reencrypted with "
            "--game-replay-cfb-key or --game-replay-cfb-auto-key"
        ),
    )
    parser.add_argument(
        "--game-replay-cfb-key",
        default=os.environ.get("FC_GAME_REPLAY_CFB_KEY", ""),
        help="8-byte DES-CFB64 key for --game-replay-cfb-plain-capture, as hex bytes",
    )
    parser.add_argument(
        "--game-replay-cfb-auto-key",
        action="store_true",
        default=env_flag("FC_GAME_REPLAY_CFB_AUTO_KEY"),
        help="recover the DES-CFB64 key from the running client after the initial login frame",
    )
    parser.add_argument(
        "--game-replay-cfb-process-name",
        default=os.environ.get("FC_GAME_REPLAY_CFB_PROCESS_NAME", "FinalCombat.exe"),
        help="process name used by --game-replay-cfb-auto-key",
    )
    parser.add_argument(
        "--game-replay-max-server-frames",
        type=int,
        default=int(os.environ.get("FC_GAME_REPLAY_MAX_SERVER_FRAMES", "0")),
        help="0 means replay all server frames available in the capture",
    )
    parser.add_argument(
        "--game-replay-patch-host",
        default=os.environ.get("FC_GAME_REPLAY_PATCH_HOST", ""),
        help=(
            "experimental: replace length-prefixed 127.0.0.1 strings in "
            "plaintext replay server templates with this host"
        ),
    )
    parser.add_argument(
        "--experimental-dmp-response",
        action="store_true",
        help="send the 109-byte BS_01 response fragment found in the 20180303 dump",
    )
    parser.add_argument(
        "--experimental-real-handshake",
        action="store_true",
        help="replay the real 15000 12-byte banner and 48-byte first response captured via MITM",
    )
    parser.add_argument("--dry-run", action="store_true", help="print commands without starting services")
    parser.add_argument("--python", default=sys.executable)
    args = parser.parse_args()
    apply_asset_profile(args, argv, parser)

    first_response_hex = args.game_first_response_hex
    banner_hex = args.game_banner_hex
    if args.experimental_dmp_response and not first_response_hex:
        first_response_hex = EXPERIMENTAL_DMP_BS1_RESPONSE_HEX
    if args.experimental_real_handshake:
        if not banner_hex:
            banner_hex = REAL_15000_BANNER_HEX
        if not first_response_hex:
            first_response_hex = REAL_15000_FIRST_RESPONSE_HEX
    if args.asset_root and (args.game_replay_capture or args.game_replay_cfb_plain_capture):
        parser.error("--asset-root cannot be combined with --game-replay-capture or --game-replay-cfb-plain-capture")
    if args.asset_root and args.channel_replay_crc_capture:
        parser.error("--asset-root cannot be combined with --channel-replay-crc-capture")
    if args.game_replay_capture and args.game_replay_cfb_plain_capture:
        parser.error("--game-replay-capture and --game-replay-cfb-plain-capture are mutually exclusive")
    if args.asset_root and not args.game_replay_cfb_key and not args.game_replay_cfb_auto_key:
        args.game_replay_cfb_auto_key = True
    if args.game_replay_cfb_plain_capture and not args.game_replay_cfb_key and not args.game_replay_cfb_auto_key:
        parser.error("--game-replay-cfb-plain-capture requires --game-replay-cfb-key or --game-replay-cfb-auto-key")

    env = os.environ.copy()
    env.update(
        {
            "FC_AUTH_HOST": args.host,
            "FC_AUTH_PORT": str(args.auth_port),
            "FC_AUTH_TICKET": args.ticket,
            "FC_PROXY_BIND": args.host,
            "FC_PROXY_HOST": args.host,
            "FC_PROXY_PORT": str(args.proxy_port),
            "FC_GAME_BIND": args.host,
            "FC_GAME_HOST": args.host,
            "FC_GAME_PORT": str(args.game_port),
            "FC_CHANNEL_BIND": args.host,
            "FC_CHANNEL_PORT": str(args.channel_port),
            "FC_CHANNEL_REPLAY_CRC_CAPTURE": args.channel_replay_crc_capture,
            "FC_CHANNEL_REPLAY_MAX_SERVER_FRAMES": str(args.channel_replay_max_server_frames),
            "FC_CHANNEL_REPLAY_MODE": args.channel_replay_mode,
            "FC_CHANNEL_DIRECT_AUTO_START_DELAY": str(args.channel_direct_auto_start_delay),
            "FC_SERVER_NAME": args.server_name,
            "FC_SERVER_ID": str(args.server_id),
            "FC_CAPTURE_DIR": args.capture_dir,
            "FC_PROTOCOL_ASSET_ROOT": args.asset_root,
            "FC_GAME_ASSET_SESSION": args.game_asset_session,
            "FC_CHANNEL_ASSET_SESSION": args.channel_asset_session,
            "FC_GAME_BANNER_HEX": banner_hex,
            "FC_GAME_FIRST_RESPONSE_HEX": first_response_hex,
            "FC_GAME_REPLAY_CAPTURE": args.game_replay_capture,
            "FC_GAME_REPLAY_CFB_PLAIN_CAPTURE": args.game_replay_cfb_plain_capture,
            "FC_GAME_REPLAY_CFB_KEY": args.game_replay_cfb_key,
            "FC_GAME_REPLAY_CFB_AUTO_KEY": "1" if args.game_replay_cfb_auto_key else "0",
            "FC_GAME_REPLAY_CFB_PROCESS_NAME": args.game_replay_cfb_process_name,
            "FC_GAME_REPLAY_MAX_SERVER_FRAMES": str(args.game_replay_max_server_frames),
            "FC_GAME_REPLAY_PATCH_HOST": args.game_replay_patch_host,
        }
    )

    game_cmd = [args.python, str(ROOT / "server_game" / "game_server.py")]
    if args.asset_root:
        game_cmd.extend(["--asset-root", args.asset_root])
        game_cmd.extend(["--asset-session", args.game_asset_session])
    if args.game_replay_capture:
        game_cmd.extend(["--replay-capture", args.game_replay_capture])
    if args.game_replay_cfb_plain_capture:
        game_cmd.extend(["--replay-cfb-plain-capture", args.game_replay_cfb_plain_capture])
    if args.game_replay_cfb_key:
        game_cmd.extend(["--replay-cfb-key", args.game_replay_cfb_key])
    if args.game_replay_cfb_auto_key:
        game_cmd.append("--replay-cfb-auto-key")
    if args.game_replay_cfb_process_name:
        game_cmd.extend(["--replay-cfb-process-name", args.game_replay_cfb_process_name])
    if args.game_replay_max_server_frames:
        game_cmd.extend(["--replay-max-server-frames", str(args.game_replay_max_server_frames)])
    if args.game_replay_patch_host:
        game_cmd.extend(["--replay-patch-host", args.game_replay_patch_host])

    auth_cmd = [args.python, str(ROOT / "server_auth" / "auth_server.py")]
    proxy_cmd = [args.python, str(ROOT / "server_proxy" / "proxy_server.py")]
    channel_cmd: list[str] | None = None
    if args.start_channel or args.channel_replay_crc_capture:
        channel_cmd = [
            args.python,
            str(ROOT / "server_game" / "channel_server.py"),
            "--host",
            args.host,
            "--port",
            str(args.channel_port),
        ]
        if args.asset_root:
            channel_cmd.extend(["--asset-root", args.asset_root])
            channel_cmd.extend(["--asset-session", args.channel_asset_session])
        if args.channel_replay_crc_capture:
            channel_cmd.extend(["--replay-crc-capture", args.channel_replay_crc_capture])
        if args.channel_replay_max_server_frames:
            channel_cmd.extend(["--replay-max-server-frames", str(args.channel_replay_max_server_frames)])
        if args.channel_replay_mode:
            channel_cmd.extend(["--replay-mode", args.channel_replay_mode])
        channel_cmd.extend(["--direct-auto-start-delay", str(args.channel_direct_auto_start_delay)])

    launch_args = (
        f"-info {args.account} "
        f"-login {args.ticket} "
        f"-proxysvrip {args.host} "
        f"-proxysvrport {args.proxy_port} "
        f"-servername {args.server_name} "
        f"-serverid {args.server_id}"
    )
    if args.dry_run:
        print("dry run: services were not started", flush=True)
        print(f"auth: {' '.join(auth_cmd)}", flush=True)
        print(f"game: {' '.join(game_cmd)}", flush=True)
        print(f"proxy: {' '.join(proxy_cmd)}", flush=True)
        if channel_cmd:
            print(f"channel: {' '.join(channel_cmd)}", flush=True)
        print("", flush=True)
        print("client launch args:", flush=True)
        print(launch_args, flush=True)
        return 0

    processes = [
        start("auth", auth_cmd, env),
        start("game", game_cmd, env),
        start("proxy", proxy_cmd, env),
    ]
    if channel_cmd:
        processes.append(start("channel", channel_cmd, env))

    print("", flush=True)
    print("client launch args:", flush=True)
    print(launch_args, flush=True)
    print("", flush=True)
    print(f"auth health: http://{args.host}:{args.auth_port}/health", flush=True)
    if args.start_channel or args.channel_replay_crc_capture:
        print(f"channel listener: {args.host}:{args.channel_port}", flush=True)
        if args.asset_root:
            print(f"protocol assets: {args.asset_root}", flush=True)
            print(f"game asset session: {args.game_asset_session}", flush=True)
            print(f"channel asset session: {args.channel_asset_session}", flush=True)
        if args.channel_replay_crc_capture:
            print(f"channel replay: {args.channel_replay_crc_capture}", flush=True)
    print("press Ctrl+C to stop all stubs", flush=True)

    def stop_all() -> None:
        for proc in processes:
            if proc.poll() is None:
                proc.terminate()
        deadline = time.time() + 5
        for proc in processes:
            remaining = max(0.1, deadline - time.time())
            try:
                proc.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                proc.kill()

    if os.name != "nt":
        signal.signal(signal.SIGTERM, lambda _sig, _frame: stop_all())

    try:
        while True:
            for proc in processes:
                code = proc.poll()
                if code is not None:
                    print(f"process exited: pid={proc.pid} code={code}", flush=True)
                    stop_all()
                    return code
            time.sleep(0.5)
    except KeyboardInterrupt:
        stop_all()
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
