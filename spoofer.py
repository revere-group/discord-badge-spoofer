#!/usr/bin/env python3
"""
discord science spoofer - inflate the playtime and games-played badges.

revere group, 2026 improved by johnny. mit licensed (see LICENSE).

posts launch_game and running_game_heartbeat events to /api/v9/science, the same
endpoint the real client uses to credit playtime. duration_tracked_ms isn't
validated so any number goes straight through.

run:
    python spoofer.py

auth bits:
    token            your account token, entered on first run           [saved]
    cookie           cf_clearance, pasted by hand via menu option 3     [saved]
    fingerprint      optional, only for the games-played count          [saved]
    analytics_token  fetched from GET /users/@me?with_analytics_token=true, cached
    super_props      from cordapi.dolfi.es (fallback: local)            [per run]
    heartbeat/launch random uuids, fresh every run                      [per run]

this breaks discord tos. your account, your problem.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
import webbrowser
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterator, Sequence

# paths
ROOT = Path(__file__).resolve().parent
GAMES_FILE = ROOT.parent / "data" / "games.json"     # full game list, downloaded if absent
STATE_FILE = ROOT / "science_state.json"             # token, cookie, cached auth

ME_URL = "https://discord.com/api/v9/users/@me?with_analytics_token=true"
SCIENCE_URL = "https://discord.com/api/v9/science"
PROPERTIES_URL = "https://cordapi.dolfi.es/api/v2/properties/windows"  # current super_props, local fallback
GAMES_CDN_URL = "https://cdn.discordapp.com/detectables/games.json"  # used if games.json isn't there
SUBSCRIBE_URL = "https://www.youtube.com/@solasity?sub_confirmation=1"
DISCORD_INVITE_LABEL = "discord.gg/QEC6QttWMh"
DISCORD_INVITE_URL = "https://discord.gg/QEC6QttWMh"
GATE_WAIT = 10            # seconds before enter is accepted on each setup step

BATCH_SIZE = 50           # events per /science request
BATCH_DELAY = 1           # seconds between requests
AUTH_MAX_AGE = 12 * 3600  # refetch the analytics token once the cache is older than this
DEBUG = False

# client identity
CLIENT_VERSION = "1.0.9253"
CLIENT_BUILD_NUMBER = 594031
NATIVE_BUILD_NUMBER = 88414
OS_VERSION = "10.0.26200"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) discord/1.0.9253 Chrome/148.0.7778.280 "
    "Electron/42.7.1 Safari/537.36"
)


def _user_id_from_token(token: str) -> str:
    # discord tokens start with base64(user_id) before the first dot
    try:
        first = token.split(".", 1)[0]
        pad = "=" * (-len(first) % 4)
        return base64.b64decode(first + pad).decode("utf-8")
    except Exception:
        return ""


# powershell that reproduces discord's executable_fingerprint. it collects pe metadata
# (file size, TimeDateStamp, SizeOfImage, header/section-table hashes, signing cert),
# binds it to your machine guid + user id, and xor-obfuscates the result.
# reverse-engineered by dolfies:
# https://gist.github.com/dolfies/d442777ab8354e18c1a3827e27f85c3a
_FINGERPRINT_PS1 = r'''
param(
  [int]$ProcessId = 0,
  [string]$Path,
  [Parameter(Mandatory = $true)][string]$UserId
)

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class CertPubKeyHash {
  const uint X509_ASN_ENCODING = 0x00000001;
  const uint PKCS_7_ASN_ENCODING = 0x00010000;
  const uint CALG_SHA_256 = 0x0000800C;

  [StructLayout(LayoutKind.Sequential)] struct Blob { public uint cbData; public IntPtr pbData; }
  [StructLayout(LayoutKind.Sequential)] struct AlgId { public IntPtr pszObjId; public Blob Parameters; }
  [StructLayout(LayoutKind.Sequential)] struct BitBlob { public uint cbData; public IntPtr pbData; public uint cUnusedBits; }
  [StructLayout(LayoutKind.Sequential)] struct PubKeyInfo { public AlgId Algorithm; public BitBlob PublicKey; }
  [StructLayout(LayoutKind.Sequential)] struct FileTime { public uint Low; public uint High; }
  [StructLayout(LayoutKind.Sequential)]
  struct CertInfo {
    public uint Version; public Blob SerialNumber; public AlgId SignatureAlgorithm; public Blob Issuer;
    public FileTime NotBefore; public FileTime NotAfter; public Blob Subject;
    public PubKeyInfo SubjectPublicKeyInfo; public BitBlob IssuerUniqueId; public BitBlob SubjectUniqueId;
    public uint ExtensionCount; public IntPtr Extensions;
  }
  [StructLayout(LayoutKind.Sequential)]
  struct CertContext {
    public uint EncodingType; public IntPtr Encoded; public uint EncodedSize;
    public IntPtr CertInfo; public IntPtr Store;
  }

  [DllImport("crypt32.dll", SetLastError = true)]
  static extern bool CryptHashPublicKeyInfo(
    IntPtr provider, uint algid, uint flags, uint encoding, ref PubKeyInfo info, byte[] hash, ref uint hashSize);

  public static byte[] Hash(IntPtr certContext) {
    var ctx = Marshal.PtrToStructure<CertContext>(certContext);
    var info = Marshal.PtrToStructure<CertInfo>(ctx.CertInfo);
    var hash = new byte[32];
    uint hashSize = 32;
    if (!CryptHashPublicKeyInfo(IntPtr.Zero, CALG_SHA_256, 0, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, ref info.SubjectPublicKeyInfo, hash, ref hashSize) || hashSize != 32)
      throw new InvalidOperationException("CryptHashPublicKeyInfo failed");
    return hash;
  }
}
"@

if (!$Path) {
  if (!$ProcessId) { throw "Pass -Path <exe> or -ProcessId <pid>." }
  $Path = (Get-Process -Id $ProcessId).Path
}
if (!$Path) { throw "Could not resolve executable path." }

$fs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
try {
  $fileSize = [UInt64]$fs.Length
  $readSize = [int][Math]::Min($fs.Length, 0x10000)
  $buf = [byte[]]::new($readSize)
  $read = $fs.Read($buf, 0, $readSize)
  if ($read -lt 0x40) { throw "File prefix is too small." }
  if ($read -ne $readSize) { [Array]::Resize([ref]$buf, $read) }
} finally {
  $fs.Dispose()
}

if ([BitConverter]::ToUInt16($buf, 0) -ne 0x5A4D) { throw "Not an MZ executable." }
$pe = [BitConverter]::ToInt32($buf, 0x3C)
if ($pe -lt 0 -or [BitConverter]::ToUInt32($buf, $pe) -ne 0x4550) { throw "Not a PE executable." }

$fh = $pe + 4
$sections = [BitConverter]::ToUInt16($buf, $fh + 2)
$timestamp = [BitConverter]::ToUInt32($buf, $fh + 4)
$optSize = [BitConverter]::ToUInt16($buf, $fh + 16)
$opt = $fh + 20
$isPe32Plus = [BitConverter]::ToUInt16($buf, $opt) -eq 0x20B
if (!$isPe32Plus) { throw "Discord only fingerprints PE32+." }
$sizeOfImage = [BitConverter]::ToUInt32($buf, $opt + 56)

$sectionTable = $opt + $optSize
$sha256 = [Security.Cryptography.SHA256]::Create()
$headerHash = $sha256.ComputeHash([byte[]]$buf[0..($sectionTable - 1)])
$sectionHash = $sha256.ComputeHash([byte[]]$buf[$sectionTable..($sectionTable + $sections * 40 - 1)])

$machineGuid = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography" -Name MachineGuid).MachineGuid
$machineUserHash = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($machineGuid + $UserId))

$sig = Get-AuthenticodeSignature -LiteralPath $Path
$signed = $sig.Status -eq "Valid" -and $sig.SignerCertificate
if ($signed) {
  $name = $sig.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
  $certHash = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($name) + [CertPubKeyHash]::Hash($sig.SignerCertificate.Handle))
} else {
  $certHash = [byte[]]::new(32)
}

$flags = 0
if ($signed) { $flags += 1 }
if ($isPe32Plus) { $flags += 2 }

$out = [byte[]](@(1, [byte]$flags) +
  [BitConverter]::GetBytes($fileSize) +
  [BitConverter]::GetBytes($timestamp) +
  [BitConverter]::GetBytes($sizeOfImage) +
  $headerHash + $machineUserHash + $sectionHash + $certHash)

$key = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($UserId + "https://discord.com/careers"))
for ($i = 1; $i -lt $out.Length; $i++) {
  $out[$i] = $out[$i] -bxor $key[($i - 1) -band 31]
}

[Convert]::ToBase64String($out)
'''


def generate_fingerprint(user_id: str, path: str = "", pid: int = 0) -> str:
    """run the powershell generator and return the base64 executable_fingerprint."""
    if os.name != "nt":
        raise RuntimeError("fingerprint generation is windows-only")
    script = Path(tempfile.gettempdir()) / f"disc_fp_{uuid.uuid4().hex}.ps1"
    script.write_text(_FINGERPRINT_PS1, encoding="utf-8")
    try:
        args = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", str(script), "-UserId", user_id]
        args += (["-ProcessId", str(pid)] if pid else ["-Path", path])
        result = subprocess.run(args, capture_output=True, text=True, timeout=60)
    finally:
        try:
            script.unlink()
        except OSError:
            pass
    if result.returncode != 0:
        lines = (result.stderr or result.stdout or "").strip().splitlines()
        raise RuntimeError(lines[-1] if lines else "powershell failed")
    out = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not out:
        raise RuntimeError("generator produced no output")
    return out[-1]


class Console:
    """colored console output."""

    RED = "\x1b[91m"
    ORANGE = "\x1b[38;5;208m"
    GREEN = "\x1b[92m"
    YELLOW = "\x1b[93m"
    WHITE = "\x1b[97m"
    GREY = "\x1b[90m"
    RESET = "\x1b[0m"
    RULE = "─" * 44

    def __init__(self) -> None:
        try:
            sys.stdout.reconfigure(encoding="utf-8")  # glyphs must encode even when stdout is piped
        except Exception:
            pass
        if sys.platform == "win32":
            self._enable_ansi()

    @staticmethod
    def _enable_ansi() -> None:
      
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # std_output_handle
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)

    def _stamp(self) -> str:
        return f"{self.GREY}{time.strftime('%H:%M:%S')}{self.RESET}"

    def _line(self, glyph: str, target: str, detail: str, color: str) -> None:
        print(f"  {self._stamp()} {glyph} {self.WHITE}{target}{self.RESET} "
              f"{self.GREY}·{self.RESET} {color}{detail}{self.RESET}")

    def ok(self, target: str, detail: str) -> None:
        self._line(f"{self.GREEN}✓{self.RESET}", target, detail, self.GREEN)

    def sent(self, target: str, detail: str) -> None:
        self._line(f"{self.GREY}·{self.RESET} {self.GREEN}sent{self.RESET}", target, detail, self.GREEN)

    def warn(self, target: str, detail: str) -> None:
        self._line(f"{self.YELLOW}!{self.RESET}", target, detail, self.YELLOW)

    def err(self, target: str, detail: str) -> None:
        self._line(f"{self.RED}✗{self.RESET}", target, detail, self.RED)

    def info(self, detail: str) -> None:
        print(f"  {self._stamp()} {self.GREY}·{self.RESET} {self.WHITE}{detail}{self.RESET}")

    def rule(self) -> None:
        print(f"  {self.GREY}{self.RULE}{self.RESET}")

    def clear(self) -> None:
        # clear screen + scrollback, home the cursor (vt processing is enabled)
        print("\x1b[2J\x1b[3J\x1b[H", end="")

    def banner(self) -> None:
        self.clear()
        print()
        print(f"  {self.ORANGE}spoofer{self.RESET} {self.GREY}·{self.RESET} {self.WHITE}discord badges{self.RESET}")
        print(f"    {self.GREY}by revere group{self.RESET}")
        print()


@dataclass
class State:
    """persisted auth: token, cookie, fingerprint, and the cached analytics token."""

    token: str = ""
    cookie: str = ""
    fingerprint: str = ""
    analytics_token: str = ""
    fetched_at: int = 0
    used_games: list[str] = None  # game ids already claimed, rotate to avoid repeats
    total_games_claimed: int = 0  # cumulative games claimed in this session
    total_hours_claimed: float = 0.0  # cumulative hours claimed in this session
    subscribed: bool = False  # passed the youtube step once
    joined_discord: bool = False  # passed the discord step once

    def __post_init__(self) -> None:
        if self.used_games is None:
            self.used_games = []

    @classmethod
    def load(cls) -> "State":
        if STATE_FILE.exists():
            data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            state = cls(**{k: data.get(k, v) for k, v in cls().__dict__.items() if k != "used_games"})
            state.used_games = data.get("used_games", [])
            return state
        return cls()

    def save(self) -> None:
        STATE_FILE.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")

    @property
    def is_stale(self) -> bool:
        return not self.analytics_token or (time.time() - self.fetched_at) > AUTH_MAX_AGE

    @property
    def has_cookie(self) -> bool:
        return bool(self.cookie.strip())

    @property
    def has_token(self) -> bool:
        return bool(self.token.strip())


def _local_props() -> dict:
    # fallback client properties if cordapi is unreachable (build number may go stale)
    return {
        "os": "Windows",
        "browser": "Discord Client",
        "release_channel": "stable",
        "client_version": CLIENT_VERSION,
        "os_version": OS_VERSION,
        "os_arch": "x64",
        "app_arch": "x64",
        "system_locale": "en-GB",
        "has_client_mods": False,
        "browser_user_agent": USER_AGENT,
        "browser_version": "42.7.1",
        "os_sdk_version": "26200",
        "client_build_number": CLIENT_BUILD_NUMBER,
        "native_build_number": NATIVE_BUILD_NUMBER,
        "client_event_source": None,
        "client_app_state": "focused",
    }


def build_super_props(launch_signature: str, heartbeat_session: str) -> str:
    # cordapi returns up-to-date client properties (keeps the build number current);
    # inject our own session ids so it stays consistent with the events we send.
    try:
        req = urllib.request.Request(PROPERTIES_URL, method="POST", data=b"{}",
                                     headers={"content-type": "application/json", "user-agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=10) as response:
            props = json.loads(response.read().decode("utf-8"))["properties"]
    except Exception:
        props = _local_props()
    props["client_launch_id"] = str(uuid.uuid4())
    props["launch_signature"] = launch_signature
    props["client_heartbeat_session_id"] = heartbeat_session
    raw = json.dumps(props, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def _read_analytics_token(auth_token: str, super_props: str) -> str:
    # the token that /science actually validates; a plain rest call returns it
    req = urllib.request.Request(ME_URL, headers={
        "authorization": auth_token,
        "user-agent": USER_AGENT,
        "x-super-properties": super_props,
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"token rejected ({exc.code})") from exc
    token = data.get("analytics_token")
    if not token:
        raise RuntimeError("no analytics_token in response")
    return token


def ensure_token(state: State, super_props: str) -> None:
    """fetch + cache the analytics token if missing or stale."""
    if not state.is_stale:
        return
    state.analytics_token = _read_analytics_token(state.token, super_props)
    state.fetched_at = int(time.time())
    state.save()


@dataclass(frozen=True)
class Session:
    """per-run client identity: fresh uuids + super_props, made each launch, never saved."""

    heartbeat_session: str
    launch_signature: str
    super_props: str

    @classmethod
    def new(cls) -> "Session":
        hb = str(uuid.uuid4())
        sig = str(uuid.uuid4())
        return cls(hb, sig, build_super_props(sig, hb))


@dataclass(frozen=True)
class Game:
    id: str
    name: str
    exe: str


def _win_exe(game: dict) -> str:
    for entry in game.get("executables", []):
        if entry.get("os") == "win32" and entry.get("name"):
            return entry["name"]
    return "game.exe"


def _download_games() -> str:
    request = urllib.request.Request(GAMES_CDN_URL, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read().decode("utf-8")
    try:
        GAMES_FILE.parent.mkdir(parents=True, exist_ok=True)
        GAMES_FILE.write_text(raw, encoding="utf-8")
    except OSError:
        pass  # cache is best-effort; a read-only dir shouldn't stop us using the data
    return raw


def _parse_games(raw: str) -> list[Game]:
    data = json.loads(raw)
    games: list[Game] = []
    seen: set[str] = set()
    for entry in data:
        gid = str(entry.get("id", ""))
        if not gid.isdigit() or gid in seen:
            continue
        if not any(e.get("os") == "win32" and e.get("name") for e in entry.get("executables", [])):
            continue
        seen.add(gid)
        games.append(Game(gid, entry.get("name", "Unknown"), _win_exe(entry)))
    return games


def load_games() -> list[Game]:
    # prefer the cached file, but re-download if it's missing, empty, or corrupt
    raw = ""
    if GAMES_FILE.exists():
        raw = GAMES_FILE.read_text(encoding="utf-8").strip()
    if raw:
        try:
            games = _parse_games(raw)
            if games:
                return games
        except (json.JSONDecodeError, ValueError):
            pass  # corrupt cache, fall through to a fresh download
    try:
        return _parse_games(_download_games())
    except Exception:
        return []


class ScienceClient:
    """builds and posts launch_game and running_game_heartbeat events."""

    def __init__(self, state: State, session: Session) -> None:
        self.state = state
        self.session = session
        self._seq = 0

    def _next_seq(self) -> int:
        # real clients use a running counter across the whole session
        self._seq += 1
        return self._seq

    def build_launch(self, game: Game) -> dict:
        now = int(time.time() * 1000)
        props = {
            "client_track_timestamp": now,
            "client_heartbeat_session_id": self.session.heartbeat_session,
            "event_sequence_number": self._next_seq(),
            "game": game.name,
            "game_id": game.id,
            "verified": True,
            "elevated": False,
            "is_launcher": False,
            "game_platform": "desktop",
            "detection_method": "verified_game",
            "is_overlay_enabled": False,
            "is_overlay_game_enabled": True,
            "is_overlay_game_source": "OOP_DEFAULT_DATABASE",
            "fullscreen_type": "UNKNOWN",
            "hardware_display_count": 1,
            "overlay_method": "Disabled",
            "activity_status_enabled": True,
            "activity_status_shared_guilds": [],
            "current_user_status": "online",
            "game_detection_enabled": True,
            "executable_path": game.exe,
            # voice/guild/perf left null - real for "not in voice" and we don't fake identifying data
            "voice_channel_id": None,
            "voice_channel_type": None,
            "voice_channel_bitrate": None,
            "voice_channel_guild_id": None,
            "hidden_by_distributor": False,
            "game_metadata": None,
            # real captured fingerprint from science_state.json; user-scoped, can't be faked
            "executable_fingerprint": self.state.fingerprint,
            "client_performance_cpu": None,
            "client_performance_memory": None,
            "cpu_core_count": None,
            "accessibility_features": 0,
            "rendered_locale": "en-GB",
            "launch_signature": self.session.launch_signature,
            "client_rtc_state": None,
            "client_app_state": "focused",
            "client_send_timestamp": now,
        }
        if not self.state.fingerprint:
            del props["executable_fingerprint"]
        return {"type": "launch_game", "properties": props}

    def build_heartbeat(self, game: Game, duration_ms: int, session_id: str,
                        initial: bool, final: bool, ts: int | None = None) -> dict:
        ts = int(time.time() * 1000) if ts is None else ts
        return {
            "type": "running_game_heartbeat",
            "properties": {
                "client_track_timestamp": ts,
                "client_heartbeat_session_id": self.session.heartbeat_session,
                "event_sequence_number": self._next_seq(),
                "game_id": game.id,
                "game_name": game.name,
                "game_metadata": None,
                "game_executable": game.exe,
                "game_detection_enabled": True,
                "initial_heartbeat": initial,
                "final_heartbeat": final,
                "game_session_id": session_id,
                "duration_tracked_ms": duration_ms,
                "rtc_connection_id": None,
                "media_session_id": None,
                "launch_signature": self.session.launch_signature,
                "client_app_state": "focused",
                "client_send_timestamp": ts,
            },
        }

    def build_session(self, game: Game, duration_ms: int) -> list[dict]:
        # real client flow: open heartbeat (0ms) -> launch_game -> close heartbeat (full duration).
        # both heartbeats share one game_session_id; timestamps span the duration when it's sane.
        sid = str(uuid.uuid4())
        now = int(time.time() * 1000)
        start = now - duration_ms
        if start < 0: # duration too large to backdate sensibly
            start = now
        return [
            self.build_heartbeat(game, 0, sid, initial=True, final=False, ts=start),
            self.build_launch(game),
            self.build_heartbeat(game, duration_ms, sid, initial=False, final=True, ts=now),
        ]

    def post(self, events: Sequence[dict]) -> int:
        """post a batch. returns the http status (204 = accepted)."""
        payload = {"token": self.state.analytics_token, "events": list(events)}
        body = json.dumps(payload).encode("utf-8")
        headers = {
            "accept": "*/*",
            "accept-language": "en-GB",
            "authorization": self.state.token,
            "content-type": "application/json",
            "cookie": self.state.cookie,
            "origin": "https://discord.com",
            "referer": "https://discord.com/channels/@me",
            "user-agent": USER_AGENT,
            "x-debug-options": "bugReporterEnabled",
            "x-discord-locale": "en-GB",
            "x-discord-timezone": "Europe/Oslo",
            "x-super-properties": self.session.super_props,
        }
        if DEBUG:
            print("\n" + "=" * 72)
            print(f"POST {SCIENCE_URL} ({len(payload['events'])} events)")
            print("headers:", json.dumps(headers, indent=2))
            print("body:", json.dumps(payload, indent=2))
            print("=" * 72)
        request = urllib.request.Request(SCIENCE_URL, data=body, method="POST", headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                return response.status
        except urllib.error.HTTPError as exc:
            return exc.code
        except Exception:
            return 0


def _chunked(items: Sequence[Game], size: int) -> Iterator[Sequence[Game]]:
    for start in range(0, len(items), size):
        yield items[start:start + size]


class Spoofer:
    """sends events in batches and logs progress."""

    def __init__(self, client: ScienceClient, console: Console) -> None:
        self.client = client
        self.console = console

    def run(self, games: Sequence[Game], build_events) -> int:
        # build_events(game) -> list of event dicts to send for that game
        total = len(games)
        sent_ok = 0
        for request_no, chunk in enumerate(_chunked(games, BATCH_SIZE), start=1):
            events = []
            for game in chunk:
                events.extend(build_events(game))
            status = self.client.post(events)
            if status == 204:
                sent_ok += len(chunk)
                self.console.sent(f"batch {request_no}", f"{sent_ok}/{total} games")
            elif status in (401, 403):
                self.console.err(f"batch {request_no}",
                                 f"[{status}] auth rejected · refresh (option 3) with a fresh cookie")
                return sent_ok
            else:
                self.console.warn(f"batch {request_no}", f"[{status}]")
            time.sleep(BATCH_DELAY)
        return sent_ok


class App:
    def __init__(self) -> None:
        self.console = Console()
        self.state = State.load()
        self.session: Session | None = None
        self.client: ScienceClient | None = None
        self.games: list[Game] = []

    # startup

    def _flush_stdin(self) -> None:
        # drop keys pressed during the countdown so an early enter doesn't skip the gate
        try:
            if sys.platform == "win32":
                import msvcrt
                while msvcrt.kbhit():
                    msvcrt.getwch()
            else:
                import termios
                termios.tcflush(sys.stdin, termios.TCIFLUSH)
        except Exception:
            pass

    def _gate_step(self, step: int, total: int, action: str, label: str, url: str, done: str) -> None:
        C = self.console
        C.rule()
        f(f"{C.ORANGE}step {step} of {total}{C.WHITE} · {action} {C.ORANGE}{label}{C.WHITE} to continue")
        C.rule()
        C.info("opening it in your browser...")
        webbrowser.open(url)
        for left in range(GATE_WAIT, 0, -1):
            print(f"\r  {C.GREY}continue available in {left}s...{C.RESET}  ", end="", flush=True)
            time.sleep(1)
        print("\r" + " " * 40 + "\r", end="")
        self._flush_stdin()
        input(f"  {C.ORANGE}›{C.RESET} press enter once you've {done} ")
        print()

    def _gate(self) -> None:
        # (state flag, action, label, url, past tense) - shown in order, each only until passed once
        steps = [
            ("subscribed", "subscribe to", "youtube.com/@solasity", SUBSCRIBE_URL, "subscribed"),
            ("joined_discord", "join", DISCORD_INVITE_LABEL, DISCORD_INVITE_URL, "joined"),
        ]
        total = len(steps)
        for i, (flag, action, label, url, done) in enumerate(steps, 1):
            if getattr(self.state, flag):
                continue
            self._gate_step(i, total, action, label, url, done)
            setattr(self.state, flag, True)
            self.state.save()
        self.console.ok("setup", f"all {total} steps done · thanks!")
        time.sleep(0.5)

    def start(self) -> None:
        self.console.banner()
        time.sleep(0.8)
        print()

        if not (self.state.subscribed and self.state.joined_discord):
            self._gate()

        # step 1: token
        C = self.console
        if not self.state.has_token:
            self._prompt_token()
        else:
            C.ok("auth", "token loaded")
            time.sleep(0.5)
        if not self.state.has_token:
            C.err("token", "required to run")
            return

        # step 2: cookie
        if not self.state.has_cookie:
            self.console.banner()
            self._prompt_cookie()
        else:
            C.ok("auth", "cookie loaded")
            time.sleep(0.5)
        if not self.state.has_cookie:
            C.err("cookie", "required to run")
            return

        # step 3: games
        self.console.banner()
        print()
        C.info("loading games...")
        time.sleep(0.4)
        self.games = load_games()
        if not self.games:
            C.err("games", "couldn't load the game list")
            C.info(f"tried {GAMES_FILE} and {GAMES_CDN_URL}")
            C.info("check your connection, or drop a valid games.json at the path above")
            return
        C.ok("games", f"{C.ORANGE}{len(self.games)}{C.WHITE} loaded")
        time.sleep(0.5)

        # step 4: fingerprint warning
        if not self.state.fingerprint:
            print()
            C.warn("fingerprint", "not set · script may not credit the badges")
            time.sleep(0.5)

        # step 5: auth
        print()
        C.info("validating auth...")
        self._new_session()  # fresh client identity for this run
        try:
            ensure_token(self.state, self.session.super_props)
        except Exception as exc:
            C.err("token", str(exc))
            return
        C.ok("auth", "ready")
        time.sleep(0.5)

        print()
        self.menu()

    def _new_session(self) -> None:
        self.session = Session.new()
        self.client = ScienceClient(self.state, self.session)

    # auth

    def _prompt_token(self) -> None:
        self.console.info("paste your discord account token")
        entered = input(f"  {self.console.GREY}token:{self.console.RESET} ").strip()
        if entered:
            self.state.token = entered
            self.state.save()
            self.console.ok("token", "saved")
            time.sleep(1.5)

    def _prompt_cookie(self) -> None:
        self.console.info("paste your cf_clearance cookie header")
        entered = input(f"  {self.console.GREY}cookie:{self.console.RESET} ").strip()
        if entered:
            self.state.cookie = entered
            self.state.save()
            self.console.ok("cookie", "saved")
            time.sleep(1.5)

    def _refresh(self) -> None:
        self.console.info("update cookie? [y/n]")
        choice = input(f"  {self.console.GREY}›{self.console.RESET} ").strip().lower()
        if choice in ("y", "yes"):
            self.console.info("paste a fresh cookie header")
            entered = input(f"  {self.console.GREY}cookie:{self.console.RESET} ").strip()
            if entered:
                self.state.cookie = entered
                self.console.ok("cookie", "updated")
            else:
                self.console.info("cookie unchanged")

        self.console.info("refreshing analytics token...")
        try:
            self.state.fetched_at = 0          # force a refetch
            ensure_token(self.state, self.session.super_props)
        except Exception as exc:
            self.console.err("auth", str(exc))
            return
        self._new_session()
        self.state.save()
        self.console.ok("auth", "refreshed")
        time.sleep(1.5)

    def _require_ready(self) -> bool:
        if not self.state.has_cookie:
            self.console.err("cookie", "not set · use option 3 to add one")
            return False
        if self.state.is_stale:
            try:
                ensure_token(self.state, self.session.super_props)
            except Exception as exc:
                self.console.err("auth", str(exc))
                return False
            self._new_session()
        return bool(self.state.analytics_token)
    def claim_games(self) -> None:
        """claim playtime on selected games. prompts for count and hours."""
        if not self._require_ready():
            return
            
        C = self.console
        print()
        C.info(f"loaded {C.GREEN}{len(self.games)}{C.WHITE} games available")

        # prompt for game count
        raw_count = input(f"  {C.GREY}how many games? [all]:{C.RESET} ").strip()
        try:
            count = int(raw_count) if raw_count else len(self.games)
        except ValueError:
            C.err("input", "invalid count")
            return
        count = min(count, len(self.games))

        # prompt for hours
        raw_hours = input(f"  {C.GREY}hours per game? [1]:{C.RESET} ").strip()
        try:
            hours = float(raw_hours) if raw_hours else 1.0
        except ValueError:
            C.err("input", "invalid hours")
            return

        calc_hours = int(count * hours)
        print(f"\n[!] You are about to send {C.ORANGE}{count}{C.RESET} games at {C.ORANGE}{hours}{C.RESET} hours each.")
        print(f"[!] Total hours: {C.ORANGE}{calc_hours:,}{C.RESET}")

        if calc_hours > 100000:
            print("[!] WARNING: This is a massive amount might take days to recieve.")

        confirm = input(f"{C.GREY}Do you want to proceed? (y/n): {C.RESET}").strip().lower()
        if confirm != 'y':
            print("Cancelled.")
            return

        # select games: prefer unused, rotate through used if necessary
        selected = self._select_games(count)
        if not selected:
            C.err("games", "none selected")
            return

        duration_ms = int(hours * 3600 * 1000)
        total_hours = len(selected) * hours
        print()
        C.info(
            f"claiming {C.ORANGE}{hours:g}h{C.WHITE} on "
            f"{C.ORANGE}{len(selected)}{C.WHITE} games "
            f"{C.GREY}·{C.WHITE} {total_hours:,.0f}h total"
        )
        C.rule()
        ok = Spoofer(self.client, self.console).run(
            selected,
            lambda g: self.client.build_session(g, duration_ms),
        )
        
        print()
        C.ok("complete", f"{ok}/{len(selected)} games · {ok * hours:,.0f}h claimed")
        
        # accumulate stats
        self.state.total_games_claimed += ok
        self.state.total_hours_claimed += ok * hours
        
        # --- HISTORY LOGGER ---
        import json
        import os
        
        history_file = "run_history.json"
        history = []
        if os.path.exists(history_file):
            try:
                with open(history_file, "r") as f:
                    history = json.load(f)
            except:
                pass
                
        username = self.get_current_user()
        history.append({
            "date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "account": username,
            "games": ok,
            "hours": hours,
            "total": ok * hours
        })
        
        with open(history_file, "w") as f:
            json.dump(history, f, indent=2)
        # ----------------------

        self.state.save()

        C.rule()
        input(f" {C.ORANGE}>{C.RESET} press enter to continue")
        C.rule()


    def _select_games(self, count: int) -> list[Game]:
        """select N games, preferring unused ones and rotating through used to avoid repeats."""
        available_ids = {g.id for g in self.games}
        unused_ids = [g.id for g in self.games if g.id not in self.state.used_games]
        used_ids = [gid for gid in self.state.used_games if gid in available_ids]


        if len(unused_ids) >= count:
            selected_ids = unused_ids[:count]
        else:
          
            selected_ids = unused_ids
            if used_ids:
                remaining = count - len(selected_ids)
                rotated = used_ids[remaining:] + used_ids[:remaining]
                selected_ids.extend(rotated[:remaining])

       
        self.state.used_games = [gid for gid in self.state.used_games if gid not in selected_ids] + selected_ids

      
        id_map = {g.id: g for g in self.games}
        return [id_map[gid] for gid in selected_ids if gid in id_map]

    # menu

        def set_fingerprint(self) -> None:
            C = self.console
            uid = _user_id_from_token(self.state.token)
            if not uid:
                C.err("fingerprint", "no valid token · set one first")
                time.sleep(1.5)
                return
            if os.name != "nt":
                C.err("fingerprint", "windows-only feature")
                time.sleep(1.5)
                return
            C.info("generate an executable_fingerprint tied to this account + machine")
            C.info(f"account: {C.ORANGE}{uid}{C.RESET}")
            C.info("point it at a game's .exe (or a running game's pid)")
            entered = input(f"  {C.GREY}exe path or pid:{C.RESET} ").strip().strip('"')
            if not entered:
                C.info("cancelled")
                time.sleep(1)
                return
            pid = int(entered) if entered.isdigit() else 0
            path = "" if pid else entered
            if path and not Path(path).exists():
                C.err("fingerprint", f"file not found: {path}")
                time.sleep(1.5)
                return
            C.info("generating...")
            try:
                fp = generate_fingerprint(uid, path=path, pid=pid)
            except Exception as exc:
                C.err("fingerprint", str(exc))
                time.sleep(2)
                return
            self.state.fingerprint = fp
            self.state.save()
            C.ok("fingerprint", f"set ({len(fp)} chars) · saved to {STATE_FILE.name}")
            time.sleep(1.5)
    def switch_profile(self) -> None:
        import os
        C = self.console
        print()
        C.info("profile manager")
        
        current_file = "science_state.json"
        
        # Save current profile
        save_name = input(f"  {C.GREY}Save current profile as (leave blank to skip):{C.RESET} ").strip()
        if save_name:
            if os.path.exists(current_file):
                backup_file = f"science_state_{save_name}.json"
                os.replace(current_file, backup_file)
                C.ok("profile", f"saved current account to {backup_file}")
            else:
                C.err("profile", "no active account found to save")
                
        # Load a profile
        load_name = input(f"  {C.GREY}Load profile name (leave blank for none):{C.RESET} ").strip()
        if load_name:
            load_file = f"science_state_{load_name}.json"
            if os.path.exists(load_file):
                os.replace(load_file, current_file)
                C.ok("profile", f"loaded profile '{load_name}'")
                print(f"  {C.GREEN}[+] Restarting script to apply changes...{C.RESET}")
                time.sleep(1.5)
                import sys
                os.execv(sys.executable, ['python'] + sys.argv)
            else:
                C.err("profile", f"profile '{load_name}' not found")
                
        time.sleep(2)
        
    def get_current_user(self) -> str:
        try:
            import urllib.request
            import json
            
            token = str(self.state.token).strip()
            cookie = str(self.state.cookie).strip()
            
            req = urllib.request.Request("https://discord.com/api/v9/users/@me")
            req.add_header("Authorization", token)
            req.add_header("Cookie", cookie)
            req.add_header("User-Agent", "Mozilla/5.0")
            
            with urllib.request.urlopen(req) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode())
                    return data.get("username", "Unknown")
                return f"Invalid Token ({response.status})"
        except Exception as e:
            return "Offline"
    def view_history(self) -> None:
        import json
        import os
        C = self.console
        C.clear()
        C.banner()
        print()
        C.info("run history")
        print()
        
        if not os.path.exists("run_history.json"):
            C.warn("history", "no runs recorded yet")
            input(f"  {C.GREY}press enter to continue...{C.RESET}")
            return
            
        try:
            with open("run_history.json", "r") as f:
                history = json.load(f)
        except:
            C.err("history", "failed to read history file")
            input(f"  {C.GREY}press enter to continue...{C.RESET}")
            return
            
        if not history:
            C.warn("history", "no runs recorded yet")
        else:
            for run in reversed(history[-10:]):
                date = run.get("date", "Unknown")
                acc = run.get("account", "Unknown")
                games = run.get("games", 0)
                hrs = run.get("hours", 0)
                total = run.get("total", 0)
                
                print(f"  {C.GREY}{date}{C.RESET} | {C.GREEN}{acc}{C.RESET} | {C.ORANGE}{games}{C.RESET} games @ {C.ORANGE}{hrs}{C.RESET}h = {C.ORANGE}{total}{C.RESET}h")
                
        print()
        input(f"  {C.GREY}press enter to continue...{C.RESET}")
    def menu(self) -> None:
        C = self.console
        while True:
            C.clear()
            C.banner()
            print()
            
         
            username = self.get_current_user()
            C.info(f"logged in as {C.GREEN}{username}{C.RESET}")
            
           
            C.info(f"loaded {C.ORANGE}{len(self.games)}{C.WHITE} games")
                        
            import json
            import os
            last_run = "Never"
            if os.path.exists("run_history.json"):
                try:
                    with open("run_history.json", "r") as f:
                        hist = json.load(f)
                        if hist:
                            last_run = hist[-1].get("date", "Unknown")
                except:
                    pass
            
            C.info(f"last run {C.ORANGE}{last_run}{C.RESET}")
            # ---------------------
            C.rule()
            C.info(f"{C.ORANGE}1{C.RESET} · claim games")
            C.info(f"{C.ORANGE}2{C.RESET} · refresh auth")
            C.info(f"{C.ORANGE}3{C.RESET} · set fingerprint")
            C.info(f"{C.ORANGE}4{C.RESET} · switch profile")
            C.info(f"{C.ORANGE}5{C.RESET} · view history")
            C.info(f"{C.ORANGE}6{C.RESET} · exit")
            
            C.rule()
            choice = input(f"  {C.ORANGE}>{C.RESET} ").strip()
            print()
            if choice == "1":
                self.claim_games()
            elif choice == "2":
                self.refresh_auth()
            elif choice == "3":
                self.set_fingerprint()
            elif choice == "4":
                self.switch_profile()
            elif choice == "5":
                self.view_history()
            elif choice == "6":
                break
            else:
                C.warn("input", "invalid option")


def main() -> None:
    try:
        App().start()
    except KeyboardInterrupt:
        print()
        Console().warn("exit", "interrupted")


if __name__ == "__main__":
    main()
