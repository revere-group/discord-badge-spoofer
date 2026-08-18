#!/usr/bin/env python3
"""
discord science spoofer - inflate the playtime and games-played badges.

revere group, 2026. mit licensed (see LICENSE).

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
import random
import sys
import time
import uuid
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterator, Sequence, Callable

# paths
ROOT = Path(__file__).resolve().parent
GAMES_FILE = ROOT.parent / "data" / "games.json"     # full game list, downloaded if absent
STATE_FILE = ROOT / "science_state.json"             # token, cookie, cached auth

ME_URL = "https://discord.com/api/v9/users/@me?with_analytics_token=true"
SCIENCE_URL = "https://discord.com/api/v9/science"
PROPERTIES_URL = "https://cordapi.dolfi.es/api/v2/properties/windows"  # current super_props, local fallback
GAMES_CDN_URL = "https://cdn.discordapp.com/detectables/games.json"  # used if games.json isn't there

# Rate‑limiting parameters – randomized to avoid detection
BATCH_SIZE_MIN = 30               # minimum events per batch
BATCH_SIZE_MAX = 50               # maximum events per batch
BATCH_DELAY_MIN = 0.5             # seconds between batches (lower bound)
BATCH_DELAY_MAX = 2.0             # seconds between batches (upper bound)
PAUSE_EVERY_N_BATCHES = 10        # after this many batches, take a longer break
PAUSE_DURATION_MIN = 5.0          # minimum break duration (seconds)
PAUSE_DURATION_MAX = 15.0         # maximum break duration (seconds)
AUTH_MAX_AGE = 12 * 3600          # refetch the analytics token once the cache is older than this
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
        # Don't try to reconfigure stdout if it's already configured
        try:
            if hasattr(sys.stdout, 'reconfigure'):
                sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
        
        # Enable ANSI on Windows
        if sys.platform == "win32":
            self._enable_ansi()
        
        # Check if we're in a terminal that supports colors
        self._has_colors = hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
        if not self._has_colors:
            # Disable colors if not in a terminal
            self.RED = self.ORANGE = self.GREEN = self.YELLOW = self.WHITE = self.GREY = self.RESET = ""

    @staticmethod
    def _enable_ansi() -> None:
        # flip on virtual terminal processing so ansi colors render on windows
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)  # std_output_handle
            mode = ctypes.c_uint32()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)
        except Exception:
            pass

    def _stamp(self) -> str:
        return f"{self.GREY}{time.strftime('%H:%M:%S')}{self.RESET}"

    def _line(self, glyph: str, target: str, detail: str, color: str) -> None:
        print(f"  {self._stamp()} {glyph} {self.WHITE}{target}{self.RESET} "
              f"{self.GREY}·{self.RESET} {color}{detail}{self.RESET}", flush=True)

    def ok(self, target: str, detail: str) -> None:
        self._line(f"{self.GREEN}✓{self.RESET}", target, detail, self.GREEN)

    def sent(self, target: str, detail: str) -> None:
        self._line(f"{self.GREY}·{self.RESET} {self.GREEN}sent{self.RESET}", target, detail, self.GREEN)

    def warn(self, target: str, detail: str) -> None:
        self._line(f"{self.YELLOW}!{self.RESET}", target, detail, self.YELLOW)

    def err(self, target: str, detail: str) -> None:
        self._line(f"{self.RED}✗{self.RESET}", target, detail, self.RED)

    def info(self, detail: str) -> None:
        print(f"  {self._stamp()} {self.GREY}·{self.RESET} {self.WHITE}{detail}{self.RESET}", flush=True)

    def game_detail(self, game: str, detail: str) -> None:
        print(f"  {self._stamp()} {self.GREY}·{self.RESET} {self.WHITE}{game}{self.RESET} "
              f"{self.GREY}·{self.RESET} {self.GREEN}{detail}{self.RESET}", flush=True)

    def rule(self) -> None:
        print(f"  {self.GREY}{self.RULE}{self.RESET}", flush=True)

    def clear(self) -> None:
        # Only clear if we're in a terminal
        if self._has_colors:
            print("\x1b[2J\x1b[3J\x1b[H", end="", flush=True)

    def banner(self) -> None:
        self.clear()
        print()
        print(f"  {self.ORANGE}spoofer{self.RESET} {self.GREY}·{self.RESET} {self.WHITE}discord badges{self.RESET}")
        print(f"    {self.GREY}by revere group{self.RESET}")
        print(flush=True)


@dataclass
class State:
    """persisted auth: token, cookie, fingerprint, and the cached analytics token."""

    token: str = ""
    cookie: str = ""
    fingerprint: str = ""
    analytics_token: str = ""
    fetched_at: int = 0

    @classmethod
    def load(cls) -> "State":
        if STATE_FILE.exists():
            try:
                data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
                return cls(**{k: data.get(k, v) for k, v in cls().__dict__.items()})
            except Exception:
                return cls()
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


def _read_analytics_token(auth_token: str) -> str:
    # the token that /science actually validates; a plain rest call returns it
    req = urllib.request.Request(ME_URL, headers={"authorization": auth_token, "user-agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"token rejected ({exc.code})") from exc
    token = data.get("analytics_token")
    if not token:
        raise RuntimeError("no analytics_token in response")
    return token


def ensure_token(state: State) -> None:
    """fetch + cache the analytics token if missing or stale."""
    if not state.is_stale:
        return
    state.analytics_token = _read_analytics_token(state.token)
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
    GAMES_FILE.parent.mkdir(parents=True, exist_ok=True)
    GAMES_FILE.write_text(raw, encoding="utf-8")
    return raw


def load_games() -> list[Game]:
    if GAMES_FILE.exists():
        raw = GAMES_FILE.read_text(encoding="utf-8")
    else:
        try:
            raw = _download_games()
        except Exception:
            return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    
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


def _chunked_random(items: Sequence[Game], min_size: int, max_size: int) -> Iterator[Sequence[Game]]:
    """Yield chunks of random sizes between min_size and max_size (inclusive)."""
    i = 0
    n = len(items)
    while i < n:
        size = random.randint(min_size, max_size)
        if i + size > n:
            size = n - i
        yield items[i:i+size]
        i += size


class Spoofer:
    """sends events in batches with randomised rate limiting and logs progress."""

    def __init__(self, client: ScienceClient, console: Console) -> None:
        self.client = client
        self.console = console
        self.batch_counter = 0

    def run(self, games_with_hours: Sequence[tuple[Game, int]], progress_callback: Callable[[Game, int], None] | None = None) -> int:
        """
        Send events for games with their assigned hours.
        
        Args:
            games_with_hours: List of (game, hours) tuples
            progress_callback: Optional callback called before each game is processed
            
        Returns:
            Number of games successfully processed
        """
        total = len(games_with_hours)
        sent_ok = 0
        self.batch_counter = 0
        
        # Flatten into chunks with events
        for chunk in self._chunk_games_with_hours(games_with_hours):
            self.batch_counter += 1
            events = []
            games_in_chunk = []
            
            for game, hours in chunk:
                if progress_callback:
                    progress_callback(game, hours)
                duration_ms = int(hours * 3600 * 1000)
                events.extend(self.client.build_session(game, duration_ms))
                games_in_chunk.append(game)
            
            status = self.client.post(events)
            if status == 204:
                sent_ok += len(games_in_chunk)
                self.console.sent(f"batch {self.batch_counter}", f"{sent_ok}/{total} games")
            elif status in (401, 403):
                self.console.err(f"batch {self.batch_counter}",
                                 f"[{status}] auth rejected · refresh (option 3) with a fresh cookie")
                return sent_ok
            else:
                self.console.warn(f"batch {self.batch_counter}", f"[{status}]")
            
            # Random jittered delay between batches
            delay = random.uniform(BATCH_DELAY_MIN, BATCH_DELAY_MAX)
            time.sleep(delay)
            
            # Occasionally take a longer break to mimic human behaviour
            if self.batch_counter % PAUSE_EVERY_N_BATCHES == 0:
                pause = random.uniform(PAUSE_DURATION_MIN, PAUSE_DURATION_MAX)
                self.console.info(f"pausing for {pause:.1f}s to avoid rate limits")
                time.sleep(pause)
        
        return sent_ok
    
    def _chunk_games_with_hours(self, games_with_hours: Sequence[tuple[Game, int]]) -> Iterator[Sequence[tuple[Game, int]]]:
        """Yield chunks of random sizes."""
        i = 0
        n = len(games_with_hours)
        while i < n:
            size = random.randint(BATCH_SIZE_MIN, BATCH_SIZE_MAX)
            if i + size > n:
                size = n - i
            yield games_with_hours[i:i+size]
            i += size


class App:
    def __init__(self) -> None:
        self.console = Console()
        self.state = State.load()
        self.session: Session | None = None
        self.client: ScienceClient | None = None
        self.games: list[Game] = []

    # startup

    def start(self) -> None:
        self.console.banner()

        if not self.state.has_token:
            self._prompt_token()
        if not self.state.has_token:
            self.console.err("token", "required to run")
            return

        self.games = load_games()
        if not self.games:
            self.console.err("games", f"not found or empty: {GAMES_FILE}")
            return
        self.console.info(f"loaded {self.console.GREEN}{len(self.games)}{self.console.WHITE} games")

        if not self.state.fingerprint:
            self.console.warn("fingerprint", "not set · games-played count won't credit (hours still work)")

        try:
            ensure_token(self.state)          # fetch analytics token if stale
        except Exception as exc:
            self.console.err("token", str(exc))
            return
        self._new_session()                    # fresh client identity for this run

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

    def _refresh(self, prompt_cookie: bool) -> None:
        if prompt_cookie:
            self.console.info("paste a fresh cookie header (enter to keep the current one)")
            entered = input(f"  {self.console.GREY}cookie:{self.console.RESET} ").strip()
            if entered:
                self.state.cookie = entered
                self.console.ok("cookie", "updated")
            else:
                self.console.info("cookie unchanged")

        self.console.info("fetching analytics token...")
        try:
            self.state.fetched_at = 0          # force a refetch
            ensure_token(self.state)
        except Exception as exc:
            self.console.err("auth", str(exc))
            return
        self._new_session()
        self.console.ok("auth", "refreshed")

    def _require_ready(self) -> bool:
        if not self.state.has_cookie:
            self.console.err("cookie", "not set · use option 3 to add one")
            return False
        if self.state.is_stale:
            try:
                ensure_token(self.state)
            except Exception as exc:
                self.console.err("auth", str(exc))
                return False
            self._new_session()
        return bool(self.state.analytics_token)

    # Helper functions for selecting games and hours

    def _select_games(self) -> list[Game]:
        """Prompt user for how many games to select and return random selection."""
        max_games = len(self.games)
        self.console.info(f"available: {self.console.GREEN}{max_games}{self.console.WHITE} games")
        
        while True:
            raw = input(f"  {self.console.GREY}how many games to process? (1-{max_games}):{self.console.RESET} ").strip()
            try:
                count = int(raw)
                if 1 <= count <= max_games:
                    break
                self.console.err("input", f"must be between 1 and {max_games}")
            except ValueError:
                self.console.err("input", "enter a number")
        
        selected = random.sample(self.games, count)
        return selected

    def _get_hours_for_games(self, games: list[Game]) -> list[tuple[Game, float]]:
        """Get hours for each game, offering multiple input modes."""
        self.console.rule()
        self.console.info("hour assignment options:")
        print(f"  {self.console.ORANGE}1{self.console.RESET} {self.console.WHITE}random range{self.console.RESET} "
              f"{self.console.GREY}· each game gets random hours in a range{self.console.RESET}")
        print(f"  {self.console.ORANGE}2{self.console.RESET} {self.console.WHITE}single value{self.console.RESET} "
              f"{self.console.GREY}· all games get the same hours{self.console.RESET}")
        print(f"  {self.console.ORANGE}3{self.console.RESET} {self.console.WHITE}per-game input{self.console.RESET} "
              f"{self.console.GREY}· manually enter hours for each game{self.console.RESET}")
        
        choice = ""
        while choice not in ("1", "2", "3"):
            choice = input(f"  {self.console.ORANGE}›{self.console.RESET} ").strip()
        
        result = []
        
        if choice == "1":
            # Random range
            self.console.info("enter min and max hours (e.g., 0.5 5.0)")
            while True:
                raw = input(f"  {self.console.GREY}min max:{self.console.RESET} ").strip()
                parts = raw.split()
                if len(parts) == 2:
                    try:
                        min_h = float(parts[0])
                        max_h = float(parts[1])
                        if min_h <= max_h and min_h >= 0:
                            break
                        self.console.err("input", "min must be <= max and both >= 0")
                    except ValueError:
                        self.console.err("input", "enter two numbers")
                else:
                    self.console.err("input", "enter min and max separated by space")
            
            for game in games:
                hours = random.uniform(min_h, max_h)
                hours = round(hours, 2)  # Round to 2 decimal places
                result.append((game, hours))
            
        elif choice == "2":
            # Single value
            while True:
                raw = input(f"  {self.console.GREY}hours per game:{self.console.RESET} ").strip()
                try:
                    hours = float(raw)
                    if hours >= 0:
                        break
                    self.console.err("input", "hours must be >= 0")
                except ValueError:
                    self.console.err("input", "enter a number")
            
            for game in games:
                result.append((game, hours))
            
        else:  # choice == "3"
            # Per-game input
            self.console.info(f"enter hours for each of the {len(games)} games:")
            for i, game in enumerate(games, 1):
                while True:
                    raw = input(f"  {self.console.GREY}[{i}/{len(games)}] {game.name} (hours):{self.console.RESET} ").strip()
                    try:
                        hours = float(raw)
                        if hours >= 0:
                            result.append((game, hours))
                            break
                        self.console.err("input", "hours must be >= 0")
                    except ValueError:
                        self.console.err("input", "enter a number")
        
        return result

    def _show_summary(self, games_with_hours: list[tuple[Game, float]]) -> None:
        """Display a summary of the games and hours to be processed."""
        self.console.rule()
        total_hours = sum(hours for _, hours in games_with_hours)
        self.console.info(f"processing {self.console.ORANGE}{len(games_with_hours)}{self.console.WHITE} games")
        self.console.info(f"total hours: {self.console.ORANGE}{total_hours:.2f}h{self.console.WHITE} "
                         f"({self.console.ORANGE}{total_hours * 60:.0f}{self.console.WHITE} minutes)")
        
        # Show a few examples if there are many games
        if len(games_with_hours) <= 10:
            for game, hours in games_with_hours:
                self.console.game_detail(game.name, f"{hours:.2f}h")
        else:
            for game, hours in games_with_hours[:5]:
                self.console.game_detail(game.name, f"{hours:.2f}h")
            self.console.info(f"... and {len(games_with_hours) - 5} more games")
        
        self.console.rule()

    # modules

    def module_playtime(self) -> None:
        if not self._require_ready():
            return
        
        # Select games
        games = self._select_games()
        
        # Get hours for each game
        games_with_hours = self._get_hours_for_games(games)
        
        # Show summary
        self._show_summary(games_with_hours)
        
        # Confirm
        confirm = input(f"  {self.console.GREY}proceed? (y/n):{self.console.RESET} ").strip().lower()
        if confirm != 'y':
            self.console.info("cancelled")
            return
        
        print()
        self.console.rule()
        
        # Process with progress callback
        def progress_callback(game: Game, hours: float) -> None:
            self.console.game_detail(game.name, f"{hours:.2f}h")
        
        ok = Spoofer(self.client, self.console).run(games_with_hours, progress_callback)
        
        total_hours = sum(hours for _, hours in games_with_hours)
        avg_hours = total_hours / len(games_with_hours) if games_with_hours else 0
        print()
        self.console.ok("complete", f"{ok}/{len(games_with_hours)} games · {avg_hours:.2f}h avg")

    def module_played_count(self) -> None:
        if not self._require_ready():
            return
        
        # Select games
        games = self._select_games()
        
        # All games get 1 minute
        games_with_hours = [(game, 1.0/60.0) for game in games]  # 1 minute in hours
        
        self.console.rule()
        self.console.info(f"marking {self.console.ORANGE}{len(games)}{self.console.WHITE} games as played")
        self.console.rule()
        
        # Confirm
        confirm = input(f"  {self.console.GREY}proceed? (y/n):{self.console.RESET} ").strip().lower()
        if confirm != 'y':
            self.console.info("cancelled")
            return
        
        print()
        self.console.rule()
        
        ok = Spoofer(self.client, self.console).run(games_with_hours)
        
        print()
        self.console.ok("complete", f"{ok}/{len(games)} games marked played")

    # menu

    def menu(self) -> None:
        C = self.console
        while True:
            cookie_state = f"{C.GREEN}set{C.RESET}" if self.state.has_cookie else f"{C.RED}unset{C.RESET}"
            C.rule()
            print(f"  {C.ORANGE}1{C.RESET} {C.WHITE}claim playtime (hours){C.RESET}")
            print(f"  {C.ORANGE}2{C.RESET} {C.WHITE}games played (count){C.RESET}")
            print(f"  {C.ORANGE}3{C.RESET} {C.WHITE}refresh auth{C.RESET} {C.GREY}· cookie {cookie_state}{C.RESET}")
            print(f"  {C.ORANGE}4{C.RESET} {C.WHITE}exit{C.RESET}")
            C.rule()

            # re-prompt on empty/invalid input without reprinting the options
            choice = ""
            while choice not in ("1", "2", "3", "4"):
                choice = input(f"  {C.ORANGE}›{C.RESET} ").strip()

            if choice == "1":
                self.module_playtime()
            elif choice == "2":
                self.module_played_count()
            elif choice == "3":
                self._refresh(prompt_cookie=True)
            elif choice == "4":
                break


def main() -> None:
    try:
        App().start()
    except KeyboardInterrupt:
        print()
        Console().warn("exit", "interrupted")


if __name__ == "__main__":
    main()
