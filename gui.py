#!/usr/bin/env python3
"""
gui.py — local web server that exposes the spoofer logic over a clean REST API.

run:
    python gui.py

opens http://localhost:8710 in your browser automatically.
no extra dependencies — stdlib only.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from functools import partial
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

# ── make sure we can import spoofer.py from the same directory ──────────────
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import spoofer  # noqa: E402  — lives next to this file

HOST = "127.0.0.1"
PORT = 8710
WEB_DIR = ROOT / "web"

# ── shared state for the background claim worker ───────────────────────────
_claim_lock = threading.Lock()
_claim_thread: threading.Thread | None = None
_claim_stop = threading.Event()
_claim_progress: dict = {"sent": 0, "total": 0, "done": True, "logs": []}


def _push_log(msg: str, cls: str = "info") -> None:
    """Thread-safe helper to append a log entry that the frontend polls."""
    with _claim_lock:
        _claim_progress["logs"].append({"msg": msg, "cls": cls})


def _drain_logs() -> list[dict]:
    """Return and clear queued log entries (called from the main/http thread)."""
    with _claim_lock:
        logs = list(_claim_progress["logs"])
        _claim_progress["logs"].clear()
    return logs


# ── claim worker ────────────────────────────────────────────────────────────
def _claim_worker(
    state: spoofer.State,
    session: spoofer.Session,
    games: list[spoofer.Game],
    hours: float,
) -> None:
    """Runs in a background thread.  Posts batches, updating _claim_progress."""
    global _claim_progress
    client = spoofer.ScienceClient(state, session)
    duration_ms = int(hours * 3600 * 1000)
    total = len(games)

    with _claim_lock:
        _claim_progress = {"sent": 0, "total": total, "done": False, "logs": []}

    sent_ok = 0
    for req_no, start in enumerate(range(0, total, spoofer.BATCH_SIZE), start=1):
        if _claim_stop.is_set():
            _push_log("Operation stopped by user", "warn")
            break

        chunk = games[start : start + spoofer.BATCH_SIZE]
        events: list[dict] = []
        for game in chunk:
            events.extend(client.build_session(game, duration_ms))

        status = client.post(events)

        if status == 204:
            sent_ok += len(chunk)
            _push_log(f"batch {req_no} — {sent_ok}/{total} games sent", "sent")
        elif status in (401, 403):
            _push_log(f"batch {req_no} — [{status}] auth rejected — refresh cookie", "err")
            break
        else:
            _push_log(f"batch {req_no} — [{status}]", "warn")

        with _claim_lock:
            _claim_progress["sent"] = sent_ok

        time.sleep(spoofer.BATCH_DELAY)

    # update persisted stats
    state.total_games_claimed += sent_ok
    state.total_hours_claimed += sent_ok * hours
    state.save()

    with _claim_lock:
        _claim_progress["sent"] = sent_ok
        _claim_progress["done"] = True

    _push_log(f"Claim complete — {sent_ok}/{total} games · {sent_ok * hours:,.0f}h", "ok")


# ── helpers ─────────────────────────────────────────────────────────────────
_session: spoofer.Session | None = None
_games: list[spoofer.Game] = []


def _ensure_session() -> spoofer.Session:
    global _session
    if _session is None:
        _session = spoofer.Session.new()
    return _session


def _ensure_games() -> list[spoofer.Game]:
    global _games
    if not _games:
        _games = spoofer.load_games()
    return _games


_cached_user: dict | None = None
_cached_user_token: str = ""


def _fetch_discord_user(token: str) -> dict | None:
    global _cached_user, _cached_user_token
    if not token:
        _cached_user = None
        _cached_user_token = ""
        return None
    if _cached_user is not None and _cached_user_token == token:
        return _cached_user

    try:
        req = urllib.request.Request(
            "https://discord.com/api/v9/users/@me",
            headers={
                "authorization": token,
                "user-agent": spoofer.USER_AGENT,
            },
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            user_id = data.get("id", "")
            avatar = data.get("avatar")
            if avatar:
                avatar_url = f"https://cdn.discordapp.com/avatars/{user_id}/{avatar}.png?size=128"
            else:
                default_idx = (int(user_id) >> 22) % 6 if user_id.isdigit() else 0
                avatar_url = f"https://cdn.discordapp.com/embed/avatars/{default_idx}.png"

            profile = {
                "id": user_id,
                "username": data.get("username", "Unknown"),
                "global_name": data.get("global_name") or data.get("username", "Unknown"),
                "avatar_url": avatar_url,
                "valid": True,
            }
            _cached_user = profile
            _cached_user_token = token
            return profile
    except urllib.error.HTTPError as exc:
        err = "Invalid or expired token (401)" if exc.code == 401 else f"Discord HTTP error ({exc.code})"
        return {"valid": False, "error": err}
    except Exception as exc:
        return {"valid": False, "error": str(exc)}


def _build_status(state: spoofer.State) -> dict:
    games = _ensure_games()
    fp = state.fingerprint
    user_info = _fetch_discord_user(state.token) if state.has_token else None
    return {
        "has_token": state.has_token,
        "has_cookie": state.has_cookie,
        "fingerprint": bool(fp),
        "fingerprint_preview": (fp[:8] + "…") if fp else "",
        "analytics_token": bool(state.analytics_token),
        "games_count": len(games),
        "total_games_claimed": state.total_games_claimed,
        "total_hours_claimed": state.total_hours_claimed,
        "used_games_count": len(state.used_games),
        "user": user_info,
    }


# ── select games (same rotation logic as the original) ─────────────────────
def _select_games(state: spoofer.State, count: int) -> list[spoofer.Game]:
    games = _ensure_games()
    available_ids = {g.id for g in games}
    unused_ids = [g.id for g in games if g.id not in state.used_games]
    used_ids = [gid for gid in state.used_games if gid in available_ids]

    if count <= 0 or count > len(games):
        count = len(games)

    if len(unused_ids) >= count:
        selected_ids = unused_ids[:count]
    else:
        selected_ids = list(unused_ids)
        if used_ids:
            remaining = count - len(selected_ids)
            rotated = used_ids[remaining:] + used_ids[:remaining]
            selected_ids.extend(rotated[:remaining])

    state.used_games = [gid for gid in state.used_games if gid not in selected_ids] + selected_ids

    id_map = {g.id: g for g in games}
    return [id_map[gid] for gid in selected_ids if gid in id_map]


# ── HTTP handler ────────────────────────────────────────────────────────────
class GUIHandler(SimpleHTTPRequestHandler):
    """Serves the web/ directory for static assets and handles /api/* JSON RPCs."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_DIR), **kwargs)

    # suppress default access-log noise
    def log_message(self, fmt, *args):
        pass

    def end_headers(self):
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()

    # ── routing ──

    def do_POST(self):  # noqa: N802
        routes = {
            "/api/status": self._handle_status,
            "/api/save_auth": self._handle_save_auth,
            "/api/refresh_auth": self._handle_refresh_auth,
            "/api/claim": self._handle_claim,
            "/api/progress": self._handle_progress,
            "/api/stop": self._handle_stop,
        }
        handler = routes.get(self.path)
        if handler:
            body = self._read_body()
            result = handler(body)
            self._json_response(result)
        else:
            self._json_response({"ok": False, "error": "unknown endpoint"}, code=404)

    # ── helpers ──

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw)
        except Exception:
            return {}

    def _json_response(self, data: dict, code: int = 200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ── API handlers ──

    def _handle_status(self, _body: dict) -> dict:
        state = spoofer.State.load()
        return {"ok": True, "status": _build_status(state)}

    def _handle_save_auth(self, body: dict) -> dict:
        state = spoofer.State.load()
        token = body.get("token", "").strip()
        cookie = body.get("cookie", "").strip()
        fingerprint = body.get("fingerprint", "").strip()

        if token and token != "•" * 20:
            global _cached_user_token
            _cached_user_token = ""
            state.token = token
        if cookie and not cookie.startswith("("):
            state.cookie = cookie
        if fingerprint and not fingerprint.startswith("("):
            state.fingerprint = fingerprint
        state.save()

        # try to load games in background
        _ensure_games()

        return {"ok": True, "status": _build_status(state)}

    def _handle_refresh_auth(self, _body: dict) -> dict:
        state = spoofer.State.load()
        if not state.has_token:
            return {"ok": False, "error": "Please enter your token first"}

        session = _ensure_session()
        state.fetched_at = 0  # force refetch
        try:
            spoofer.ensure_token(state, session.super_props)
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

        global _session
        _session = spoofer.Session.new()

        return {"ok": True, "status": _build_status(state)}

    def _handle_claim(self, body: dict) -> dict:
        global _claim_thread
        if _claim_thread and _claim_thread.is_alive():
            return {"ok": False, "error": "Another claim operation is already running"}

        state = spoofer.State.load()
        if not state.has_token:
            return {"ok": False, "error": "Please enter your token first"}
        if not state.has_cookie:
            return {"ok": False, "error": "Please enter cookie first"}

        hours = body.get("hours", 1)
        count = body.get("count", 0)

        session = _ensure_session()

        # ensure analytics token is fresh
        try:
            spoofer.ensure_token(state, session.super_props)
        except Exception as exc:
            return {"ok": False, "error": f"Failed to refresh token: {exc}"}

        selected = _select_games(state, count)
        if not selected:
            return {"ok": False, "error": "No games available"}

        state.save()

        _claim_stop.clear()
        _claim_thread = threading.Thread(
            target=_claim_worker,
            args=(state, session, selected, hours),
            daemon=True,
        )
        _claim_thread.start()

        return {"ok": True, "total": len(selected), "hours": hours}

    def _handle_progress(self, _body: dict) -> dict:
        with _claim_lock:
            result = {
                "ok": True,
                "sent": _claim_progress["sent"],
                "total": _claim_progress["total"],
                "done": _claim_progress["done"],
            }
        result["logs"] = _drain_logs()
        return result

    def _handle_stop(self, _body: dict) -> dict:
        _claim_stop.set()
        return {"ok": True}


# ── main ────────────────────────────────────────────────────────────────────
def main() -> None:
    # pre-load games in background
    threading.Thread(target=_ensure_games, daemon=True).start()

    server = HTTPServer((HOST, PORT), GUIHandler)
    url = f"http://{HOST}:{PORT}"
    print(f"\n  ⚡ Discord Badge Spoofer GUI")
    print(f"  ➜  {url}\n")

    # open browser after a short delay
    threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  ⏹  stopped")
        server.server_close()


if __name__ == "__main__":
    main()
