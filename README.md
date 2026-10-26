# discord-badge-spoofer

inflates your discord profile badges - add hours played and mark games as played.

## join https://discord.gg/solasity for support

**how it works:** discord's analytics endpoint (`/api/v9/science`) tracks what games you play and how long you play them. this tool posts the same events the real client does (`launch_game` and `running_game_heartbeat`), but with custom hours and game lists. discord accepts the events (`204`) and they do show up in your badges.

**status:** verified working and currently unpatched. badges take 1-2 days to update, so don't expect results right away. your token and cookie are stored locally only - nothing leaves your machine. this may break at any time if discord patches the endpoint.

**important:** this violates discord's tos. use it on accounts you're comfortable losing.

## setup

no dependencies - pure python stdlib (needs python 3.10+).

1. run it:
   ```
   python spoofer.py
   ```

2. first run asks for your discord account token. paste it and it gets saved to `science_state.json` (reused after that). the analytics token is fetched automatically from `GET /users/@me?with_analytics_token=true`.

3. you also need a cookie (`cf_clearance`). on startup it'll ask for one, or you can add/update it later via option `3` (refresh auth). grab the full `cookie` header from any `/science` request in devtools (network tab). it gets saved to `science_state.json`.

5. **optional: fingerprint for games-played count.** the fingerprint isn't strictly necessary - users have reported getting the games-played badge without setting one. if you want to set it, grab a real `executable_fingerprint` from a `launch_game` request in your client's devtools and add it to `science_state.json` as `"fingerprint": "..."`.

## menu

- `1` claim playtime - asks for hours per game, applies to every game
- `2` games played - marks every game as played (1 minute each)
- `3` refresh auth - pulls a fresh analytics token and lets you update the cookie
- `4` exit

## web gui (optional)

prefer a graphical interface? launch the local web gui:

```bash
python gui.py
```

or double-click `start_gui.bat` on Windows. it opens at `http://127.0.0.1:8710` featuring:
- interactive glassmorphism UI with live progress bar and activity log
- real-time Discord profile verification (shows avatar, handle, and connection status)
- built-in interactive guide tooltips for retrieving tokens and cookies
- custom hours slider and game count selector


## how auth works

- `token` - your account token, entered on first run, saved to `science_state.json`
- `analytics_token` - fetched from `GET /users/@me?with_analytics_token=true`
- `super_props` / heartbeat / launch ids - generated automatically
- `cookie` (cf_clearance) - pasted by hand, via option `3`
- `fingerprint` - optional, only needed for the games-played count (see below)

badges update on discord's analytics cycle (1-2 days), so don't expect to see results right away.

## about the fingerprint

hours work with just your token and cookie. the games-played count might need a real `executable_fingerprint` - we're not 100% sure yet. users have reported getting badges without one, so try it first. if it doesn't work after a few days, grab a real `executable_fingerprint` from a `launch_game` request in your client's devtools and add it to `science_state.json`:

```json
{ "fingerprint": "Ab5ekw..." }
```

either way, the tool will post the events - we just want feedback on whether the badges move with or without the fingerprint so we can figure out what's actually required.

## disclaimer

this breaks discord's terms of service. use it on accounts you're fine losing.
provided as-is with no warranty.

## license

released under the mit license. see [LICENSE](LICENSE).
