# Architecture (M0 implemented)

MCP client --stdio--> openrdc-gateway (TS thin adapter) --HTTP 127.0.0.1+Bearer--> openrdc-host (Rust).

Host owns coordinate transform, validation, capabilities, audit. Gateway never touches desktop.
Backends hidden behind `ScreenBackend`/`InputBackend` traits; only `x11` impl exists in M0.
Frame flow: capture -> frame_id + geometry -> click in frame space -> host transforms to native.
Loopback binding reduces exposure only; bearer token + 0600 file perms are the real auth.
License: Apache-2.0.

## Running as a daemon

Always pass `--caps` as an absolute path. Daemon launchers often change cwd
(e.g. start-stop-daemon chdirs to `/`), and a relative path would then miss
the file. Since M0.2 the host refuses to start when the capability file
cannot be opened or parsed — it never silently boots with empty grants.
