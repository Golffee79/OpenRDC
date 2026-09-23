# Architecture (M0 implemented)

MCP client --stdio--> openrdc-gateway (TS thin adapter) --HTTP 127.0.0.1+Bearer--> openrdc-host (Rust).

Host owns coordinate transform, validation, capabilities, audit. Gateway never touches desktop.
Backends hidden behind `ScreenBackend`/`InputBackend` traits; only `x11` impl exists in M0.
Frame flow: capture -> frame_id + geometry -> click in frame space -> host transforms to native.
Loopback binding reduces exposure only; bearer token + 0600 file perms are the real auth.
License: Apache-2.0.
