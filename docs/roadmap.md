# Roadmap

- M0 (done): local X11, 4 ops, caps, audit, stdio gateway.
- M0.1 (done): audit-error handling, audited body limits, press-audit consistency.
- M0.2 dogfood (real Cinnamon/X11): capability-path fail-closed, optional-auth
  inspector. Finding carried to M1: real-desktop focus race.
- M1: trusted approval (approval_id + approval_required), Streamable HTTP, per-client tokens.
  M1 requirement from M0.2 dogfood: real-desktop focus race — between capture
  and input, window focus may move (focus steal), so a click can land in the
  wrong window. M1 must add capture-time interaction context (e.g. focused
  window identity at capture) + pre-action context validation (re-check focus
  still matches before acting, fail instead of acting blindly). No sleeps or
  forced-refocus hacks; no focus/window protocol in M0.
- M2+: Windows/Wayland backends (no protocol change), clipboard/fs/terminal, syslog signing.
