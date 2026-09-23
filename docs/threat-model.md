# Threat model (M0)

Trust: single-user local X11 machine. 127.0.0.1 is NOT a security boundary; other local
processes can connect, so the random 256-bit bearer token (0600 at creation, symlinks
refused, existing files verified) + exact capability checks are mandatory.
Agent self-approval impossible: no approve flag; ANY modifier-bearing key press needs
keyboard.press.dangerous (no shortcut deny-list in M0), else forbidden_capability.
`approval_required` is reserved for M1 and never returned in M0. Audit records are
flushed+fsynced per record; write failures fail closed. The hash chain is
tamper-evident, not tamper-proof: file-write attackers can truncate/regenerate;
external anchoring deferred to M2. X11 offers no client isolation (accepted, documented).

## Act-then-audit window (M0.1)

Allow-path records are written AFTER the input action executes. If audit
persistence fails at that point (disk full, I/O error), the desktop action
has already happened but has no log line; the client receives 500
"audit unavailable" instead of "ok" (and may retry, repeating the action).
This window is unavoidable without write-ahead journaling, which is
explicitly deferred. Operator behavior: treat repeated 500 "audit
unavailable" responses as a stop-work signal — stop the host, fix storage,
then restart. All deny/validation paths fail closed (500 before any action),
so only one in-flight allow per failure onset can go unattributed.
