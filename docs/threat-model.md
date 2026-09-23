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
