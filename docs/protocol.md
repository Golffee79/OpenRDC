# Protocol v1 (M0)

See ../openrdc-protocol/openapi.yaml (normative). Summary: frame-based coords
(frame_id + x/y in output space, host transforms; x/y beyond u32::MAX rejected),
exact capability match, modifier-bearing keyboard.press needs
keyboard.press.dangerous (modifier-free keys need only keyboard.press),
approval_id reserved (M0 rejects if present), stale_frame on expired frames.
One request_id per request, shared by the error envelope and the audit record.
Request bodies capped at 64 KiB (413 beyond).
