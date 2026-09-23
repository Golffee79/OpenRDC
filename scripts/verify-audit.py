#!/usr/bin/env python3
"""E2E audit INSPECTOR (not a cryptographic verifier): checks seq continuity,
hash-link continuity, required fields, method coverage, and that typed text
never appears. Real hash recomputation (exact serde canonicalization) is done
by `openrdc-host --verify`, which the E2E script runs separately."""
import json, sys
path = sys.argv[1]
recs = [json.loads(l) for l in open(path) if l.strip()]
assert recs, "empty audit log"
prev, methods = "GENESIS", set()
for i, v in enumerate(recs, 1):
    assert v["seq"] == i, f"seq gap at {i}"
    assert v["prev_hash"] == prev, f"link break at {i}"
    for k in ("ts", "request_id", "method", "decision", "hash"):
        assert k in v, f"missing {k} at {i}"
    assert v["decision"] in ("allow", "deny")
    methods.add(v["method"])
    blob = json.dumps(v.get("params_redacted", {}))
    assert "E2E-SECRET-TYPED-TEXT" not in blob, "typed text leaked into audit!"
    prev = v["hash"]
for m in ("screen.capture", "mouse.click", "keyboard.type", "keyboard.press"):
    assert m in methods, f"missing audit for {m}"
# auth is optional: a healthy run may contain zero failed-auth attempts.
print(f"records={len(recs)} links_ok=true methods={sorted(methods)} no_typed_text=true")
