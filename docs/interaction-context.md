# Interaction context (M1)

Opaque, backend-neutral binding between what the agent saw and what it acts
on. No X11 window IDs (or any backend identifiers) enter the protocol.
License: Apache-2.0.

## Protocol addition

Capture response gains:

```json
"context": {
  "context_id": "<opaque UUID, host-issued>",
  "captured_at": "<rfc3339 timestamp>",
  "focused_app": "<string label, display-only>",
  "focused_window_title": "<string, display-only>"
}
```

- `focused_app` / `focused_window_title` are human-readable labels for the
  agent/approver only. Equality is computed server-side from internal
  identity, never from client-supplied fields.
- Decision: opaque UUID + server-side equality.
  Alternatives considered: client-side context comparison (client echoes
  window title and host string-compares it; rejected: spoofable, locale-
  fragile); exposing window IDs in the protocol (rejected: leaks backend
  internals, breaks backend-neutrality, invites client forgery).
  Why chosen: unforgeable binding, backend-neutral wire format.
  Security: client cannot craft or replay a valid context for a different
  focus state; replay of its own stale context fails the generation check.
  Migration cost: none for clients beyond storing the opaque block; future
  backends reuse the same fields.

## Host registry

- In-memory map `context_id -> snapshot { bound frame_ids, focused internal
  identity, geometry, workspace, monitor-layout generation, captured
  generation }` plus a global monotonic `context_generation: u64`.
- Bounded: max 64 entries, TTL 60 seconds (mirrors the frame store).
  Expired or evicted `context_id` lookups behave exactly like an unknown
  ID: `stale_context`, zero input, audited.
- The counter is bumped on any observed interaction-relevant change:
  active window/app change; focused-window geometry change beyond 8px
  epsilon (covers move/minimize/maximize); workspace change; monitor layout
  change; screen lock/unlock.
- Decision: single monotonic generation + per-context captured generation.
  Alternatives considered: exposing backend identifiers (rejected: see
  above); per-field client-visible versioning (rejected: leaks topology).
  Why chosen: one cheap integer comparison covers all change classes;
  avoids exposing identifiers; in-memory only, no persistence to secure.
  Security: fail-safe — any missed observation keeps the old generation
  only if nothing changed; any observed change invalidates all older
  contexts. Migration cost: future backends only decide when to bump; the
  counter mechanism is unchanged.

## Input validation (mandatory, no opt-out)

- Click: resolves frame_id -> its bound context snapshot (no new client
  field). Type / keyboard.press: REQUIRE a `context_id` field (new required
  field; missing => `bad_argument`).
- Host re-reads the live snapshot immediately before input emission and
  requires BOTH (a) stored generation
  == current generation AND (b) current focused identity == stored focused
  identity. Any observed mismatch => `stale_context` error (HTTP 410,
  retryable=true), ZERO input emitted for that request, audited as decision `stale`.
- Honest TOCTOU boundary: validation runs immediately before emission, but
  the focus check and the X11 input call are not atomically indivisible
  from external desktop changes — a focus switch landing exactly between
  the final check and emission cannot be observed. OpenRDC guarantees no
  input is emitted when a mismatch IS observed during validation; it does
  not claim the window is unexploitable. No sleeps (they would not close
  it either).
- Applies to click, type, AND keyboard.press. No opt-out flag.
- Decision: server-side two-part check with fail-closed 410.
  Alternatives considered: title-ignoring equality (rejected: fails safe
  the wrong way — a tab switch that changes only the title would wrongly
  validate); client-side opt-out flag (rejected: agent would disable its
  own seatbelt). Why chosen: fail-safe over-approximation; retryable
  signal tells the agent to re-capture. Security: an observed focus-steal
  between capture and input emits nothing. Migration cost: none — check lives in
  the host, backends only supply snapshots.

## Honest boundaries

- Window-title change (e.g. browser tab switch that retitles the window)
  INVALIDATES context: title feeds the snapshot, so a retitle bumps the
  generation. Fail-safe over-approximation — some invalidations are
  spurious, accepted deliberately.
- Same-window popovers/menus, in-page DOM changes, and app-internal state
  are INVISIBLE to the host and NOT covered. Host-level context cannot solve
  application-internal semantic change; documenting this limit is part of
  the design.
- Locked desktop always invalidates (lock/unlock bumps the generation).
- Decision: over-invalidate at the host level, document the rest as
  residual risk. Why: the host sees windows, not app semantics; pretending
  otherwise would be unsafe. Migration cost: a future semantic layer
  (accessibility tree, app-provided state) would be a new mechanism, not a
  change to this one.

## Wayland honesty

Future backends under portal constraints may be unable to observe focus or
geometry. They may return coarse snapshots (generation bump per capture =
effectively per-frame binding). The protocol is unchanged: same opaque
fields, same `stale_context` semantics, only more frequent invalidation.

## Backend abstraction

- New separate trait `InteractionContextBackend`, implemented for X11.
  The X11 impl reads `_NET_ACTIVE_WINDOW` / `WM_CLASS` / geometry /
  `_NET_CURRENT_DESKTOP` internally; none of these primitives enter the
  protocol. The server reasons only over backend-neutral snapshot structs.
- Decision: separate trait; do NOT extend ScreenBackend/InputBackend.
  Alternatives considered: extending the existing traits (rejected: mixes
  capture/input duties with focus observation; forces dummy impls on every
  future backend). Why chosen: single responsibility, independent testing
  and substitution. Security: protocol layer cannot accidentally forward a
  backend identifier. Migration cost: each new backend implements one small
  trait returning the neutral snapshot.
