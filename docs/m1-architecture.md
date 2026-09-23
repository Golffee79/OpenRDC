# M1 architecture (safety before remote networking)

M0 (done, unchanged): MCP stdio gateway (TypeScript) + Rust localhost host +
X11 backend + frame-based input + exact capabilities + bearer token + audit
hash chain. M1 adds safety layers inside the host. No architecture redesign
of M0 layers.
License: Apache-2.0.

## Layers

```
MCP clients (one stdio gateway instance per client)
  --stdio--> openrdc-gateway (thin adapter, holds exactly one client credential)
  --HTTP 127.0.0.1 + per-client bearer--> openrdc-host (Rust)
    |-- client registry (client_id, principal_kind agent|approver, credential hash, capability grants)
    |-- context registry (context_id -> snapshot + internal generation; bounded: max 64 entries, TTL 60s)
    |-- approval registry (approval_id lifecycle; detail in approval-flow.md)
    |-- backends: ScreenBackend (x11) / InputBackend (x11)
                  / InteractionContextBackend (new, x11 impl)
```

- Gateway stays thin: no desktop access, no context comparison, no approval
  decisions. One gateway instance holds one client credential; it never
  multiplexes clients.
- Host owns all safety checks: capability match, context validation, approval
  validation, audit. Backends remain hidden behind traits.
- New in M1 is the `InteractionContextBackend` trait plus the host-side
  context registry. Screen/Input traits are untouched (see
  interaction-context.md).

## Data flows (context checks)

- Capture: host captures frame via ScreenBackend, reads live snapshot via
  InteractionContextBackend, allocates opaque `context_id` (UUID), stores
  snapshot in context registry, returns frame + `context` block together.
- Click: client sends frame-space coords with frame_id. Host resolves
  frame_id -> its bound context snapshot, re-reads live snapshot, requires
  stored generation == current generation AND stored focused identity ==
  current focused identity. Mismatch => `stale_context` (410), zero input.
- Type / keyboard.press: client MUST send `context_id` (new required field;
  missing => `bad_argument`). Host looks up stored snapshot, re-reads live
  snapshot, same two-part equality check. Mismatch => `stale_context` (410),
  zero input. Mandatory, no opt-out.
- All context decisions (allow + stale) are audited; stale emits zero input.

## Approval handle flow (overview)

Dangerous ops (modifier-bearing `keyboard.press`) return `approval_required`
with an `approval_id` + `expires_at` instead of acting. Sensitive ops
(click, type, modifier-free press) require context validation + capability
only — never approval. Safe ops (`screen.capture`) require no approval.

Capability: "May this client request this class of operation?" Approval:
"Has a trusted human authorized this specific dangerous operation?" A
capability MUST NOT imply approval; approval MUST NOT grant a missing
capability.

The agent presents the `approval_id` to the operator out of band. The
operator's approver CLI (separate local process, authenticating as a
`principal_kind=approver` client holding `approval.review`) approves or
rejects that `approval_id`; the host records the decision server-side
(`pending` -> `approved`/`rejected`). The agent retries the original
request with the SAME `approval_id`. Knowledge of the ID authorizes
nothing; only the host-side state transition does. No signatures, no
self-contained tokens. Detail in approval-flow.md (not this file).

## Principal separation (structural, not configuration-only)

Every client record carries `principal_kind = agent | approver`.
Agent principals may use computer-control endpoints per capabilities, and
are rejected by approval-review endpoints even if configuration
accidentally grants `approval.review`. Approver principals may use
approval-review endpoints per `approval.review`, and cannot invoke
computer-control operations. Self-approval is blocked structurally, not
by careful config.

## Explicitly NOT in M1

No remote transport. No WebRTC. No Windows/Wayland backends. No
filesystem/shell/clipboard ops. No focus/window control protocol. No change
to M0 frame-based coordinates or exact capability semantics. The hash-chain
mechanism remains unchanged; the audit record schema evolves to v2 with
additional M1 fields.

## Remote-transport compatibility constraints (documented, not implemented)

M1 must not paint M2 remote work into a corner. These are constraints on
M1's design, not M1 features:

- Pairing: per-client credentials must already be per-client (no shared
  bearer) so a future pairing ceremony has something to bind.
- Mutual auth: gateway-to-host auth must be replaceable (bearer today, mTLS
  or equivalent later) without changing op semantics.
- NAT: no protocol assumption that client and host share a LAN; all host
  checks are local-state checks, never address-based.
- Sessions: context_id and approval_id are host-issued opaque handles tied
  to host-side registries; a future session/resume layer can persist or
  scope them without client-visible format change.
- Rotation: client credentials must be rotatable/revocable per client
  without host restart semantics leaking into the op protocol.
- Remote approval UX: the approval request payload (action description + context labels) must be displayable on a
  device other than the controlled desktop (labels only, no backend IDs),
  so a future remote approver needs no protocol change.
