# M1 Plan (safety before remote networking)

Scope: multi-client identity + interaction context validation (sibling document, assumed) + per-action approval. No remote transport, no WebRTC, no Windows/Wayland, no filesystem/shell/clipboard in M1.

## Protocol delta proposal

| Endpoint | Change |
|---|---|
| `screen.capture` response | += `context` object: opaque `context_id` + `captured_at` + display labels (`focused_app`, `focused_window_title`). Generation counters and backend window IDs stay host-internal and never appear on the wire |
| `mouse.click` | fields unchanged; context carried via frame binding (frame already binds capture-time context) |
| `keyboard.type` | += REQUIRED `context_id` |
| `keyboard.press` | += REQUIRED `context_id`; += optional `approval_id` (required when modifier-bearing) |
| Errors | new `410 stale_context` (`retryable: true`); `403 approval_required` (`retryable: false`, carries `approval_id` + `expires_at` for the pending approval record; no `challenge_id`) |
| `system.features` | += `{ context_validation, approval, approval_id_accepted, multi_client }`, all `true` |
| Error audit | error responses share `request_id` with the audit record (M0 rule preserved) |

`retryable: false` means the original request must NOT be automatically
repeated unchanged. It MAY be intentionally retried with the approved
`approval_id` after human authorization (same action, same `approval_id`).

M0-client failure predictability: missing `context_id` => `bad_argument`; dangerous press without approval => `approval_required` (+ `approval_id`), never silent allow.

## Audit schema delta proposal

Record gains: `client_id` (nullable — null for requests failing
authentication before an identity resolves; mandatory once authenticated),
`context_id` (nullable), `approval_id` (nullable). `decision` extended with
`approval_required | stale | approved | rejected | consumed`. Capability and
approval outcomes recorded per attempt (`capability_result`,
`approval_result` alongside `reason`), so agent actions, approver
decisions, and auth failures are all reconstructible. Add `audit_version:
2`. Verifier accepts v1 + v2; chain continuity across restart preserved.
Never log credentials, credential hashes, keys, or typed text.

## First-slice acceptance criteria

- Client-A-identified capture returns context.
- Click / type with matching context succeed.
- Focus change between capture and input => `stale_context` (410) with zero input executed.
- Modifier shortcut => `approval_required` (403 + `approval_id`) => test-approver approves => retry with SAME `approval_id` succeeds exactly once => replay of same `approval_id` => 400 unknown.
- Client B presenting A's `approval_id` => 403; A's approval remains valid for A's own retry (no burn on wrong presentation).
- Xvfb automated tests plus one real-desktop dogfood procedure (capture, focus-steal, stale rejection observed).

## Implementation task breakdown

1. Context backend trait + X11 impl + fakes (per sibling context document).
2. Generation counter + capture-time context binding + registry bounds (64 entries, 60s TTL).
3. Input validation paths (context check immediately before every backend call).
4. Client registry with `principal_kind` + enrollment CLI + legacy token migration.
5. Gateway client-credential startup (fail-closed).
6. Approval registry (pending/approved/rejected/consumed, no burn on mismatch) + `openrdc-approve` CLI.
7. Audit v2 writer + v1/v2 verifier.
8. MCP tool updates for `context_id` / `approval_id` passthrough.
9. Xvfb tests incl. adversarial (cross-client approval, replay, stale, wrong-action, principal separation).
10. Docs + real-desktop dogfood procedure.

## Migration / backward-compatibility notes

- Legacy single-token file auto-imported once as client `local-default` (logged).
- M0 clients fail predictably: `bad_argument` (no context) or `approval_required` (dangerous press), never silent behavior change.
- Audit v1 records verify under the v2 verifier; chain not broken by upgrade.

## Decisions intentionally deferred

Asymmetric client keys, Streamable HTTP auth, per-agent identity, remote transport, signed approval tokens, policy engine beyond the safe/sensitive/dangerous table.

## Open architectural risks

- Same-window popover blindness (context sees window, not in-window change).
- Title-change over-invalidation UX (generation churn).
- Approver CLI is local-only (no remote approval path yet).
- Challenge/approval TTL tuning (120s) unvalidated under real operator latency.
- Residual TOCTOU: validation immediately precedes input, but focus check +
  X11 emission are not atomically indivisible from external desktop change.
  No sleeps; accepted and documented.
- Residual consumed-then-failed: approval transitions to consumed, then the
  backend input may fail; no distributed transactions in M1 (client sees an
  error and must request a fresh approval).

## Architecture consistency review (8 questions)

1. Self-approval path? No. Approvals transition to approved only via a human decision through a `principal_kind=approver` client; agent principals are rejected by approval-review endpoints even under capability misconfiguration. IDs are host-memory random UUIDs the agent cannot forge.
2. Cross-client use? No. Credential check is hash match per request; approval is client-bound; wrong-client presentation fails WITHOUT consuming the approval, so A's approval stays valid for A's retry.
3. Input after staleness? Prevented fail-safe, not atomic: context validation runs immediately before every backend call and observed mismatch emits zero input (410). A residual TOCTOU window between final check and X11 emission exists and is documented; it cannot be closed without backend-level atomicity that X11 does not offer.
4. Replay? Fails. Consume-on-successful-validation + short TTL; second valid use => 400 unknown. No burn on mismatched presentation, so failures never destroy another valid request's approval.
5. X11 IDs in protocol? No. Opaque `context_id` + display labels only; generations stay internal.
6. Remote migration? Needs channel work, but the identity model (stable `client_id`, `CredentialKind` enum, opaque handles) survives; no replacement of grants/audit shapes.
7. Capability vs approval? Separated explicitly AND structurally (`principal_kind`): capability = may request the class; approval = human authorized this instance; dangerous press requires both.
8. Complexity verdict? Per subsystem: context validation cheap; client registry small; audit v2 mechanical; approval CLI is the heaviest piece, justified as the only human-authorization path.
