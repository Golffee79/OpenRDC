# Threat model (M1 delta)

M0 model still applies (single-user local X11 machine; loopback NOT a
boundary; bearer + exact capabilities mandatory; hash chain tamper-evident
only). This file is the M1 delta: what context + per-client approvals fix,
what remains, and what M1 assumes.
License: Apache-2.0.

## New threats mitigated

- Focus-steal wrong-window action (M0.2 dogfood finding): between capture
  and input, another app takes focus, so frame-space coords land in the
  wrong window. Mitigated by capture-time context + pre-action validation
  (see interaction-context.md): mismatch => `stale_context` (410), zero
  input, audited as `stale`. Alternatives considered: sleeps / forced
  refocus (rejected in M0.2: racy hacks, not integrity). Why chosen:
  fail-closed check at the single choke point. Migration cost: none beyond
  clients handling 410 by re-capturing.
- Cross-client credential/approval reuse: M0's single shared bearer means
  any holder acts with full grants. M1 issues per-client credentials bound
  to capabilities and binds each approval to one client + action + context.
  A stolen/second client's replay validates against the wrong binding and
  fails. Alternatives considered: keeping one bearer + tagging approvals
  with a client label (rejected: label is client-asserted, forgeable). Why
  chosen: server-side binding, unforgeable. Migration cost: credential
  issuance/rotation tooling, carried into M2 pairing.
- Agent self-approval: the agent channel can never mint approvals; only the
  operator's approver CLI can, and the host verifies. Alternatives
  considered: an approve op on the same channel with a confirm flag
  (rejected: the attacker IS the channel). Why chosen: separate privilege
  path. Migration cost: approver UX evolves (incl. remote approver in M2)
  but the binding semantics stay.
- Replayed approvals: each approval_id is single-use, expiry-bounded, and
  bound to action + context generation. Reuse or use-after-focus-change
  fails (expired/consumed/stale). Mismatched presentations (wrong client,
  wrong action) fail WITHOUT consuming the approval, so probing cannot
  destroy another valid request's authorization. Alternatives considered: burn-on-any-presentation (rejected: lets any credential holder grief others' approvals; also destroys evidence of what the valid request was); multi-use approval tokens for agent convenience (rejected: widens the window for replay after a focus steal). Why chosen: least privilege per action + no cross-request interference. Migration cost: agents retry the approval flow more often; accepted.

## Residual risks (explicitly NOT fixed in M1)

- Same-window popovers/menus and app-internal state change: invisible to
  the host, not covered by context (see interaction-context.md honest
  boundaries). Host-level context cannot solve application-internal
  semantic change.
- X11 no-isolation carried over from M0: any local X client can observe or
  inject; M1 narrows the agent's own error window but does not sandbox X.
- Disk-full audit window carried over from M0: allow-path records are
  written after the action; a persistence failure at that point leaves an
  unattributed action + 500 "audit unavailable" (stop-work signal).
- Context-check TOCTOU (new, accepted): validation runs immediately before
  input emission, but the check and the X11 call are not atomic against
  external desktop changes. A focus switch in that exact window is
  unobservable. No sleeps; documented as residual.

## Trust assumptions

- Single-user local machine; the operator who runs the approver CLI is
  trusted and distinct from the agent channel.
- Loopback (127.0.0.1) is not a security boundary; other local processes
  can connect, so per-client bearers + exact capabilities + approval
  binding are the real access control.
- Operator-run approver CLI: approval minting happens off-channel on the
  same machine; compromise of the operator's session compromises approvals
  (accepted, out of scope).
- No remote transport in M1: no network attacker in scope yet; M1's
  per-client credentials and opaque handles are shaped so M2 pairing,
  mutual auth, and remote approval UX need no protocol change (see
  m1-architecture.md constraints).
