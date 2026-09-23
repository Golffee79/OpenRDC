# Approval Flow (M1)

One opaque server-side `approval_id`. No separate challenge_id. No signed
self-contained tokens. No custom crypto.

## Trigger

Dangerous `keyboard.press` (any modifiers, per M0 rule) presented WITH
`keyboard.press.dangerous` capability but WITHOUT a valid `approval_id`
=> `403 approval_required`. The host creates an approval record:

`{ approval_id (random opaque UUID, CSPRNG), state=pending, client_id,
canonical action (method + normalized key + sorted modifiers),
bound context (generation at creation), created_at, expires_at (TTL 120s) }`

and the 403 carries `approval_id` + `expires_at`. Knowledge of the ID is
NOT authorization; only a host-side state transition authorizes it.

## Approver

Operator-run CLI (`openrdc-approve list | approve | reject`) authenticating
as a `principal_kind=approver` client holding `approval.review`. The human
decision transitions the record `pending` -> `approved` / `rejected`
(server-side only).

## Retry

The agent retries the ORIGINAL request with the SAME `approval_id` (same
action, same context expectation).

## Consumption (no burn on mismatch)

On a request presenting `approval_id`, the host processes strictly in
order and stops at the first failure WITHOUT consuming a valid approval:

1. authenticate client (unknown credential => 401, audited, `client_id: null`)
2. validate capability (missing => `forbidden_capability`)
3. validate action shape (malformed => `bad_argument`)
4. validate current context (mismatch => `stale_context`, zero input)
5. load approval (unknown/consumed/expired/rejected => error, see below)
6. verify state == approved
7. verify TTL unexpired
8. verify client binding (wrong client => 403)
9. verify action binding (wrong action => 403)
10. verify context binding — approval's bound generation still current
    (moved => `stale_context`)
11. atomically transition `approved` -> `consumed`
12. immediately perform input

Wrong-client, wrong-action, malformed, expired, rejected, or
stale-context presentations MUST NOT consume a valid approval belonging
to another valid request. A second valid use after successful consumption
fails (unknown/consumed ID => 400). Error mapping: wrong client/action
=> 403; expired/rejected => 403; unknown or already-consumed ID => 400;
context moved => `stale_context` (410).

Residual (documented, accepted): the approval is consumed in step 11 and
the backend input in step 12 may still fail. The client sees an error and
must request a fresh approval. No distributed transactions in M1.

Agent can never mint, modify, or self-sign: `approval_id`s are random
UUIDs meaningful only in host memory, and agent principals cannot touch
approval-review endpoints (see principal separation).

## Capability vs approval

Capability = client may REQUEST the class. Approval = human authorized THIS instance. Dangerous press now requires BOTH (intentional M0 behavior change; M0-era clients get predictable `approval_required` + `approval_id` instead of silent allow).

## Dangerous classification (M1, no policy engine beyond this table)

- Safe: `screen.capture` (read-only).
- Sensitive: click, type, modifier-free press. Needs context validation, no approval.
- Dangerous: modifier-bearing press. Needs dangerous capability + per-action approval.
