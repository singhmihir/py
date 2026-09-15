# SNOWUSEMTP-1420 — Trident closure governance

Final state (update set `SNOWUSEMTP-1420_MS_Trident Resolve Approval Retrigger_V2.3`, scope
Configuration Compliance, 4 updates):

- `BOFA Trident closure lifecycle.js` — the single before-update business rule on
  `sn_vulc_result_group` (settings in the `.meta.txt`): close gate, reopen window, staging of the
  governance approval request on every move into Resolved, cleanup when a task leaves
  Pending Approval. Order 1000, returns early when an earlier rule aborted the save. Condition
  selector: State changes to/from Closed, State changes to/from Resolved, Reason changes
  to/from Pending Approval.
- `TridentClosureUtil.js` — shared script include (`applyClosureRequest` only skips while an
  approval set is genuinely awaiting a decision).
- `Normalize Trident closure requests.fix.js` — one-time fix script to run after commit.
- `resolve_broker_transform.js` / `resolve_client_script.js` — workspace Resolve modal guard
  (attachment required for Trident tasks), from the earlier "resolve requires attachment" set.

Why it works: the flow "Trident Closure Approval" triggers on
`substate=100 ^ approval!=requested ^ active=true` (for each unique change). Staging flips
`approval` to Not Yet Requested and sets Reason to Pending Approval in the same write, so at least
one trigger field changes on every resolve, including on records left stuck by a rejection.

Verification performed on the PDI: full resolve → reject → resolve → approve → reopen cycles,
every ordered state pair (42) and every Reason transition with a probe rule carrying the
identical selector, refused-write safety, deferral Reason preservation.
