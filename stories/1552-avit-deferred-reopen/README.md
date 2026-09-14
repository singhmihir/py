# SNOWUSEMTP-1552 — closed and re-opened AVITs stay Deferred inside a valid deferral window

## What the platform already does
- Property **`sn_vul.auto_defer_avit_in_active_exception_window`** (Vulnerability Response scope, default `false`;
  siblings `sn_vul.auto_defer_vit_in_active_exception_window`, `sn_vul_container.auto_defer_cvit_in_active_exception_window`,
  `sn_vulc.auto_defer_test_result_in_active_exception_window`).
- Read by the out-of-box before rule **Run exception rules** on `sn_vul_app_vulnerable_item` (order 1000, insert and
  update; filter: CI or application product model and vulnerability present, and one of those changes or **active changes
  to true**). When the property is `true`, `ignore_expiration` (Until) and `backup_substate` are set, `ignore_expiration >
  gs.daysAgoStart(0)`, the state is not Deferred and no exception rule matched, it sets state 12 Deferred, substate =
  `backup_substate`, `defer_count + 1`, `ignore_date` and `last_state_changed_on` = now, work note *Deferred by <user> as
  the application vulnerable item falls under valid exception window*.
- `backup_substate` is written at deferral time by the exception approval (`sn_sec_exception.StateChangeManager`, also
  `ExceptionSettings` for policy exceptions and `DeferralExtension`), and cleared by the expiry job and by a manual re-open
  (`VulnerabilityUtils.reopenVulnerableItem(gr, false, true)` also clears the Until date).
- Scanner path (`sn_vul.AVRImportAPIBase.createOrUpdateAVIT`): a Deferred item whose finding the scanner reports as
  fixed becomes Closed with the mapped substate; a Closed item found again becomes Open. The re-open flips `active` to true
  through *Transit to Open* (40) and *Vulnerable Item Active State Management* (250), which is what fires the rule above.

## Answers for the QA notes on the story
1. Property name: `sn_vul.auto_defer_avit_in_active_exception_window`.
2. **Date only.** The comparison uses the Until date (`ignore_expiration`, a date field) against the start of the current
   day in the time zone of the session that processes the scan. Until = tomorrow or later: the item stays deferred.
   Until = yesterday: it re-opens. Until = today: depends on that time zone (kept in an IST session, re-opened in a UTC
   session); the integration runs as a scheduled job, so the system time zone decides. Test with tomorrow and yesterday.

## Simulation on the PDI (`simulate.py`, results in `simulate_results.json`)
Fixture items with a CI and an application vulnerability entry, deferred the way the approval writes it (state 12, substate
Risk Accepted, backup substate, Until, ignored by, reason), then the two writes the import API makes: Closed with the
scanner substate, then Open.

| Case | Result after the scanner re-open |
|---|---|
| A property false, Until tomorrow, closed Fixed | Open; Until and backup substate kept |
| B property true, Until tomorrow, closed Fixed | **Deferred / Risk Accepted**, defer count 1, work note written |
| C property true, closed Stale by the auto-close rule | Deferred / Risk Accepted |
| D property true, Until yesterday | Open |
| E property true, Until today, session IST | Deferred |
| F property true, Until today, session UTC | Open |
| G property true, manual Reopen action | Open; Until and backup substate cleared |
| H property true, two close/re-open cycles | Deferred both times, defer count 2 |

Deferral on the remediation task instead of the item (`simulate_task_deferral.py`: fixture task deferred, item inherits
Deferred / Risk Accepted with backup substate and Until, then the same two writes):

| Case | Result after the scanner re-open |
|---|---|
| property false | Open; the Deferred task does not pull the item back |
| property true | Deferred / Risk Accepted, defer count 1 |

So the property decides in both cases; without it a re-opened item stays Open whether the deferral was granted on the
item or on its task.

`AVIT Rescan Simulation - Background Script.js` (attached to INC0010003) plays the same two writes on one existing
deferred item by number and prints it before and after each step, with the deferred tasks of the item and the reason
when an update is refused, for QA on the client dev instance.

## What runs on the two writes (rules on `sn_vul_app_vulnerable_item`, all out of the box)
Scanner close (state 3, substate Fixed or Stale): *Check for group state inheritance update* (50) resets the inheritance
count; *Transit to Closed* (100) fills resolution and closed data and the work note; *Vulnerable Item Active State
Management* (250) sets active false; *Process inactivation* (300) computes the closed age; *Run exception rules* (1000)
does not run (its filter needs active changing to true or a CI / vulnerability change). After: *Link to Remediation
Tasks* (90) re-evaluates the task link; a Closed / Fixed item is never overridden by its task. Until date and backup
substate survive the close.

Scanner re-open (state 1): *Transit to Open* (40) sets active true, clears substate and closed data, keeps the deferral
fields; *Active State Management* (250) counts the re-open; *Process activation* (300) marks reopened; *Run exception
rules* (1000) runs the exception rules, then, only when the property is true, the Until date is after the start of the
day and a backup substate exists, puts the item back to Deferred. With the property false nothing else in the chain
re-defers the item; the task-side rules push state to items only when the task itself changes.

If the client script shows no change at all, the item did not meet the rule filter (needs a CI or an application
release with a product model, and a vulnerability) or an update was refused; the script prints both.

## Deliverable
Update set `SNOWUSEMTP-1552_MS_AVIT Deferral Kept On Scanner Reopen_V1.0`, Vulnerability Response scope, one update
(the property set to true); `build_export.py` captures, exports natively, scrubs, proves through the XML upload and archives.
File `AVIT Deferral Kept On Scanner Reopen - Update Set.xml`, attached to INC0010003. The PDI now holds the property as true.
