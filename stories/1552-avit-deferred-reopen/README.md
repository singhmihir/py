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

`AVIT Rescan Simulation - Background Script.js` (attached to INC0010003) plays the same two writes on one existing
deferred item by number and prints it before and after each step, for QA on the client dev instance.

## Deliverable
Update set `SNOWUSEMTP-1552_MS_AVIT Deferral Kept On Scanner Reopen_V1.0`, Vulnerability Response scope, one update
(the property set to true); `build_export.py` captures, exports natively, scrubs, proves through the XML upload and archives.
File `AVIT Deferral Kept On Scanner Reopen - Update Set.xml`, attached to INC0010003. The PDI now holds the property as true.
