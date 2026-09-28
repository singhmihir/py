# SNOWUSEMTP-2021 — Verification ID keeps every ID VAMP sends (AVIT)

Story: a verification record from VAMP names the finding by Source AVIT ID; the AVIT's Verification ID
(`u_verification_id`, Mihir 28 Sep) must keep all IDs, one per line, oldest first, each with the date it was added.

## Build (Global, set `SNOWUSEMTP-2021_MS_AVIT Verification ID History_V1.1`, 4 updates; V1.0 stamped the date only)
- `u_verification_id` on `sn_vul_app_vulnerable_item`: string, max length 4000 (a string over 255 shows as a multi-line
  box). On the client the field exists: the dictionary update raises its length and sets the label "Verification ID".
- `BOFA_SI_VerificationIdHistory` (global): `recordVerification(sourceAvitId, verificationId)` finds every AVIT with that
  Source AVIT ID and writes the ID (returns the count; one `gs.error` when refused); `appendToHistory(current, previous)`
  turns a single new ID into `<old lines>\n<ID> (MM-dd-yyyy HH:mm:ss)` (Mihir 28 Sep: date and time; time zone of the
  session saving the record, so the integration user's on the inbound), skips an ID already present, leaves several lines
  or a stamped entry, with or without time (a user editing the history), as written.
- `BOFA_BR_AVIT_VerificationIdHistory`: before insert/update, order 1000, condition Verification ID changes, returns on an
  aborted action, calls `appendToHistory`. Any writer (inbound transform map field map, REST, form) gets the history.
- 1804 (outbound to VAMP) does not send `u_verification_id`; nothing changes there.

## Tests (`test.py`, 25 checks, run twice, 25/25 both on V1.1; `test_results.json`)
First ID, second below, same ID again, trimmed spaces, earlier ID again, two AVITs sharing a Source AVIT ID, unknown
Source AVIT ID, empty IDs (3 error lines in the standard format), old undated value kept on top, user edits kept,
cleared field, insert without previous, rule and field definitions, every stamp within the run's own date and time. Borrowed AVITs restored after each run.
