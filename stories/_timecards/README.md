# Time cards

Bi-weekly ServiceNow time card workbooks (Daily Notes, Daily Timecard, Deloitte Reconciliation) in the
layout of the 27-Jul to 07-Aug-2026 workbook. Deloitte T&E is the system of record.

- `build_timecards.py` – all day data, notes and the three-sheet writer; `python3 build_timecards.py`.
- `cache_values.py` – stores each formula result inside the file so previewers show totals
  (`python3 cache_values.py *.xlsx`); LibreOffice `recalc.py` is the authoritative check.
- `verify_timecards.py` – evaluates every formula in Python, prints the tie-out and scans for text that must not leave.

Rule for the week ending 22-Aug-2026: VDI unavailable, so project hours are capped at 3.00 per day on the
ServiceNow side; that week shows CHECK against the Deloitte 8.00h days by design.
