# Primary AIT resolution without new fields or tables

Keeps the Primary AIT on the discovered item tables (`sn_sec_cmn_src_ci.u_primary_ait`,
`sn_vul_app_release.u_primary_ait`, `sn_vul_container_image.u_bofa_primary_ait`) current with no new
column anywhere. Replaces the earlier field-based design in `stories/primary-ait-performance/`.

## How it works
- **Derivation** (`AitResolver.ciAit`): services of the CI from `svc_ci_assoc` (both ends), the CI itself
  when it is a service, and `sn_vul_m2m_ci_services`; when empty, the same sources on the CIs related through
  `cmdb_rel_ci` (the current rule's fallback). Primary AIT of a service = lowest RTO tier among the AITs of
  the business applications related to it, tie by AIT number. Sources and fallback are properties.
- **Import path**: before rules on the three discovered item tables write the value in the same transaction
  when the CI is set or changes.
- **Keyed propagation**: after rules on `svc_ci_assoc`, `sn_vul_m2m_ci_services`, `cmdb_rel_ci`, the business
  application (AIT reference changes) and the AIT (tier changes) queue one event `usem.ait.refresh`
  (parm1 = `ait | app | service | ci | rel`, parm2 = sys_ids) on the sequential queue `usem_ait`. The script
  action expands the key to the CIs it can affect, resolves each once, groups by value and stamps each
  discovered item table in 200-CI chunks (only rows holding a different value; clearing row by row).
- **Safety nets**: `USEM Primary AIT catch-up` (every 15 min, replays the last 30 minutes of association,
  Related Services and relationship inserts) and `USEM Primary AIT reconcile` (daily 02:00, re-derives every
  discovered item with a CI in 16 partitions per table, clears orphans). Both idempotent.
- No cache outlives a transaction: a session cache was tried and dropped after it stamped a stale value
  from a scheduler session (the saving was about 2 ms per item).

## Files
- `AitResolver.js` – the script include. `build.py` – deploys everything into the Global update set
  `SNOWUSEMTP-AIT_MS_Primary AIT Resolution_V1.0` (re-runnable; rule names are kept within the 40-character
  limit of `sys_script.name`). `state.json` – sys_ids of the deployed records.
- `fixtures.py` – fixture graph (5 applications, 6 services, 10 CIs, 34 discovered items, tiers 1/2/3/2 on
  the four stand-in AITs; adds the stand-in `rto_tier` column in the stand-in scope). `fixtures.py remove`
  takes it away; store-table rows go through the REST table API because scripts from another scope cannot
  delete them.
- `test.py` – 42 checks (`test_run1.log`, `test_run2.log`): insert-time stamping, re-pointing, every keyed
  change and its reversal, Related Services, idempotence, reconcile repair, orphan clearing, catch-up job in
  the job context, no resolver errors.
- `measure.py` – timings (`measure.json`): import path with the rule on and off, a service gaining 2,000 CIs,
  one reconcile partition, the whole nightly job.
- `export.py` – points the AIT table name at the client table for the export, native exporter, scrub, XML
  upload proof, archive under `stories/_update_sets/`. `Primary AIT Resolution - Update Set.xml`.
- `build_tdd.js` – the technical design document (`Primary AIT Resolution - Technical Design.docx`, attached
  to INC0010003 with `attach.py`).

## Timings on the PDI (281,887 discovered items, 100,001 of their CIs, near-empty service graph)
| Path | Result |
|---|---|
| Discovered item insert, CI with a service, rule on / off | 30.3 ms / 13.1 ms per insert |
| Discovered item insert, CI resolved through a related CI, rule on / off | 29.8 ms / 12.0 ms |
| Discovered item insert, CI without any link, rule on / off | 19.1 ms / 12.8 ms |
| One keyed refresh after a service gained 2,001 CIs (2,004 items) | 13.0 s stamping, 7.0 s when nothing is stale |
| Clearing the same 2,004 items after the associations were removed | 13.8 s |
| Nightly pass, one partition of the discovered item table (6,182 CIs) | 22.3 s (3.6 ms per CI) |
| Nightly pass, all three tables, 16 partitions each, orphan passes | 5.8 min in four foreground batches; the job itself ran on demand without errors |
| Keyed change to stamped item | 7 to 11 s observed with the 10 s poll |

## Instance notes
- Updates to the 'Related Services' table from a global script: inserts and updates work, deletes are refused
  silently (application access 'Can delete' off); the REST table API deletes them.
- `updateMultiple` with `'NULL'` cleared the reference on `sn_sec_cmn_src_ci` but stored the literal text
  `NULL` on `sn_vul_container_image`; the resolver therefore clears row by row with `setValue(field, '')`.
- A reference field condition `STARTSWITH` applies to the display value; partitions use the dot-walked
  `cmdb_ci.sys_id`.
- The benchmark column `cmdb_ci.u_primary_ait` from the earlier design still exists on the PDI and is not used.

## Assumptions to confirm with the client
- AIT table `x_boar_bofa_techad_ait` and its tier field (`rto_tier` assumed): property `usem.ait.tier_field`
  and the condition of `USEM Primary AIT - AIT tier`.
- Business application AIT reference (`u_primary_ait` assumed): property `usem.ait.app_ait_field` and the
  condition of `USEM Primary AIT - application AIT`.
- Story number for the update set name (delivered as `SNOWUSEMTP-AIT_...`).
