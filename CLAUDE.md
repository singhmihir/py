# Working agreement for this repository (BofA USEM ServiceNow stories)

Read this before doing anything. It captures how Mihir wants stories built, tested and delivered.
Follow it without being asked again.

## Context
- Client work: Bank of America **USEM** (Unified Security Exposure Management) on ServiceNow
  Vulnerability Response / Configuration Compliance. Stories live in JIRA project **SNOWUSEMTP**.
- Build and test everything on the personal developer instance (PDI) `https://dev390397.service-now.com`
  as user **ZK5LG9V** only (never another user). The password is provided by Mihir at the start of a
  session and lives only in the environment (`SN_USER`, `SN_PASSWORD`) — never in files, commits, docs,
  logs or chat summaries. Harness: `tools/snui.py`.
- The PDI hibernates after inactivity: `stats.do` returning an *Instance Hibernating* page (HTTP 200)
  or a 502 means asleep. Traffic cannot wake it; Mihir wakes it from the Developer Portal. Re-check
  later instead of hammering it.
- Fixture users on the PDI: `vso.owner.one` / `vso.owner.two` (active), `vso.owner.gone` (inactive).
  Simulated BofA tables on the PDI live in scoped app `x_196061_bofasim` (`_ait` with `app_mgr_netid`,
  `_consequence` with `state` and `u_consequence_level`); Global custom columns get auto-prefixed
  `u_`, so unprefixed stand-in columns need a scoped table.

## Deliverables — what Mihir hands to BofA
- Default deliverable is an **update set XML** plus a short summary in chat. Word documents only when
  asked (build with docx-js; PDFs only if asked).
- Every artifact must look human-made and must never mention the PDI, the tooling or the working user.
  Scrub before sending: `dev390397`, `ZK5LG9V` (exported XML: replace with `admin`), `service-now.com`,
  the password, `x_196061`, `bofasim`, and any AI / model names. Word documents additionally avoid the
  words *measured, proven, verified, evidence* (as prose) and *PASS*.
- Update set naming: `SNOWUSEMTP-<story>_MS_<Title>_V<major.minor>` (P3.17 style for sprint stories:
  `SNOWUSEMTP.26.P3.17_MS_<Title>_V1.0`). Bump the version on every re-delivery; never reuse a name.
- Give the file a plain business name, e.g. `Trident Resolve Approval Retrigger - Update Set.xml`.
- **Update set scope must equal the application scope of every captured update** (single scope, or a
  parent + child batch). Audit the captured rows before export and abort on any mismatch.
- **Export only with the platform's own exporter**: `new UpdateSetExport().exportUpdateSet(set)` then
  download `export_update_set.do?sysparm_sys_id=<remote id>&sysparm_delete_when_done=true&sysparm_is_remote=false&sysparm_ck=<token>`
  (`SNUI.export_update_set`). Hand-built XML once imported empty on the client instance.
- Then prove the file: push it through `sys_upload.do` (target `sys_remote_update_set`) and confirm the
  retrieved set shows every update (`SNUI.ui_import_test`), and delete the retrieved copy.
- **Never load an export back with `GlideUpdateManager2.loadXML` when the rows carry the local sys_ids** —
  that re-points the local set's own rows and empties it. Native exports carry fresh ids and are safe.
- Scheduled jobs (`sysauto_script`) are not update-set tracked on this release (`update_synch=false`):
  capture them with `new GlideUpdateManager2().saveRecord(gr)`. Same trick re-captures any unchanged
  record into a new set. Records edited with no change are not captured.
- A notification created by script must set `generation_type = 'event'` or the event processor ignores it.
- Pin the current update set with `new GlideUpdateSet().set(id)`; the pin persists per user across
  requests, so never run two builds concurrently. Switch scope with the concourse picker and, for global,
  also save the `apps.current_app` preference (the picker alone does not persist it).
- Completed sets refuse edits: reopen (`state = in progress`) in a separate transaction first.
- Before sending a file, a scrub scan and, for XML, a well-formedness parse.

## Code style Mihir expects (ServiceNow)
- Follow ServiceNow documented best practices; be ready to cite them. Script includes use
  `Class.create()` / `prototype` / `type`, meaningful names, single responsibility, `initialize` for config.
  Extend with `Object.extendsObject` when a second class shares logic.
- **One try/catch per feature**, in the entry point, logging a single `gs.error`. No `gs.info` / `gs.warn`
  chatter ("sent / received" style logs are unwanted). No return values that nothing consumes.
- **No defensive path/field validation helpers** (`pathValid`, `moduleReady`, `getED().getReference()`
  walks): treat configured dot-walk paths as valid.
- GlideAggregate exactly as documented: `addQuery('active', true)`, `addAggregate('COUNT')`, `groupBy(...)`,
  `getValue(field)` for group values, `parseInt(getAggregate('COUNT'))` — no radix argument.
- Never `JSON.stringify` a GlideRecord; render fields explicitly (display values for references/choices,
  formatted dates, strings). Dates via `GlideDateTime` / `GlideDate.getByFormat`.
- No custom tables for reporting logic; aggregate-first designs (collect owners with one grouped query per
  table, then one grouped query per owner per module).
- Anything an admin may need to customise (field lists per table, association tables, lists of
  supported tables) lives in **system properties** (`usem.<area>.<purpose>`, comma separated,
  `json_name=field` for renames), read at run time; scripts hold no such lists and no per-field
  "kind" flags - render by the dictionary internal type instead. Ship the properties in the same
  update set.
- One error message format per feature (`<class>: <what failed> for <table> <sys_id> - <reason>`);
  derive facts from the record (e.g. `current.operation()` for insert/update) instead of parameters.
- Comments only where genuinely needed (a config block header, a JSDoc on the public method). Clean,
  thorough, precise; no chatty comments.
- Business rules: prefer **one rule** with the whole lifecycle; condition selector limited to exactly the
  transitions the script acts on (e.g. `State changes to/from Resolved, to/from Closed, Reason changes
  to/from Pending Approval`); run last among before-rules (order 1000) and return early on
  `current.isActionAborted()`; never cancel/side-effect approval rows before knowing the save will happen.
- Consequence records in Deferred (2), Closed (3), Cancelled (4) never count; only Open counts.

## Testing standard
- Test on the PDI with real fixtures, twice for critical logic, positive and negative paths, and — for
  business rules — **every ordered state pair** and every Reason transition (probe rule with the identical
  selector + the real rule's effects). Report exact results (counts, contexts, approval rows).
- Fixture data on VR tables: out-of-box calculators rewrite `risk_rating`, auto-close jobs close
  detection-less VITs, and `deleteRecord()` from global silently no-ops on `sn_vul_*` tables — force values
  with `setWorkflow(false)` right before measuring and clean up by deactivate + unlink, not delete.
- Fixture record numbers can collide with old demo data (e.g. `VIT0010011`): always query by sys_id or link.

## Domain facts learned (Vulnerability Response / Configuration Compliance)
- Trident CRGs: `sn_vulc_result_group`; states 1 Open, 2 Under Investigation, 3 Closed, 10 Awaiting
  Implementation, 11 In Review, 12 Deferred, 101 Resolved; Reason (`substate`) 100 = Pending Approval,
  4 = Fixed. Flow "Trident Closure Approval" triggers on `substate=100 ^ approval!=requested ^ active=true`,
  run trigger *For each unique change* → a fresh cycle needs a condition field to change value; flipping
  `approval` to `not requested` while setting Reason = 100 in the same write always re-fires. Approval
  engine decision writes do not re-fire the trigger. `TridentClosureUtil` (sn_vulc) holds the shared logic.
- Owner of a finding = App Manager (`app_mgr_netid`, reference to user) on the **Primary AIT** of the
  finding's discovered record: AVIT `application_release.u_primary_ait`, VIT/CTR `src_ci.u_primary_ait`,
  CVIT (`sn_vul_container_image_vulnerable_item`) `discovered_container_image.u_bofa_primary_ait`.
  AIT table `x_boar_bofa_techad_ait`; consequence table `x_boar_bofa_usem_0_consequence` linked from each
  finding table by `u_consequence` (`u_consequence_level` 1/2, `state` 1 Open 2 Deferred 3 Closed 4 Cancelled).
- Remediation task tables: `sn_vul_vulnerability` (IVR), `sn_vul_app_vulnerability` (AVR),
  `sn_vul_container_vulnerability` (CVR), `sn_vulc_result_group` (CC). Change requests link through
  `sn_vul_m2m_vg_change_request`, `sn_vul_app_m2m_vg_change_request`,
  `sn_vul_container_m2m_remediation_task_change_request`, `sn_vulc_m2m_trg_change_request`; exception
  approvals are `sn_sec_exception_change_approval` (`record` + `table`, `approval_state` 1 Approved 4 Expired).
- Kafka outbound (SNOWUSEMTP-1625): topic `sn_usem_remtask_outbound`, namespace `com.bofa.usem`,
  envelope + `rem_tasks[].remediation_task`, dates `MM-dd-yyyy HH:mm:ss`, mapping sheet
  *Outbound to CDP (RemTask)*.

## Repository layout
- `tools/snui.py` – harness. `stories/<story>/` – scripts, build/fixture/test/export drivers, README.
  `stories/_update_sets/` – native exports of every delivered update set (index.json).
- Git: work on branch `claude/bofa-user-stories-build-l390e9`; commit story folders when asked; never
  commit secrets or AI/model identifiers in file contents.
