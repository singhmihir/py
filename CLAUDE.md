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
- Speed: `tools/pdi_keep_fast.py` (23 Sep) switched off the idle-instance load (Now Assist troubleshooting notifications,
  CMDB Get Well collectors, the ATF and Virtual Agent pollers), keeps 7 days of syslog, and installed the hourly job
  "PDI Keep Fast" that re-applies it and writes `pdi.keep_fast.last_run`; `--restore` puts the originals back. About 220
  `sys_trigger` rows dated 2013 or at the instance build look overdue but never run: count only the last day.
- Fixture users on the PDI: `vso.owner.one` / `vso.owner.two` (active), `vso.owner.gone` (inactive).
  Simulated BofA tables on the PDI live in scoped app `x_196061_bofasim` (`_ait` with `app_mgr_netid`,
  `_consequence` with `state` and `u_consequence_level`); Global custom columns get auto-prefixed
  `u_`, so unprefixed stand-in columns need a scoped table.
- An app created on the PDI carries the PDI's vendor prefix `x_196061_`, which every scoped property and
  API name inherits. To build a scoped story with the client's own names, insert a `sys_app` with the
  client's scope name and sys_id (`setNewGuidValue`) and set its `source` to that same scope name (the
  exporter stamps `source` on every `sys_scope` reference; rows captured before such a correction must be
  captured again), create the client's tables in it and build there — the native export then imports on
  the client instance as it is.

## How Mihir works
- **Drop-box incidents on the PDI** carry every file he passes to BofA: **INC0010003**
  (`b657ee9093064710e3aef0aefaba10c8`) for the Qualys CI lookup rules with their decks, walkthroughs and
  run scripts, **INC0010004** (`5689744193864f10e3aef0aefaba109e`) for the outbound integration stories
  (story zips in, deliverables out). Attach with a driver that deletes an attachment of the same name
  first (`stories/primary-ait-no-fields/attach.py`, `stories/1624-consequence-cdp-outbound/attach_1624.py`)
  and always add a comment saying what changed and what he or the client has to do next.
- **He runs read-only scripts on the client dev instance himself** and attaches the output back. When he
  is short of time he can run **exactly one**, so put everything needed into a single background script,
  say in the comment that it creates and updates nothing, and name the file to attach back.
- **He is often minutes from a meeting.** Deliver first and explain in a few lines afterwards; never ask
  permission mid-task and never hand back a plan in place of the artifact. But when a request can be read two
  ways (which script, which property, sync or async), ask the few concrete questions **before** building
  (AskUserQuestion, one line of context each): he asked for exactly that on 23 Sep after a merge was built on a
  wrong reading. Say what is on the PDI and what is already on the drop-box incident, so he looks at the right file.
- He reads deliverables closely and asks about details (a stray scope prefix in a property name, an empty
  record link, a slide that overflows). Everything inside a deliverable carries the client's own names.
- **Size is part of the deliverable**: a deck he cannot open or show has not been delivered. One worked
  example per rule unless he asks for more; keep the fuller data in the repository for a later build.
- No unrequested work alongside a change (no diagrams or documents he did not ask for).

## Explanation artifacts (decks, walkthrough documents)
- Shape he approved: per rule, pages for *what it looks for*, *how the script works* (numbered steps in
  two columns) and *when it declines*; then the worked example, and after it **step-by-step pages** — the
  step, what the script does at that point, what it found for this item, and a **link to every record and
  every filter** on the client dev instance (item, rule record, properties, the records walked, the CI).
  The links come from a read-only trace script he runs there, which records each search with its table,
  filter and the rows found with their sys_ids.
- Examples must be **dedicated to the rule** (no CI an earlier rule could have returned) and carry real
  values; vague matches get questioned by the client.
- Bank of America palette: red `E31837`, navy `012169`, dark grey `4D4F53` for body text, light grey page,
  white cards. PowerPoint does not shrink text to fit, so **measure every text box** and split content
  over more pages instead of crowding one.
- Check a build by rendering it (`soffice --headless --convert-to pdf`, then `pdftoppm`) and looking at
  the pages, not only at the data behind them.

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
  retrieved set shows every update (`SNUI.ui_import_test`), and delete the retrieved copy. The file carries
  the sys_ids of the exporter's temporary copy, which the platform deletes in the background after the
  download: an upload before that delete finishes loses random rows to it (measured: 21 and 15 of 24), and the
  retrieved set keeps the file's creation stamp. The harness waits for the copy to go and finds the retrieved
  set by the file's sys_id.
- **Never load an export back with `GlideUpdateManager2.loadXML` when the rows carry the local sys_ids** —
  that re-points the local set's own rows and empties it. Native exports carry fresh ids and are safe.
- Scheduled jobs (`sysauto_script`) and CI lookup rules (`sn_sec_cmn_ci_lookup_rule`, no `update_synch`
  attribute) are not update-set tracked on this release: capture them with
  `new GlideUpdateManager2().saveRecord(gr)` after the update. Same trick re-captures any unchanged
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
  thorough, precise; no chatty comments. **Exception, the CDP outbound payload builders** (VAMP,
  consequence): he asked for a JSDoc header on every function, input checks (record fetched and existing,
  property configured, every line well formed) and a validation of the finished payload before it leaves
  the processor — each failure one `gs.error` in the standard format, and an empty payload that stops the
  caller before anything is sent.
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
- Discovered Items (`sn_sec_cmn_src_ci`) hold each scanned host's payload (`source_data` JSON), the resolved CI and
  `state` matched/unmatched; the PDI holds 281,700 unmatched items from the client. VITs reach them through `src_ci`.
  `cmdb_ci_lb` (load balancer device) extends Server, not Network Gear; VIPs are `cmdb_ci_lb_service` (extends cmdb_ci).
- Qualys CI lookup rules (SNOWUSEMTP-895): 16 custom USEM rules, orders 175-850 (set V2.4), plus rules 420/430/460 (set V3.4, which also deletes the six former usem.ci_lookup.* properties), the class agreement set (350/410/705/730/740) and the 15 Sep refinements set (350/410 accept a Linux fingerprint on Network Gear / Load Balancer / Storage Server; 700/705/730/740 require the CI on the address to carry the scanned host name); `test_v6.py` holds the cases; `test_evidence.py` replays the client run lines with rebuilt evidence. The platform's `CIIdentify` drops retired CIs after a rule returns them when `sn_sec_cmn.filterOutDecommissionedCI` is true (its default; no property row on the PDI), so retired handling belongs to that property, not to the rules
  (management controllers, network interfaces, load balancer services). Mihir wants **no custom system properties** in these
  rules: every suffix / marker / product list is an inline array in the script (the general properties rule above does not
  apply here). Global, script method
  `process(rule, sourceValue, sourcePayload)`; exactly-one-match via `next()` / `hasNext()`, no `setLimit`;
  the OOB `CIIdentify._queryMatch` helper is private and returns the first duplicate, so it is not used.
  Comment style Mihir wants in delivered scripts: short header (purpose, **the sample payload**, input and returns
  with the sample values, the sample's outcome, place in the chain by rule name, never by order number), notes only
  on the matching stages and each ending with a `Sample:` sentence that walks the sample through the stage, inline
  sample values on the prep lines, no sample sys_ids or "data after this line" trails, written as first-hand notes
  on the client system.
- Qualys rules on the client dev instance are named `BOFA ...` (same orders as the PDI's `USEM ...`); rule 430 there
  reads the IP field (dead rule) and 450 runs a longer script than delivered. `measure_rules.js` (read-only, run by
  Mihir on the client instance, output attached to INC0010003) is the agreed way to judge the rules: 499/500 matched
  items reproduce, unmatched are 87% hosts absent from the CMDB, then class contradictions (44/500), address
  duplicates and retired records. Decisions 15 Sep: retired CIs stay candidates by the client's design expectation (do not propose excluding them
  again; the platform property `sn_sec_cmn.filterOutDecommissionedCI` governs it anyway); the appliance change was built the
  same day; a storage node rule stays a follow-up. `cmdb_ci_ip_phone` extends `cmdb_ci` directly and `cmdb_ci_scanner` sits
  under `cmdb_ci_imaging_hardware`, both outside the Hardware tree, so rule 415 `USEM Device Name Match` (set Device Name
  Match V1.0) resolves the contact-centre Avaya phones (`avx<mac tail>.cc.bofa.com`, no OS) and scanners by name. Unmatched
  items get an IRE placeholder in `cmdb_ci_unclassed_hardware` (ignored class, `matching_type created_by_ire`) and are only
  re-evaluated on re-import or reapply. Rule 455 `USEM Load Balancer Member Match` (set Load Balancer Member Match V1.0, before 460) walks Load Balancer
  Service -> Pool -> Pool Member -> server and returns the real server only when exactly one sits behind the virtual server;
  otherwise 460 attaches the VIP record. Client data 17 Sep: 634 items on 460, 6 on 455 (all servers). Set Load Balancer
  Refinements V1.0 (17 Sep, `build_rules_v9.py`): 350 refuses a load balancer device at the end of its chain; 455/460 treat
  several service records of one name (HA pair, test copy) as one virtual server recorded more than once (`service_one()` +
  `narrow()` in the generator: records on the scanned address kept, then the live ones; 460 returns the one record left and
  declines when two live records compete; 455 walks the pools of every record kept; two different names still decline);
  455 treats server records of one name (first label, case-insensitive) as one machine: a retired record is set aside for
  the live one, two live records decline, two different names decline. **Mihir's standard (17 Sep): "perfection in mapping",
  never match unless the exact record is found, leave ambiguity unmatched; no fitness heuristics (class depth, last update,
  "fittest twin") in any rule.** `retired()` mirrors the platform's decommissioned test (install_status 7, operational_status
  6, life cycle stage Retired). V1.1: 455 declines when any member leads to no server (partly unknown pool). V1.2 (Mihir:
  "service match is supposed to match lbservice"): 460 never reads the pool; it attaches the VIP record whenever the member
  rule cannot name the machine (two live twin records still decline). "Decline both" meant 455 declines a partly known pool
  and the VIP keeps the service record. Client service records carry no fqdn and are named `/Common/...`; fixtures must
  mimic that (no fqdn) or the OOB rule 900 FQDN matches them on the PDI. Reapply on the client: the job re-runs unmatched
  items plus items matched by rules flagged `reapply` (set when a rule's script/order/field changes), written only when CI
  or rule differ; matched items otherwise change only on a new import or the list action. bofadev shows US time, exports
  carry UTC: never compare the two. He also asked for no unrequested work (no diagrams, documents) alongside a rule change.
  `Load Balancer Member Match - Explain Script.js` replays the walk per item on the client instance.
  Rhino/GlideRecord trap: `'' + gr.getValue(f)` is the string "null" for an empty field and `addQuery(f, 'null')` selects the
  empty values; coerce with `|| ''` first. Rule 430 on the client instance reads the IP field and must be
  set back to DNS by their administrator. **Never change a lookup rule without asking him first.** Full state in
  `stories/qualys-ci-lookup-rules/README.md`.
- Ignore classes (SNOWUSEMTP-1825, `stories/ignore-ci-classes/`): `sn_sec_cmn.ignoreCIClass` (scope sn_sec_cmn, set
  `..._MS_Ignore CI Classes for Lookup Rules_V1.0` in that scope) now carries the story's 19 classes on top of the five OOB
  ones; the platform compares exact class names (`_checkCIIgnored`, no hierarchy). `cmdb_ci_lb` on the list removes the
  client's Linux-on-balancer matches (three in `test_evidence.py`, expected) and 850's vm_instance sample; Mihir ships it
  as listed and will have the client drop `cmdb_ci_lb` later. A property in a scoped app is captured by running the update
  in that scope (`ui.js(code, scope=<scope sys_id>)`) into a set whose application is that scope. Certificates (17 Sep
  evening): 2,370 client items sat on `cmdb_ci_certificate` via 850/NetBIOS; Ravali wants the class ignored, AIT logic is
  off limits; certificates on bofadev link to devices only through `cmdb_rel_ci` "Used by::Uses" (the Installed
  Certificate table never sets `server`); 244 lead to one live device, 194 of them out-of-band devices the existing rules
  match by name/address once re-evaluated; decision: no certificate rule, reapply the items with the list action. Reapply
  facts: the job takes unmatched items plus items of rules flagged `reapply`; the list action re-runs selected items
  regardless; `sn_sec_cmn.update_on_ci_change` true keeps vulnerable items and moves them in place.
- Kafka outbound (SNOWUSEMTP-1625): topic `sn_usem_remtask_outbound`, namespace `com.bofa.usem`,
  envelope + `rem_tasks[].remediation_task`, dates `MM-dd-yyyy HH:mm:ss`, mapping sheet
  *Outbound to CDP (RemTask)* — only rows with *CDP Required? = Yes*; one property per table with one
  `servicenow_field=json_field` pair per line; a field missing on the table or empty is sent as `""`.
  One script include only (`RemediationTaskPayloadBuilder`).
- Kafka stories, current sets (22 Sep review): 1625 `..._Remediation Task CDP Payload_V2.6` (global) plus the client copy
  record XML, producer `INC0010003_MS_Kafka Producer V2 with Payload Validation_V1.5` (record XML), 1624 `..._V1.5`,
  1804 `..._V2.3`. 23 Sep decisions: **one Kafka producer for remediation tasks and consequence**
  (`x_boar_bofa_usem_1.BOFA_SI_KafkaProducerV2`; the record's table picks the topic property in `TOPIC_PROPERTIES`:
  finding tables -> `x_boar_bofa_usem_1.x_boar_bofa.usem.kafka.topic_sys_id` (client's own), remediation task tables ->
  `REMEDIATION_TASK_TOPIC_PROPERTY` = the finding property until Mihir finalises their topic, consequence ->
  `x_boar_bofa_usem_0.usem.consequence.kafka.topic_sys_id` (stays in the consequence app); **synchronous send for all
  tables and the Kafka response shown on the record** (Mihir's answers 23 Sep); `BOFASIKafkaProducerConsequence` deleted
  (bofadev also has `BOFA_SI_KafkaProducer_Consequence`, IS_SYNC true); payload builders stay separate; VAMP keeps its
  own producer because AVIT is both a finding table and the VAMP table). The processors show two info messages, the
  payload and the configured fields the instance lacks; activity INSERT/UPDATE only; element_count compared strictly to the list. On the PDI
  the producer lives in the mirror of x_boar_bofa_usem_1 under the client's sys_id. Rendering contract of the CDP payloads (1625, 1624): choices as labels, plain integers as stored
  (display adds "1,250"), `[code]...[/code]` display markup as its visible text (`cr_count`), references `""` when the
  record is gone, journals from the latest `sys_journal_field` entry without its header; VAMP keeps its sheet types
  (Integer/String stored, Reference display). Each story keeps one field property + one topic property.
- Scoped-script traps (measured): `GlideElementDescriptor.getChoice()` does not exist in a scope (`isChoiceTable()` does);
  a record handed to a scoped include from inside a function of a global script refuses `getED()`
  (`StatefulElementDescriptor ... not allowed in scope`) - read descriptors from a GlideRecord the scoped code opens;
  `getRefRecord()` of a document id with an empty table field gives null or a method-less object, so test
  `typeof x.isValidRecord == 'function'`. A journal field is `nil()` on a loaded record; in an after rule
  `getJournalEntry(1)` already holds the comment of that save.
- Re-deliveries with new sys_ids: `sys_properties` names are unique (a second insert fails, so the client keeps the
  older value), script includes and rules duplicate. Keep the current sys_ids and put a DELETE for every earlier
  sys_id in the set (create the record under the old sys_id and delete it; a current property of that name steps
  aside meanwhile), recorded before the current rows; in record XML put `action="DELETE"` elements first (Import
  XML honours them and skips unknown sys_ids). `SNUI.ui_preview_test` runs the platform preview on the uploaded copy.
- Log checks: `syslog.sys_created_on` has one-second resolution, so a check block starts with `gs.sleep(1100)` before
  taking its start time and reads only lines at or after it. ProducerV2 is absent on the PDI:
  `new sn_ih_kafka.ProducerV2()` throws `undefined is not a function.`
- VAMP inbound (SNOWUSEMTP-1639, `stories/1639-vamp-inbound/`, drop-box INC0010013): consume `sn_usem_vamp_inbound` into
  an import set and transform (no flows), modelled on Mohammad's CDP IVR inbound (1615). Waiting for the payload; 16
  questions with plain explanations posted 23 Sep; blockers 1, 2, 5, 6, plus 7-9 if the story creates/updates AVITs, 12
  for testing on dev.

## Repository layout
- `tools/snui.py` – harness. `stories/<story>/` – scripts, build/fixture/test/export/attach drivers, README.
  `stories/_update_sets/` – native exports of every delivered update set (index.json).
- Git: the PDI is the system of record, GitHub the copy of the work. Since 23 Sep Mihir gives a free hand on
  GitHub: commit and push on my own (branch `claude/bofa-user-stories-build-l390e9`), and create or update the
  pull request as useful. Before every push, scan the commits for the password, the PDI user and AI/model
  identifiers in file contents; never commit secrets. Deliverables still go to him through the drop-box
  incidents on the PDI. Pull requests #1 and #2 were closed on 23 Sep (not by me): do not reopen one unasked.
- `singhmihir/py` was a public fork of codebasics/py. 23 Sep, at his request: history rewritten to this work only
  (`stories/`, `tools/`, `CLAUDE.md`, `pentaho-rest-client/`; the tutorials and their ~300 commits gone, master = this
  branch); he detaches it (Settings, Leave fork network) and makes it private himself, since this integration has no
  admin rights (repository creation 403) and the proxy refuses branch deletion (403). Until it is confirmed private,
  client files never go there. The files he uploads to the incidents (164 on 23 Sep, INC0010003/4/5/13, 1.68 GB,
  98 MB with xz) are rebuilt with `tools/incident_files.py <dir>` for a private repository.
