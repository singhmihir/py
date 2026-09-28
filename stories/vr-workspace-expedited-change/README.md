# VR workspace: Expedited change from Create Change

Request (28 Sep): creating a change from an application remediation task (AVUL) in the workspace offers no Expedited type,
the classic form does; add it and make it work. Mihir's direction after a first build with a page variant: no variants or
new records, edit the out-of-box page directly and change the script that creates the change (override allowed in the
script include); upgrade skips are accepted. Answers 28 Sep: the client instance already has an Expedited change model and
its flows (ship no model); ship the change_request Type choice list with Expedited.

## Why the workspace lacked it
- Classic form: `sn_vul_action_create_cr.change_request_type` takes its choices from `change_request.type`.
- Workspace: declarative action *Create Change* (`sn_vul_app_vulnerability` and `sn_vul_vulnerability`) opens the page
  *Modal - Create Change Request* (`sys_ux_macroponent` `59061b92b7072010aed5b064ce11a92c`); its *Change type* picker has
  three static items (standard, normal, emergency).
- Both paths call `sn_vul.ChangeMgmt().actionCreateChange()` -> `createNewChangeRequest()`, whose switch sends any other
  type to `ChangeRequest.newNormal()`: on a change-model instance the Normal model's preset (`type=normal`) is applied on
  insert and presets cannot change afterwards (rule *Change Model: read only presets*), so Expedited came out Normal.
- Out of box, `actionCreateChange` never stops on a missing change: its check is `change.isValid()`, which tests the table,
  not the record, so an empty id goes on to link an empty change to the task and write work notes.

## Change (batch `SNOWUSEMTP_MS_VR Workspace Expedited Change_V1.0`, 3 rows, one file)
- Parent (Global): `sys_choice_change_request_type`, the Type choice list standard, normal, emergency, expedited, model.
  A choice list update replaces the whole list on commit (Mihir accepted).
- Child `SNOWUSEMTP_MS_VR Workspace Expedited Change - Vulnerability Response_V1.0`:
  - page `59061b92b7072010aed5b064ce11a92c`: item `expedited` / *Expedited* / *Create an expedited Change Request.* in the
    Change type picker (plus both strings in `required_translations`); only `standard` is special-cased in the page.
  - `sn_vul.ChangeMgmt` (`ChangeMgmt.js`): `actionCreateChange` ends in error before anything is created when no active
    change model presets `type=expedited` (one `gs.error`; the staging record's error message, which the workspace dialog
    shows; the classic form shows its own generic "Unable to create the change request");
    `createNewChangeRequest` creates Expedited with `global.ChangeRequest.newChange(<that model>)`, the platform's own call,
    and fills the fields as the base does; every other type goes to the base unchanged.
- Exported with the platform's batch export (`UpdateSetExport.exportHierarchy`, `export_base_update_set.do`).

## PDI-only stand-ins (`fixtures.py apply|remove`, captured in the default sets, never delivered)
- The Create Change button needs plugin `sn_sow_chg` (on the client, not on the PDI): ChangeMgmt gets
  `isITSMAdvancedPluginActive` returning true on top of the delivered script.
- The client's Expedited change model: copy of Normal with the platform's Copy Model (`STTRMModel.copy`: 8 states,
  2 state attributes, 15 transitions, 10 transition conditions), preset `type=expedited`. The Normal flows trigger on the
  Normal model only, so on the PDI the stand-in gets no approvals; the client's model has its own flows.

## Tests (`test.py`; browser driver `test_browser.js` over `browser.js`)
Twice, on AVUL0010093, AVUL0010037, AVUL0010008, AVUL0010031: dialog options, Expedited submitted from the dialog
(staging type, change type and model, link), Normal submitted, Standard showing the template picker, the classic form's
path, and the negative path with the model switched off (nothing created or linked, task untouched, one error line).
Changes removed and tasks restored after each run.
Notes: Chrome's parallel connections through the local proxy fail (ERR_TOO_MANY_RETRIES), so `browser.js` fetches every
request through Playwright four at a time, on the proxy named in HTTPS_PROXY (its port changes between containers); a
global script cannot delete `sn_vul_*` rows (cross-scope policy), so staging records go through the Table API; deleting a
change runs rules that assign a global `o`, so test scripts name their result objects otherwise.

## Delivery (28 Sep)
Mihir applies the change by hand on bofadev (no update set import). On INC0010004: `VR Workspace Expedited Change -
Build Steps.docx` (`build_doc.js`: what changes, prerequisite model check, the two update sets, the dialog item by
background script `Add Expedited to Create Change Dialog.js` or by hand in the Composition field after the Emergency
item, `ChangeMgmt.js`, the Type choice, tests, undo), plus both scripts. The batch on the PDI (`build.py`, `export.py`)
stays as the reference; no XML was sent. UI Builder keeps out-of-box pages read-only, so the page is edited in the
record (`composition`, pretty-printed JSON, 4 spaces; `required_translations` is read-only and maintained by UI Builder,
not needed for the English labels).
