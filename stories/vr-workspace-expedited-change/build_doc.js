// Builds "VR Workspace Expedited Change - Build Steps.docx": how to add the Expedited change type to the workspace
// Create Change dialog and to the change creation code on the dev instance by hand (no update set import).
// Usage: NODE_MODULES=<dir with docx> node build_doc.js
const fs = require('fs');
const path = require('path');
const H = require('../1639-vamp-inbound/doc_helpers.js');
const { Document, Packer, Paragraph } = H.D;
const { NAVY, RED, t, p, body, h1, h2, code, bullet, numbered, rec, list, link, table, INST } = H;
const m = (s) => t(s, { mono: true, size: 18 });
const b = (s) => t(s, { bold: true });
const numbered2 = (runs) => new Paragraph({ children: Array.isArray(runs) ? runs : [t(runs)], numbering: { reference: 'steps2', level: 0 }, spacing: { after: 100, line: 260 } });
const numbered3 = (runs) => new Paragraph({ children: Array.isArray(runs) ? runs : [t(runs)], numbering: { reference: 'steps3', level: 0 }, spacing: { after: 100, line: 260 } });
const numbered4 = (runs) => new Paragraph({ children: Array.isArray(runs) ? runs : [t(runs)], numbering: { reference: 'steps4', level: 0 }, spacing: { after: 100, line: 260 } });
const numbered5 = (runs) => new Paragraph({ children: Array.isArray(runs) ? runs : [t(runs)], numbering: { reference: 'steps5', level: 0 }, spacing: { after: 100, line: 260 } });
const PAGE = '59061b92b7072010aed5b064ce11a92c';
const CHANGE_MGMT = '8d44bcd1b726330004aae3fdde11a95c';
const dialogScript = fs.readFileSync(path.join(__dirname, 'Add Expedited to Create Change Dialog.js'), 'utf8').trimEnd().split('\n');
const changeMgmt = fs.readFileSync(path.join(__dirname, 'ChangeMgmt.js'), 'utf8').trimEnd().split('\n');

const children = [];
children.push(new Paragraph({ children: [t('Expedited Change from the VR Workspace', { size: 38, bold: true, color: NAVY })], spacing: { after: 60 } }));
children.push(new Paragraph({ children: [t('Build steps on the dev instance: Create Change dialog, change creation code and Type choice', { size: 23, color: RED })], spacing: { after: 60 } }));
children.push(body('Prepared 28 September 2026. Three changes, made by hand on the dev instance and recorded in update sets for the higher instances.', { size: 18 }));

children.push(h1('1. What changes and what stays the same'));
children.push(table(['Record', 'Change', 'Scope'], [
  [[p([rec('sys_ux_macroponent', PAGE, 'Modal - Create Change Request')], { after: 0 })], 'Expedited added to the Change type list of the workspace Create Change dialog, after Standard, Normal and Emergency.', 'Vulnerability Response'],
  [[p([rec('sys_script_include', CHANGE_MGMT, 'ChangeMgmt')], { after: 0 })], 'An Expedited change is created from the Expedited change model through the platform change API. Before, every type other than Standard, Normal and Emergency came out as a Normal change, from the classic form too.', 'Vulnerability Response'],
  [[p([list('sys_choice', 'name=change_request^element=type', 'change_request Type choices')], { after: 0 })], 'The choice Expedited (value expedited), if it is not there yet.', 'Global'],
], [30, 52, 18]));
children.push(p([b('Everything else works as it does today. '), t('The new code runs only when the chosen type is '), m('expedited'),
  t('. Standard, Normal, Emergency and every other change model go through the out-of-box code unchanged, from the workspace dialog and from the classic Create Change form.')], { before: 120 }));

children.push(h1('2. Before you start'));
children.push(h2('The Expedited change model'));
children.push(p([t('Open '), list('chg_model', 'active=true', 'Change Models'), t(' (Change > Administration > Change Models). The Expedited model must be '),
  b('active'), t(' and its '), b('Record preset'), t(' must set '), b('Type = Expedited'), t('. The code looks the model up by that preset, so its name does not matter.')]));
children.push(p([t('Check the value behind the Expedited type in the '), list('sys_choice', 'name=change_request^element=type', 'Type choices'),
  t(': it must be '), m('expedited'), t('. The dialog item and the code use that value.')]));
children.push(h2('Update sets'));
children.push(body('The page and ChangeMgmt belong to Vulnerability Response and the choice to Global, so the work goes into two update sets. Making the second a child of the first keeps them together as one batch.'));
children.push(numbered([t('Application picker '), b('Global'), t(': create and select '), m('SNOWUSEMTP_MS_VR Workspace Expedited Change_V1.0'), t('.')]));
children.push(numbered([t('Application picker '), b('Vulnerability Response'), t(': create and select '), m('SNOWUSEMTP_MS_VR Workspace Expedited Change - Vulnerability Response_V1.0'),
  t(', with '), b('Parent'), t(' set to the Global set above.')]));
children.push(body('Sections 3 and 4 run with Vulnerability Response in the picker and its set selected; section 5 with Global and its set.'));

children.push(h1('3. Create Change dialog: add Expedited'));
children.push(p([t('The dialog is the UI Builder page '), rec('sys_ux_macroponent', PAGE, 'Modal - Create Change Request'),
  t(' (table sys_ux_macroponent). UI Builder keeps this out-of-box page read-only, so the change goes into the record itself, in its '),
  b('Composition'), t(' field: the JSON that describes every element of the page. The Change type list is the element '), m('change_type'),
  t('; its items are listed under '), m('propertyValues > items > container'), t('. Use method A or method B; both give the same result.')]));

children.push(h2('Method A (recommended): background script'));
children.push(numbered2([t('Application picker '), b('Vulnerability Response'), t(', update set '), m('... - Vulnerability Response_V1.0'), t('.')]));
children.push(numbered2([t('Open '), link(INST + 'sys.scripts.do', 'Scripts - Background'), t(', leave the scope on global, paste the script below and run it.')]));
children.push(numbered2([t('The output must read '), m('Change type items: standard, normal, emergency, expedited'), t('. Running it again changes nothing.')]));
children.push(numbered2([t('Open the update set: its Customer Updates list shows '), m('sys_ux_macroponent_' + PAGE), t('.')]));
code(dialogScript).forEach((x) => children.push(x));

children.push(h2('Method B: edit the Composition field by hand'));
children.push(numbered3([t('Application picker '), b('Vulnerability Response'), t(', update set '), m('... - Vulnerability Response_V1.0'), t('.')]));
children.push(numbered3([t('Open '), rec('sys_ux_macroponent', PAGE, 'Modal - Create Change Request'), t(' and click into the '), b('Composition'), t(' field.')]));
children.push(numbered3([t('Search (Ctrl+F) for '), m('"value": "emergency"'), t('. It occurs once: the id of the Emergency item.')]));
children.push(numbered3([t('Go down to the end of that item. It ends with these lines (the last '), m('}'), t(' closes the item, and the next line is '), m(']'), t(', which closes the list):')]));
code([
  '                "message": "Create an emergency Change Request"',
  '            }',
  '        }',
  '    },',
  '    "type": "MAP_CONTAINER"',
  '}',
  ']',
]).forEach((x) => children.push(x));
children.push(numbered3([t('Directly after that '), m('}'), t(' and before the '), m(']'), t(', type a comma and paste the block below. Indentation does not matter.')]));
code([
  ',',
  '{',
  '    "container": {',
  '        "id": { "type": "JSON_LITERAL", "value": "expedited" },',
  '        "label": { "type": "TRANSLATION_LITERAL", "value": { "code": null, "comment": "", "message": "Expedited" } },',
  '        "sublabel": { "type": "TRANSLATION_LITERAL", "value": { "code": null, "comment": "", "message": "Create an expedited Change Request." } }',
  '    },',
  '    "type": "MAP_CONTAINER"',
  '}',
]).forEach((x) => children.push(x));
children.push(numbered3([t('Click '), b('Update'), t('. The form refuses JSON that does not parse; if it does, compare the pasted block with the one above (usually the comma).')]));
children.push(p([t('Result: the Change type list offers Standard, Normal, Emergency and Expedited. The page only treats Standard differently (template picker instead of the implementation plan), so Expedited shows the same fields as Normal and Emergency.')], { before: 80 }));

children.push(h1('4. Change creation: ChangeMgmt'));
children.push(p([t('Both the workspace dialog and the classic Create Change form call '), m('actionCreateChange'), t(' of '),
  rec('sys_script_include', CHANGE_MGMT, 'ChangeMgmt'), t(' (API name '), m('sn_vul.ChangeMgmt'),
  t('). Out of box it is an empty extension of '), m('ChangeMgmtBase'), t(', meant for overrides. Two functions are overridden:')]));
children.push(bullet([m('actionCreateChange'), t(': for Expedited, checks that an active change model presets Type = Expedited. Without one it stops with an error ("No active change model presets the Expedited type.") before anything is created or linked, and logs one error line. Every other type goes straight to the base.')]));
children.push(bullet([m('createNewChangeRequest'), t(': for Expedited, creates the change with '), m('global.ChangeRequest.newChange(<Expedited model>)'),
  t(', so the model applies its presets, states and flows, then fills the same fields as the base (parent task, descriptions, implementation plan, assignment, planned end date, priority, justification). Every other type goes to the base.')]));
children.push(numbered4([t('Application picker '), b('Vulnerability Response'), t(', update set '), m('... - Vulnerability Response_V1.0'), t('.')]));
children.push(numbered4([t('Open '), rec('sys_script_include', CHANGE_MGMT, 'ChangeMgmt'), t('. If its script is only the empty class (a '), m("type: 'ChangeMgmt'"),
  t(' line and nothing else), replace the whole script with the one below. If it already holds other code, keep that code and add the constant '),
  m('EXPEDITED'), t(' and the three functions next to it.')]));
children.push(numbered4([t('Click '), b('Update'), t('. The update set shows '), m('sys_script_include_' + CHANGE_MGMT), t('.')]));
code(changeMgmt).forEach((x) => children.push(x));

children.push(h1('5. Type choice (Global)'));
children.push(numbered5([t('Application picker '), b('Global'), t(', update set '), m('SNOWUSEMTP_MS_VR Workspace Expedited Change_V1.0'), t('.')]));
children.push(numbered5([t('Open the '), list('sys_choice', 'name=change_request^element=type', 'Type choices of change_request'), t('. If a row with value '), m('expedited'), t(' is there, this step is done.')]));
children.push(numbered5([t('Otherwise click '), b('New'), t(': Table '), m('change_request'), t(', Element '), m('type'), t(', Label '), m('Expedited'),
  t(', Value '), m('expedited'), t(', Language '), m('en'), t(', Sequence '), m('4'), t(', and Submit.')]));

children.push(h1('6. Test'));
children.push(bullet([b('Workspace: '), t('open an application remediation task (AVUL) in the IT Remediation Workspace, click Create Change, choose Expedited and click Create change request. The new change has type Expedited, the Expedited model and the remediation task as parent, and appears on the task.')]));
children.push(bullet([b('Other types: '), t('Normal and Emergency still create Normal and Emergency changes; Standard still asks for a template.')]));
children.push(bullet([b('Classic form: '), t('Create Change on the remediation task form with type Expedited gives the same Expedited change.')]));
children.push(bullet([b('IT remediation tasks: '), t('the same dialog and code serve Create Change on remediation tasks of Vulnerability Response, so Expedited is there as well.')]));

children.push(h1('7. Undo'));
children.push(bullet('Dialog: remove the Expedited block from the Composition field (method B, in reverse), or revert the page to its previous version in the Versions list of the record.'));
children.push(bullet('ChangeMgmt: put back the previous script (Versions list of the record).'));
children.push(bullet('Choice: delete the Expedited row only if it was added in section 5.'));

const doc = new Document({
  creator: 'Mihir Singh',
  styles: { default: { document: { run: { font: H.FONT, size: 20, color: H.INK } } } },
  numbering: { config: ['steps', 'steps2', 'steps3', 'steps4', 'steps5'].map((ref) => ({ reference: ref, levels: [{ level: 0, format: 'decimal', text: '%1.', alignment: 'left',
    style: { paragraph: { indent: { left: 540, hanging: 360 } } } }] })) },
  sections: [{ properties: { page: { margin: { top: 1000, bottom: 1000, left: 1000, right: 1000 } } }, children: children }],
});
const out = path.join(__dirname, 'VR Workspace Expedited Change - Build Steps.docx');
Packer.toBuffer(doc).then((buf) => { fs.writeFileSync(out, buf); console.log('written:', out, buf.length, 'bytes'); });
