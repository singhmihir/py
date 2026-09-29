// Builds "VR Workspace Expedited Change - Build Steps.docx": how to add the Expedited change type to the workspace
// Create Change dialogs and to the change creation code of every remediation task type on the dev instance by hand
// (no update set import). Usage: NODE_MODULES=<dir with docx> node build_doc.js
const fs = require('fs');
const path = require('path');
const H = require('../1639-vamp-inbound/doc_helpers.js');
const { Document, Packer, Paragraph } = H.D;
const { NAVY, RED, t, p, body, h1, h2, code, bullet, rec, list, link, table, INST } = H;
const m = (s) => t(s, { mono: true, size: 18 });
const b = (s) => t(s, { bold: true });
const LISTS = ['steps', 'steps2', 'steps3', 'steps4', 'steps5', 'steps6', 'steps7'];
const num = (ref) => (runs) => new Paragraph({ children: Array.isArray(runs) ? runs : [t(runs)], numbering: { reference: ref, level: 0 }, spacing: { after: 100, line: 260 } });
const [n1, n2, n3, n4, n5, n6, n7] = LISTS.map(num);
const note = (runs) => new Paragraph({ children: runs, spacing: { before: 80, after: 140, line: 260 }, indent: { left: 180, right: 180 },
  shading: { type: 'clear', fill: 'FCE8EC' }, border: { left: { style: 'single', size: 18, color: RED, space: 6 } } });
const read = (f) => fs.readFileSync(path.join(__dirname, f), 'utf8').trimEnd().split('\n');

const PAGES = [
  ['59061b92b7072010aed5b064ce11a92c', 'Modal - Create Change Request', 'Vulnerability Response', 'IT and application remediation tasks (VUL, AVUL)'],
  ['fd9d6e2953021110501fddeeff7b1296', 'Modal - Container Create Change Request default', 'Vulnerability Response and Configuration Compliance for Containers', 'container remediation tasks (CVUL)'],
  ['996c1f486db42110f877388cdecc4b6f', 'Modal - CC Create Change Request', 'Configuration Compliance', 'Configuration Compliance remediation tasks (CRG)'],
];
const SI = { vr: '8d44bcd1b726330004aae3fdde11a95c', cvul: '1976d74581391150f8772bff535ed770', crg: '73c7954fc74c201032589ef727c26008' };
const SETS = {
  parent: 'SNOWUSEMTP_MS_VR Workspace Expedited Change_V1.0',
  vr: 'SNOWUSEMTP_MS_VR Workspace Expedited Change - Vulnerability Response_V1.0',
  cvul: 'SNOWUSEMTP_MS_VR Workspace Expedited Change - Containers_V1.0',
  crg: 'SNOWUSEMTP_MS_VR Workspace Expedited Change - Configuration Compliance_V1.0',
};
const ccEdits = JSON.parse(fs.readFileSync(path.join(__dirname, 'cc_edits.json'), 'utf8'));
const lines = (s) => s.replace(/\n$/, '').split('\n');

const children = [];
children.push(new Paragraph({ children: [t('Expedited Change from the VR Workspace', { size: 38, bold: true, color: NAVY })], spacing: { after: 60 } }));
children.push(new Paragraph({ children: [t('Build steps on the dev instance for every remediation task type: dialogs, change creation code, Type choice', { size: 23, color: RED })], spacing: { after: 60 } }));
children.push(body('Prepared 29 September 2026. Made by hand on the dev instance and recorded in update sets for the higher instances.', { size: 18 }));

children.push(h1('1. What changes and what stays the same'));
children.push(table(['Record', 'Change', 'Application'], [
  ...PAGES.map((pg) => [[p([rec('sys_ux_macroponent', pg[0], pg[1])], { after: 0 })], 'Create Change dialog of ' + pg[3] + ': Expedited added after Standard, Normal and Emergency.', pg[2]]),
  [[p([rec('sys_script_include', SI.vr, 'ChangeMgmt')], { after: 0 })], 'IT and application remediation tasks: an Expedited change is created from the Expedited change model. Also finds that model for the other two applications.', 'Vulnerability Response'],
  [[p([rec('sys_script_include', SI.cvul, 'ChangeMgmt')], { after: 0 })], 'Container remediation tasks: an Expedited change is created from the Expedited change model.', 'Containers'],
  [[p([rec('sys_script_include', SI.crg, 'ChangeMgmt')], { after: 0 })], 'Configuration Compliance remediation tasks: two small edits in the out-of-box code, which has no extension to override.', 'Configuration Compliance'],
  [[p([list('sys_choice', 'name=change_request^element=type', 'change_request Type choices')], { after: 0 })], 'The choice Expedited (value expedited), if it is not there yet.', 'Global'],
], [30, 50, 20]));
children.push(p([b('Everything else works as it does today. '), t('The new code runs only when the chosen type is '), m('expedited'),
  t('. Standard, Normal, Emergency and every other change model go through the out-of-box code unchanged, from the workspace dialogs and from the classic Create Change forms. Before this change, Expedited picked on a classic form came out as a Normal change; it now comes out as Expedited there too.')], { before: 120 }));

children.push(h1('2. Before you start'));
children.push(h2('The Expedited change model'));
children.push(p([t('Open '), list('chg_model', 'active=true', 'Change Models'), t(' (Change > Administration > Change Models). The Expedited model must be '),
  b('active'), t(' and its '), b('Record preset'), t(' must set '), b('Type = Expedited'), t('. The code looks the model up by that preset, so its name does not matter.')]));
children.push(p([t('Check the value behind the Expedited type in the '), list('sys_choice', 'name=change_request^element=type', 'Type choices'),
  t(': it must be '), m('expedited'), t('. The dialog items and the code use that value.')]));
children.push(h2('Update sets'));
children.push(body('Each record belongs to one application, so the work goes into one update set per application. Making the three application sets children of the Global set keeps them together as one batch.'));
children.push(n1([t('Application picker '), b('Global'), t(': create '), m(SETS.parent), t('.')]));
children.push(n1([t('Application picker '), b('Vulnerability Response'), t(': create '), m(SETS.vr), t(', Parent = the Global set.')]));
children.push(n1([t('Application picker '), b('Vulnerability Response and Configuration Compliance for Containers'), t(': create '), m(SETS.cvul), t(', Parent = the Global set.')]));
children.push(n1([t('Application picker '), b('Configuration Compliance'), t(': create '), m(SETS.crg), t(', Parent = the Global set.')]));
children.push(body('Every step below names the application to select in the picker; select its update set with it.'));

children.push(h1('3. Create Change dialogs: add Expedited'));
children.push(p([t('Each dialog is a UI Builder page (table sys_ux_macroponent). UI Builder keeps these out-of-box pages read-only, so the change goes into the record itself, in its '),
  b('Composition'), t(' field: the JSON that describes every element of the page. The Change type list is the element '), m('change_type'),
  t('; its items are listed under '), m('propertyValues > items > container'), t('. Use method A or method B; both give the same result.')]));
children.push(table(['Dialog', 'Application', 'Serves'], PAGES.map((pg) => [[p([rec('sys_ux_macroponent', pg[0], pg[1])], { after: 0 })], pg[2], pg[3]]), [38, 34, 28]));

children.push(h2('Method A (recommended): background script'));
children.push(body('The script changes the dialog of the application selected in the picker, so it runs three times, once per application.'));
children.push(n2([t('Select '), b('Vulnerability Response'), t(' in the application picker (and its update set). Open '), link(INST + 'sys.scripts.do', 'Scripts - Background'),
  t(', leave the scope on global, paste the script below and run it. The output reads '), m('Modal - Create Change Request - Change type items: standard, normal, emergency, expedited'), t('.')]));
children.push(n2([t('Select '), b('Vulnerability Response and Configuration Compliance for Containers'), t(' and run the same script: '), m('Modal - Container Create Change Request default - Change type items: standard, normal, emergency, expedited'), t('.')]));
children.push(n2([t('Select '), b('Configuration Compliance'), t(' and run it again: '), m('Modal - CC Create Change Request - Change type items: standard, normal, emergency, expedited'), t('.')]));
children.push(n2('Running it again changes nothing. Each update set now lists its page under Customer Updates.'));
code(read('Add Expedited to Create Change Dialog.js')).forEach((x) => children.push(x));

children.push(h2('Method B: edit the Composition field by hand'));
children.push(note([b('Only add. '), t('The Standard, Normal and Emergency items stay exactly as they are; the new block goes after the Emergency item. Replacing or deleting the Emergency block removes Emergency from the dialog.')]));
children.push(body('For each of the three dialogs, with its application selected in the picker:'));
children.push(n3([t('Open the dialog record (links in the table above) and click into the '), b('Composition'), t(' field.')]));
children.push(n3([t('Search (Ctrl+F) for '), m('"value": "emergency"'), t('. It occurs once: the id of the Emergency item.')]));
children.push(n3([t('Go down to the end of that item. It ends with these lines: the last '), m('}'), t(' closes the Emergency item and the next line, '), m(']'), t(', closes the list.')]));
code(['                "message": "Create an emergency Change Request"', '            }', '        }', '    },', '    "type": "MAP_CONTAINER"', '}', ']']).forEach((x) => children.push(x));
children.push(n3([t('Put the cursor right after that '), m('}'), t(' (before the '), m(']'), t(') and paste the block below, starting with its comma. Indentation does not matter.')]));
code([',', '{', '    "container": {', '        "id": { "type": "JSON_LITERAL", "value": "expedited" },',
  '        "label": { "type": "TRANSLATION_LITERAL", "value": { "code": null, "comment": "", "message": "Expedited" } },',
  '        "sublabel": { "type": "TRANSLATION_LITERAL", "value": { "code": null, "comment": "", "message": "Create an expedited Change Request." } }',
  '    },', '    "type": "MAP_CONTAINER"', '}']).forEach((x) => children.push(x));
children.push(n3([t('The end of the list now reads: the Emergency item, then '), m('},'), t(', then the Expedited item, then '), m(']'), t('. Click '), b('Update'),
  t('. The form refuses JSON that does not parse; if it does, compare the pasted block with the one above (usually the comma).')]));
children.push(p([t('Result: each dialog offers Standard, Normal, Emergency and Expedited. The dialogs treat only Standard differently (template picker), so Expedited shows the same fields as Normal and Emergency.')], { before: 80 }));

children.push(h1('4. ChangeMgmt: Vulnerability Response'));
children.push(p([t('Used by IT and application remediation tasks. Both the workspace dialog and the classic Create Change form call '), m('actionCreateChange'), t(' of '),
  rec('sys_script_include', SI.vr, 'ChangeMgmt'), t(' (API name '), m('sn_vul.ChangeMgmt'), t('). Out of box it is an empty extension of '), m('ChangeMgmtBase'), t(', meant for overrides.')]));
children.push(bullet([m('actionCreateChange'), t(': for Expedited, checks that an active change model presets Type = Expedited. Without one it stops with the error "No active change model presets the Expedited type." before anything is created or linked, and logs one error line. Every other type goes straight to the base.')]));
children.push(bullet([m('createNewChangeRequest'), t(': for Expedited, creates the change with '), m('global.ChangeRequest.newChange(<Expedited model>)'),
  t(', so the model applies its presets, states and flows, then fills the same fields as the base. Every other type goes to the base.')]));
children.push(bullet([m('getExpeditedChangeModel'), t(': finds the Expedited model; the Containers and Configuration Compliance code call it too.')]));
children.push(n4([t('Application picker '), b('Vulnerability Response'), t(', update set '), m(SETS.vr), t('.')]));
children.push(n4([t('Open '), rec('sys_script_include', SI.vr, 'ChangeMgmt'), t('. If its script is only the empty class (a '), m("type: 'ChangeMgmt'"),
  t(' line and nothing else), replace the whole script with the one below. If it already holds other code, keep that code and add the constant and the three functions next to it.')]));
children.push(n4([t('Click '), b('Update'), t('.')]));
code(read('ChangeMgmt.js')).forEach((x) => children.push(x));

children.push(h1('5. ChangeMgmt: Containers'));
children.push(p([t('Used by container remediation tasks: '), rec('sys_script_include', SI.cvul, 'ChangeMgmt'), t(' (API name '), m('sn_vul_container.ChangeMgmt'),
  t('), also an empty extension out of box, of the containers '), m('ChangeMgmtBase'), t('. Same two functions as section 4; the model comes from the Vulnerability Response ChangeMgmt.')]));
children.push(n5([t('Application picker '), b('Vulnerability Response and Configuration Compliance for Containers'), t(', update set '), m(SETS.cvul), t('.')]));
children.push(n5([t('Open '), rec('sys_script_include', SI.cvul, 'ChangeMgmt'), t('. If its script is only the empty class, replace it with the one below; otherwise keep the existing code and add the constant and the two functions.')]));
children.push(n5([t('Click '), b('Update'), t('.')]));
code(read('ChangeMgmt (Containers).js')).forEach((x) => children.push(x));

children.push(h1('6. ChangeMgmt: Configuration Compliance'));
children.push(p([t('Used by Configuration Compliance remediation tasks: '), rec('sys_script_include', SI.crg, 'ChangeMgmt'), t(' (API name '), m('sn_vulc.ChangeMgmt'),
  t('). This one is the full out-of-box code with no extension, so it is edited in place: two edits, each replacing the first line(s) of a function.')]));
children.push(n6([t('Application picker '), b('Configuration Compliance'), t(', update set '), m(SETS.crg), t('.')]));
children.push(n6([t('Open '), rec('sys_script_include', SI.crg, 'ChangeMgmt'), t(' and make the two edits below. Each "find" text occurs once in the script.')]));
children.push(n6([t('Click '), b('Update'), t('.')]));
ccEdits.forEach((e, i) => {
  children.push(h2('Edit ' + (i + 1) + ': ' + e.where));
  children.push(p([t(i === 0 ? 'Find the first line of the function:' : 'Find the first two lines of the function:')]));
  code(lines(e.find)).forEach((x) => children.push(x));
  children.push(p([t(i === 0 ? 'Replace it with (the same line, then the check for the Expedited model):' : 'Replace them with (Expedited is created from its model; every other type exactly as before):')]));
  code(lines(e.replace)).forEach((x) => children.push(x));
});
children.push(body('The rest of the function stays as it is: for Expedited it goes on to fill the fields and sets the type to expedited, which the model presets as well.'));

children.push(h1('7. Type choice (Global)'));
children.push(n7([t('Application picker '), b('Global'), t(', update set '), m(SETS.parent), t('.')]));
children.push(n7([t('Open the '), list('sys_choice', 'name=change_request^element=type', 'Type choices of change_request'), t('. If a row with value '), m('expedited'), t(' is there, this step is done.')]));
children.push(n7([t('Otherwise click '), b('New'), t(': Table '), m('change_request'), t(', Element '), m('type'), t(', Label '), m('Expedited'),
  t(', Value '), m('expedited'), t(', Language '), m('en'), t(', Sequence '), m('4'), t(', and Submit.')]));

children.push(h1('8. Test'));
children.push(body('In the IT Remediation Workspace, for one remediation task of each type (VUL, AVUL, CVUL, CRG):'));
children.push(bullet([b('Expedited: '), t('Create Change, choose Expedited, Create change request. The new change has type Expedited, the Expedited model and the remediation task as parent, and appears on the task.')]));
children.push(bullet([b('Other types: '), t('Normal and Emergency still create Normal and Emergency changes; Standard still asks for a template.')]));
children.push(bullet([b('Classic form: '), t('Create Change on the remediation task form with type Expedited gives the same Expedited change.')]));
children.push(p([t('Out of box, in the container and Configuration Compliance dialogs, choosing Standard first and then another type leaves Create change request greyed out; closing and reopening the dialog clears it. This is not part of this change.')], { before: 80 }));

children.push(h1('9. Undo'));
children.push(bullet('Dialogs: remove the Expedited block from the Composition field, or revert the page in the Versions list of the record.'));
children.push(bullet('ChangeMgmt (all three): put back the previous script from the Versions list of the record.'));
children.push(bullet('Choice: delete the Expedited row only if it was added in section 7.'));

const doc = new Document({
  creator: 'Mihir Singh',
  styles: { default: { document: { run: { font: H.FONT, size: 20, color: H.INK } } } },
  numbering: { config: LISTS.map((ref) => ({ reference: ref, levels: [{ level: 0, format: 'decimal', text: '%1.', alignment: 'left',
    style: { paragraph: { indent: { left: 540, hanging: 360 } } } }] })) },
  sections: [{ properties: { page: { margin: { top: 1000, bottom: 1000, left: 1000, right: 1000 } } }, children: children }],
});
const out = path.join(__dirname, 'VR Workspace Expedited Change - Build Steps.docx');
Packer.toBuffer(doc).then((buf) => { fs.writeFileSync(out, buf); console.log('written:', out, buf.length, 'bytes'); });
