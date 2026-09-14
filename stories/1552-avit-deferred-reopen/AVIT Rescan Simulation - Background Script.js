/* AVIT rescan simulation (SNOWUSEMTP-1552)
   Plays a scanner "closed, then found again" on one application vulnerable item: the two writes the
   AVR import API makes on the item record. Every business rule on the item runs as during an import.
   Take SYS_ID from the item's form URL (numbers are not unique on these instances). The item must be
   Deferred through an approved exception: that leaves the Until date in ignore_expiration and the
   reason in backup_substate, which the platform rule reads. An item deferred by editing the form has
   neither; PREPARE_DEFERRAL = true fills the two fields the way an approval would, for a test item. */

var SYS_ID = '';                // sys_id of the deferred application vulnerable item
var CLOSE_SUBSTATE = 4;         // 4 = Fixed (scanner reports the finding fixed), 6 = Stale (auto-close rule)
var PREPARE_DEFERRAL = false;   // true: copy Until and reason into the fields an approval fills

var PROPERTY = 'sn_vul.auto_defer_avit_in_active_exception_window';
var TABLE = 'sn_vul_app_vulnerable_item';

function item() {
    var gr = new GlideRecord(TABLE);
    gr.get(SYS_ID);
    return gr;
}

function describe(gr) {
    return 'state ' + gr.getDisplayValue('state') + ' (' + gr.getValue('state') + ') / ' + (gr.getDisplayValue('substate') || '-') +
        ', active ' + gr.getValue('active') + ', until date ' + (gr.getValue('ignore_expiration') || '-') +
        ', until date-time ' + (gr.getValue('ignore_expiration_dt_tm') || '-') + ', backup substate ' + (gr.getValue('backup_substate') || '-') +
        ', ignored by ' + (gr.getDisplayValue('ignored_by') || '-') + ', defer count ' + (gr.getValue('defer_count') || '0') +
        ', reopened ' + gr.getValue('reopened') + ' (' + (gr.getValue('reopened_count') || '0') + ')';
}

function lastNote(gr) {
    var note = new GlideRecord('sys_journal_field');
    note.addQuery('element_id', gr.getUniqueValue());
    note.addQuery('element', 'work_notes');
    note.orderByDesc('sys_created_on');
    note.setLimit(1);
    note.query();
    return note.next() ? note.getValue('value') : '-';
}

function sameNumber(gr) {
    var other = new GlideRecord(TABLE);
    other.addQuery('number', gr.getValue('number'));
    other.query();
    return other.getRowCount();
}

function prepareDeferral(gr) {
    gr.setValue('ignore_expiration', new GlideDateTime(gr.getValue('ignore_expiration_dt_tm')).getDate());
    gr.setValue('backup_substate', gr.getValue('substate'));
    gr.update();
}

function scanner(label, state, substate) {
    var gr = item();
    gr.setValue('state', state);
    if (substate)
        gr.setValue('substate', substate);
    var saved = gr.update();
    var after = item();
    var outcome = saved ? '' : ' - update refused: ' + gs.getErrorMessages();
    if (saved && after.getValue('state') == '12' && state == 1)
        outcome = ' - put back to Deferred by the platform rule';
    else if (saved && after.getValue('state') != state)
        outcome = ' - the state write was undone by a rule (now ' + after.getDisplayValue('state') + ')';
    gs.print(label + outcome);
    gs.print('   ' + describe(after));
    gs.print('   last work note: ' + lastNote(after));
}

var start = item();
if (!start.isValidRecord())
    gs.print('No application vulnerable item with sys_id ' + SYS_ID);
else {
    gs.print('Property ' + PROPERTY + ' = ' + gs.getProperty(PROPERTY) + ', session time zone ' + gs.getSession().getTimeZoneName() + ', today ' + new GlideDate().getValue());
    gs.print('Item ' + start.getValue('number') + ' (' + sameNumber(start) + ' item(s) carry this number), source ' + (start.getDisplayValue('source') || '-') + ', vulnerability ' + (start.getDisplayValue('vulnerability') || '-') + ', CI ' + (start.getDisplayValue('cmdb_ci') || '-'));
    if (PREPARE_DEFERRAL && start.getValue('state') == '12')
        prepareDeferral(start);
    gs.print('1. Before');
    gs.print('   ' + describe(item()));
    if (!item().getValue('ignore_expiration') || !item().getValue('backup_substate'))
        gs.print('   The platform rule needs the until date and the backup substate; this item lacks one of them, so it will re-open as Open. Defer it through an approved exception, or set PREPARE_DEFERRAL = true on a test item.');
    scanner('2. Scanner reports the finding fixed', 3, CLOSE_SUBSTATE);
    scanner('3. Scanner finds it again', 1);
}
