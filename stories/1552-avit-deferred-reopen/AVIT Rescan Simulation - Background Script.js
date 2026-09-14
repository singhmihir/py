/* AVIT rescan simulation (SNOWUSEMTP-1552)
   Plays a scanner "closed, then found again" on one application vulnerable item: the two writes the
   AVR import API makes on the item record. Every business rule on the item runs as during an import.
   Run in Scripts - Background with the property sn_vul.auto_defer_avit_in_active_exception_window
   false, then true, on an item that is Deferred with a future Until date. */

var NUMBER = 'AVIT0000000';   // the deferred application vulnerable item
var CLOSE_SUBSTATE = 4;       // 4 = Fixed (scanner reports the finding fixed), 6 = Stale (auto-close rule)

var PROPERTY = 'sn_vul.auto_defer_avit_in_active_exception_window';
var TABLE = 'sn_vul_app_vulnerable_item';

function item() {
    var gr = new GlideRecord(TABLE);
    gr.get('number', NUMBER);
    return gr;
}

function snapshot(label) {
    var gr = item();
    var note = new GlideRecord('sys_journal_field');
    note.addQuery('element_id', gr.getUniqueValue());
    note.addQuery('element', 'work_notes');
    note.orderByDesc('sys_created_on');
    note.setLimit(1);
    note.query();
    gs.print(label);
    gs.print('   state ' + gr.getDisplayValue('state') + ' / ' + (gr.getDisplayValue('substate') || '-') +
        ', active ' + gr.getValue('active') + ', until ' + (gr.getValue('ignore_expiration') || '-') +
        ', backup substate ' + (gr.getValue('backup_substate') || '-') + ', defer count ' + (gr.getValue('defer_count') || '0') +
        ', reopened ' + gr.getValue('reopened') + ' (' + (gr.getValue('reopened_count') || '0') + ')');
    gs.print('   deferred tasks of this item: ' + deferredTasks(gr) + ', last work note: ' + (note.next() ? note.getValue('value') : '-'));
}

function deferredTasks(gr) {
    var names = [];
    var link = new GlideRecord('sn_vul_app_m2m_vul_group_item');
    link.addQuery(TABLE, gr.getUniqueValue());
    link.addQuery('sn_vul_app_vulnerability.state', 12);
    link.query();
    while (link.next())
        names.push(link.sn_vul_app_vulnerability.getDisplayValue());
    return names.length ? names.join(', ') : 'none';
}

function scanner(label, state, substate) {
    var gr = item();
    gr.setValue('state', state);
    if (substate)
        gr.setValue('substate', substate);
    var saved = gr.update();
    snapshot(label + (saved ? '' : ' - update refused: ' + gs.getErrorMessages()));
}

if (!item().isValidRecord())
    gs.print('No application vulnerable item ' + NUMBER);
else {
    gs.print('Property ' + PROPERTY + ' = ' + gs.getProperty(PROPERTY) + ', session time zone ' + gs.getSession().getTimeZoneName() + ', today ' + new GlideDate().getValue());
    snapshot('1. Before');
    scanner('2. Scanner reports the finding fixed', 3, CLOSE_SUBSTATE);
    scanner('3. Scanner finds it again', 1);
}
