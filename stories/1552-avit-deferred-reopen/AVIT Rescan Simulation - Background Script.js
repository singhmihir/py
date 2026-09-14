/* AVIT rescan simulation for SNOWUSEMTP-1552 (Scripts - Background, Vulnerability Response or global scope)
   -------------------------------------------------------------------------------------------------
   Plays a scanner "close then re-open" on one application vulnerable item and prints the item before
   and after each step, so the effect of sn_vul.auto_defer_avit_in_active_exception_window can be checked
   without waiting for a real scan. The two writes are the ones the AVR import API makes on the item
   record when a scanner reports a finding as fixed and later as open again; all the standard business
   rules on the item run, exactly as they do during an import.

   Use an item that is Deferred through an approved exception (Until date in the future). Set NUMBER
   and, if wanted, the substate the scanner close should carry (4 = Fixed, 6 = Stale as the auto-close
   rule would set). Run once with the property false and once with it true; nothing else is changed.
   ------------------------------------------------------------------------------------------------- */
var NUMBER = 'AVIT0000000';   // the deferred application vulnerable item to play the rescan on
var CLOSE_SUBSTATE = 4;       // 4 = Fixed (scanner reports the finding fixed), 6 = Stale (auto-close rule)

var PROP = 'sn_vul.auto_defer_avit_in_active_exception_window';
function read(gr) {
    gr = new GlideRecord('sn_vul_app_vulnerable_item');
    gr.get('number', NUMBER);
    var note = '';
    var j = new GlideRecord('sys_journal_field');
    j.addQuery('element_id', gr.getUniqueValue());
    j.addQuery('element', 'work_notes');
    j.orderByDesc('sys_created_on');
    j.setLimit(1);
    j.query();
    if (j.next())
        note = ('' + j.getValue('value')).substring(0, 110);
    return 'state ' + gr.getDisplayValue('state') + ' / ' + (gr.getDisplayValue('substate') || '-') + ' | active ' + gr.getValue('active') +
        ' | until ' + (gr.getValue('ignore_expiration') || '-') + ' | backup substate ' + (gr.getValue('backup_substate') || '-') +
        ' | defer count ' + (gr.getValue('defer_count') || '0') + ' | reopened ' + gr.getValue('reopened') + ' (' + (gr.getValue('reopened_count') || '0') + ')' +
        ' | ignored by ' + (gr.getDisplayValue('ignored_by') || '-') + ' | last work note: ' + note;
}
var item = new GlideRecord('sn_vul_app_vulnerable_item');
if (!item.get('number', NUMBER)) {
    gs.print('No application vulnerable item ' + NUMBER);
} else {
    gs.print('Property ' + PROP + ' = ' + gs.getProperty(PROP) + ' | session time zone ' + gs.getSession().getTimeZoneName() + ' | today ' + new GlideDate().getValue());
    gs.print('1. before:            ' + read());
    var close = new GlideRecord('sn_vul_app_vulnerable_item');
    close.get(item.getUniqueValue());
    close.setValue('state', 3);
    close.setValue('substate', CLOSE_SUBSTATE);
    close.update();
    gs.print('2. scanner closes it: ' + read());
    var reopen = new GlideRecord('sn_vul_app_vulnerable_item');
    reopen.get(item.getUniqueValue());
    reopen.setValue('state', 1);
    reopen.update();
    gs.print('3. scanner finds it:  ' + read());
}
