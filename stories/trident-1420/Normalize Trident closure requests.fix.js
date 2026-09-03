// One-time normalization to run once after committing the Trident single
// business rule fix. It repairs remediation tasks left behind by earlier
// versions of the closure logic:
//  1) Tasks carrying Reason = Pending Approval while no longer Resolved get
//     the marker cleared and leftover approval rows cancelled.
//  2) Resolved tasks whose closure request never produced an approval set
//     get the request raised again so the approval flow triggers.
var util = new sn_vulc.TridentClosureUtil();
var cleared = 0, restaged = 0;

var stale = new GlideRecord('sn_vulc_result_group');
stale.addQuery('substate', util.PENDING_APPROVAL);
stale.addQuery('state', '!=', util.STATE_RESOLVED);
stale.addQuery('state', '!=', util.STATE_CLOSED);
stale.query();
while (stale.next()) {
    if (!util.isTridentTask(stale))
        continue;
    util.cancelOpenApprovals(stale, 'Cancelled while normalizing Trident closure requests.');
    stale.setValue('substate', '');
    stale.setValue('approval', 'not requested');
    stale.update();
    cleared++;
}

var stuck = new GlideRecord('sn_vulc_result_group');
stuck.addQuery('state', util.STATE_RESOLVED);
stuck.addQuery('substate', util.PENDING_APPROVAL);
stuck.addQuery('approval', '!=', 'requested');
stuck.query();
while (stuck.next()) {
    if (!util.isTridentTask(stuck))
        continue;
    var open = new GlideRecord('sysapproval_approver');
    open.addQuery('sysapproval', stuck.getUniqueValue());
    open.addQuery('state', 'requested');
    open.setLimit(1);
    open.query();
    if (open.hasNext())
        continue;
    var pulse = new GlideRecord('sn_vulc_result_group');
    if (!pulse.get(stuck.getUniqueValue()))
        continue;
    pulse.setValue('substate', '');
    pulse.update();
    var again = new GlideRecord('sn_vulc_result_group');
    if (!again.get(stuck.getUniqueValue()))
        continue;
    again.setValue('substate', util.PENDING_APPROVAL);
    again.update();
    restaged++;
}
gs.info('Trident closure normalization: ' + cleared + ' stale request(s) cleared, ' + restaged + ' resolved task(s) staged again for approval.');
