(function executeRule(current, previous) {
    // runs last among the before rules (order 1000): if an earlier rule has
    // already refused this write, do nothing - no approval rows are touched
    // for a save that will not happen
    if (current.isActionAborted())
        return;
    var util = new sn_vulc.TridentClosureUtil();
    if (!util.isTridentTask(current))
        return;

    var closing    = current.getValue('state') == util.STATE_CLOSED && previous.getValue('state') != util.STATE_CLOSED;
    var reopening  = previous.getValue('state') == util.STATE_CLOSED && current.getValue('state') != util.STATE_CLOSED;
    var resolving  = current.getValue('state') == util.STATE_RESOLVED && previous.getValue('state') != util.STATE_RESOLVED;
    var requesting = current.getValue('substate') == util.PENDING_APPROVAL &&
                     previous.getValue('substate') != util.PENDING_APPROVAL;

    // 1. Closing: only an approved closure request with evidence may close.
    if (closing) {
        if (!util.hasEvidence(current)) {
            gs.addErrorMessage(util.MSG_NO_EVIDENCE);
            current.setAbortAction(true);
            return;
        }
        if (!util.closeApproved(current, previous)) {
            gs.addErrorMessage(util.MSG_NEEDS_APPROVAL);
            current.setAbortAction(true);
            return;
        }
        return;
    }

    // 2. Reopening a closed task: only within the reopen window.
    if (reopening) {
        if (!util.reopenAllowed(previous)) {
            gs.addErrorMessage('Reopening of Trident findings is only allowed up to ' + util.reopenWindowDays + ' days after closure.');
            current.setAbortAction(true);
            return;
        }
        current.setValue('approval', 'not requested');
        if (!current.substate.changes())
            current.setValue('substate', '');
    }

    // 3. Every move into Resolved (and any direct change of Reason to
    //    Pending Approval) stages a fresh closure request on this same
    //    write: leftover approvals are cancelled, the approval value is
    //    reset to Not Yet Requested and Reason is set to Pending Approval.
    //    At least one of the approval flow's trigger fields changes value
    //    in the write, so the flow raises a new approval cycle every time,
    //    including after a rejection.
    if (resolving || requesting) {
        var outcome = util.applyClosureRequest(current);
        if (outcome == 'no_evidence') {
            gs.addErrorMessage(util.MSG_NO_EVIDENCE);
            current.setAbortAction(true);
        } else if (outcome == 'pending') {
            gs.addInfoMessage('A closure request is already awaiting approval for this remediation task.');
        } else {
            gs.addInfoMessage('Closure requested, the remediation task is now pending approval from the governance team.');
        }
        return;
    }

    // 4. Any other move away from a pending request (a governance rejection
    //    sending the task to Awaiting Implementation, a reopen, a deferral)
    //    clears the request marker and cancels leftover approvals, so the
    //    record always raises a clean request on its next resolve. A Reason
    //    chosen in the same write (e.g. a deferral reason) is kept.
    if (previous.getValue('substate') == util.PENDING_APPROVAL) {
        var cancelled = util.cancelOpenApprovals(current,
            'Approval cancelled: the remediation task left Pending Approval before the governance decision was made.');
        if (!current.substate.changes())
            current.setValue('substate', '');
        current.setValue('approval', 'not requested');
        if (cancelled > 0)
            gs.addInfoMessage('The pending governance approval was cancelled because the remediation task left Pending Approval.');
    }
})(current, previous);
