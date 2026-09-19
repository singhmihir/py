var TridentClosureUtil = Class.create();
TridentClosureUtil.prototype = {
    initialize: function() {
        this.governanceGroup = gs.getProperty('trident.closure.governance_group', '');
        this.tridentSource = gs.getProperty('trident.finding.source', 'Trident');
        this.reopenWindowDays = parseInt(gs.getProperty('trident.reopen.window_days', '30'), 10);
    },

    PENDING_APPROVAL: 100,
    STATE_RESOLVED: 101,
    STATE_OPEN: 1,
    STATE_CLOSED: 3,
    STATE_AWAITING_IMPLEMENTATION: 10,

    MSG_NO_EVIDENCE: 'Evidence has not been attached to this remediation task. Please use the paperclip icon to attach relevant evidence before attempting to submit the remediation task for closure.',
    MSG_NEEDS_APPROVAL: 'Trident remediation tasks can only be closed through a governance approval. Use Request Closure to submit the task for review.',

    isTridentTask: function(taskGr) {
        var m2m = new GlideRecord('sn_vulc_m2m_result_result_group');
        m2m.addQuery('group', taskGr.getUniqueValue());
        m2m.addQuery('result.source', this.tridentSource);
        m2m.setLimit(1);
        m2m.query();
        return m2m.hasNext();
    },

    isTridentResult: function(resultGr) {
        return resultGr.getValue('source') == this.tridentSource;
    },

    hasEvidence: function(taskGr) {
        var att = new GlideRecord('sys_attachment');
        att.addQuery('table_name', taskGr.getTableName());
        att.addQuery('table_sys_id', taskGr.getUniqueValue());
        att.setLimit(1);
        att.query();
        return att.hasNext();
    },

    isGovernanceMember: function(userId) {
        if (!this.governanceGroup)
            return false;
        var gm = new GlideRecord('sys_user_grmember');
        gm.addQuery('group', this.governanceGroup);
        gm.addQuery('user', userId || gs.getUserID());
        gm.setLimit(1);
        gm.query();
        return gm.hasNext();
    },

    /**
     * Stage a closure request on the record WITHOUT calling update().
     * Safe to use from a before business rule: the outer save persists the
     * values, so the record is written exactly once and any record-triggered
     * flow fires exactly once.
     */
    applyClosureRequest: function(taskGr) {
        if (!this.hasEvidence(taskGr))
            return 'no_evidence';
        // only skip when an approval set is genuinely out for a decision;
        // a task merely carrying a stale Pending Approval marker (e.g. after
        // a rejection) is restaged so the approval flow can trigger again
        if (taskGr.getValue('substate') == this.PENDING_APPROVAL &&
            taskGr.getValue('approval') == 'requested')
            return 'pending';
        // a new request always starts from a clean slate: no dangling
        // approval rows from an earlier cycle, and an approval value the
        // flow trigger can match
        this.cancelOpenApprovals(taskGr, 'Superseded by a new closure request.');
        taskGr.setValue('approval', 'not requested');
        taskGr.setValue('substate', this.PENDING_APPROVAL);
        taskGr.work_notes = 'Closure requested for governance review. Evidence attached: ' + this._evidenceNames(taskGr);
        return 'ok';
    },

    /**
     * Full closure request for callers that own the write (UI action, fix
     * scripts). Never call from a before rule on the same record.
     */
    requestClosure: function(taskGr) {
        if (taskGr.getValue('state') == this.STATE_CLOSED)
            return 'closed';
        var outcome = this.applyClosureRequest(taskGr);
        if (outcome == 'ok')
            taskGr.update();
        return outcome;
    },

    cancelOpenApprovals: function(taskGr, note) {
        var appr = new GlideRecord('sysapproval_approver');
        appr.addQuery('sysapproval', taskGr.getUniqueValue());
        appr.addQuery('state', 'requested');
        appr.query();
        var cancelled = 0;
        while (appr.next()) {
            appr.setValue('state', 'cancelled');
            if (note)
                appr.comments = note;
            appr.update();
            cancelled++;
        }
        return cancelled;
    },

    closeApproved: function(current, previous) {
        return previous.getValue('substate') == this.PENDING_APPROVAL && current.getValue('approval') == 'approved';
    },

    reopenAllowed: function(gr) {
        var closedAt = gr.getValue('closed_at') || gr.getValue('resolution_dt_tm');
        if (!closedAt)
            return false;
        var cutoff = new GlideDateTime();
        cutoff.addDaysUTC(-this.reopenWindowDays);
        return new GlideDateTime(closedAt).compareTo(cutoff) >= 0;
    },

    _evidenceNames: function(taskGr) {
        var names = [];
        var att = new GlideRecord('sys_attachment');
        att.addQuery('table_name', taskGr.getTableName());
        att.addQuery('table_sys_id', taskGr.getUniqueValue());
        att.query();
        while (att.next())
            names.push(att.getValue('file_name'));
        return names.join(', ');
    },

    type: 'TridentClosureUtil'
};
