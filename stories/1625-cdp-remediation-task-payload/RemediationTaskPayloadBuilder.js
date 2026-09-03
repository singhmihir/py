var RemediationTaskPayloadBuilder = Class.create();
RemediationTaskPayloadBuilder.prototype = {
    initialize: function() {
        this.TOPIC_NAME = 'sn_usem_remtask_outbound';
        this.NAMESPACE = 'com.bofa.usem';
        this.CORE_VERSION = '1.0.0';
        this.OUTBOUND_VERSION = '1.0.0';
        this.DEFAULT_ACTIVITY = 'INSERT';
        this.WORKSPACE_PATH = 'now/vr-analysis/record/';
        this.DATE_TIME_FORMAT = 'MM-dd-yyyy HH:mm:ss';
        this.DATE_FORMAT = 'MM-dd-yyyy';
        // field order and handling follow the agreed remediation task payload
        this.FIELDS = [
            { name: 'assigned_to',           kind: 'display' },
            { name: 'assignment_type',       kind: 'display' },
            { name: 'closed_at',             kind: 'datetime' },
            { name: 'closed_by',             kind: 'display' },
            { name: 'defer_extend_count',    kind: 'value' },
            { name: 'number',                kind: 'value' },
            { name: 'opened_at',             kind: 'datetime' },
            { name: 'opened_by',             kind: 'display' },
            { name: 'reassignment_count',    kind: 'value' },
            { name: 'resolution_date',       kind: 'date' },
            { name: 'resolved_by',           kind: 'display' },
            { name: 'risk_score',            kind: 'value' },
            { name: 'short_description',     kind: 'value' },
            { name: 'state',                 kind: 'display' },
            { name: 'status_updated_on',     kind: 'datetime' },
            { name: 'sys_created_by',        kind: 'value' },
            { name: 'sys_created_on',        kind: 'datetime' },
            { name: 'sys_updated_by',        kind: 'value' },
            { name: 'sys_updated_on',        kind: 'datetime' },
            { name: 'total_cis',             kind: 'value' },
            { name: 'ttr_status',            kind: 'display' },
            { name: 'ttr_target_date',       kind: 'datetime' },
            { name: 'defer_count',           kind: 'value' },
            { name: 'total_vis',             kind: 'value' },
            { name: 'u_avul_record_url',     kind: 'url' },
            { name: 'u_verification_status', kind: 'display' }
        ];
    },

    /**
     * Builds the outbound Kafka payload for one remediation task.
     * @param {GlideRecord} remediationTask - a remediation task record
     * @param {String} activity - INSERT or UPDATE, defaults to INSERT
     * @returns {String} JSON payload, or an empty string when the payload cannot be built
     */
    buildPayload: function(remediationTask, activity) {
        try {
            if (!this._isRecord(remediationTask))
                throw new Error('a valid remediation task record is required');
            var payload = {
                envelope: this._buildEnvelope(activity),
                rem_tasks: [{
                    remediation_task: this._buildRemediationTask(remediationTask)
                }]
            };
            return JSON.stringify(payload);
        } catch (e) {
            gs.error('RemediationTaskPayloadBuilder: payload not built - ' + e.message);
            return '';
        }
    },

    _isRecord: function(gr) {
        return gr !== null && typeof gr === 'object' && typeof gr.isValidRecord === 'function' && gr.isValidRecord();
    },

    _buildEnvelope: function(activity) {
        return {
            type: 'record',
            topic_name: this.TOPIC_NAME,
            namespace: this.NAMESPACE,
            core_version: this.CORE_VERSION,
            outbound_version: this.OUTBOUND_VERSION,
            event_id: this._newEventId(),
            event_timestamp: this._utcTimestamp(),
            element_count: 1,
            element_activity: gs.nil(activity) ? this.DEFAULT_ACTIVITY : String(activity).toUpperCase()
        };
    },

    _buildRemediationTask: function(gr) {
        var task = {};
        for (var i = 0; i < this.FIELDS.length; i++) {
            var field = this.FIELDS[i];
            if (field.kind === 'url') {
                task[field.name] = this._workspaceUrl(gr);
                continue;
            }
            if (!gr.isValidField(field.name) || gs.nil(gr.getValue(field.name)))
                continue;
            task[field.name] = this._render(gr, field);
        }
        return task;
    },

    _render: function(gr, field) {
        var value = gr.getValue(field.name);
        if (field.kind === 'display')
            return String(gr.getDisplayValue(field.name) || value);
        if (field.kind === 'datetime')
            return this._formatDateTime(value);
        if (field.kind === 'date')
            return this._formatDate(value);
        return String(value);
    },

    _formatDateTime: function(value) {
        var gdt = new GlideDateTime(value);
        return gdt.getDate().getByFormat(this.DATE_FORMAT) + ' ' + gdt.getTime().getByFormat('HH:mm:ss');
    },

    _formatDate: function(value) {
        var gd = new GlideDate();
        gd.setValue(value);
        return gd.getByFormat(this.DATE_FORMAT);
    },

    _workspaceUrl: function(gr) {
        var base = gs.getProperty('glide.servlet.uri', '');
        if (base.charAt(base.length - 1) !== '/')
            base += '/';
        return base + this.WORKSPACE_PATH + gr.getTableName() + '/' + gr.getUniqueValue();
    },

    _newEventId: function() {
        var guid = gs.generateGUID();
        return guid.substring(0, 8) + '-' + guid.substring(8, 12) + '-' + guid.substring(12, 16) + '-' +
            guid.substring(16, 20) + '-' + guid.substring(20, 32);
    },

    _utcTimestamp: function() {
        return new GlideDateTime().getValue().replace(' ', 'T') + 'Z';
    },

    type: 'RemediationTaskPayloadBuilder'
};
