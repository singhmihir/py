var RemediationTaskPayloadBuilder = Class.create();
RemediationTaskPayloadBuilder.prototype = {
    initialize: function() {
        this.TOPIC_NAME = 'sn_usem_remtask_outbound';
        this.NAMESPACE = 'com.bofa.usem';
        this.CORE_VERSION = '1.0.0';
        this.OUTBOUND_VERSION = '1.0.0';
        this.WORKSPACE_PATH = 'now/vr-analysis/record/';
        this.DATE_FORMAT = 'MM-dd-yyyy';
        this.TIME_FORMAT = 'HH:mm:ss';
        this.URL_FIELD = 'u_avul_record_url';
        // field types rendered with their display value; dates, journals and
        // everything else are handled in _renderElement
        this.DISPLAY_TYPES = ['reference', 'glide_list', 'boolean', 'glide_duration', 'timer', 'domain_id', 'sys_class_name', 'integer', 'string'];
        this.FIELDS = [
            'assigned_to', 'assignment_type', 'closed_at', 'closed_by', 'defer_extend_count', 'number',
            'opened_at', 'opened_by', 'reassignment_count', 'resolution_date', 'resolved_by', 'risk_score',
            'short_description', 'state', 'status_updated_on', 'sys_created_by', 'sys_created_on',
            'sys_updated_by', 'sys_updated_on', 'total_cis', 'ttr_status', 'ttr_target_date', 'defer_count',
            'total_vis', 'u_verification_status'
        ];
    },

    /**
     * Builds the outbound Kafka payload for one remediation task. The activity
     * comes from the record itself: the operation in progress when called from
     * a business rule, otherwise INSERT for a record that has never been
     * updated and UPDATE for any other.
     * @param {GlideRecord} record - a remediation task record
     * @returns {String} JSON payload, or an empty string when the payload cannot be built
     */
    buildPayload: function(record) {
        try {
            if (!this._isRecord(record))
                throw new Error('record is not a valid GlideRecord');
            var payload = {
                envelope: this._buildEnvelope(this._activity(record)),
                rem_tasks: [{
                    remediation_task: this._buildRemediationTask(record)
                }]
            };
            return JSON.stringify(payload);
        } catch (e) {
            gs.error(this._errorMessage(record, e));
            return '';
        }
    },

    _isRecord: function(record) {
        return record !== null && typeof record === 'object' && typeof record.isValidRecord === 'function' && record.isValidRecord();
    },

    _errorMessage: function(record, e) {
        var subject = this._isRecord(record) ? ' for ' + record.getTableName() + ' ' + record.getUniqueValue() : '';
        return this.type + ': payload not built' + subject + ' - ' + e.message;
    },

    _activity: function(record) {
        var operation = String(record.operation() || '').toUpperCase();
        if (operation)
            return operation;
        return parseInt(record.getValue('sys_mod_count')) > 0 ? 'UPDATE' : 'INSERT';
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
            element_activity: activity
        };
    },

    _buildRemediationTask: function(record) {
        var task = {};
        for (var i = 0; i < this.FIELDS.length; i++) {
            var name = this.FIELDS[i];
            if (!record.isValidField(name) || record.getElement(name).nil())
                continue;
            task[name] = this._renderElement(record.getElement(name));
        }
        task[this.URL_FIELD] = this._workspaceUrl(record);
        return task;
    },

    _renderElement: function(element) {
        if (element.nil())
            return '';
        var type = String(element.getED().getInternalType());
        if (type === 'glide_date_time')
            return this._formatDateTime(element.getValue());
        if (type === 'glide_date')
            return this._formatDate(element.getValue());
        if (type === 'journal_input')
            return String(element.getJournalEntry(1)).trim();
        if (this.DISPLAY_TYPES.indexOf(type) > -1)
            return String(element.getDisplayValue());
        return String(element.getValue());
    },

    _formatDateTime: function(value) {
        var gdt = new GlideDateTime(value);
        return gdt.getDate().getByFormat(this.DATE_FORMAT) + ' ' + gdt.getTime().getByFormat(this.TIME_FORMAT);
    },

    _formatDate: function(value) {
        var gd = new GlideDate();
        gd.setValue(value);
        return gd.getByFormat(this.DATE_FORMAT);
    },

    _workspaceUrl: function(record) {
        var base = gs.getProperty('glide.servlet.uri', '');
        if (base.charAt(base.length - 1) !== '/')
            base += '/';
        return base + this.WORKSPACE_PATH + record.getTableName() + '/' + record.getUniqueValue();
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
