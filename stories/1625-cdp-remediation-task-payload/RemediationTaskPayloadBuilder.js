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
        this.FIELDS_PROPERTY = 'usem.remtask.payload.fields';
    },

    /**
     * Builds the outbound Kafka payload for one remediation task. The fields
     * come from the system property usem.remtask.payload.fields; the activity
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
        this._addFields(task, record, this._fieldList(this.FIELDS_PROPERTY), false);
        task[this.URL_FIELD] = this._workspaceUrl(record);
        return task;
    },

    /**
     * Reads a comma separated field list from a system property. Each entry is
     * a field name, or json_name=field when the payload key differs.
     * @returns {Array} [[jsonName, fieldName], ...]
     */
    _fieldList: function(property) {
        var value = gs.getProperty(property, '');
        if (!value)
            throw new Error('property ' + property + ' is not set');
        var list = [];
        var entries = value.split(',');
        for (var i = 0; i < entries.length; i++) {
            var entry = entries[i].trim();
            if (!entry)
                continue;
            var parts = entry.split('=');
            list.push(parts.length > 1 ? [parts[0].trim(), parts[1].trim()] : [entry, entry]);
        }
        return list;
    },

    _addFields: function(task, record, fields, keepEmpty) {
        for (var i = 0; i < fields.length; i++) {
            var jsonName = fields[i][0];
            var fieldName = fields[i][1];
            var present = record.isValidField(fieldName) && !record.getElement(fieldName).nil();
            if (present)
                task[jsonName] = this._renderElement(record.getElement(fieldName));
            else if (keepEmpty)
                task[jsonName] = '';
        }
    },

    /**
     * Renders one field as the string CDP expects, decided by the field's
     * dictionary type: dates are formatted, journals give their latest entry,
     * fields whose stored value is a key (references, choices, lists,
     * booleans, durations) give their display value, everything else its
     * stored value.
     */
    _renderElement: function(element) {
        switch (String(element.getED().getInternalType())) {
            case 'glide_date_time':
                return this._formatDateTime(element.getValue());
            case 'glide_date':
                return this._formatDate(element.getValue());
            case 'journal_input':
                return String(element.getJournalEntry(1)).trim();
            case 'reference':
            case 'glide_list':
            case 'boolean':
            case 'glide_duration':
            case 'timer':
            case 'domain_id':
            case 'sys_class_name':
            case 'integer':
            case 'string':
                return String(element.getDisplayValue());
            default:
                return String(element.getValue());
        }
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
