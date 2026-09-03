var RemediationTaskPayloadBuilder = Class.create();
RemediationTaskPayloadBuilder.prototype = {
    initialize: function() {
        this.TOPIC_NAME = 'sn_usem_remtask_outbound';
        this.NAMESPACE = 'com.bofa.usem';
        this.CORE_VERSION = '1.0.0';
        this.OUTBOUND_VERSION = '1.0.0';
        this.DATE_FORMAT = 'MM-dd-yyyy';
        this.TIME_FORMAT = 'HH:mm:ss';
        this.FIELDS_PROPERTY_PREFIX = 'usem.cdp.remtask.fields.';
        this.EXCEPTION_TABLE = 'sn_sec_exception_change_approval';
        this.EXCEPTION_STATES = '1,4';
        // change requests are associated to each remediation task table through its own m2m table
        this.CHANGE_LINKS = {
            sn_vul_vulnerability:           { table: 'sn_vul_m2m_vg_change_request',                          field: 'sn_vul_vulnerability' },
            sn_vul_app_vulnerability:       { table: 'sn_vul_app_m2m_vg_change_request',                      field: 'sn_vul_app_vulnerability' },
            sn_vul_container_vulnerability: { table: 'sn_vul_container_m2m_remediation_task_change_request',  field: 'sn_vul_container_vulnerability' },
            sn_vulc_result_group:           { table: 'sn_vulc_m2m_trg_change_request',                        field: 'result_group' }
        };
    },

    /**
     * Builds the outbound Kafka payload for one remediation task. The fields
     * come from the system property usem.cdp.remtask.fields.<table> as
     * servicenow_field=json_field pairs; a field missing on the table or
     * empty is sent as "". The activity is the operation in progress when
     * called from a business rule, otherwise INSERT for a record that has
     * never been updated and UPDATE for any other.
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
        var table = record.getTableName();
        var mapping = this._fieldMapping(table);
        var task = {};
        for (var i = 0; i < mapping.length; i++)
            task[mapping[i].json] = this._fieldValue(record, mapping[i].field);
        task.change_requests = this._changeRequests(record, this.CHANGE_LINKS[table]);
        task.exception_requests = this._exceptionRequests(record);
        return task;
    },

    /**
     * Reads the table's property: comma separated servicenow_field=json_field
     * pairs (a bare field name keeps its own name in the payload).
     * @returns {Array} [{field, json}, ...] in property order
     */
    _fieldMapping: function(table) {
        var property = this.FIELDS_PROPERTY_PREFIX + table;
        var value = gs.getProperty(property, '');
        if (!value)
            throw new Error('table ' + table + ' is not configured in property ' + property);
        var mapping = [];
        var entries = value.split(',');
        for (var i = 0; i < entries.length; i++) {
            var pair = entries[i].split('=');
            var field = pair[0].trim();
            if (!field)
                continue;
            mapping.push({ field: field, json: pair.length > 1 && pair[1].trim() ? pair[1].trim() : field });
        }
        return mapping;
    },

    _fieldValue: function(record, field) {
        if (!record.isValidField(field))
            return '';
        var element = record.getElement(field);
        if (element === null || element.nil())
            return '';
        return this._renderElement(element);
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

    _changeRequests: function(record, link) {
        var numbers = [];
        if (!link)
            return '';
        var m2m = new GlideRecord(link.table);
        m2m.addQuery(link.field, record.getUniqueValue());
        m2m.addNotNullQuery('change_request');
        m2m.orderBy('change_request.number');
        m2m.query();
        while (m2m.next())
            numbers.push(m2m.getDisplayValue('change_request'));
        return numbers.join(',');
    },

    _exceptionRequests: function(record) {
        var numbers = [];
        var exception = new GlideRecord(this.EXCEPTION_TABLE);
        exception.addQuery('table', record.getTableName());
        exception.addQuery('record', record.getUniqueValue());
        exception.addQuery('approval_state', 'IN', this.EXCEPTION_STATES);
        exception.orderBy('number');
        exception.query();
        while (exception.next())
            numbers.push(exception.getValue('number'));
        return numbers.join(',');
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
