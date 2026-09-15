var BOA_SI_USEM_RemediationTaskPayloadBuilder = Class.create();
BOA_SI_USEM_RemediationTaskPayloadBuilder.prototype = {

    /**
     * Configuration: envelope constants, date formats, the prefix of the field mapping property per
     * table, the exception approval states counted and the change request association table per
     * remediation task table.
     * @returns {void}
     */
    initialize: function() {
        this.TOPIC_NAME = 'sn_usem_remtask_outbound';
        this.NAMESPACE = 'com.bofa.usem';
        this.CORE_VERSION = '1.0.0';
        this.OUTBOUND_VERSION = '1.0.0';
        this.DATE_FORMAT = 'MM-dd-yyyy';
        this.TIME_FORMAT = 'HH:mm:ss';
        this.FIELDS_PROPERTY_PREFIX = 'x_boar_bofa_usem_1.usem.cdp.remtask.fields.';
        this.EXCEPTION_TABLE = 'sn_sec_exception_change_approval';
        this.EXCEPTION_STATES = '1,4';
        this.CHANGE_CANCELED = '4';
        this.CHANGE_LINKS = {
            sn_vul_vulnerability: {
                table: 'sn_vul_m2m_vg_change_request',
                field: 'sn_vul_vulnerability'
            },
            sn_vul_app_vulnerability: {
                table: 'sn_vul_app_m2m_vg_change_request',
                field: 'sn_vul_app_vulnerability'
            },
            sn_vul_container_vulnerability: {
                table: 'sn_vul_container_m2m_remediation_task_change_request',
                field: 'sn_vul_container_vulnerability'
            },
            sn_vulc_result_group: {
                table: 'sn_vulc_m2m_trg_change_request',
                field: 'result_group'
            }
        };
    },

    /**
     * Builds the outbound Kafka payload (envelope plus one remediation task) for a record. Fields
     * come from the property usem.cdp.remtask.fields.<table>, one servicenow_field=json_field pair per
     * line, a field missing on the table or empty being sent as ""; on failure logs once and returns "".
     * @param {GlideRecord} record - the remediation task record
     * @param {String} normalizedOperation - the operation to report in the envelope, if known
     * @returns {Object} the payload object, or "" when it cannot be built
     */
    buildPayload: function(record, normalizedOperation) {
        try {
            if (!this._isRecord(record))
                throw new Error('record is not a valid GlideRecord');
            var payload = {
                envelope: this._buildEnvelope(this._activity(record, normalizedOperation)),
                rem_tasks: [{
                    remediation_task: this._buildRemediationTask(record)
                }]
            };
            return payload;
        } catch (e) {
            gs.error(this._errorMessage(record, e));
            return '';
        }
    },

    /**
     * Tells whether the value is a GlideRecord positioned on an existing record.
     * @param {*} record - the value to check
     * @returns {Boolean} true for a valid GlideRecord
     */
    _isRecord: function(record) {
        return record !== null && typeof record === 'object' && typeof record.isValidRecord === 'function' && record.isValidRecord();
    },

    /**
     * Formats the single error line: <class>: payload not built for <table> <sys_id> - <reason>.
     * @param {GlideRecord} record - the record being processed, if any
     * @param {Error} e - the error caught
     * @returns {String} the message to log
     */
    _errorMessage: function(record, e) {
        var subject = this._isRecord(record) ? ' for ' + record.getTableName() + ' ' + record.getUniqueValue() : '';
        return this.type + ': payload not built' + subject + ' - ' + e.message;
    },

    /**
     * Resolves the envelope activity: the given operation, otherwise the operation in progress on
     * the record.
     * @param {GlideRecord} record - the remediation task record
     * @param {String} normalizedOperation - the operation to report, if known
     * @returns {String} the operation in upper case, "" when none is known
     */
    _activity: function(record, normalizedOperation) {
        return String(normalizedOperation || record.operation() || '').toUpperCase();
    },

    /**
     * Builds the message envelope: topic, namespace, versions, a new event id, the UTC timestamp,
     * the element count and the activity.
     * @param {String} activity - the operation reported, e.g. INSERT or UPDATE
     * @returns {Object} the envelope
     */
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

    /**
     * Renders the mapped fields of the record in property order, then adds the derived
     * change_requests and exception_requests.
     * @param {GlideRecord} record - the remediation task record
     * @returns {Object} json_field to value, every value a string
     */
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
     * Reads the table's field mapping property: one servicenow_field=json_field pair per line, a bare
     * field name keeping its own name; throws when the table has no property.
     * @param {String} table - the remediation task table name
     * @returns {Array} [{field, json}] in property order
     */
    _fieldMapping: function(table) {
        var property = this.FIELDS_PROPERTY_PREFIX + table;
        var value = gs.getProperty(property, '');
        if (!value)
            throw new Error('table ' + table + ' is not configured in property ' + property);
        var mapping = [];
        var entries = value.split(/\r?\n|,/);
        for (var i = 0; i < entries.length; i++) {
            var pair = entries[i].split('=');
            var field = pair[0].trim();
            if (!field)
                continue;
            mapping.push({
                field: field,
                json: pair.length > 1 && pair[1].trim() ? pair[1].trim() : field
            });
        }
        return mapping;
    },

    /**
     * Reads one field of the record as the string to send; "" when the field does not exist on the
     * table or is empty.
     * @param {GlideRecord} record - the remediation task record
     * @param {String} field - the field name
     * @returns {String} the rendered value
     */
    _fieldValue: function(record, field) {
        if (!record.isValidField(field))
            return '';
        var element = record.getElement(field);
        if (element === null || element.nil())
            return '';
        return this._renderElement(element);
    },

    /**
     * Renders one populated field by its dictionary type: dates formatted, journals as their latest
     * entry, key-type fields (reference, choice, list, boolean, duration) as their display value,
     * everything else as the stored value.
     * @param {GlideElement} element - the field element
     * @returns {String} the rendered value
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

    /**
     * Formats a stored date/time as MM-dd-yyyy HH:mm:ss.
     * @param {String} value - the stored date/time value
     * @returns {String} the formatted date and time
     */
    _formatDateTime: function(value) {
        var gdt = new GlideDateTime(value);
        return gdt.getDate().getByFormat(this.DATE_FORMAT) + ' ' + gdt.getTime().getByFormat(this.TIME_FORMAT);
    },

    /**
     * Formats a stored date as MM-dd-yyyy.
     * @param {String} value - the stored date value
     * @returns {String} the formatted date
     */
    _formatDate: function(value) {
        var gd = new GlideDate();
        gd.setValue(value);
        return gd.getByFormat(this.DATE_FORMAT);
    },

    /**
     * Collects the numbers of the change requests associated with the record through its table's
     * association table, excluding cancelled change requests, in number order.
     * @param {GlideRecord} record - the remediation task record
     * @param {Object} link - {table, field} of the association table, undefined when the table has none
     * @returns {String} comma-separated change request numbers, "" when none
     */
    _changeRequests: function(record, link) {
        var numbers = [];
        if (!link)
            return '';
        var m2m = new GlideRecord(link.table);
        m2m.addQuery(link.field, record.getUniqueValue());
        m2m.addQuery("change_request.state", "!=", this.CHANGE_CANCELED);
        m2m.addNotNullQuery('change_request');
        m2m.orderBy('change_request.number');
        m2m.query();
        while (m2m.next())
            numbers.push(m2m.getDisplayValue('change_request'));
        return numbers.join(',');
    },

    /**
     * Collects the numbers of the approved or expired exception approvals raised for the record.
     * @param {GlideRecord} record - the remediation task record
     * @returns {String} comma-separated exception numbers, "" when none
     */
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

    /**
     * Generates the envelope event id.
     * @returns {String} a new id in UUID form (8-4-4-4-12)
     */
    _newEventId: function() {
        var guid = gs.generateGUID();
        return guid.substring(0, 8) + '-' + guid.substring(8, 12) + '-' + guid.substring(12, 16) + '-' +
            guid.substring(16, 20) + '-' + guid.substring(20, 32);
    },

    /**
     * Gives the current time for the envelope.
     * @returns {String} UTC time as yyyy-MM-ddTHH:mm:ssZ
     */
    _utcTimestamp: function() {
        return new GlideDateTime().getValue().replace(' ', 'T') + 'Z';
    },

    type: 'BOA_SI_USEM_RemediationTaskPayloadBuilder'
};