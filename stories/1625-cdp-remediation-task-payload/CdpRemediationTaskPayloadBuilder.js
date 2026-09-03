var CdpRemediationTaskPayloadBuilder = Class.create();
CdpRemediationTaskPayloadBuilder.prototype = Object.extendsObject(RemediationTaskPayloadBuilder, {
    initialize: function() {
        RemediationTaskPayloadBuilder.prototype.initialize.call(this);
        this.PROPERTY_PREFIX = 'usem.cdp.remtask.';
        this.EXCEPTION_TABLE = 'sn_sec_exception_change_approval';
        this.EXCEPTION_STATES = '1,4';
    },

    /**
     * Full CDP payload body for the record's table: the common field list plus
     * the table's own list, the change requests associated with the task and
     * the approved or expired exception requests raised on it.
     */
    _buildRemediationTask: function(record) {
        var table = record.getTableName();
        var task = {};
        this._addFields(task, record, this._fieldList(this.PROPERTY_PREFIX + 'fields.common'), true);
        this._addFields(task, record, this._tableFields(table), true);
        task.change_requests = this._changeRequests(record, this._changeLink(table));
        task.exception_requests = this._exceptionRequests(record);
        return task;
    },

    _tableFields: function(table) {
        if (!gs.getProperty(this.PROPERTY_PREFIX + 'fields.' + table, ''))
            throw new Error('table ' + table + ' is not configured in property ' + this.PROPERTY_PREFIX + 'fields.' + table);
        return this._fieldList(this.PROPERTY_PREFIX + 'fields.' + table);
    },

    _changeLink: function(table) {
        var value = gs.getProperty(this.PROPERTY_PREFIX + 'changes.' + table, '');
        var parts = value.split('.');
        return parts.length == 2 ? { table: parts[0].trim(), field: parts[1].trim() } : null;
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

    type: 'CdpRemediationTaskPayloadBuilder'
});
