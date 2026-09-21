var BOFASIConsequenceOutboundProcessor = Class.create();
BOFASIConsequenceOutboundProcessor.prototype = {

    initialize: function() {
        this.TOPIC_NAME = 'sn_usem_consequence_outbound';
        this.NAMESPACE = 'com.bofa.usem';
        this.CORE_VERSION = '1.0.0';
        this.OUTBOUND_VERSION = '1.0.0';
        this.DATE_FORMAT = 'MM-dd-yyyy';
        this.TIME_FORMAT = 'HH:mm:ss';
        this.FIELDS_PROPERTY_PREFIX = 'x_boar_bofa_usem_1.usem.consequence.fields.';
        this.REFERENCES = {
            x_boar_bofa_usem_0_consequence_rule: 'u_rule'
        };
    },

    buildPayload: function(record) {
        try {
            var missing = [];
            var payload = {
                envelope: this._buildEnvelope(this._activity(record)),
                consequences: [this._buildConsequence(record, missing)]
            };
            var message = JSON.stringify(payload);
            gs.addInfoMessage('Consequence payload for ' + record.getValue('number') + ': ' + message)
            if (missing.length)
                gs.addInfoMessage('Consequence fields not found on this instance, sent as "": ' + missing.join(', '))
            return message;
        } catch (e) {
            gs.error(this.type + ': payload not built for ' + record.getTableName() + ' ' + record.getUniqueValue() + ' - ' + (e.message || e));
            return '';
        }
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

    _buildConsequence: function(record, missing) {
        var mapping = this._fieldMapping(record.getTableName());
        var element = {};
        var records = {};
        for (var i = 0; i < mapping.length; i++) {
            var at = mapping[i].field.indexOf('.');
            var table = at < 0 ? record.getTableName() : mapping[i].field.substring(0, at);
            var field = at < 0 ? mapping[i].field : mapping[i].field.substring(at + 1);
            if (!records.hasOwnProperty(table))
                records[table] = this._sectionRecord(record, table);
            if (!new GlideRecord(table).isValidField(field))
                missing.push(table + '.' + field);
            if (!element[table])
                element[table] = {};
            element[table][mapping[i].json] = this._fieldValue(records[table], field);
        }
        return element;
    },

    _sectionRecord: function(record, table) {
        if (table == record.getTableName())
            return record;
        if (this.REFERENCES[table])
            return record.getElement(this.REFERENCES[table]).getRefRecord();
        throw new Error('table ' + table + ' in property ' + this.FIELDS_PROPERTY_PREFIX + record.getTableName() + ' is not a source of the payload');
    },

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
            mapping.push({ field: field, json: pair.length > 1 && pair[1].trim() ? pair[1].trim() : field });
        }
        return mapping;
    },

    _fieldValue: function(record, field) {
        if (!record || !record.isValidRecord() || !record.isValidField(field))
            return '';
        var element = record.getElement(field);
        if (element === null || element.nil())
            return '';
        return this._renderElement(element);
    },

    _renderElement: function(element) {
        switch (String(element.getED().getInternalType())) {
            case 'glide_date_time':
                return this._formatDateTime(element.getValue());
            case 'glide_date':
                return this._formatDate(element.getValue());
            case 'reference':
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

    _newEventId: function() {
        var guid = gs.generateGUID();
        return guid.substring(0, 8) + '-' + guid.substring(8, 12) + '-' + guid.substring(12, 16) + '-' +
            guid.substring(16, 20) + '-' + guid.substring(20, 32);
    },

    _utcTimestamp: function() {
        return new GlideDateTime().getValue().replace(' ', 'T') + 'Z';
    },

    type: 'BOFASIConsequenceOutboundProcessor'
};
