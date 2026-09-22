var BOFASIVampOutboundProcessor = Class.create();
BOFASIVampOutboundProcessor.prototype = {

    /**
     * Configuration of the VAMP outbound payload: the envelope constants, the date and time formats,
     * the two properties that hold the payload structure (the sections and their fields) and the path
     * from the application vulnerable item to every other record of the payload. A path with "list"
     * is a many to many: its section is sent as an array, one entry per related record.
     */
    initialize: function() {
        this.TOPIC_NAME = 'sn_usem_verification_outbound';
        this.NAMESPACE = 'com.bofa.usem';
        this.CORE_VERSION = '1.0.0';
        this.OUTBOUND_VERSION = '1.0.0';
        this.DATE_FORMAT = 'MM-dd-yyyy';
        this.TIME_FORMAT = 'HH:mm:ss';
        this.ACTIVITIES = ['INSERT', 'UPDATE', 'DELETE'];
        this.FIELDS_PROPERTY_PREFIX = 'x_boar_bofa_usem_1.usem.vamp.fields.';
        this.SECTIONS_PROPERTY_PREFIX = 'x_boar_bofa_usem_1.usem.vamp.sections.';
        this.RELATED = {
            sn_vul_app_vul_entry: { reference: 'vulnerability' },
            sn_vul_pen_test_assessment_request: { reference: 'assessment_request' },
            sn_vul_app_vulnerability: { list: 'sn_vul_app_m2m_vul_group_item', item: 'sn_vul_app_vulnerable_item', related: 'sn_vul_app_vulnerability', order: 'number' }
        };
        this.UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
        this.TIMESTAMP_PATTERN = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/;
    },

    /**
     * Builds the VAMP message for one application vulnerable item and shows it on the record.
     * @param {GlideRecord} record the application vulnerable item the business rule is running on
     * @returns {string} the JSON text of the payload, or an empty string when it could not be built
     */
    buildPayload: function(record) {
        try {
            this._requireRecord(record);
            var table = record.getTableName();
            var sections = this._sections(table);
            var mapping = this._fieldMapping(table);
            this._requireConfiguration(sections, mapping, table);
            var missing = [];
            var findings = [this._buildFinding(record, sections, mapping, missing)];
            var payload = {
                envelope: this._buildEnvelope(this._activity(record), findings.length),
                findings: findings
            };
            this._validatePayload(payload, sections, mapping, record);
            var message = JSON.stringify(payload);
            gs.addInfoMessage('VAMP payload for ' + record.getValue('number') + ': ' + message)
            if (missing.length)
                gs.addInfoMessage('VAMP fields not found on this instance, sent as "": ' + missing.join(', '))
            return message;
        } catch (e) {
            gs.error(this.type + ': payload not built for ' + this._recordKey(record) + ' - ' + (e.message || e));
            return '';
        }
    },

    /**
     * Refuses a record the payload cannot be built from.
     * @param {GlideRecord} record the record the business rule passed in
     * @throws when no record was given or the record does not exist
     */
    _requireRecord: function(record) {
        if (!record || !record.getTableName)
            throw new Error('no record was given');
        if (!record.isValidRecord())
            throw new Error('the record does not exist');
    },

    /**
     * Names a record in an error message, also when the record itself is the reason for the error.
     * @param {GlideRecord} record the record the payload was being built for
     * @returns {string} "<table> <sys_id>", or "no record"
     */
    _recordKey: function(record) {
        try {
            return record.getTableName() + ' ' + record.getUniqueValue();
        } catch (e) {
            return 'no record';
        }
    },

    /**
     * The activity of the message, taken from the operation the business rule is running for.
     * @param {GlideRecord} record the application vulnerable item
     * @returns {string} INSERT, UPDATE or DELETE
     */
    _activity: function(record) {
        var operation = String(record.operation() || '').toUpperCase();
        if (operation)
            return operation;
        return parseInt(record.getValue('sys_mod_count')) > 0 ? 'UPDATE' : 'INSERT';
    },

    /**
     * The CDP envelope of the message.
     * @param {string} activity INSERT, UPDATE or DELETE
     * @param {number} elements the number of findings the message carries
     * @returns {Object} the envelope
     */
    _buildEnvelope: function(activity, elements) {
        return {
            type: 'record',
            topic_name: this.TOPIC_NAME,
            namespace: this.NAMESPACE,
            core_version: this.CORE_VERSION,
            outbound_version: this.OUTBOUND_VERSION,
            event_id: this._newEventId(),
            event_timestamp: this._utcTimestamp(),
            element_count: elements,
            element_activity: activity
        };
    },

    /**
     * Builds one finding: every configured section in the order of the sections property, each
     * section from its own record, a section reached through a many to many as an array.
     * @param {GlideRecord} record the application vulnerable item
     * @param {Array} sections the sections property, parsed
     * @param {Array} mapping the fields property, parsed
     * @param {Array} missing collects the configured fields this instance does not have
     * @returns {Object} the finding
     */
    _buildFinding: function(record, sections, mapping, missing) {
        var finding = {};
        for (var i = 0; i < sections.length; i++) {
            var section = sections[i];
            var fields = this._sectionFields(mapping, section.table);
            this._noteMissing(section.table, fields, missing);
            var records = this._sectionRecords(record, section.table);
            if (!section.many) {
                finding[section.json] = this._sectionValues(records.length ? records[0] : null, fields);
                continue;
            }
            var entries = [];
            for (var r = 0; r < records.length; r++)
                entries.push(this._sectionValues(records[r], fields));
            finding[section.json] = entries;
        }
        return finding;
    },

    /**
     * The records behind one section: the item itself, the record its reference field points at, or
     * every record the many to many links to it.
     * @param {GlideRecord} record the application vulnerable item
     * @param {string} table the ServiceNow table of the section
     * @returns {Array} the records, empty when the section has none
     * @throws when the section has no path from the application vulnerable item
     */
    _sectionRecords: function(record, table) {
        if (table == record.getTableName())
            return [record];
        var path = this.RELATED[table];
        if (!path)
            throw new Error('section ' + table + ' has no path from ' + record.getTableName());
        return path.reference ? this._referenced(record, path.reference) : this._listed(record, path);
    },

    /**
     * The record a reference field points at, opened in its own class.
     * @param {GlideRecord} record the application vulnerable item
     * @param {string} field the reference field
     * @returns {Array} one record, or empty when the field is empty or the target is gone
     */
    _referenced: function(record, field) {
        var element = record.getElement(field);
        if (element === null || element.nil())
            return [];
        var referenced = element.getRefRecord();
        if (!referenced || !referenced.isValidRecord())
            return [];
        return [this._inOwnClass(referenced)];
    },

    /**
     * Every record a many to many links to the item, in a stable order, each opened in its own class.
     * @param {GlideRecord} record the application vulnerable item
     * @param {Object} path the many to many configuration of the section
     * @returns {Array} the related records, empty when the item has none
     */
    _listed: function(record, path) {
        var found = [];
        var link = new GlideRecord(path.list);
        link.addQuery(path.item, record.getUniqueValue());
        link.addNotNullQuery(path.related);
        link.orderBy(path.related + '.' + path.order);
        link.query();
        while (link.next()) {
            var related = link.getElement(path.related).getRefRecord();
            if (related && related.isValidRecord())
                found.push(this._inOwnClass(related));
        }
        return found;
    },

    /**
     * Re-opens a record in the class it belongs to, so that the fields of an extended table are read
     * as well: a reference to a base table hands out a record of that base table only.
     * @param {GlideRecord} referenced the record as the reference handed it over
     * @returns {GlideRecord} the record in its own class, or the record itself when it has no class
     */
    _inOwnClass: function(referenced) {
        var className = String(referenced.getValue('sys_class_name') || '');
        if (!className || className == referenced.getTableName())
            return referenced;
        var actual = new GlideRecord(className);
        return actual.get(referenced.getUniqueValue()) ? actual : referenced;
    },

    /**
     * The values of one section, the payload names of the fields property in its order.
     * @param {GlideRecord} sectionRecord the record of the section, null when the item has none
     * @param {Array} fields the fields of the section
     * @returns {Object} the payload names and their values, every value a string
     */
    _sectionValues: function(sectionRecord, fields) {
        var values = {};
        for (var i = 0; i < fields.length; i++)
            values[fields[i].json] = this._fieldValue(sectionRecord, fields[i].field);
        return values;
    },

    /**
     * Records the configured fields of a section this instance does not have. The check is made
     * against the configured table, once per section, so that the message names the same fields
     * whether the item has one related record, several or none.
     * @param {string} table the configured ServiceNow table of the section
     * @param {Array} fields the fields of the section
     * @param {Array} missing the list collected while the payload is built
     */
    _noteMissing: function(table, fields, missing) {
        var probe = new GlideRecord(table);
        for (var i = 0; i < fields.length; i++) {
            var name = table + '.' + fields[i].field;
            if (!probe.isValidField(fields[i].field) && missing.indexOf(name) < 0)
                missing.push(name);
        }
    },

    /**
     * The sections of the payload, read from the sections property in its order.
     * @param {string} table the table the business rule runs on
     * @returns {Array} {table, json, many} per section
     * @throws when the property is not configured, holds no section or a line without a payload name
     */
    _sections: function(table) {
        var property = this.SECTIONS_PROPERTY_PREFIX + table;
        var value = gs.getProperty(property, '');
        if (!value)
            throw new Error('table ' + table + ' is not configured in property ' + property);
        var sections = [];
        var entries = value.split(/\r?\n|,/);
        for (var i = 0; i < entries.length; i++) {
            var pair = entries[i].split('=');
            var name = pair[0].trim();
            if (!name)
                continue;
            if (pair.length < 2 || !pair[1].trim())
                throw new Error('property ' + property + ' holds a line without a payload name: "' + entries[i].trim() + '"');
            sections.push({ table: name, json: pair[1].trim(), many: !!(this.RELATED[name] && this.RELATED[name].list) });
        }
        if (!sections.length)
            throw new Error('property ' + property + ' holds no section');
        return sections;
    },

    /**
     * The fields of the payload, read from the fields property in its order: the fields of the item
     * itself plain, the fields of another section as <table>.<field>.
     * @param {string} table the table the business rule runs on
     * @returns {Array} {table, field, json} per field
     * @throws when the property is not configured, holds no field or a line without a field name
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
            var path = pair[0].trim();
            if (!path && entries[i].trim())
                throw new Error('property ' + property + ' holds a line without a field name: "' + entries[i].trim() + '"');
            if (!path)
                continue;
            var at = path.indexOf('.');
            mapping.push({
                table: at < 0 ? table : path.substring(0, at),
                field: at < 0 ? path : path.substring(at + 1),
                json: pair.length > 1 && pair[1].trim() ? pair[1].trim() : path
            });
        }
        if (!mapping.length)
            throw new Error('property ' + property + ' holds no field');
        return mapping;
    },

    /**
     * The fields configured for one section.
     * @param {Array} mapping the fields property, parsed
     * @param {string} table the ServiceNow table of the section
     * @returns {Array} the fields of that section in the order of the property
     */
    _sectionFields: function(mapping, table) {
        var fields = [];
        for (var i = 0; i < mapping.length; i++)
            if (mapping[i].table == table)
                fields.push(mapping[i]);
        return fields;
    },

    /**
     * Refuses a configuration the payload cannot be built from: a field of a table that is not a
     * section, or a section without a single field.
     * @param {Array} sections the sections property, parsed
     * @param {Array} mapping the fields property, parsed
     * @param {string} table the table the business rule runs on
     * @throws when the two properties do not describe the same payload
     */
    _requireConfiguration: function(sections, mapping, table) {
        var known = {};
        for (var s = 0; s < sections.length; s++) {
            known[sections[s].table] = true;
            if (!this._sectionFields(mapping, sections[s].table).length)
                throw new Error('section ' + sections[s].table + ' of property ' + this.SECTIONS_PROPERTY_PREFIX + table + ' has no field in property ' + this.FIELDS_PROPERTY_PREFIX + table);
        }
        for (var m = 0; m < mapping.length; m++)
            if (!known[mapping[m].table])
                throw new Error('field ' + mapping[m].table + '.' + mapping[m].field + ' of property ' + this.FIELDS_PROPERTY_PREFIX + table + ' belongs to no section of property ' + this.SECTIONS_PROPERTY_PREFIX + table);
    },

    /**
     * Checks the finished payload before it is handed over: the envelope, the sections and the
     * fields of the two properties, every value a string and nothing else in the message.
     * @param {Object} payload the payload as it will be sent
     * @param {Array} sections the sections property, parsed
     * @param {Array} mapping the fields property, parsed
     * @param {GlideRecord} record the application vulnerable item
     * @throws naming every problem found
     */
    _validatePayload: function(payload, sections, mapping, record) {
        var problems = [];
        var envelope = payload.envelope || {};
        if (envelope.type != 'record' || envelope.topic_name != this.TOPIC_NAME || envelope.namespace != this.NAMESPACE ||
            envelope.core_version != this.CORE_VERSION || envelope.outbound_version != this.OUTBOUND_VERSION)
            problems.push('the envelope does not carry the configured constants');
        if (!this.UUID_PATTERN.test(String(envelope.event_id)))
            problems.push('event_id is not a UUID');
        if (!this.TIMESTAMP_PATTERN.test(String(envelope.event_timestamp)))
            problems.push('event_timestamp is not a UTC timestamp');
        if (this.ACTIVITIES.indexOf(String(envelope.element_activity)) < 0)
            problems.push('element_activity "' + envelope.element_activity + '" is none of ' + this.ACTIVITIES.join(', '));
        var findings = payload.findings;
        if (!findings || !findings.length)
            problems.push('the message carries no finding');
        else if (envelope.element_count !== findings.length)
            problems.push('element_count ' + envelope.element_count + ' is not the number of findings ' + findings.length);
        for (var f = 0; findings && f < findings.length; f++) {
            var finding = findings[f];
            for (var s = 0; s < sections.length; s++) {
                var section = sections[s];
                var value = finding[section.json];
                if (value === undefined) {
                    problems.push('section ' + section.json + ' is missing');
                    continue;
                }
                var entries = section.many ? value : [value];
                if (section.many && !this._isArray(value)) {
                    problems.push('section ' + section.json + ' is not a list');
                    continue;
                }
                for (var e = 0; e < entries.length; e++)
                    this._checkSection(problems, section, entries[e], this._sectionFields(mapping, section.table));
            }
            for (var key in finding)
                if (!this._sectionNamed(sections, key))
                    problems.push('the finding carries "' + key + '", which is not a configured section');
        }
        if (problems.length)
            throw new Error('payload invalid for ' + record.getValue('number') + ': ' + problems.join('; '));
    },

    /**
     * Checks one section of the payload against the fields configured for it.
     * @param {Array} problems collects what is wrong
     * @param {Object} section the section of the sections property
     * @param {Object} values the section as built
     * @param {Array} fields the fields configured for the section
     */
    _checkSection: function(problems, section, values, fields) {
        if (!values || typeof values != 'object')
            problems.push('section ' + section.json + ' is not an object');
        else {
            for (var i = 0; i < fields.length; i++) {
                if (!values.hasOwnProperty(fields[i].json))
                    problems.push(section.json + '.' + fields[i].json + ' is missing');
                else if (typeof values[fields[i].json] != 'string')
                    problems.push(section.json + '.' + fields[i].json + ' is not a string');
            }
            for (var key in values)
                if (!this._fieldNamed(fields, key))
                    problems.push('section ' + section.json + ' carries "' + key + '", which is not a configured field');
        }
    },

    /**
     * @param {Array} sections the sections property, parsed
     * @param {string} name a payload key of the finding
     * @returns {boolean} true when a configured section carries that name
     */
    _sectionNamed: function(sections, name) {
        for (var i = 0; i < sections.length; i++)
            if (sections[i].json == name)
                return true;
        return false;
    },

    /**
     * @param {Array} fields the fields of one section
     * @param {string} name a payload key of the section
     * @returns {boolean} true when a configured field carries that name
     */
    _fieldNamed: function(fields, name) {
        for (var i = 0; i < fields.length; i++)
            if (fields[i].json == name)
                return true;
        return false;
    },

    /**
     * @param {*} value any value of the payload
     * @returns {boolean} true when the value is an array
     */
    _isArray: function(value) {
        return Object.prototype.toString.call(value) == '[object Array]';
    },

    /**
     * The value of one field, rendered for the payload.
     * @param {GlideRecord} record the record of the section, or null when the item has none
     * @param {string} field the ServiceNow field
     * @returns {string} the rendered value, "" when the record, the field or the value is absent
     */
    _fieldValue: function(record, field) {
        if (!record || !record.isValidRecord() || !record.isValidField(field))
            return '';
        var element = record.getElement(field);
        if (element === null || element.nil())
            return '';
        return this._renderElement(element);
    },

    /**
     * Renders one field by its dictionary type: a reference as the display value of the record it
     * points at (and "" when that record is gone, never the stored sys_id), a date or date and time
     * in the configured format, everything else as stored.
     * @param {GlideElement} element the field of the record
     * @returns {string} the rendered value
     */
    _renderElement: function(element) {
        switch (String(element.getED().getInternalType())) {
            case 'glide_date_time':
                return this._formatDateTime(element.getValue());
            case 'glide_date':
                return this._formatDate(element.getValue());
            case 'reference':
                var referenced = element.getRefRecord();
                return referenced && referenced.isValidRecord() ? String(element.getDisplayValue()) : '';
            default:
                return String(element.getValue());
        }
    },

    /**
     * @param {string} value a stored date and time
     * @returns {string} the value as MM-dd-yyyy HH:mm:ss
     */
    _formatDateTime: function(value) {
        var gdt = new GlideDateTime(value);
        return gdt.getDate().getByFormat(this.DATE_FORMAT) + ' ' + gdt.getTime().getByFormat(this.TIME_FORMAT);
    },

    /**
     * @param {string} value a stored date
     * @returns {string} the value as MM-dd-yyyy
     */
    _formatDate: function(value) {
        var gd = new GlideDate();
        gd.setValue(value);
        return gd.getByFormat(this.DATE_FORMAT);
    },

    /**
     * @returns {string} a fresh event id in UUID form
     */
    _newEventId: function() {
        var guid = gs.generateGUID();
        return guid.substring(0, 8) + '-' + guid.substring(8, 12) + '-' + guid.substring(12, 16) + '-' +
            guid.substring(16, 20) + '-' + guid.substring(20, 32);
    },

    /**
     * @returns {string} the current time as an ISO 8601 UTC timestamp
     */
    _utcTimestamp: function() {
        return new GlideDateTime().getValue().replace(' ', 'T') + 'Z';
    },

    type: 'BOFASIVampOutboundProcessor'
};
