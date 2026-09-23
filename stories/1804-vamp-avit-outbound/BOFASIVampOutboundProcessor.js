/**
 * Builds the outbound VAMP payload of one application vulnerable item: the envelope and a single
 * finding element that holds the sections of the mapping sheet "SN to VAMP", each named by the JSON
 * structure of the sheet (tpe, remediation_task, finding, ptreq).
 *
 * Configuration lives in initialize() and in one system property of the application:
 *   <scope>.usem.vamp.fields.<item table>
 *     one servicenow_field=json_field pair per line, in payload order; on the left the ServiceNow
 *     field, the item's own plain and another section's as <table>.<field>; on the right the payload
 *     name as <json structure>.<json field>, the two columns of the sheet. The sections of the
 *     payload are the structures in the order the property introduces them, and the section of a
 *     table reached through a many to many is a list, one entry per linked record.
 * The path from the item to every other section is the RELATED map of initialize(): a reference field
 * for the vulnerability entry and the pen test request, the group item table for the remediation
 * tasks. A record reached through a reference is re-opened in its own class, so that the fields of an
 * extended table are read as well.
 * Rendering by dictionary type, as the sheet's types ask: references and document ids as the display
 * value of the record they point at, journals as their latest entry, lists and domains as displayed,
 * date/times as MM-dd-yyyy HH:mm:ss, dates as MM-dd-yyyy, integers and strings as stored; a field
 * missing on the table, an empty field, a reference whose record is gone or a section without a record
 * gives "". Field types are read from a record of the section's table the processor opens itself: a
 * scoped application may not read the dictionary descriptor of a record handed over from inside a
 * function of a global script.
 *
 * Entry point: buildPayload(record). It holds the one try/catch of the feature: any failure, including
 * a line of the property that does not parse and a payload that does not validate, is logged once
 * with gs.error and returns an empty string, so that nothing is sent.
 */
var BOFASIVampOutboundProcessor = Class.create();
BOFASIVampOutboundProcessor.prototype = {

    /**
     * Constants of the envelope, the formats of the rendered values, the prefix of the property that
     * holds the payload structure and the path from the application vulnerable item to every other
     * record of the payload. A path with "list" is a many to many: its section is sent as an array,
     * one entry per related record.
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
        this.RELATED = {
            sn_vul_app_vul_entry: { reference: 'vulnerability' },
            sn_vul_pen_test_assessment_request: { reference: 'assessment_request' },
            sn_vul_app_vulnerability: { list: 'sn_vul_app_m2m_vul_group_item', item: 'sn_vul_app_vulnerable_item', related: 'sn_vul_app_vulnerability', order: 'number' }
        };
        this.UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
        this.TIMESTAMP_PATTERN = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/;
        this.JOURNAL_TYPES = ['journal_input', 'journal', 'journal_list'];
    },

    /**
     * Builds the message of one application vulnerable item and shows it on the record, with a second
     * message naming any configured field this instance does not have.
     * @param {GlideRecord} record - the application vulnerable item the business rule is running on
     * @returns {string} the payload as JSON text, or "" when it could not be built or did not validate
     */
    buildPayload: function(record) {
        try {
            this._requireRecord(record);
            var table = record.getTableName();
            var sections = this._payloadMap(table);
            var missing = [];
            var findings = [this._buildFinding(record, sections, missing)];
            var payload = {
                envelope: this._buildEnvelope(this._activity(record), findings.length),
                findings: findings
            };
            this._validatePayload(payload, sections, record);
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
     * @param {GlideRecord} record - the record the business rule passed in
     * @throws {Error} when no record was given or the record does not exist
     */
    _requireRecord: function(record) {
        if (!record || !record.getTableName)
            throw new Error('no record was given');
        if (!record.isValidRecord())
            throw new Error('the record does not exist');
    },

    /**
     * Names a record in an error message, also when the record itself is the reason for the error.
     * @param {GlideRecord} record - the record the payload was being built for
     * @returns {string} "<table> <sys_id>", or "no record"
     */
    _recordKey: function(record) {
        if (!record || typeof record.getTableName != 'function')
            return 'no record';
        return (record.getTableName() + ' ' + (record.getUniqueValue() || '')).trim();
    },

    /**
     * The activity of the message, taken from the operation the business rule is running for.
     * @param {GlideRecord} record - the application vulnerable item
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
     * @param {string} activity - INSERT, UPDATE or DELETE
     * @param {number} elements - the number of findings the message carries
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
     * Builds one finding: every configured section in the order the property introduces it, each
     * section from its own record, a section reached through a many to many as an array.
     * @param {GlideRecord} record - the application vulnerable item
     * @param {Array} sections - the property, parsed
     * @param {Array} missing - collects the configured fields this instance does not have
     * @returns {Object} the finding
     */
    _buildFinding: function(record, sections, missing) {
        var finding = {};
        for (var i = 0; i < sections.length; i++) {
            var section = sections[i], fields = section.fields;
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
     * every record the many to many links to it (the property allows only tables with a path).
     * @param {GlideRecord} record - the application vulnerable item
     * @param {string} table - the ServiceNow table of the section
     * @returns {Array} the records, empty when the section has none
     */
    _sectionRecords: function(record, table) {
        if (table == record.getTableName())
            return [record];
        var path = this.RELATED[table];
        return path.reference ? this._referenced(record, path.reference) : this._listed(record, path);
    },

    /**
     * The record a reference field points at, opened in its own class.
     * @param {GlideRecord} record - the application vulnerable item
     * @param {string} field - the reference field
     * @returns {Array} one record, or empty when the field is empty or the target is gone
     */
    _referenced: function(record, field) {
        var element = record.getElement(field);
        if (element === null || element.nil())
            return [];
        var referenced = element.getRefRecord();
        if (!this._isRecord(referenced))
            return [];
        return [this._inOwnClass(referenced)];
    },

    /**
     * Every record a many to many links to the item, in a stable order, each opened in its own class
     * and taken once however many links point at it.
     * @param {GlideRecord} record - the application vulnerable item
     * @param {Object} path - the many to many configuration of the section
     * @returns {Array} the related records, empty when the item has none
     */
    _listed: function(record, path) {
        var found = [], seen = {};
        var link = new GlideRecord(path.list);
        link.addQuery(path.item, record.getUniqueValue());
        link.addNotNullQuery(path.related);
        link.orderBy(path.related + '.' + path.order);
        link.query();
        while (link.next()) {
            var id = '' + link.getValue(path.related);
            if (seen[id])
                continue;
            seen[id] = true;
            var related = link.getElement(path.related).getRefRecord();
            if (this._isRecord(related))
                found.push(this._inOwnClass(related));
        }
        return found;
    },

    /**
     * Re-opens a record in the class it belongs to, so that the fields of an extended table are read
     * as well: a reference to a base table hands out a record of that base table only.
     * @param {GlideRecord} referenced - the record as the reference handed it over
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
     * The values of one section, the payload names of the property in its order.
     * @param {GlideRecord} sectionRecord - the record of the section, null when the item has none
     * @param {Array} fields - the fields of the section
     * @returns {Object} the payload names and their values, every value a string
     */
    _sectionValues: function(sectionRecord, fields) {
        var values = {};
        var dictionary = this._isRecord(sectionRecord) ? new GlideRecord(sectionRecord.getTableName()) : null;
        for (var i = 0; i < fields.length; i++)
            values[fields[i].json] = this._fieldValue(sectionRecord, dictionary, fields[i].field);
        return values;
    },

    /**
     * Records the configured fields of a section this instance does not have. The check is made
     * against the configured table, once per section, so that the message names the same fields
     * whether the item has one related record, several or none.
     * @param {string} table - the configured ServiceNow table of the section
     * @param {Array} fields - the fields of the section
     * @param {Array} missing - the list collected while the payload is built
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
     * The payload structure, read from the one property in its order: every line carries the
     * ServiceNow field on the left (the item's own plain, another section's as <table>.<field>) and
     * the payload name on the right as <json structure>.<json field>. The sections are the structures
     * in the order the property introduces them.
     * @param {string} table - the table the business rule runs on
     * @returns {Array} {json, table, many, fields:[{field, json}]} per section, in payload order
     * @throws {Error} when the property is not configured, holds no field, or holds a line with more
     *                 than one "=", without a field name, with a field that is not <field> or
     *                 <table>.<field>, of a table with no path from the item, without a payload name,
     *                 with a payload name that is not <structure>.<field>, with a section taking fields
     *                 from two tables, or with one payload name twice in a section
     */
    _payloadMap: function(table) {
        var property = this.FIELDS_PROPERTY_PREFIX + table;
        var value = gs.getProperty(property, '');
        if (!value)
            throw new Error('table ' + table + ' is not configured in property ' + property);
        var sections = [], byStructure = {}, entries = value.split(/\r?\n|,/);
        for (var i = 0; i < entries.length; i++) {
            var line = entries[i].trim();
            if (!line)
                continue;
            var pair = line.split('=');
            if (pair.length > 2)
                throw new Error('property ' + property + ' holds a line with more than one "=": "' + line + '"');
            var left = pair[0].trim(), right = pair.length > 1 ? pair[1].trim() : '';
            if (!left)
                throw new Error('property ' + property + ' holds a line without a field name: "' + line + '"');
            if (!right)
                throw new Error('property ' + property + ' holds a line without a payload name: "' + line + '"');
            var names = right.split('.');
            var structure = names[0].trim(), payloadField = names.length == 2 ? names[1].trim() : '';
            if (!structure || !payloadField)
                throw new Error('property ' + property + ' holds the payload name "' + right + '", which is not <structure>.<field>: "' + line + '"');
            var parts = left.split('.');
            var sectionTable = parts.length == 2 ? parts[0].trim() : table, field = parts[parts.length - 1].trim();
            if (parts.length > 2 || !sectionTable || !field)
                throw new Error('property ' + property + ' holds the field "' + left + '", which is not <field> or <table>.<field>: "' + line + '"');
            if (sectionTable != table && !this.RELATED.hasOwnProperty(sectionTable))
                throw new Error('property ' + property + ' names table ' + sectionTable + ', which has no path from ' + table + ': "' + line + '"');
            var section = byStructure[structure];
            if (!section) {
                section = byStructure[structure] = { json: structure, table: sectionTable, many: !!(this.RELATED[sectionTable] && this.RELATED[sectionTable].list), fields: [] };
                sections.push(section);
            }
            if (section.table != sectionTable)
                throw new Error('section ' + structure + ' of property ' + property + ' takes fields from ' + section.table + ' and from ' + sectionTable);
            if (this._fieldNamed(section.fields, payloadField))
                throw new Error('section ' + structure + ' of property ' + property + ' names ' + payloadField + ' twice');
            section.fields.push({ field: field, json: payloadField });
        }
        if (!sections.length)
            throw new Error('property ' + property + ' holds no field');
        return sections;
    },

    /**
     * Checks the finished payload before it is handed over: the envelope, the sections and the
     * fields of the property, every value a string and nothing else in the message.
     * @param {Object} payload - the payload as it will be sent
     * @param {Array} sections - the property, parsed
     * @param {GlideRecord} record - the application vulnerable item
     * @throws {Error} naming every problem found
     */
    _validatePayload: function(payload, sections, record) {
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
                    this._checkSection(problems, section, entries[e], section.fields);
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
     * @param {Array} problems - collects what is wrong
     * @param {Object} section - the section, as parsed from the property
     * @param {Object} values - the section as built
     * @param {Array} fields - the fields configured for the section
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
     * @param {Array} sections - the property, parsed
     * @param {string} name - a payload key of the finding
     * @returns {boolean} true when a configured section carries that name
     */
    _sectionNamed: function(sections, name) {
        for (var i = 0; i < sections.length; i++)
            if (sections[i].json == name)
                return true;
        return false;
    },

    /**
     * @param {Array} fields - the fields of one section
     * @param {string} name - a payload key of the section
     * @returns {boolean} true when a configured field carries that name
     */
    _fieldNamed: function(fields, name) {
        for (var i = 0; i < fields.length; i++)
            if (fields[i].json == name)
                return true;
        return false;
    },

    /**
     * @param {*} value - any value of the payload
     * @returns {boolean} true when the value is an array
     */
    _isArray: function(value) {
        return Object.prototype.toString.call(value) == '[object Array]';
    },

    /**
     * The value of one field, rendered for the payload.
     * @param {GlideRecord} record - the record of the section, or null when the item has none
     * @param {GlideRecord} dictionary - a record of the same table, opened by the processor, whose field
     *                                   descriptors give the field types; null with the record
     * @param {string} field - the ServiceNow field
     * @returns {string} the rendered value, "" when the record, the field or the value is absent
     */
    _fieldValue: function(record, dictionary, field) {
        if (!this._isRecord(record) || !record.isValidField(field))
            return '';
        var element = record.getElement(field);
        if (element === null)
            return '';
        var descriptor = dictionary.getElement(field).getED();
        if (this.JOURNAL_TYPES.indexOf(String(descriptor.getInternalType())) >= 0)
            return this._latestEntry(element);
        if (element.nil())
            return '';
        return this._renderElement(element, descriptor);
    },

    /**
     * The text of the latest entry of a journal field, without the header line the platform adds
     * (date and time, author). A journal keeps its entries apart from the record, so the field itself
     * is empty on every save that adds no entry.
     * @param {GlideElement} element - the journal field
     * @returns {string} the latest entry's text, "" when the journal has none
     */
    _latestEntry: function(element) {
        var entry = String(element.getJournalEntry(1) || '');
        var header = entry.indexOf('\n');
        return header < 0 ? '' : entry.substring(header + 1).trim();
    },

    /**
     * Renders one field by its dictionary type: a reference or a document id as the display value of
     * the record it points at (and "" when that record is gone, never the stored sys_id), a list or a
     * domain as displayed (names, not sys_ids), a date or date and time in the configured format,
     * everything else as stored.
     * @param {GlideElement} element - the field of the record
     * @param {GlideElementDescriptor} descriptor - the field's dictionary descriptor
     * @returns {string} the rendered value
     */
    _renderElement: function(element, descriptor) {
        switch (String(descriptor.getInternalType())) {
            case 'glide_date_time':
            case 'due_date':
                return this._formatDateTime(element.getValue());
            case 'glide_date':
                return this._formatDate(element.getValue());
            case 'reference':
                return this._isRecord(element.getRefRecord()) ? String(element.getDisplayValue()) : '';
            case 'document_id':
                var target = element.getRefRecord();
                return this._isRecord(target) ? String(target.getDisplayValue()) : '';
            case 'glide_list':
            case 'domain_id':
                return String(element.getDisplayValue());
            default:
                return String(element.getValue());
        }
    },

    /**
     * Tells whether a value is a record that exists. getRefRecord() of a document id whose table
     * field is empty gives null, or in a scoped script an empty object without the record methods.
     * @param {*} value - the value to check
     * @returns {boolean} true for a GlideRecord positioned on an existing record
     */
    _isRecord: function(value) {
        return value != null && typeof value.isValidRecord == 'function' && value.isValidRecord();
    },

    /**
     * @param {string} value - a stored date and time
     * @returns {string} the value as MM-dd-yyyy HH:mm:ss
     */
    _formatDateTime: function(value) {
        var gdt = new GlideDateTime(value);
        return gdt.getDate().getByFormat(this.DATE_FORMAT) + ' ' + gdt.getTime().getByFormat(this.TIME_FORMAT);
    },

    /**
     * @param {string} value - a stored date
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
