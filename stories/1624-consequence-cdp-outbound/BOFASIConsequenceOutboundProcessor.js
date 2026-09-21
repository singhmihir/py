/**
 * Builds the outbound CDP payload of one consequence record: the envelope and a single element that
 * holds the consequence section and its rule section, both keyed by table name.
 *
 * Configuration lives in initialize() and in one system property of the application:
 *   <scope>.usem.consequence.fields.<consequence table>
 *     one servicenow_field=payload_field pair per line, in payload order; the consequence's own fields
 *     plain, the rule's fields as <rule table>.<field>; the rule table is reached through the reference
 *     field named in REFERENCES.
 * Rendering: references and document ids as the display value of the record they point at, date/times
 * as MM-dd-yyyy HH:mm:ss, dates as MM-dd-yyyy, everything else as stored; a field missing on the table,
 * an empty field or a section without a record gives "".
 *
 * Entry point: buildPayload(record). It holds the one try/catch of the feature: any failure, including
 * a payload that does not validate, is logged once with gs.error and returns an empty string, so that
 * nothing is sent.
 */
var BOFASIConsequenceOutboundProcessor = Class.create();
BOFASIConsequenceOutboundProcessor.prototype = {

    /**
     * Constants of the envelope, the formats of the rendered values, the property prefix of the field
     * mapping and the reference fields through which the other sections are reached.
     */
    initialize: function() {
        this.TOPIC_NAME = 'sn_usem_consequence_outbound';
        this.NAMESPACE = 'com.bofa.usem';
        this.CORE_VERSION = '1.0.0';
        this.OUTBOUND_VERSION = '1.0.0';
        this.ELEMENT_COUNT = 1;
        this.ACTIVITIES = ['INSERT', 'UPDATE', 'DELETE'];
        this.DATE_FORMAT = 'MM-dd-yyyy';
        this.TIME_FORMAT = 'HH:mm:ss';
        this.FIELDS_PROPERTY_PREFIX = 'x_boar_bofa_usem_0.usem.consequence.fields.';
        this.REFERENCES = {
            x_boar_bofa_usem_0_consequence_rule: 'u_rule'
        };
        this.UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
        this.TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
    },

    /**
     * Builds and validates the payload of one consequence record and shows it on the record.
     * @param {GlideRecord} record - the consequence record (current in the business rule)
     * @returns {string} the JSON text of the payload; an empty string when it could not be built or did
     *   not validate, in which case the reason has been logged
     */
    buildPayload: function(record) {
        try {
            this._requireRecord(record);
            var mapping = this._fieldMapping(record.getTableName());
            var missing = [];
            var payload = {
                envelope: this._buildEnvelope(this._activity(record)),
                consequences: [this._buildConsequence(record, mapping, missing)]
            };
            this._validatePayload(payload, record, mapping);
            var message = JSON.stringify(payload);
            gs.addInfoMessage('Consequence payload for ' + record.getValue('number') + ': ' + message)
            if (missing.length)
                gs.addInfoMessage('Consequence fields not found on this instance, sent as "": ' + missing.join(', '))
            return message;
        } catch (e) {
            gs.error(this.type + ': payload not built for ' + this._recordKey(record) + ' - ' + (e.message || e));
            return '';
        }
    },

    /**
     * Refuses anything that is not a fetched GlideRecord.
     * @param {GlideRecord} record - the value handed in as the record
     * @throws {Error} when the record is absent, not a GlideRecord or not an existing row
     */
    _requireRecord: function(record) {
        if (!record || typeof record.isValidRecord != 'function')
            throw new Error('no record was given');
        if (!record.isValidRecord())
            throw new Error('the record does not exist');
    },

    /**
     * Names a record for the error log without assuming it is usable.
     * @param {GlideRecord} record - the record, possibly absent or invalid
     * @returns {string} "<table> <sys_id>" when the record can be read, otherwise "no record"
     */
    _recordKey: function(record) {
        try {
            return record.getTableName() + ' ' + record.getUniqueValue();
        } catch (e) {
            return 'no record';
        }
    },

    /**
     * The activity the envelope reports: the operation of the business rule that runs, else derived from
     * the update count when the processor is called outside a rule.
     * @param {GlideRecord} record - the consequence record
     * @returns {string} INSERT, UPDATE or DELETE
     */
    _activity: function(record) {
        var operation = String(record.operation() || '').toUpperCase();
        if (operation)
            return operation;
        return parseInt(record.getValue('sys_mod_count')) > 0 ? 'UPDATE' : 'INSERT';
    },

    /**
     * The envelope of the message.
     * @param {string} activity - INSERT, UPDATE or DELETE
     * @returns {Object} the envelope with the constants of initialize(), a new event id and the current UTC time
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
            element_count: this.ELEMENT_COUNT,
            element_activity: activity
        };
    },

    /**
     * The one element of the message: one section per table of the mapping, each holding the payload
     * names of that table with the rendered values, in mapping order.
     * @param {GlideRecord} record - the consequence record
     * @param {Object[]} mapping - the parsed field property, see _fieldMapping
     * @param {string[]} missing - receives "<table>.<field>" for every mapped field the instance lacks
     * @returns {Object} the element keyed by table name
     */
    _buildConsequence: function(record, mapping, missing) {
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

    /**
     * The record a section is read from: the consequence itself, or the record behind one of the
     * reference fields of REFERENCES.
     * @param {GlideRecord} record - the consequence record
     * @param {string} table - the table name of the section
     * @returns {GlideRecord} the record of the section; for a reference left empty, a record that
     *   isValidRecord() rejects, which renders every field as ""
     * @throws {Error} when the mapping names a table the processor cannot reach
     */
    _sectionRecord: function(record, table) {
        if (table == record.getTableName())
            return record;
        if (this.REFERENCES[table])
            return record.getElement(this.REFERENCES[table]).getRefRecord();
        throw new Error('table ' + table + ' in property ' + this.FIELDS_PROPERTY_PREFIX + record.getTableName() + ' is not a source of the payload');
    },

    /**
     * Reads and parses the field property of the table.
     * @param {string} table - the table of the record
     * @returns {Object[]} one {field, json} per configured pair, in property order; the payload name
     *   defaults to the field when no "=payload_field" follows it
     * @throws {Error} when the property is missing or empty, or a line has no field name before "="
     */
    _fieldMapping: function(table) {
        var property = this.FIELDS_PROPERTY_PREFIX + table;
        var value = gs.getProperty(property, '');
        if (!value)
            throw new Error('table ' + table + ' is not configured in property ' + property);
        var mapping = [];
        var entries = value.split(/\r?\n|,/);
        for (var i = 0; i < entries.length; i++) {
            var entry = entries[i].trim();
            if (!entry)
                continue;
            var pair = entry.split('=');
            var field = pair[0].trim();
            if (!field)
                throw new Error('property ' + property + ' holds a line without a field name: "' + entry + '"');
            mapping.push({ field: field, json: pair.length > 1 && pair[1].trim() ? pair[1].trim() : field });
        }
        if (!mapping.length)
            throw new Error('property ' + property + ' holds no field');
        return mapping;
    },

    /**
     * Checks the built payload against the envelope constants and the field mapping before it is sent.
     * @param {Object} payload - the payload object
     * @param {GlideRecord} record - the consequence record it was built from
     * @param {Object[]} mapping - the parsed field property
     * @throws {Error} naming every problem found: an envelope value missing or off its constant, a
     *   malformed event id or timestamp, an element count other than one, a section or payload name
     *   of the mapping missing, a value that is not a string, a section not named in the mapping, or a
     *   consequence section with no value at all
     */
    _validatePayload: function(payload, record, mapping) {
        var problems = [];
        var envelope = payload.envelope || {};
        var expected = { type: 'record', topic_name: this.TOPIC_NAME, namespace: this.NAMESPACE, core_version: this.CORE_VERSION, outbound_version: this.OUTBOUND_VERSION, element_count: this.ELEMENT_COUNT };
        for (var key in expected)
            if (envelope[key] !== expected[key])
                problems.push('envelope.' + key + ' is "' + envelope[key] + '", expected "' + expected[key] + '"');
        if (!this.UUID_PATTERN.test(String(envelope.event_id)))
            problems.push('envelope.event_id "' + envelope.event_id + '" is not a UUID');
        if (!this.TIMESTAMP_PATTERN.test(String(envelope.event_timestamp)))
            problems.push('envelope.event_timestamp "' + envelope.event_timestamp + '" is not a UTC timestamp');
        if (this.ACTIVITIES.indexOf(envelope.element_activity) < 0)
            problems.push('envelope.element_activity "' + envelope.element_activity + '" is not one of ' + this.ACTIVITIES.join(', '));
        var elements = payload.consequences;
        if (!elements || elements.length !== this.ELEMENT_COUNT)
            problems.push('payload holds ' + (elements ? elements.length : 'no') + ' element(s), expected ' + this.ELEMENT_COUNT);
        var element = elements && elements.length ? elements[0] : {};
        var expectedNames = {};
        for (var i = 0; i < mapping.length; i++) {
            var at = mapping[i].field.indexOf('.');
            var table = at < 0 ? record.getTableName() : mapping[i].field.substring(0, at);
            if (!expectedNames[table])
                expectedNames[table] = {};
            expectedNames[table][mapping[i].json] = true;
            var section = element[table];
            if (!section || !section.hasOwnProperty(mapping[i].json))
                problems.push('section ' + table + ' lacks ' + mapping[i].json);
            else if (typeof section[mapping[i].json] != 'string')
                problems.push('section ' + table + '.' + mapping[i].json + ' is not a string');
        }
        for (var name in element) {
            if (!expectedNames[name])
                problems.push('section ' + name + ' is not in the field property');
            else
                for (var json in element[name])
                    if (!expectedNames[name][json])
                        problems.push('section ' + name + ' carries ' + json + ', which is not in the field property');
        }
        var own = element[record.getTableName()] || {}, filled = 0;
        for (var field in own)
            if (own[field] !== '')
                filled++;
        if (!filled)
            problems.push('section ' + record.getTableName() + ' holds no value');
        if (problems.length)
            throw new Error('payload invalid: ' + problems.join('; '));
    },

    /**
     * Renders one field of a record.
     * @param {GlideRecord} record - the record of the section; may be absent or invalid
     * @param {string} field - the field name
     * @returns {string} the rendered value; "" when the record is missing or invalid, the field does not
     *   exist or is empty
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
     * Renders a non-empty element by its dictionary type.
     * @param {GlideElement} element - the element to render
     * @returns {string} references and document ids as the display value of the record they point at
     *   ("" for a document id whose record or class is missing), date/times and dates in the configured
     *   formats, anything else as stored
     */
    _renderElement: function(element) {
        switch (String(element.getED().getInternalType())) {
            case 'glide_date_time':
                return this._formatDateTime(element.getValue());
            case 'glide_date':
                return this._formatDate(element.getValue());
            case 'reference':
                return String(element.getDisplayValue());
            case 'document_id':
                var target = element.getRefRecord();
                return target && target.isValidRecord() ? String(target.getDisplayValue()) : '';
            default:
                return String(element.getValue());
        }
    },

    /**
     * Formats a stored date/time value.
     * @param {string} value - the stored value (yyyy-MM-dd HH:mm:ss, UTC)
     * @returns {string} the value as MM-dd-yyyy HH:mm:ss
     */
    _formatDateTime: function(value) {
        var gdt = new GlideDateTime(value);
        return gdt.getDate().getByFormat(this.DATE_FORMAT) + ' ' + gdt.getTime().getByFormat(this.TIME_FORMAT);
    },

    /**
     * Formats a stored date value.
     * @param {string} value - the stored value (yyyy-MM-dd)
     * @returns {string} the value as MM-dd-yyyy
     */
    _formatDate: function(value) {
        var gd = new GlideDate();
        gd.setValue(value);
        return gd.getByFormat(this.DATE_FORMAT);
    },

    /**
     * A new event id in UUID form, built from a platform GUID.
     * @returns {string} 8-4-4-4-12 hexadecimal groups
     */
    _newEventId: function() {
        var guid = gs.generateGUID();
        return guid.substring(0, 8) + '-' + guid.substring(8, 12) + '-' + guid.substring(12, 16) + '-' +
            guid.substring(16, 20) + '-' + guid.substring(20, 32);
    },

    /**
     * The current time in UTC.
     * @returns {string} yyyy-MM-ddTHH:mm:ssZ
     */
    _utcTimestamp: function() {
        return new GlideDateTime().getValue().replace(' ', 'T') + 'Z';
    },

    type: 'BOFASIConsequenceOutboundProcessor'
};
