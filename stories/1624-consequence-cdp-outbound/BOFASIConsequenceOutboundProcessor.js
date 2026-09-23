/**
 * Builds the outbound CDP payload of one consequence record: the envelope and a single element that
 * holds the consequence section and its rule section, named by the JSON structures of the sheet
 * "Outbound to CDP (consequence)": consequence and rule.
 *
 * Configuration lives in initialize() and in one system property of the application:
 *   <scope>.usem.consequence.fields.<consequence table>
 *     one servicenow_field=payload_field pair per line, in payload order; the consequence's own fields
 *     plain, the rule's fields as <rule table>.<field>. SECTIONS of initialize() names the section of
 *     each table and the reference field through which the rule is reached.
 * Rendering by dictionary type: references and document ids as the display value of the record they
 * point at ("" when that record is gone), journals as their latest entry, choices as their labels,
 * counts as stored, date/times as MM-dd-yyyy HH:mm:ss, dates as MM-dd-yyyy, strings and booleans as
 * displayed, anything else as stored; a field missing on the table, an empty field or a section
 * without a record gives "".
 *
 * Entry point: buildPayload(record). It holds the one try/catch of the feature: any failure, including
 * a payload that does not validate, is logged once with gs.error and returns an empty string, so that
 * nothing is sent.
 */
var BOFASIConsequenceOutboundProcessor = Class.create();
BOFASIConsequenceOutboundProcessor.prototype = {

    /**
     * Constants of the envelope, the formats of the rendered values, the property prefix of the field
     * mapping, the section of each table (its payload name, and for the rule the reference field of
     * the consequence that leads to it), the table searched for a document id whose class field
     * names no table, the journal field types and the display markup the platform wraps around some
     * values.
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
        this.SECTIONS = {
            x_boar_bofa_usem_0_consequence: { json: 'consequence' },
            x_boar_bofa_usem_0_consequence_rule: { json: 'rule', reference: 'u_rule' }
        };
        this.DOCUMENT_TABLES = { cmdb_ci: 'cmdb_ci' };
        this.JOURNAL_TYPES = ['journal_input', 'journal', 'journal_list'];
        this.MARKUP = /^\[code\]([\s\S]*)\[\/code\]$/;
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
     * @returns {string} "<table> <sys_id>" (the table alone for a record without a sys_id), "no record"
     *   for anything that is not a record
     */
    _recordKey: function(record) {
        if (!record || typeof record.getTableName != 'function')
            return 'no record';
        return (record.getTableName() + ' ' + (record.getUniqueValue() || '')).trim();
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
     * The one element of the message: one section per table of the mapping, named as in SECTIONS,
     * each holding the payload names of that table with the rendered values, in mapping order. Field
     * types are read from a record of each table the processor opens itself: a scoped application
     * may not read the dictionary descriptor of a record handed over by a global script.
     * @param {GlideRecord} record - the consequence record
     * @param {Object[]} mapping - the parsed field property, see _fieldMapping
     * @param {string[]} missing - receives "<table>.<field>" for every mapped field the instance lacks
     * @returns {Object} the element, its sections keyed by their payload names
     */
    _buildConsequence: function(record, mapping, missing) {
        var element = {};
        var records = {}, dictionaries = {};
        for (var i = 0; i < mapping.length; i++) {
            var table = mapping[i].table, field = mapping[i].field, section = mapping[i].section;
            if (!records.hasOwnProperty(table)) {
                records[table] = this._sectionRecord(record, table);
                dictionaries[table] = new GlideRecord(table);
            }
            if (!dictionaries[table].isValidField(field))
                missing.push(table + '.' + field);
            if (!element[section])
                element[section] = {};
            element[section][mapping[i].json] = this._fieldValue(records[table], dictionaries[table], field);
        }
        return element;
    },

    /**
     * The record a section is read from: the consequence itself, or the record behind the reference
     * field SECTIONS names for the table.
     * @param {GlideRecord} record - the consequence record
     * @param {string} table - the table name of the section
     * @returns {GlideRecord} the record of the section; for a reference left empty or pointing at a
     *   record that is gone, a record that isValidRecord() rejects, which renders every field as ""
     */
    _sectionRecord: function(record, table) {
        if (table == record.getTableName())
            return record;
        return record.getElement(this.SECTIONS[table].reference).getRefRecord();
    },

    /**
     * Reads and parses the field property of the table.
     * @param {string} table - the table of the record
     * @returns {Object[]} one {table, field, section, json} per configured pair, in property order
     * @throws {Error} when the table has no section, the property is missing or empty, holds no field,
     *   or holds a line with more than one "=", without a field name, with a field that is not <field>
     *   or <table>.<field>, without a payload name, of a table that has no section, or naming a payload
     *   field of its section twice
     */
    _fieldMapping: function(table) {
        if (!this.SECTIONS[table])
            throw new Error('table ' + table + ' has no section in the payload');
        var property = this.FIELDS_PROPERTY_PREFIX + table;
        var value = gs.getProperty(property, '');
        if (!value)
            throw new Error('table ' + table + ' is not configured in property ' + property);
        var mapping = [], names = {};
        var entries = value.split(/\r?\n|,/);
        for (var i = 0; i < entries.length; i++) {
            var entry = entries[i].trim();
            if (!entry)
                continue;
            var pair = entry.split('=');
            if (pair.length > 2)
                throw new Error('property ' + property + ' holds a line with more than one "=": "' + entry + '"');
            var left = pair[0].trim(), json = pair.length > 1 ? pair[1].trim() : '';
            if (!left)
                throw new Error('property ' + property + ' holds a line without a field name: "' + entry + '"');
            if (!json)
                throw new Error('property ' + property + ' holds a line without a payload name: "' + entry + '"');
            var parts = left.split('.');
            var source = parts.length == 2 ? parts[0].trim() : table, field = parts[parts.length - 1].trim();
            if (parts.length > 2 || !source || !field)
                throw new Error('property ' + property + ' holds the field "' + left + '", which is not <field> or <table>.<field>: "' + entry + '"');
            if (!this.SECTIONS.hasOwnProperty(source) || (source != table && !this.SECTIONS[source].reference))
                throw new Error('property ' + property + ' names table ' + source + ', which is not a section of the payload: "' + entry + '"');
            var section = this.SECTIONS[source].json;
            if (names[section + '.' + json])
                throw new Error('property ' + property + ' names ' + json + ' twice in section ' + section);
            names[section + '.' + json] = true;
            mapping.push({ table: source, field: field, section: section, json: json });
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
            var name = mapping[i].section;
            if (!expectedNames[name])
                expectedNames[name] = {};
            expectedNames[name][mapping[i].json] = true;
            var section = element[name];
            if (!section || !section.hasOwnProperty(mapping[i].json))
                problems.push('section ' + name + ' lacks ' + mapping[i].json);
            else if (typeof section[mapping[i].json] != 'string')
                problems.push('section ' + name + '.' + mapping[i].json + ' is not a string');
        }
        for (var key in element) {
            if (!expectedNames[key])
                problems.push('section ' + key + ' is not in the field property');
            else
                for (var json in element[key])
                    if (!expectedNames[key][json])
                        problems.push('section ' + key + ' carries ' + json + ', which is not in the field property');
        }
        var ownName = this.SECTIONS[record.getTableName()].json;
        var own = element[ownName] || {}, filled = 0;
        for (var field in own)
            if (own[field] !== '')
                filled++;
        if (!filled)
            problems.push('section ' + ownName + ' holds no value');
        if (problems.length)
            throw new Error('payload invalid: ' + problems.join('; '));
    },

    /**
     * Renders one field of a record; a journal field as its latest entry.
     * @param {GlideRecord} record - the record of the section; may be absent or invalid
     * @param {GlideRecord} dictionary - a record of the same table, opened by the processor, whose field
     *   descriptors give the field types
     * @param {string} field - the field name
     * @returns {string} the rendered value; "" when the record is missing or invalid, the field does not
     *   exist or is empty
     */
    _fieldValue: function(record, dictionary, field) {
        if (!this._isRecord(record) || !record.isValidField(field))
            return '';
        var element = record.getElement(field);
        if (element === null)
            return '';
        var descriptor = dictionary.getElement(field).getED();
        if (this.JOURNAL_TYPES.indexOf(String(descriptor.getInternalType())) >= 0)
            return this._plainText(this._latestEntry(element));
        if (element.nil())
            return '';
        return this._renderElement(element, descriptor, field);
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
     * Renders a non-empty element by its dictionary type.
     * @param {GlideElement} element - the element to render
     * @param {GlideElementDescriptor} descriptor - the field's dictionary descriptor
     * @param {string} field - the field name
     * @returns {string} date/times and dates in the configured formats; a reference as its display
     *   value, "" when the record it points at is gone; a document id as the display value of its
     *   record (see _documentDisplay); an integer with choices as its label and a plain count as
     *   stored (a display value would carry the thousands separator of the user); strings, lists,
     *   booleans, durations, domains and classes as displayed, so choices give their labels; anything
     *   else as stored. Display markup of the form [code]...[/code] gives its visible text.
     */
    _renderElement: function(element, descriptor, field) {
        switch (String(descriptor.getInternalType())) {
            case 'glide_date_time':
            case 'due_date':
                return this._formatDateTime(element.getValue());
            case 'glide_date':
                return this._formatDate(element.getValue());
            case 'reference':
                return this._isRecord(element.getRefRecord()) ? String(element.getDisplayValue()) : '';
            case 'document_id':
                return this._documentDisplay(element, field);
            case 'integer':
                return descriptor.isChoiceTable() ? String(element.getDisplayValue()) : String(element.getValue());
            case 'string':
            case 'glide_list':
            case 'boolean':
            case 'glide_duration':
            case 'timer':
            case 'domain_id':
            case 'sys_class_name':
            case 'choice':
                return this._plainText(String(element.getDisplayValue()));
            default:
                return this._plainText(String(element.getValue()));
        }
    },

    /**
     * The display value of the record a document id points at: in the table its class field names,
     * otherwise, for a field of DOCUMENT_TABLES, in that table by sys_id (a class field left empty or
     * naming another class than the record's).
     * @param {GlideElement} element - the document id field
     * @param {string} field - the field name
     * @returns {string} the display value, "" when no record is found
     */
    _documentDisplay: function(element, field) {
        var target = element.getRefRecord();
        if (this._isRecord(target))
            return String(target.getDisplayValue());
        if (!this.DOCUMENT_TABLES[field])
            return '';
        var found = new GlideRecord(this.DOCUMENT_TABLES[field]);
        return found.get(String(element.getValue())) ? String(found.getDisplayValue()) : '';
    },

    /**
     * Tells whether a value is a record that exists. getRefRecord() of a document id whose class field
     * is empty gives null, or in a scoped script an empty object without the record methods.
     * @param {*} value - the value to check
     * @returns {boolean} true for a GlideRecord positioned on an existing record
     */
    _isRecord: function(value) {
        return value != null && typeof value.isValidRecord == 'function' && value.isValidRecord();
    },

    /**
     * Turns display markup ([code]<a href=...>3</a>[/code]) into its visible text; any other value is
     * returned unchanged.
     * @param {string} value - the value as the platform gives it
     * @returns {string} the value without markup
     */
    _plainText: function(value) {
        var markup = this.MARKUP.exec(value);
        if (!markup)
            return value;
        return markup[1].replace(/<[^>]*>/g, '').replace(/&nbsp;/g, ' ').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
            .replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, '&').trim();
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
