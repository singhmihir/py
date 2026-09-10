var BOFA_SI_KafkaPayloadValidator = Class.create();
BOFA_SI_KafkaPayloadValidator.prototype = {

    /*
     * Every outbound message is an envelope plus one list of elements:
     * { "envelope": {...}, "rem_tasks": [ { "remediation_task": {...} } ] }
     */
    initialize: function() {
        this.ENVELOPE_KEY = 'envelope';
        this.ENVELOPE_FIELDS = ['type', 'topic_name', 'namespace', 'core_version', 'outbound_version',
            'event_id', 'event_timestamp', 'element_count', 'element_activity'];
    },

    /**
     * Checks that a payload is well-formed JSON that follows the outbound message
     * contract: an envelope carrying every mandatory field, and exactly one list of
     * elements whose length matches envelope.element_count.
     * @param {String|Object} payload - a JSON string, or the object it was built from
     * @returns {String} the payload serialised as the message text to send
     * @throws {Error} naming the first problem found
     */
    validate: function(payload) {
        if (this._isEmpty(payload))
            throw new Error('payload is empty');
        var message = typeof payload === 'string' ? this._parse(payload) : payload;
        if (!this._isObject(message))
            throw new Error('payload is not a JSON object');
        this._checkEnvelope(message[this.ENVELOPE_KEY]);
        this._checkElements(message);
        return JSON.stringify(message);
    },

    _parse: function(text) {
        if (!text.trim())
            throw new Error('payload is empty');
        try {
            return JSON.parse(text);
        } catch (e) {
            throw new Error('payload is not valid JSON - ' + (e.message || e));
        }
    },

    _checkEnvelope: function(envelope) {
        if (!this._isObject(envelope))
            throw new Error(this.ENVELOPE_KEY + ' is missing');
        for (var i = 0; i < this.ENVELOPE_FIELDS.length; i++)
            if (this._isEmpty(envelope[this.ENVELOPE_FIELDS[i]]))
                throw new Error(this.ENVELOPE_KEY + '.' + this.ENVELOPE_FIELDS[i] + ' is missing or empty');
    },

    _checkElements: function(message) {
        var keys = Object.keys(message);
        var lists = keys.filter(function(key) {
            return key !== this.ENVELOPE_KEY;
        }, this);
        if (lists.length !== 1)
            throw new Error('payload must hold the ' + this.ENVELOPE_KEY + ' and one list of elements, found ' + keys.join(', '));
        var name = lists[0];
        var elements = message[name];
        if (!Array.isArray(elements) || elements.length === 0)
            throw new Error(name + ' is not a list of elements');
        var count = Number(message[this.ENVELOPE_KEY].element_count);
        if (count !== elements.length)
            throw new Error(this.ENVELOPE_KEY + '.element_count is ' + count + ' but ' + name + ' holds ' + elements.length);
        for (var i = 0; i < elements.length; i++)
            if (!this._isObject(elements[i]) || Object.keys(elements[i]).length === 0)
                throw new Error(name + '[' + i + '] is not an element');
    },

    _isObject: function(value) {
        return value !== null && typeof value === 'object' && !Array.isArray(value);
    },

    _isEmpty: function(value) {
        return value === undefined || value === null || String(value) === '';
    },

    type: 'BOFA_SI_KafkaPayloadValidator'
};
