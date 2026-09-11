var BOFA_SI_KafkaProducerV2 = Class.create();
BOFA_SI_KafkaProducerV2.prototype = {

    /*
     * Sends outbound messages to Hermes Kafka through sn_ih_kafka.ProducerV2:
     * send(topicSysID, key, message, isSync, headers, schemaID)
     * https://www.servicenow.com/docs/r/api-reference/server-api-reference/ProducerV2ScopedAPI.html
     */
    initialize: function() {
        this.IS_SYNC = false; // the caller does not wait for the broker acknowledgement
        this.HEADERS = null; // optional, subject to discussion
        this.SCHEMA_ID = null; // optional, no Avro schema in use
        // Each property holds the sys_id of a Kafka Topic [sys_kafka_topic]. The remediation
        // task tables point at the finding topic until a topic of their own exists.
        this.FINDING_TOPIC_PROPERTY = 'x_boar_bofa_usem_1.x_boar_bofa.usem.kafka.topic_sys_id';
        this.REMEDIATION_TASK_TOPIC_PROPERTY = 'x_boar_bofa_usem_1.x_boar_bofa.usem.kafka.topic_sys_id';
        this.TOPIC_PROPERTIES = {
            sn_vul_vulnerable_item: this.FINDING_TOPIC_PROPERTY,
            sn_vul_app_vulnerable_item: this.FINDING_TOPIC_PROPERTY,
            sn_vul_container_image_vulnerable_item: this.FINDING_TOPIC_PROPERTY,
            sn_vulc_result: this.FINDING_TOPIC_PROPERTY,
            sn_vul_vulnerability: this.REMEDIATION_TASK_TOPIC_PROPERTY,
            sn_vul_app_vulnerability: this.REMEDIATION_TASK_TOPIC_PROPERTY,
            sn_vul_container_vulnerability: this.REMEDIATION_TASK_TOPIC_PROPERTY,
            sn_vulc_result_group: this.REMEDIATION_TASK_TOPIC_PROPERTY
        };
        // Payload validation: every message is an envelope carrying these fields plus one
        // list of elements, e.g. { "envelope": {...}, "rem_tasks": [ { "remediation_task": {...} } ] }
        this.ENVELOPE_KEY = 'envelope';
        this.ENVELOPE_FIELDS = ['type', 'topic_name', 'namespace', 'core_version', 'outbound_version',
            'event_id', 'event_timestamp', 'element_count', 'element_activity'];
    },

    /**
     * Sends one message to the Kafka topic of the record's table. The payload is
     * validated first (see the payload validation section below), so a malformed
     * message is logged and never sent. The message key is <table>.<sys_id>, which
     * keeps every message about one record on the same partition.
     * @param {String|Object} payload - the message as a JSON string or as the object it was built from
     * @param {GlideRecord} record - the record the message is about
     */
    sendPayload: function(payload, record) {
        var subject = 'record';
        try {
            var table = record.getTableName();
            var sysId = record.getUniqueValue();
            subject = table + ' ' + sysId;
            var topicSysId = this._topicSysId(table);
            var message = this._validate(payload);
            this._send(topicSysId, table + '.' + sysId, message);
        } catch (e) {
            gs.error(this.type + ': message not sent for ' + subject + ' - ' + (e.message || e));
        }
    },

    _topicSysId: function(table) {
        if (!this.TOPIC_PROPERTIES.hasOwnProperty(table))
            throw new Error('no Kafka topic is associated with table ' + table);
        var topicSysId = gs.getProperty(this.TOPIC_PROPERTIES[table], '');
        if (!topicSysId)
            throw new Error('property ' + this.TOPIC_PROPERTIES[table] + ' holds no topic sys_id');
        return topicSysId;
    },

    _send: function(topicSysId, key, message) {
        new sn_ih_kafka.ProducerV2().send(topicSysId, key, message, this.IS_SYNC, this.HEADERS, this.SCHEMA_ID);
    },

    // ________________________________________________________________________________________
    //
    // Payload validation. The code below checks a payload before it is sent: well-formed JSON,
    // the envelope with every mandatory field, and exactly one list of elements whose length
    // matches envelope.element_count. Each check throws an Error naming the first problem
    // found, which sendPayload logs instead of sending.
    // ________________________________________________________________________________________

    /**
     * @param {String|Object} payload - a JSON string, or the object it was built from
     * @returns {String} the payload serialised as the message text to send
     */
    _validate: function(payload) {
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

    type: 'BOFA_SI_KafkaProducerV2'
};
