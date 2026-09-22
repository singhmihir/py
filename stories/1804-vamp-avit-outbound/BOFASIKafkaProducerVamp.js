/**
 * Sends a VAMP payload to the Kafka topic of the application through Stream Connect
 * (sn_ih_kafka.ProducerV2). Configuration lives in initialize(): the property that holds the sys_id
 * of the Kafka Topic record [sys_kafka_topic] and the send options.
 *
 * Entry point: sendPayload(payload, record). It holds the one try/catch of the feature: a missing
 * topic, a payload the topic must not receive or a failure of the send is logged once with gs.error
 * and never reaches the rule.
 * Documentation of the API used: https://www.servicenow.com/docs/r/api-reference/server-api-reference/ProducerV2ScopedAPI.html
 */
var BOFASIKafkaProducerVamp = Class.create();
BOFASIKafkaProducerVamp.prototype = {

    /** The topic property and the options of the send: asynchronous, no headers, no schema. */
    initialize: function() {
        this.TOPIC_PROPERTY = 'x_boar_bofa_usem_1.usem.vamp.kafka.topic_sys_id';
        this.IS_SYNC = false;
        this.HEADERS = null;
        this.SCHEMA_ID = null;
        this.SYS_ID_PATTERN = /^[0-9a-f]{32}$/;
    },

    /**
     * Sends one payload, keyed by the record it was built from, and shows the response on the record.
     * @param {string} payload - the JSON text built by BOFASIVampOutboundProcessor
     * @param {GlideRecord} record - the application vulnerable item the payload belongs to
     */
    sendPayload: function(payload, record) {
        var key = this._messageKey(record);
        try {
            var topicSysId = this._topicSysId();
            this._requirePayload(payload);
            var response = new sn_ih_kafka.ProducerV2().send(topicSysId, key, payload, this.IS_SYNC, this.HEADERS, this.SCHEMA_ID);
            gs.addInfoMessage('VAMP Kafka response for ' + key + ': ' + JSON.stringify(response))
        } catch (e) {
            gs.error(this.type + ': message not sent for ' + key + ' - ' + (e.message || e));
        }
    },

    /**
     * The message key: table and sys_id of the record.
     * @param {GlideRecord} record - the application vulnerable item, possibly absent
     * @returns {string} "<table>.<sys_id>", or "no record" when the record cannot be read
     */
    _messageKey: function(record) {
        try {
            return record.getTableName() + '.' + record.getUniqueValue();
        } catch (e) {
            return 'no record';
        }
    },

    /**
     * Reads the topic property.
     * @returns {string} the sys_id of the Kafka Topic record
     * @throws {Error} when the property is empty or its value is not a sys_id
     */
    _topicSysId: function() {
        var topicSysId = String(gs.getProperty(this.TOPIC_PROPERTY, '')).trim();
        if (!topicSysId)
            throw new Error('property ' + this.TOPIC_PROPERTY + ' holds no topic');
        if (!this.SYS_ID_PATTERN.test(topicSysId))
            throw new Error('property ' + this.TOPIC_PROPERTY + ' is not a sys_id: "' + topicSysId + '"');
        return topicSysId;
    },

    /**
     * Refuses a payload that is not the JSON text of an envelope with its findings.
     * @param {string} payload - the payload text
     * @throws {Error} when the payload is empty, is not JSON, lacks the envelope or the findings, or
     *                 counts a number of elements other than the findings it carries
     */
    _requirePayload: function(payload) {
        if (!payload)
            throw new Error('the payload is empty');
        var message;
        try {
            message = JSON.parse(payload);
        } catch (e) {
            throw new Error('the payload is not JSON');
        }
        if (!message || !message.envelope || !message.findings)
            throw new Error('the payload has no envelope or no findings');
        if (!message.findings.length)
            throw new Error('the payload carries no finding');
        if (message.envelope.element_count !== message.findings.length)
            throw new Error('the payload counts ' + message.envelope.element_count + ' element(s) and carries ' + message.findings.length);
    },

    type: 'BOFASIKafkaProducerVamp'
};
