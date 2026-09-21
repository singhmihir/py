/**
 * Sends a consequence payload to the Kafka topic of the application through Stream Connect
 * (sn_ih_kafka.ProducerV2). Configuration lives in initialize(): the property that holds the sys_id
 * of the Kafka Topic record [sys_kafka_topic] and the send options.
 *
 * Entry point: sendPayload(payload, record). It holds the one try/catch of the feature: a missing topic,
 * an unusable payload or a failure of the send is logged once with gs.error and never reaches the rule.
 * Documentation of the API used: https://www.servicenow.com/docs/r/api-reference/server-api-reference/ProducerV2ScopedAPI.html
 */
var BOFASIKafkaProducerConsequence = Class.create();
BOFASIKafkaProducerConsequence.prototype = {

    /** The topic property and the options of the send: asynchronous, no headers, no schema. */
    initialize: function() {
        this.TOPIC_PROPERTY = 'x_boar_bofa_usem_0.usem.consequence.kafka.topic_sys_id';
        this.IS_SYNC = false;
        this.HEADERS = null;
        this.SCHEMA_ID = null;
        this.SYS_ID_PATTERN = /^[0-9a-f]{32}$/;
    },

    /**
     * Sends one payload, keyed by the record it was built from, and shows the response on the record.
     * @param {string} payload - the JSON text built by BOFASIConsequenceOutboundProcessor
     * @param {GlideRecord} record - the consequence record the payload belongs to
     */
    sendPayload: function(payload, record) {
        var key = this._messageKey(record);
        try {
            var topicSysId = this._topicSysId();
            this._requirePayload(payload);
            var response = new sn_ih_kafka.ProducerV2().send(topicSysId, key, payload, this.IS_SYNC, this.HEADERS, this.SCHEMA_ID);
            gs.addInfoMessage('Consequence Kafka response for ' + key + ': ' + JSON.stringify(response))
        } catch (e) {
            gs.error(this.type + ': message not sent for ' + key + ' - ' + (e.message || e));
        }
    },

    /**
     * The message key: table and sys_id of the record.
     * @param {GlideRecord} record - the consequence record, possibly absent
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
        var value = gs.getProperty(this.TOPIC_PROPERTY, '');
        if (!value)
            throw new Error('property ' + this.TOPIC_PROPERTY + ' holds no topic');
        if (!this.SYS_ID_PATTERN.test(value))
            throw new Error('property ' + this.TOPIC_PROPERTY + ' holds "' + value + '", which is not a sys_id');
        return value;
    },

    /**
     * Refuses a payload that is not the JSON text of an envelope with its consequences.
     * @param {string} payload - the payload text
     * @throws {Error} when the payload is empty, not JSON, or lacks the envelope or the consequences
     */
    _requirePayload: function(payload) {
        if (!payload)
            throw new Error('the payload is empty');
        var parsed;
        try {
            parsed = JSON.parse(payload);
        } catch (e) {
            throw new Error('the payload is not JSON');
        }
        if (!parsed || !parsed.envelope || !parsed.consequences)
            throw new Error('the payload has no envelope or no consequences');
    },

    type: 'BOFASIKafkaProducerConsequence'
};
