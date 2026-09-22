var BOFASIKafkaProducerVamp = Class.create();
BOFASIKafkaProducerVamp.prototype = {

    /**
     * Configuration of the send: the property that holds the Kafka topic record and the arguments of
     * the producer that never change for this integration.
     */
    initialize: function() {
        this.TOPIC_PROPERTY = 'x_boar_bofa_usem_1.usem.vamp.kafka.topic_sys_id';
        this.IS_SYNC = false;
        this.HEADERS = null;
        this.SCHEMA_ID = null;
        this.SYS_ID_PATTERN = /^[0-9a-f]{32}$/;
    },

    /**
     * Sends one VAMP payload to the outbound topic, keyed by the record it was built from.
     * @param {string} payload the JSON text the processor returned
     * @param {GlideRecord} record the application vulnerable item the payload belongs to
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
     * The message key of the record, also when no record was given.
     * @param {GlideRecord} record the application vulnerable item
     * @returns {string} "<table>.<sys_id>", or "no record"
     */
    _messageKey: function(record) {
        try {
            return record.getTableName() + '.' + record.getUniqueValue();
        } catch (e) {
            return 'no record';
        }
    },

    /**
     * The Kafka topic record to send to.
     * @returns {string} the sys_id of the topic record
     * @throws when the property is empty or does not hold a sys_id
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
     * Refuses a payload the topic must not receive: nothing was built, the text is not JSON, or the
     * message does not carry an envelope and at least one finding.
     * @param {string} payload the JSON text the processor returned
     * @throws naming what is wrong with the payload
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
