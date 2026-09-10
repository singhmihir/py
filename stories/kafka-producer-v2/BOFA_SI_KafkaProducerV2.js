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
    },

    /**
     * Sends one message to the Kafka topic of the record's table. The payload is
     * checked by BOFA_SI_KafkaPayloadValidator first, so a malformed message is
     * logged and never sent. The message key is <table>.<sys_id>, which keeps every
     * message about one record on the same partition.
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
            var message = new BOFA_SI_KafkaPayloadValidator().validate(payload);
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

    type: 'BOFA_SI_KafkaProducerV2'
};
