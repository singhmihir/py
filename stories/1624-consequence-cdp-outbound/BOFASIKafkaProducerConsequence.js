var BOFASIKafkaProducerConsequence = Class.create();
BOFASIKafkaProducerConsequence.prototype = {

    initialize: function() {
        this.TOPIC_PROPERTY = 'x_boar_bofa_usem_1.usem.consequence.kafka.topic_sys_id';
        this.IS_SYNC = false;
        this.HEADERS = null;
        this.SCHEMA_ID = null;
    },

    sendPayload: function(payload, record) {
        var key = record.getTableName() + '.' + record.getUniqueValue();
        try {
            var topicSysId = gs.getProperty(this.TOPIC_PROPERTY, '');
            var response = new sn_ih_kafka.ProducerV2().send(topicSysId, key, payload, this.IS_SYNC, this.HEADERS, this.SCHEMA_ID);
            gs.addInfoMessage('Consequence Kafka response for ' + key + ': ' + JSON.stringify(response))
        } catch (e) {
            gs.error(this.type + ': message not sent for ' + key + ' - ' + (e.message || e));
        }
    },

    type: 'BOFASIKafkaProducerConsequence'
};
