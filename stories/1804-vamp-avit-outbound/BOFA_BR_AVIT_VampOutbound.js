(function executeRule(current, previous /*null when async*/ ) {
    try {
        var payload = new x_boar_bofa_usem_1.BOFASIVampOutboundProcessor().buildPayload(current);
        if (payload)
            new x_boar_bofa_usem_1.BOFASIKafkaProducerVamp().sendPayload(payload, current);
    } catch (e) {
        gs.error('BOFA_BR_AVIT_VampOutbound: outbound message failed for ' + current.getTableName() + ' ' + current.getUniqueValue() + ' - ' + (e.message || e));
    }
})(current, previous);
