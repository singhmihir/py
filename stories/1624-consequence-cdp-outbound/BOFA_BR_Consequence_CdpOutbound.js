(function executeRule(current, previous /*null when async*/ ) {
    try {
        var payload = new x_boar_bofa_usem_0.BOFASIConsequenceOutboundProcessor().buildPayload(current);
        if (payload)
            new x_boar_bofa_usem_0.BOFASIKafkaProducerConsequence().sendPayload(payload, current);
    } catch (e) {
        gs.error('BOFA_BR_Consequence_CdpOutbound: outbound message failed for ' + current.getTableName() + ' ' + current.getUniqueValue() + ' - ' + (e.message || e));
    }
})(current, previous);
