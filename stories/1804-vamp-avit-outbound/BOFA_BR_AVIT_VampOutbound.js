/**
 * After insert and update on the application vulnerable item: builds the VAMP outbound payload and
 * sends it to the outbound topic. A payload the processor refused to build is not sent, and neither
 * step can abort the save; whatever fails is logged once by the script include that owns it.
 */
(function executeRule(current, previous /*null when async*/ ) {
    try {
        var payload = new x_boar_bofa_usem_1.BOFASIVampOutboundProcessor().buildPayload(current);
        if (!payload)
            return;
        new x_boar_bofa_usem_1.BOFASIKafkaProducerVamp().sendPayload(payload, current);
    } catch (e) {
        gs.error('BOFA_BR_AVIT_VampOutbound: outbound message failed for ' + current.getTableName() + ' ' + current.getUniqueValue() + ' - ' + (e.message || e));
    }
})(current, previous);
