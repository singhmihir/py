/**
 * BOFA_BR_AVIT_VampOutbound - after insert and update on the application vulnerable item table,
 * order 100. Builds the VAMP payload of the record with BOFASIVampOutboundProcessor and hands it to
 * BOFASIKafkaProducerVamp. An empty payload means the processor could not build or validate it and
 * has logged why; nothing is sent then. Both steps sit in one try/catch: a failure is logged once
 * and never blocks the record.
 * @param {GlideRecord} current - the application vulnerable item as saved
 * @param {GlideRecord} previous - the record before the save (null on insert), not used
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
