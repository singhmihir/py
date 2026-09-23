/**
 * BOFA_BR_Consequence_CdpOutbound - after insert and update on the consequence table, order 100.
 * Builds the CDP payload of the record with BOFASIConsequenceOutboundProcessor and hands it to the
 * shared Kafka producer BOFA_SI_KafkaProducerV2 of the CDP integration application, which sends the
 * remediation task payloads as well. An empty payload means the processor could not build or validate it
 * and has logged why; nothing is sent then. Both steps sit in one try/catch: a failure is logged once
 * and never blocks the record.
 * @param {GlideRecord} current - the consequence record as saved
 * @param {GlideRecord} previous - the record before the save (null on insert), not used
 */
(function executeRule(current, previous /*null when async*/ ) {
    try {
        var payload = new x_boar_bofa_usem_0.BOFASIConsequenceOutboundProcessor().buildPayload(current);
        if (!payload)
            return;
        new x_boar_bofa_usem_1.BOFA_SI_KafkaProducerV2().sendPayload(payload, current);
    } catch (e) {
        gs.error('BOFA_BR_Consequence_CdpOutbound: outbound message failed for ' + current.getTableName() + ' ' + current.getUniqueValue() + ' - ' + (e.message || e));
    }
})(current, previous);
