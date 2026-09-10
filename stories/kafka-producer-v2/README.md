# Kafka producer V2 and outbound payload validator (INC0010003)

Received on INC0010003 as three record exports (`original/`): the producer script include
`BOFA_SI_KafkaProducerV2`, the payload builder `BOA_SI_USEM_RemediationTaskPayloadBuilder` and the
rule `BOA_BR_VUL_KafkaOutbound` on `sn_vul_vulnerability`, all in application scope
`x_boar_bofa_usem_1` (rule in `sn_vul`). Asked for: a standardised, efficient producer that keeps
every existing parameter and behaviour, plus a script that handles a malformed payload.

## Delivered
- `BOFA_SI_KafkaProducerV2.js` — same class, same public method `sendPayload(payload, record)`,
  same property, same topic-per-table grouping (finding tables, remediation task tables reusing the
  finding topic until their own exists), same key `<table>.<sys_id>`, same `ProducerV2.send` call
  with the same arguments (asynchronous, no headers, no schema). Now: configuration in `initialize`,
  a table-to-property map instead of two if-chains, the property read with a default and a clear
  error when empty, the payload validated before anything is sent, the send isolated in `_send`, one
  try/catch with one `gs.error` in the format `BOFA_SI_KafkaProducerV2: message not sent for <table>
  <sys_id> - <reason>`, no unused return values, no trailing comma in the argument list.
- `BOFA_SI_KafkaPayloadValidator.js` — new. `validate(payload)` accepts the JSON string or the
  object, returns the canonical JSON text to send, and throws an Error naming the first problem:
  empty payload, JSON that does not parse (with the parser's reason), not an object, envelope
  missing, any of the nine envelope fields missing or empty, no or more than one element list,
  element list not an array or empty, `element_count` not matching, an element that is not an
  object. The producer logs that reason and does not send.
- `Kafka Producer V2 - Script Includes.xml` — both records for *Import XML* on the client instance:
  the producer under its existing sys_id, the validator new, both in `x_boar_bofa_usem_1`, access
  public. User and timestamp fields are left out so the import stamps them.

## Suggested rule body (optional, the rule was not part of the ask)
The producer serialises and checks the payload itself, so the rule no longer needs
`JSON.stringify`, the info message or the validation placeholder:
```javascript
(function executeRule(current, previous /*null when async*/ ) {
    try {
        var payload = new x_boar_bofa_usem_1.BOA_SI_USEM_RemediationTaskPayloadBuilder().buildPayload(current, current.operation().toUpperCase());
        new x_boar_bofa_usem_1.BOFA_SI_KafkaProducerV2().sendPayload(payload, current);
    } catch (ex) {
        gs.error('BOA_BR_VUL_KafkaOutbound: outbound message failed for {0} {1} - {2}', [current.getTableName(), current.getUniqueValue(), ex.message || ex]);
    }
})(current, previous);
```

## Testing (PDI, stand-in scope `x_196061_bofasim`)
`build.py` deploys both script includes into the stand-in scope under a pinned update set and
creates the topic property the producer reads (a test fixture holding a generated sys_id).
`test.py` runs 86 checks; run twice, 86/86 both times:
- A. validator: 64 cases — the good payload from the real builder comes back canonical (string and
  object), and every refusal reason above is produced by the exact input that should trigger it.
- B. producer with `_send` captured: all eight tables, string and object payloads (16 sends) with
  the topic from the property, key `<table>.<sys_id>`, canonical message; five refusals (unmapped
  table, malformed JSON, stringified empty string, empty string, envelope breach) never reach send
  and each is logged with its reason; null record and a real send without Stream Connect do not
  throw; defaults are async / no headers / no schema.
- C. empty topic property refused before send, naming the property; property restored.
- D. a temporary rule identical in shape to `BOA_BR_VUL_KafkaOutbound` on two real updates of
  VUL0004576: builder → producer ran in the rule's transaction, the producer logged the send
  failure (Stream Connect is not installed on the PDI) and the rule's own catch was never needed.

The real `ProducerV2.send` cannot run on the PDI (no Stream Connect subscription), so the last step
is covered by the argument capture in B and by the API reference, not by a broker round trip.
