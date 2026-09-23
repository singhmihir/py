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
- Payload validation lives in the same script include, after a separator line of underscores and a
  comment saying so: `_validate(payload)` accepts the JSON string or the object, returns the canonical
  JSON text to send, and throws an Error naming the first problem: empty payload (also the JSON text
  of an empty string or of null, which the current rule passes after a failed build), JSON that does
  not parse (with the parser's reason), not an object, envelope missing, any of the nine envelope
  fields missing or empty, no or more than one element list, element list not an array or empty,
  `element_count` not a whole number (a number, or its digits as text) or not matching, an element
  that is not an object. `sendPayload` logs that reason and does not send. The earlier separate
  `BOFA_SI_KafkaPayloadValidator` is withdrawn.
- A missing record or one without a sys_id is refused (`no record was given`, `the record has no
  sys_id`), so no message goes out keyed `<table>.null`.
- The topic property is read with the spaces around its value ignored; an empty value and a value
  that is not a sys_id (a topic name, for instance) are refused before the send, naming the property
  and the value.
- `Kafka Producer V2 - Script Include.xml` — the producer for *Import XML* on the client instance,
  under its existing sys_id in `x_boar_bofa_usem_1`, access public, preceded by a deletion of the
  separate validator `BOFA_SI_KafkaPayloadValidator` V1.0 delivered (`prior_records.json`; Import XML
  deletes a record of an `action="DELETE"` element and ignores a sys_id it does not hold). User and timestamp fields are left
  out so the import stamps them.

## Suggested rule body (optional, the rule was not part of the ask)
The producer serialises and checks the payload itself, so the rule needs neither `JSON.stringify`,
the info message nor the validation placeholder. When the builder cannot build a payload it logs why
and returns an empty string; the rule then stops, so one failure gives one error line (the rule as
written serialises the empty string and the producer adds a second line, `payload is empty`):
```javascript
(function executeRule(current, previous /*null when async*/ ) {
    try {
        var payload = new x_boar_bofa_usem_1.BOA_SI_USEM_RemediationTaskPayloadBuilder().buildPayload(current, current.operation().toUpperCase());
        if (!payload)
            return;
        new x_boar_bofa_usem_1.BOFA_SI_KafkaProducerV2().sendPayload(payload, current);
    } catch (ex) {
        gs.error('BOA_BR_VUL_KafkaOutbound: outbound message failed for ' + current.getTableName() + ' ' + current.getUniqueValue() + ' - ' + (ex.message || ex));
    }
})(current, previous);
```

## Testing (PDI, stand-in scope `x_196061_bofasim`)
`build.py` deploys the script include into the stand-in scope under a pinned update set (set name
`INC0010003_MS_Kafka Producer V2 with Payload Validation_V1.3`), removes the earlier separate
validator, and creates the topic property the producer reads (a test fixture holding a generated
sys_id). `test.py` runs 111 checks; run twice, all passing both times. Every log check reads only the
lines written by the script under test (a fresh second is awaited before its start time is taken).
- A. validation: every refusal reason from the exact input that triggers it — empty text, blank
  text, null, undefined, the JSON of an empty string or of null (what a rule that serialises a failed
  build passes), JSON that does not parse (with the parser's reason), JSON that is not an object,
  envelope missing, each of the nine envelope fields missing, empty or null, no list or two lists,
  list not an array or empty, `element_count` that is not a whole number (true, 1.5, "1.0", " 1", -1,
  [1], "x") or does not match the list, an element that is not an object (first and second
  position); accepted: the builder's payload as text, as object, pretty-printed (sent compact), the
  client builder's object, `element_count` as the digits "1", two elements, a list of another name.
- A2. one script include in the scope, equal to the repository copy; send methods before the
  separator line, validation after it; `ProducerV2.send` called once with the documented argument
  order (topic, key, message, isSync, headers, schemaID).
- B. producer with `_send` captured: all eight tables, string and object payloads (16 sends) with
  the topic from the property, key `<table>.<sys_id>`, canonical message; five refusals never reach
  send; exactly eight lines logged, one per refusal plus the null record, a record without a sys_id
  and the real send; the real
  send on this instance fails with the platform's own error for the missing Kafka API
  (`undefined is not a function.`) in the same format.
- C. topic property padded with spaces (trimmed and sent), in capitals (accepted), empty and holding
  a topic name (refused before send, naming the property and the value); property restored.
- D. the client's rule `BOA_BR_VUL_KafkaOutbound` exactly as exported (only its log tag changed),
  created in the Vulnerability Response scope on `sn_vul_vulnerability`, on a real update and a real
  insert: builder → producer ran in the rule's transaction, the payload the rule serialised equals the
  builder's, and the producer logged only the send failure; with the builder's property blanked the
  builder logs its reason and the producer adds `payload is empty` (the rule serialises the empty
  string), nothing sent. The suggested rule body above: the same success, and on failure one line
  (the builder's).

The real `ProducerV2.send` cannot run on the PDI (no Stream Connect subscription), so the last step
is covered by the argument capture in B and by the API reference, not by a broker round trip.
