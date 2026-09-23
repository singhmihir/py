# Kafka producer V2 and outbound payload validator (INC0010003)

Received on INC0010003 as three record exports (`original/`): the producer script include
`BOFA_SI_KafkaProducerV2`, the payload builder `BOA_SI_USEM_RemediationTaskPayloadBuilder` and the
rule `BOA_BR_VUL_KafkaOutbound` on `sn_vul_vulnerability`, all in application scope
`x_boar_bofa_usem_1` (rule in `sn_vul`). Asked for: a standardised, efficient producer that keeps
every existing parameter and behaviour, plus a script that handles a malformed payload. Since V1.5 the
same producer also sends the consequence payloads (SNOWUSEMTP-1624): one producer for the remediation tasks
and the consequence table, each with its own payload builder.

## Delivered
- `BOFA_SI_KafkaProducerV2.js` — same class, same public method `sendPayload(payload, record)`,
  the topic property picked by the record's table in `TOPIC_PROPERTIES`, one property per topic:
  | tables | topic property |
  |---|---|
  | `sn_vul_vulnerable_item`, `sn_vul_app_vulnerable_item`, `sn_vul_container_image_vulnerable_item`, `sn_vulc_result` (findings) | `x_boar_bofa_usem_1.x_boar_bofa.usem.kafka.topic_sys_id` (the client's existing property) |
  | `sn_vul_vulnerability`, `sn_vul_app_vulnerability`, `sn_vul_container_vulnerability`, `sn_vulc_result_group` (remediation tasks) | `x_boar_bofa_usem_1.usem.cdp.remtask.kafka.topic_sys_id` (new in V1.5, delivered empty with the producer) |
  | `x_boar_bofa_usem_0_consequence` | `x_boar_bofa_usem_0.usem.consequence.kafka.topic_sys_id` (in the consequence application, delivered with SNOWUSEMTP-1624; its rule calls `x_boar_bofa_usem_1.BOFA_SI_KafkaProducerV2`) |

  Until V1.4 the remediation task tables reused the finding property, as the client's placeholder did;
  findings, remediation tasks and consequences now each have their own topic. Same key `<table>.<sys_id>`, same `ProducerV2.send` call
  with the same arguments (asynchronous, no headers, no schema). Now: configuration in `initialize`,
  a table-to-property map instead of two if-chains, the property read with a default and a clear
  error when empty, the payload validated before anything is sent, the send isolated in `_send`, one
  try/catch with one `gs.error` in the format `BOFA_SI_KafkaProducerV2: message not sent for <table>
  <sys_id> - <reason>`, no unused return values, no trailing comma in the argument list.
- Payload validation lives in the same script include, after a separator line of underscores and a
  comment saying so: `_validate(payload)` accepts the JSON string or the object (an object is serialised
  first and the serialised copy is what is checked and sent, so a value JSON cannot hold never passes the
  checks and then drops out of the message), returns the canonical JSON text to send, and throws an Error naming the first problem: empty payload (also the JSON text
  of an empty string or of null, which the current rule passes after a failed build), JSON that does
  not parse (with the parser's reason), not an object, envelope missing, any of the nine envelope
  fields missing or empty, no or more than one element list, element list not an array or empty,
  `element_count` other than the number of elements in the list, an element
  that is not an object. `sendPayload` logs that reason and does not send. The earlier separate
  `BOFA_SI_KafkaPayloadValidator` is withdrawn.
- A missing record, or one that does not exist (never saved, or deleted), is refused (`no record was given`,
  `the record does not exist`), so no message goes out keyed `<table>.null` or for a record CDP never sees.
  Both rules that call the producer run after insert and update, where the record exists.
- The topic property is read with the spaces around its value ignored; an empty value and a value
  that is not a sys_id (32 lowercase hexadecimal characters: a topic name, or a sys_id typed in capitals)
  are refused before the send, naming the property and the value.
- `Kafka Producer V2 - Script Include.xml` — the producer for *Import XML* on the client instance,
  under its existing sys_id in `x_boar_bofa_usem_1`, access public, preceded by a deletion of the
  separate validator `BOFA_SI_KafkaPayloadValidator` V1.0 delivered (`prior_records.json`; Import XML
  deletes a record of an `action="DELETE"` element and ignores a sys_id it does not hold), and followed by the
  remediation task topic property `x_boar_bofa_usem_1.usem.cdp.remtask.kafka.topic_sys_id`, empty: after the
  import the client sets it to the sys_id of the Kafka Topic record of `sn_usem_remtask_outbound`. User and
  timestamp fields are left out so the import stamps them.

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

## Testing (PDI, mirror of the integration application)
`build.py` deploys the script include into the PDI mirror of `x_boar_bofa_usem_1` (the client's scope name and
application sys_id) under the client's own sys_id, where the consequence rule calls it by its client name, under a
pinned update set (set name `INC0010003_MS_Kafka Producer V2 with Payload Validation_V1.5`); removes the copy of
earlier versions from the stand-in scope, creates the remediation task topic property in the application (a generated
sys_id on the PDI, delivered empty) and the finding topic property the client already has (a global test fixture holding a
generated sys_id). `test.py` runs 111 checks; run twice, all passing both times. Every log check reads only the
lines written by the script under test (a fresh second is awaited before its start time is taken).
- A. validation: every refusal reason from the exact input that triggers it — empty text, blank
  text, null, undefined, the JSON of an empty string or of null (what a rule that serialises a failed
  build passes), JSON that does not parse (with the parser's reason), JSON that is not an object,
  envelope missing, each of the nine envelope fields missing, empty or null, no list or two lists,
  list not an array or empty, `element_count` that does not equal the length of the list (2, 0, true, 1.5, "1.0", " 1", -1,
  [1], "x", "1"), an element that is not an object (first and second
  position), an empty array, an object whose element serialises to `{}` (a value `undefined`) and one
  whose envelope field is a function (dropped by the serialisation, so reported missing); accepted: the
  builder's payload as text, as object, pretty-printed (sent compact), the client builder's object, two
  elements, a list of another name.
- A2. one script include in the scope, equal to the repository copy; send methods before the
  separator line, validation after it; `ProducerV2.send` called once with the documented argument
  order (topic, key, message, isSync, headers, schemaID).
- B. producer with `_send` captured: all nine tables, string and object payloads (18 sends) with
  the topic of the table's property (the consequence table its own, read from the consequence
  application), the producer's table map checked against the three groups and the three topic sys_ids
  different, key `<table>.<sys_id>`, canonical message; seven refusals never reach send; exactly nine
  lines logged, one per refusal plus the null record, a record without a sys_id, a record never saved
  and the real send; the real
  send on this instance fails with the platform's own error for the missing Kafka API
  (`undefined is not a function.`) in the same format.
- C. each of the three topic properties in turn: padded with spaces (trimmed and sent), empty, holding a
  topic name and in capitals (refused before send, naming the property and the value), while a record of
  each of the other two groups still goes to its own topic; properties restored.
- D. the client's rule `BOA_BR_VUL_KafkaOutbound` exactly as exported (only its log tag changed),
  created in the Vulnerability Response scope on `sn_vul_vulnerability`, on a real update and a real
  insert: builder → producer ran in the rule's transaction, the payload the rule serialised equals the
  builder's, and the producer logged only the send failure; with the builder's property blanked the
  builder logs its reason and the producer adds `payload is empty` (the rule serialises the empty
  string), nothing sent. The suggested rule body above: the same success, and on failure one line
  (the builder's).

The real `ProducerV2.send` cannot run on the PDI (no Stream Connect subscription), so the last step
is covered by the argument capture in B and by the API reference, not by a broker round trip.
