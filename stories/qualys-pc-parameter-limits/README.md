# Qualys PC integration — parameter length and paging limits

Supporting note for a story comment: how long an outbound REST parameter value can be, what the
Posture Info page size actually is, and why the integration makes one request per policy.

## Files
- `instance_readings.json` — every figure read from the instance: application versions, nine
  dictionary columns with their record ids, the three integration parameters (definition and
  instance value ids), the REST message / method / query parameter records, the script lines, the
  policy loop, and the four length experiments.
- `citations.json` — 27 confirmed published sources in six groups (how a value reaches the request,
  how field length behaves, the Qualys integration application, the Posture Info API, the Policy
  List API, request method and request length), each with the exact sentence quoted.
- `build_doc.js` — docx-js generator. `node build_doc.js` writes
  `../Qualys PC Integration - Parameter Limits.docx`.
- `workflow_result.json` — raw research output behind `citations.json`.

## Findings
- Four places a value can sit, four different ceilings: HTTP Query Parameter Value 1,000;
  Integration Instance Parameter 512; system property 4,000; and a value passed at run time by
  `setStringParameter()`, which is held in no column at all and is bounded only by the request URL.
- The shipped Qualys integration takes the configured route, so 512 is the binding figure for
  anything an administrator sets — not the 1,000 on the query parameter.
- The Posture Info page size is `truncation_limit_pc_result`, shipped and set to 5,000, which is the
  Qualys default for a single-policy request. The 1,000 figure belongs to the Host List call.
- `policy_id` takes one policy per request; `policy_ids` caps at ten and turns paging off. A long id
  list has no route into this call. The `ids` parameter on the Policy List call is where a character
  budget question would actually apply.
- Around 2,000 characters of query string is the conservative planning figure against an unknown
  server (IIS 2,048 default; Apache 8,190 request line; RFC 9110 recommends supporting 8,000 octets).

## Rebuilding
```
node build_doc.js
```
