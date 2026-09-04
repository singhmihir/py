# SNOWUSEMTP-895 — Qualys CI lookup rules, readable rewrite

Global-scope update set `SNOWUSEMTP-895_MS_Qualys CI Lookup Rules_V2.0`: the script field of the
16 custom USEM lookup rules for the Qualys Cloud Platform source (orders 175 to 850). Rule names,
orders, sources, fields and descriptions are untouched; only the scripts changed.

What every rewritten script contains, in this order:

1. A header with the sample Qualys Host Detection payload the rule is written for, what
   `sourceValue` and `sourcePayload` hold for that payload, and *why the rule sits at its order*:
   what ran before it, which hosts reach it, and which rules follow.
2. The code with a comment on every processing line carrying the example value at that point
   (what `trim()` strips, what `indexOf` finds, what `classFor` returns for a given OS text,
   which CI a search would return), written for a non-developer reader.

Logic changes compared with the previous scripts:

- `setLimit` is gone. A rule now runs the exact-match search and accepts the CI only when the
  first row is the only row (`next()` then `hasNext()`), so "exactly one candidate" is checked
  against the whole result set instead of a capped one. The candidate-collection rules (250/260
  FQDN with IP tie-break, 300/310 hostname + domain, 350 layered DNS, 200 phone adapters, 730/740
  adapter and layered IP) iterate every row without a cap.
- Nothing else changed: class preference from the OS text, the ignore-class property
  (`sn_sec_cmn.ignoreCIClass`), load-balancer rejection, class-contradiction check and the
  IP tie-breaks are the same as before.

`_queryMatch` from the out-of-box `CIIdentify` script include was considered and not used: it is
a private helper (underscore prefix, undocumented, free to change on upgrade), it returns the
first of several matching CIs after only logging the duplication, it mutates the framework's own
result object (`returnObj.ciIds`, capped at 10) and it only performs a query the rules already
express in two lines. The rules need "exactly one match or decline", which it does not offer.

Files: `rules/<order>_<name>.js` (delivered scripts), `current/` (scripts as they were before,
with a metadata line on top), `live_rules.json` (all lookup rules and the helper script include as
read from the instance), `build_rules.py` (set, script update, explicit capture of every rule with
`GlideUpdateManager2.saveRecord` because `sn_sec_cmn_ci_lookup_rule` is not update-set tracked,
Global audit), `export_rules.py` (native export, scrub, parse, upload proof, archive copy).
