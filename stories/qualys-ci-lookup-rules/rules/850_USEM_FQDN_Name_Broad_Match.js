/* =====================================================================
   RULE 850 - USEM FQDN Name Broad Match
   =====================================================================
   SAMPLE PAYLOAD (one Qualys Host Detection record) this rule is written for:
   {
     "ID": "71973166",
     "IP": "164.91.209.12",
     "TRACKING_METHOD": "AGENT",
     "OS": "Red Hat Enterprise Linux 8.10",
     "DNS": "lva40bneehcs01.ecomm.devicenp.rpg",
     "QG_HOSTID": "633781ed-019b-0002-2f2f-0050569d20ff"
   }

   sourceValue   = the DNS field  -> "lva40bneehcs01.ecomm.devicenp.rpg"
   sourcePayload = the whole record above

   WHY THIS RULE SITS AT ORDER 850
   Rules run from the lowest order to the highest; the first rule that
   returns a CI wins and every later rule is skipped.
   - Before it : every hardware-scoped rule (175-740) has declined for this
                 host.
   - Reaches it: the rare CI that is named with the full FQDN but lives outside
                 the hardware tree (for example a virtual or logical CI). This
                 is the only USEM rule allowed to search the broad cmdb_ci table
                 by name, which is why it is deliberately the last custom rule.
   - After it  : the out-of-box Qualys rules (860 QUALYS HOST ID, 880 cloud
                 resource id, 900 FQDN, 920 NetBIOS, 940 DNS, 950/960 IP which
                 are inactive by default), the vendor best-effort matching.
   ===================================================================== */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // payload has no DNS -> nothing to look up
        return null;
    var fqdn = ('' + sourceValue).trim().toLowerCase();   // "lva40bneehcs01.ecomm.devicenp.rpg"
    if (fqdn.indexOf('.') == -1)                  // bare labels were covered by 400/410
        return null;

    // Classes that must never be matched (for example unclassed or retired CI
    // classes) are listed by the administrators in the system property
    // sn_sec_cmn.ignoreCIClass. The CI identification framework may hand the
    // same list to the script as _ignoreClass; either way it ends up in
    // "ignore", e.g. "cmdb_ci_unclassed,cmdb_ci_ip_address_dns_name".
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');

    var gr = new GlideRecord('cmdb_ci');          // the broad CI table - every class
    gr.addQuery('name', fqdn);                    // name = "lva40bneehcs01.ecomm.devicenp.rpg"
    if (ignore)
        gr.addQuery('sys_class_name', 'NOT IN', ignore);

    gr.query();                                   // run the search
    if (!gr.next())                               // no CI at all -> this rule declines, the next rule gets its turn
        return null;
    var match = gr.getUniqueValue();              // sys_id of the CI found, e.g. "b5f1c2d3e4f5a6b7c8d9e0f1a2b3c4d5"
    if (gr.hasNext())                             // a second CI carries the same value -> ambiguous, never guess
        return null;
    return match;                                 // exactly one CI -> this is the match
})(rule, sourceValue, sourcePayload);
