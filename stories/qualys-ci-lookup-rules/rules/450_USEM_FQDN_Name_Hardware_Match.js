/* =====================================================================
   RULE 450 - USEM FQDN Name Hardware Match
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

   WHY THIS RULE SITS AT ORDER 450
   Rules run from the lowest order to the highest; the first rule that
   returns a CI wins and every later rule is skipped.
   - Before it : every rule so far compared the short hostname or the fqdn
                 field.
   - Reaches it: CIs that some CMDB sources name with the complete FQDN string
                 (typical for the .rpg appliance domains): the CI name itself is
                 "lva40bneehcs01.ecomm.devicenp.rpg", so a short-name search can
                 never find it.
   - After it  : 700+ (IP address rules) and finally 850, the only rule allowed
                 to search the broad cmdb_ci table by name.
   ===================================================================== */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // payload has no DNS -> nothing to look up
        return null;
    var fqdn = ('' + sourceValue).trim().toLowerCase();   // "lva40bneehcs01.ecomm.devicenp.rpg"
    if (fqdn.indexOf('.') == -1)                  // a bare label was already covered by 400/410
        return null;

    // Classes that must never be matched (for example unclassed or retired CI
    // classes) are listed by the administrators in the system property
    // sn_sec_cmn.ignoreCIClass. The CI identification framework may hand the
    // same list to the script as _ignoreClass; either way it ends up in
    // "ignore", e.g. "cmdb_ci_unclassed,cmdb_ci_ip_address_dns_name".
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');

    var gr = new GlideRecord('cmdb_ci_hardware'); // the whole hardware tree
    gr.addQuery('name', fqdn);                    // name = "lva40bneehcs01.ecomm.devicenp.rpg" (the full string)
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
