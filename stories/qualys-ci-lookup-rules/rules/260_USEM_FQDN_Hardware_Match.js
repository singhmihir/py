/* =================================================================================================
   RULE 260 - USEM FQDN Hardware Match
   =================================================================================================
   Match by exact FQDN anywhere in the hardware tree. Second FQDN stage, for hosts whose OS gives no
   class or whose CI is classed differently from the OS.

   SAMPLE PAYLOAD (one Qualys Host Detection record, used in every example below)
   {
     "ID": "35920204",
     "IP": "171.135.28.125",
     "TRACKING_METHOD": "IP",
     "OS": "Ubuntu / Tiny Core Linux / Linux 2.6.x / IBM ASM / HP StoreOnce / F5 Networks Big-IP / Cisco IOS Software",
     "DNS": "txr9gxcenah031.sdi.corp.bankofamerica.com"
   }

   sourceValue   = the DNS field -> "txr9gxcenah031.sdi.corp.bankofamerica.com"
   sourcePayload = the whole record; the rule also reads the IP from it
   Expected for the sample: the one hardware CI whose fqdn is
   "txr9gxcenah031.sdi.corp.bankofamerica.com", for example the Server CI "txr9gxcenah031";
   duplicates are resolved by the IP 171.135.28.125 or declined.

   WHY THIS RULE SITS AT ORDER 260
   Rules run from the lowest order to the highest; the first rule that returns a CI wins and the
   later rules are skipped. A rule that returns null passes the host on.
   - Before it : 250 tried the exact FQDN inside the class the OS implies.
   - Reaches it: hosts whose OS gives no class (the sample is an unauthenticated scan with seven
                 guesses) or whose CI is classed differently from the OS.
   - After it  : 300/310 use hostname plus domain evidence for CIs that carry no fqdn value at all.
   ================================================================================================= */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // nothing to look up -> null = "no match from this rule"
        return null;
    var fqdn = ('' + sourceValue).trim().toLowerCase();   // "txr9gxcenah031.sdi.corp.bankofamerica.com"
    if (fqdn.indexOf('.') == -1)                  // no domain part -> the hostname rules (400+) handle bare labels
        return null;
    var ip = sourcePayload.IP ? '' + sourcePayload.IP : '';   // "171.135.28.125", used only to break ties
    // CI classes that must never be matched (placeholder and technical classes). Administrators
    // keep the list in the property sn_sec_cmn.ignoreCIClass; the framework may pass the same list
    // in as _ignoreClass.
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');
    // -> ignore =
    //    "sn_sec_cmn_unmatched_ci,sn_vul_qualys_ci,cmdb_ci_unclassed_hardware,cmdb_ci_incomplete_ip,cmdb_ci_dns_name"
    // ====== STAGE 1: Exact FQDN search with the scanned IP as tie-break (pickFqdn) ===============
    // What   : pickFqdn() searches one table for CIs whose fqdn field equals the scanned name,
    //          collects every hit and notes which of them also carry the scanned IP. One hit ->
    //          match. Several hits but exactly one with the scanned IP -> that one. Anything else
    //          -> null.
    // Why    : an FQDN should be unique, but CMDBs carry duplicates (a retired server and its
    //          rebuilt replacement, a cluster alias on two nodes). The scanned IP is the second
    //          piece of evidence that breaks such a tie safely; without it the rule declines.
    // Sample : the Server "txr9gxcenah031" has fqdn "txr9gxcenah031.sdi.corp.bankofamerica.com" and
    //          ip_address "171.135.28.125" -> ids = ["3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c"], ipHits =
    //          ["3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c"] -> return "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c".
    // =============================================================================================
    function pickFqdn(table) {
        var gr = new GlideRecord(table);
        if (!gr.isValid())
            return null;
        gr.addQuery('fqdn', fqdn);                // fqdn = "txr9gxcenah031.sdi.corp.bankofamerica.com"
        if (ignore)
            gr.addQuery('sys_class_name', 'NOT IN', ignore);
        gr.query();
        var ids = [];                             // every CI carrying the FQDN
        var ipHits = [];                          // those that also carry the scanned IP
        while (gr.next()) {
            ids.push(gr.getUniqueValue());
            if (ip && gr.getValue('ip_address') == ip)
                ipHits.push(gr.getUniqueValue());
        }
        // -> ids = ["3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c"], ipHits =
        //    ["3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c"] for the sample; a duplicate would give ids =
        //    ["3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c", "8c1d5e2f7a9b4c3d6e0f1a2b3c4d5e6f"]
        if (ids.length == 1)                      // one CI -> match
            return ids[0];
        if (ids.length > 1 && ipHits.length == 1) // duplicates, one confirmed by the IP -> that one
            return ipHits[0];
        return null;                              // none, or an unresolved tie -> decline
    }
    return pickFqdn('cmdb_ci_hardware');      // exact FQDN anywhere under Hardware
})(rule, sourceValue, sourcePayload);
