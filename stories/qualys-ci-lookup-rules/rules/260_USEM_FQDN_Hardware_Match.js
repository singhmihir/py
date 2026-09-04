/* =====================================================================
   RULE 260 - USEM FQDN Hardware Match
   =====================================================================
   SAMPLE PAYLOAD (one Qualys Host Detection record) this rule is written for:
   {
     "ID": "35920204",
     "IP": "171.135.28.125",
     "TRACKING_METHOD": "IP",
     "OS": "Ubuntu / Tiny Core Linux / Linux 2.6.x / IBM ASM / HP StoreOnce / F5 Networks Big-IP / Cisco IOS Software",
     "DNS": "txr9gxcenah031.sdi.corp.bankofamerica.com"
   }

   sourceValue   = the DNS field  -> "txr9gxcenah031.sdi.corp.bankofamerica.com"
   sourcePayload = the whole record above (IP is read from it)

   WHY THIS RULE SITS AT ORDER 260
   Rules run from the lowest order to the highest; the first rule that
   returns a CI wins and every later rule is skipped.
   - Before it : 250 tried the exact FQDN inside the class the OS implies.
   - Reaches it: hosts whose OS gives no class (unauthenticated multi-guess
                 fingerprint as above) or whose CI is classed differently from
                 the OS - the FQDN is now searched across the whole hardware
                 tree.
   - After it  : 300/310 use hostname + domain evidence for CIs that do not
                 carry an fqdn value at all.
   ===================================================================== */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // payload has no DNS -> nothing to look up
        return null;
    var fqdn = ('' + sourceValue).trim().toLowerCase();   // "txr9gxcenah031.sdi.corp.bankofamerica.com"
    if (fqdn.indexOf('.') == -1)                  // bare label -> hostname rules handle it
        return null;
    var ip = sourcePayload.IP ? '' + sourcePayload.IP : '';   // "171.135.28.125" - tie-breaker only

    // Classes that must never be matched (for example unclassed or retired CI
    // classes) are listed by the administrators in the system property
    // sn_sec_cmn.ignoreCIClass. The CI identification framework may hand the
    // same list to the script as _ignoreClass; either way it ends up in
    // "ignore", e.g. "cmdb_ci_unclassed,cmdb_ci_ip_address_dns_name".
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');

    // pickFqdn() searches one table for CIs whose fqdn field equals the scanned
    // name and decides whether the answer is safe to use.
    function pickFqdn(table) {
        var gr = new GlideRecord(table);
        if (!gr.isValid())                        // class missing on this instance -> decline
            return null;
        gr.addQuery('fqdn', fqdn);                // fqdn = "txr9gxcenah031.sdi.corp.bankofamerica.com"
        if (ignore)
            gr.addQuery('sys_class_name', 'NOT IN', ignore);
        gr.query();
        var ids = [];                             // every CI carrying this FQDN
        var ipHits = [];                          // those of them whose ip_address is also the scanned IP
        while (gr.next()) {
            ids.push(gr.getUniqueValue());
            if (ip && gr.getValue('ip_address') == ip)
                ipHits.push(gr.getUniqueValue());
        }
        if (ids.length == 1)                      // one CI carries the FQDN -> match
            return ids[0];
        // Two or more CIs carry the same FQDN (a retired and a rebuilt server, a
        // cluster alias ...). Accept only when the scanned IP points at exactly
        // one of them, otherwise decline and let a later rule decide.
        if (ids.length > 1 && ipHits.length == 1)
            return ipHits[0];
        return null;
    }

    return pickFqdn('cmdb_ci_hardware');          // exact FQDN anywhere under Hardware
})(rule, sourceValue, sourcePayload);
