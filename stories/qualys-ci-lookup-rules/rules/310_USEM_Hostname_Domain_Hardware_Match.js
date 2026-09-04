/* =====================================================================
   RULE 310 - USEM Hostname Domain Hardware Match
   =====================================================================
   SAMPLE PAYLOAD (one Qualys Host Detection record) this rule is written for:
   {
     "ID": "35884392",
     "IP": "171.128.140.192",
     "TRACKING_METHOD": "IP",
     "OS": "Ubuntu/Linux",
     "DNS": "lrche01xtrapd01.sdi.corp.bankofamerica.com"
   }

   sourceValue   = the DNS field  -> "lrche01xtrapd01.sdi.corp.bankofamerica.com"
   sourcePayload = the whole record above (IP is read from it)

   WHY THIS RULE SITS AT ORDER 310
   Rules run from the lowest order to the highest; the first rule that
   returns a CI wins and every later rule is skipped.
   - Before it : 300 tried hostname + domain inside the class the OS implies.
   - Reaches it: hosts whose CI is classed generically (Server, Computer) or
                 differently from the scanned OS, so the class-scoped search
                 found nothing; the same combination is now searched across the
                 whole hardware tree.
   - After it  : 350 (layered DNS records) and 400/410 (short hostname without
                 domain evidence).
   ===================================================================== */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // payload has no DNS -> nothing to look up
        return null;
    var full = ('' + sourceValue).trim().toLowerCase();   // "lrche01xtrapd01.sdi.corp.bankofamerica.com"
    var dot = full.indexOf('.');                  // 15
    if (dot < 1)                                  // needs hostname + domain
        return null;
    var host = full.substring(0, dot);            // "lrche01xtrapd01"
    var domain = full.substring(dot + 1);         // "sdi.corp.bankofamerica.com"
    var ip = sourcePayload.IP ? '' + sourcePayload.IP : '';   // "171.128.140.192" - tie-breaker only

    // Classes that must never be matched (for example unclassed or retired CI
    // classes) are listed by the administrators in the system property
    // sn_sec_cmn.ignoreCIClass. The CI identification framework may hand the
    // same list to the script as _ignoreClass; either way it ends up in
    // "ignore", e.g. "cmdb_ci_unclassed,cmdb_ci_ip_address_dns_name".
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');

    // pickCombo() searches one table for CIs whose name is the short hostname
    // and keeps only those whose own domain information agrees with the
    // scanned domain.
    function pickCombo(table) {
        var gr = new GlideRecord(table);
        if (!gr.isValid())
            return null;
        gr.addQuery('name', host);                // name = "lrche01xtrapd01" (CMDB names compare case-insensitively)
        if (ignore)
            gr.addQuery('sys_class_name', 'NOT IN', ignore);
        gr.query();
        var good = [];                            // CIs whose domain evidence confirms the scanned domain
        var ipHits = [];                          // those of them that also carry the scanned IP
        while (gr.next()) {
            var cifqdn = ('' + gr.getValue('fqdn')).toLowerCase();        // e.g. "lrche01xtrapd01.sdi.corp.bankofamerica.com"
            var cidom = ('' + gr.getValue('dns_domain')).toLowerCase();   // e.g. "sdi.corp.bankofamerica.com"
            // The CI confirms the domain when its fqdn equals the scanned name,
            // or its dns_domain equals the scanned domain, or its fqdn starts
            // with "hostname." and contains the scanned domain.
            if (cifqdn == full || cidom == domain ||
                (cifqdn && cifqdn.indexOf(host + '.') == 0 && cifqdn.indexOf(domain) > 0)) {
                good.push(gr.getUniqueValue());
                if (ip && gr.getValue('ip_address') == ip)
                    ipHits.push(gr.getUniqueValue());
            }
        }
        if (good.length == 1)                     // one CI has the name AND the domain -> match
            return good[0];
        if (good.length > 1 && ipHits.length == 1)   // several: accept only the one the scanned IP confirms
            return ipHits[0];
        return null;                              // none, or several without an IP tie-break -> decline
    }

    return pickCombo('cmdb_ci_hardware');         // hostname + domain anywhere under Hardware
})(rule, sourceValue, sourcePayload);
