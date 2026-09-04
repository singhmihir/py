/* =================================================================================================
   RULE 310 - USEM Hostname Domain Hardware Match
   =================================================================================================
   Match by short hostname plus domain evidence anywhere in the hardware tree. Second combination
   stage, for hosts whose CI is classed generically (Server, Computer) or differently from the OS.

   SAMPLE PAYLOAD (one Qualys Host Detection record, used in every example below)
   {
     "ID": "35884392",
     "IP": "171.128.140.192",
     "TRACKING_METHOD": "IP",
     "OS": "Ubuntu/Linux",
     "DNS": "lrche01xtrapd01.sdi.corp.bankofamerica.com"
   }

   sourceValue   = the DNS field -> "lrche01xtrapd01.sdi.corp.bankofamerica.com"
   sourcePayload = the whole record; the rule also reads the IP from it
   Expected for the sample: the hardware CI named "lrche01xtrapd01" whose fqdn is
   "lrche01xtrapd01.sdi.corp.bankofamerica.com" or whose dns_domain is "sdi.corp.bankofamerica.com",
   for example a CI in the generic Server class.

   WHY THIS RULE SITS AT ORDER 310
   Rules run from the lowest order to the highest; the first rule that returns a CI wins and the
   later rules are skipped. A rule that returns null passes the host on.
   - Before it : 300 tried hostname plus domain inside the class the OS implies (Linux Server for
                 the sample OS "Ubuntu/Linux").
   - Reaches it: hosts whose CI is classed generically (Server, Computer) or differently from the
                 scanned OS, so the class-scoped search found nothing.
   - After it  : 350 (layered DNS records) and 400/410 (short hostname without domain evidence).
   ================================================================================================= */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // nothing to look up -> null = "no match from this rule"
        return null;
    var full = ('' + sourceValue).trim().toLowerCase();   // "lrche01xtrapd01.sdi.corp.bankofamerica.com"
    var dot = full.indexOf('.');                  // 15, position of the first dot
    if (dot < 1)                                  // no domain part -> the hostname rules (400+) handle bare labels
        return null;
    var host = full.substring(0, dot);            // "lrche01xtrapd01"
    var domain = full.substring(dot + 1);         // "sdi.corp.bankofamerica.com"
    var ip = sourcePayload.IP ? '' + sourcePayload.IP : '';   // "171.128.140.192", used only to break ties
    // CI classes that must never be matched (placeholder and technical classes). Administrators
    // keep the list in the property sn_sec_cmn.ignoreCIClass; the framework may pass the same list
    // in as _ignoreClass.
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');
    // -> ignore =
    //    "sn_sec_cmn_unmatched_ci,sn_vul_qualys_ci,cmdb_ci_unclassed_hardware,cmdb_ci_incomplete_ip,cmdb_ci_dns_name"
    // ====== STAGE 1: Hostname plus domain evidence, with the scanned IP as tie-break (pickCombo) =
    // What   : pickCombo() searches one table for CIs named with the short hostname and keeps a CI
    //          only when its own domain information agrees with the scanned domain: its fqdn equals
    //          the scanned name, or its dns_domain equals the scanned domain, or its fqdn starts
    //          with the hostname and contains the domain. One confirmed CI -> match. Several but
    //          exactly one with the scanned IP -> that one. Anything else -> null.
    // Why    : the same short hostname can exist in several domains (a test and a production
    //          machine both called app01). Domain evidence on the CI itself stops the findings from
    //          landing on the namesake in another domain.
    // Sample : the Server "lrche01xtrapd01" has dns_domain "sdi.corp.bankofamerica.com" ->
    //          confirmed -> good = ["3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c"] -> return
    //          "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c". A CI "lrche01xtrapd01" with dns_domain
    //          "lab.example.net" is skipped.
    // =============================================================================================
    function pickCombo(table) {
        var gr = new GlideRecord(table);
        if (!gr.isValid())
            return null;
        gr.addQuery('name', host);                // name = "lrche01xtrapd01" (case-insensitive)
        if (ignore)
            gr.addQuery('sys_class_name', 'NOT IN', ignore);
        gr.query();
        var good = [];                            // CIs whose domain evidence agrees
        var ipHits = [];                          // those that also carry the scanned IP
        while (gr.next()) {
            var cifqdn = ('' + gr.getValue('fqdn')).toLowerCase();        // e.g. "lrche01xtrapd01.sdi.corp.bankofamerica.com"
            var cidom = ('' + gr.getValue('dns_domain')).toLowerCase();   // e.g. "sdi.corp.bankofamerica.com"
            if (cifqdn == full || cidom == domain ||
                (cifqdn && cifqdn.indexOf(host + '.') == 0 && cifqdn.indexOf(domain) > 0)) {
                good.push(gr.getUniqueValue());
                if (ip && gr.getValue('ip_address') == ip)
                    ipHits.push(gr.getUniqueValue());
            }
        }
        // -> good = ["3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c"], ipHits =
        //    ["3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c"] for the sample
        if (good.length == 1)                     // one confirmed CI -> match
            return good[0];
        if (good.length > 1 && ipHits.length == 1) // several, one confirmed by the IP -> that one
            return ipHits[0];
        return null;                              // none, or an unresolved tie -> decline
    }
    return pickCombo('cmdb_ci_hardware');     // hostname + domain anywhere under Hardware
})(rule, sourceValue, sourcePayload);
