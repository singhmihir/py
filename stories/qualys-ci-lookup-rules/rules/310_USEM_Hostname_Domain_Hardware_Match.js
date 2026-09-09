/* USEM Hostname Domain Hardware Match
   -------------------------------------------------------------------------------------------------
   Short hostname plus domain evidence again, across the whole hardware tree, for CIs classed
   generically (Server, Computer) or differently from the scanned OS.

   Input  : sourceValue is the DNS field; the rule also reads the IP from sourcePayload.
   Returns: the sys_id of the one hardware CI named with the short hostname whose fqdn or dns_domain
            agrees with the scanned domain; null otherwise.

   Place in the chain (the first rule to return a CI wins; a null hands the host to the next rule)
   Before : USEM Hostname Domain Class Match tried the same evidence inside the class the OS
            implies.
   Reaches: hosts whose CI is classed generically or differently from the scanned OS, so the
            class-scoped search found nothing.
   After  : USEM Layered DNS Match and then the plain hostname rules.
   ------------------------------------------------------------------------------------------------- */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // nothing to look up
        return null;
    var full = ('' + sourceValue).trim().toLowerCase();   // e.g. "lrche01xtrapd01.sdi.corp.bankofamerica.com"
    var dot = full.indexOf('.');
    if (dot < 1)                                  // a bare label is left to the hostname rules
        return null;
    var host = full.substring(0, dot);            // "lrche01xtrapd01"
    var domain = full.substring(dot + 1);         // "sdi.corp.bankofamerica.com"
    var ip = sourcePayload.IP ? '' + sourcePayload.IP : '';   // only used to break a tie
    // Classes that must never be matched (placeholder and technical CIs); the list lives in the
    // property sn_sec_cmn.ignoreCIClass and the framework may pass it in as _ignoreClass.
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');
    // -- Short hostname plus domain evidence, scanned IP as the tie-break -------------------------
    // pickCombo() looks for CIs under Hardware named with the short hostname and keeps one only
    // when its own record agrees with the scanned domain: fqdn equal to the scanned name,
    // dns_domain equal to the scanned domain, or an fqdn that starts with the hostname and contains
    // the domain. The same short name lives in several domains (a test and a production box both
    // called app01), and this check is what keeps the findings off the namesake. One confirmed CI
    // is the match; several with exactly one carrying the scanned IP gives that one; anything else
    // declines.
    function pickCombo(table) {
        var gr = new GlideRecord(table);
        if (!gr.isValid())
            return null;
        gr.addQuery('name', host);                // name compares case-insensitively
        if (ignore)
            gr.addQuery('sys_class_name', 'NOT IN', ignore);
        gr.query();
        var good = [];                            // CIs whose domain evidence agrees
        var ipHits = [];                          // those that also carry the scanned IP
        while (gr.next()) {
            var cifqdn = ('' + gr.getValue('fqdn')).toLowerCase();
            var cidom = ('' + gr.getValue('dns_domain')).toLowerCase();
            if (cifqdn == full || cidom == domain ||
                (cifqdn && cifqdn.indexOf(host + '.') == 0 && cifqdn.indexOf(domain) > 0)) {
                good.push(gr.getUniqueValue());
                if (ip && gr.getValue('ip_address') == ip)
                    ipHits.push(gr.getUniqueValue());
            }
        }
        if (good.length == 1)
            return good[0];
        if (good.length > 1 && ipHits.length == 1) // several, one confirmed by the IP
            return ipHits[0];
        return null;                              // none, or a tie nothing can break
    }
    return pickCombo('cmdb_ci_hardware');     // hostname plus domain anywhere under Hardware
})(rule, sourceValue, sourcePayload);
