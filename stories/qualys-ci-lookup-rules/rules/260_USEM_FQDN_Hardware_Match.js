/* USEM FQDN Hardware Match
   -------------------------------------------------------------------------------------------------
   The exact FQDN search again, across the whole hardware tree. It picks up the hosts whose OS gives
   no class and the CIs kept in a generic or different class than the OS suggests.

   Sample payload (one Qualys host record, used in every note below)
   {
     "ID": "35920204",
     "IP": "171.135.28.125",
     "TRACKING_METHOD": "IP",
     "OS": "Ubuntu / Tiny Core Linux / Linux 2.6.x / IBM ASM / HP StoreOnce / F5 Networks Big-IP / Cisco IOS Software",
     "DNS": "txr9gxcenah031.sdi.corp.bankofamerica.com"
   }
   Input  : sourceValue is the DNS field, "txr9gxcenah031.sdi.corp.bankofamerica.com"; the rule also
            reads the IP from sourcePayload.
   Returns: the sys_id of the one hardware CI whose fqdn equals the scanned name; with duplicates,
            the one that also carries the scanned IP; null otherwise.
   Sample : the Server CI "txr9gxcenah031" whose fqdn is the scanned name; duplicates are resolved
            by the IP 171.135.28.125 or declined.

   Place in the chain (the first rule to return a CI wins; a null hands the host to the next rule)
   Before : USEM FQDN Class Match tried the exact FQDN inside the class the OS implies; the sample
            OS is a list of seven guesses, so that rule declined without searching.
   Reaches: hosts whose OS gives no class (unauthenticated scans with a multi-guess OS, as in the
            sample) or whose CI is classed differently from the OS.
   After  : the hostname-plus-domain rules, for CIs that carry no fqdn value at all.
   ------------------------------------------------------------------------------------------------- */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // nothing to look up
        return null;
    var fqdn = ('' + sourceValue).trim().toLowerCase();   // "txr9gxcenah031.sdi.corp.bankofamerica.com"
    if (fqdn.indexOf('.') == -1)                  // a bare label is left to the hostname rules
        return null;
    var ip = sourcePayload.IP ? '' + sourcePayload.IP : '';   // "171.135.28.125", only used to break a tie
    // Classes that must never be matched (placeholder and technical CIs); the list lives in the
    // property sn_sec_cmn.ignoreCIClass and the framework may pass it in as _ignoreClass.
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');
    // -- Exact FQDN, scanned IP as the tie-break --------------------------------------------------
    // pickFqdn() collects every CI under Hardware whose fqdn equals the scanned name and notes
    // which of them also carry the scanned IP. One hit is the match. Duplicates do exist in the
    // CMDB (a retired server and its rebuilt replacement, a cluster alias on two nodes); when
    // exactly one of them carries the scanned IP that one is taken, otherwise the rule declines
    // rather than guess.
    // Sample: the Server "txr9gxcenah031" has fqdn "txr9gxcenah031.sdi.corp.bankofamerica.com", so
    //         ids holds that one CI and its sys_id is returned. Were a second CI to carry the same
    //         fqdn, the one with ip_address "171.135.28.125" would be taken; if neither or both
    //         carried it, the rule would decline.
    function pickFqdn(table) {
        var gr = new GlideRecord(table);
        if (!gr.isValid())
            return null;
        gr.addQuery('fqdn', fqdn);
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
        if (ids.length == 1)
            return ids[0];
        if (ids.length > 1 && ipHits.length == 1) // duplicates, one confirmed by the IP
            return ipHits[0];
        return null;                              // none, or a tie nothing can break
    }
    return pickFqdn('cmdb_ci_hardware');      // exact FQDN anywhere under Hardware
})(rule, sourceValue, sourcePayload);
