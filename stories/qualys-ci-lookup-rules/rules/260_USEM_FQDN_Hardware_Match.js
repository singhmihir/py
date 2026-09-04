/* =================================================================================================
   RULE 260 - USEM FQDN Hardware Match
   =================================================================================================
   PURPOSE
   Match by exact FQDN anywhere in the hardware tree. This is the second FQDN stage, for hosts whose
   OS gives no class or whose CI is classed differently from the OS.

   SAMPLE PAYLOAD
   One Qualys Host Detection record, used for every example in this script:
   {
     "ID": "35920204",
     "IP": "171.135.28.125",
     "TRACKING_METHOD": "IP",
     "OS": "Ubuntu / Tiny Core Linux / Linux 2.6.x / IBM ASM / HP StoreOnce / F5 Networks Big-IP / Cisco IOS Software",
     "DNS": "txr9gxcenah031.sdi.corp.bankofamerica.com"
   }

   sourceValue   = the DNS field of that record -> "txr9gxcenah031.sdi.corp.bankofamerica.com"
   sourcePayload = the whole record above; the rule also reads the IP from it
   rule          = this lookup rule record (name, order, source); the logic does not need it
   Expected outcome for the sample: the one hardware CI whose fqdn is
   "txr9gxcenah031.sdi.corp.bankofamerica.com", for example the Server CI "txr9gxcenah031";
   duplicates are resolved by the IP 171.135.28.125 or declined.

   WHY THIS RULE SITS AT ORDER 260
   Rules run from the lowest order to the highest. The first rule that returns a CI wins and every
   later rule is skipped; a rule that returns null simply passes the host on to the next rule.
   - Before it : 250 tried the exact FQDN inside the class the OS implies.
   - Reaches it: hosts whose OS gives no class (the sample is an unauthenticated scan with seven
                 guesses) or whose CI is classed differently from the OS, so 250 found nothing.
   - After it  : 300 and 310 use hostname plus domain evidence for CIs that carry no fqdn value at
                 all.

   THE STAGES OF THIS SCRIPT
    1. Check that Qualys sent a DNS name
    2. Clean the DNS name and require a domain part
    3. Note the scanned IP address for tie-breaks
    4. Read the list of CI classes that must never be matched
    5. The helper pickFqdn(table)
    6. Run the helper on the whole hardware tree
   ================================================================================================= */
(function process(rule, sourceValue, sourcePayload) {
    // ---------------------------------------------------------------------------------------------
    // STAGE 1 - Check that Qualys sent a DNS name
    // What happens : the rule stops with null when the field is empty. null is the signal "no match
    //                from this rule"; the framework then tries the next rule in order.
    // Why          : a search for an empty value can never identify one machine and would only cost
    //                time on every host that lacks the field.
    // Sample       : sourceValue = "txr9gxcenah031.sdi.corp.bankofamerica.com" -> not empty -> the
    //                rule carries on.
    // ---------------------------------------------------------------------------------------------
    if (!sourceValue)
        return null;
    // -> for the sample the condition is false and nothing happens; for an empty value the rule
    //    ends here with null.
    // ---------------------------------------------------------------------------------------------
    // STAGE 2 - Clean the DNS name and require a domain part
    // What happens : '' + sourceValue turns the value into plain text, trim() removes blanks at
    //                both ends and toLowerCase() lowers it. Then the rule requires at least one dot
    //                in the name.
    // Why          : DNS names are case-insensitive and CMDB values are stored in mixed case, so
    //                both sides are compared in lower case. A name without a dot is a bare
    //                hostname, which the hostname rules (400 and above) look after.
    // Sample       : fqdn = "txr9gxcenah031.sdi.corp.bankofamerica.com"; indexOf(".") finds a dot
    //                -> carry on. A bare label "txr9gxcenah031" has no dot -> indexOf(".") = -1 ->
    //                decline.
    // ---------------------------------------------------------------------------------------------
    var fqdn = ('' + sourceValue).trim().toLowerCase();
    // -> fqdn = "txr9gxcenah031.sdi.corp.bankofamerica.com".
    if (fqdn.indexOf('.') == -1)
        return null;
    // -> indexOf(".") = 14 for the sample (the position of the first dot) -> not -1 -> carry on.
    // ---------------------------------------------------------------------------------------------
    // STAGE 3 - Note the scanned IP address for tie-breaks
    // What happens : copies the IP field of the payload into plain text, or an empty text when the
    //                payload has none.
    // Why          : the IP is not used to search; it is only used later to choose between two CIs
    //                that both carry the scanned name.
    // Sample       : ip = "171.135.28.125".
    // ---------------------------------------------------------------------------------------------
    var ip = sourcePayload.IP ? '' + sourcePayload.IP : '';
    // -> ip = "171.135.28.125" (or "" when the payload has no IP field).
    // ---------------------------------------------------------------------------------------------
    // STAGE 4 - Read the list of CI classes that must never be matched
    // What happens : reads the list of CI classes that must never be matched. Administrators keep
    //                it in the system property sn_sec_cmn.ignoreCIClass as comma separated class
    //                names. The framework may also hand the same list to the script as a variable
    //                called _ignoreClass; when that variable exists and is filled the script uses
    //                it, otherwise it reads the property directly.
    // Why          : placeholder and technical classes must never receive vulnerability findings:
    //                the unmatched CI placeholders that Security Operations creates, the Qualys
    //                staging CI class, Unclassed Hardware, incomplete IP records and DNS Name
    //                records. Keeping the list in one property means it can be changed without
    //                editing sixteen scripts.
    // Sample       : with the platform default the property holds
    //                "sn_sec_cmn_unmatched_ci,sn_vul_qualys_ci,cmdb_ci_unclassed_hardware,cmdb_ci_incomplete_ip,cmdb_ci_dns_name";
    //                an empty property gives ignore = "" and then no class filter is added to the
    //                searches below.
    // ---------------------------------------------------------------------------------------------
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');
    // -> ignore =
    //    "sn_sec_cmn_unmatched_ci,sn_vul_qualys_ci,cmdb_ci_unclassed_hardware,cmdb_ci_incomplete_ip,cmdb_ci_dns_name",
    //    one text, comma separated, ready for a NOT IN condition.
    // ---------------------------------------------------------------------------------------------
    // STAGE 5 - The helper pickFqdn(table)
    // What happens : defines the helper used in the next stage. It searches one table for CIs whose
    //                fqdn field equals the scanned name (ignored classes left out), collects the
    //                sys_id of every CI found, notes which of them also carry the scanned IP
    //                address, and decides: one CI -> that CI; several CIs but exactly one with the
    //                scanned IP -> that one; anything else -> null.
    // Why          : an FQDN is meant to be unique, but CMDBs do carry duplicates: a retired server
    //                and its rebuilt replacement, or a cluster alias loaded on two nodes. The
    //                scanned IP is the second piece of evidence that can safely break such a tie;
    //                without it the rule declines rather than guess.
    // Sample       : the Server "txr9gxcenah031" (sys_id 3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c) has fqdn
    //                = "txr9gxcenah031.sdi.corp.bankofamerica.com" -> ids =
    //                ["3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c"], ipHits =
    //                ["3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c"] because its ip_address is also
    //                "171.135.28.125" -> ids.length == 1 -> return
    //                "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c".
    // ---------------------------------------------------------------------------------------------
    function pickFqdn(table) {
        var gr = new GlideRecord(table);
        // -> gr = a search on the table given (the class and every class beneath it); nothing has
        //    run yet
        if (!gr.isValid())
            return null;
        // -> isValid() is false only when the class does not exist on this instance; then the
        //    helper declines rather than fail
        gr.addQuery('fqdn', fqdn);
        // -> condition added: fqdn = "txr9gxcenah031.sdi.corp.bankofamerica.com" (exact match,
        //    case-insensitive)
        if (ignore)
            gr.addQuery('sys_class_name', 'NOT IN', ignore);
        // -> condition added: sys_class_name NOT IN (sn_sec_cmn_unmatched_ci, sn_vul_qualys_ci,
        //    cmdb_ci_unclassed_hardware, cmdb_ci_incomplete_ip, cmdb_ci_dns_name)
        gr.query();
        // -> the search has run; gr sits before the first row of the result
        var ids = [];
        var ipHits = [];
        // -> two empty lists: ids will hold every CI found, ipHits the ones that also carry the
        //    scanned IP
        while (gr.next()) {
            // -> each pass of the loop looks at one CI of the result
            ids.push(gr.getUniqueValue());
            // -> ids = ["3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c"] after the first CI,
            //    ["3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c", "8c1d5e2f7a9b4c3d6e0f1a2b3c4d5e6f"] when a
            //    second one exists
            if (ip && gr.getValue('ip_address') == ip)
                ipHits.push(gr.getUniqueValue());
            // -> ipHits = ["3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c"] when this CI's ip_address field is
            //    "171.135.28.125"; unchanged otherwise
        }
        if (ids.length == 1)
            return ids[0];
        // -> exactly one CI carries the FQDN -> its sys_id is the answer
        if (ids.length > 1 && ipHits.length == 1)
            return ipHits[0];
        // -> two or more CIs carry the FQDN and exactly one of them also has the scanned IP -> that
        //    one is the answer
        return null;
        // -> no CI, or several CIs without a single IP confirmation -> decline
    }

    // ---------------------------------------------------------------------------------------------
    // STAGE 6 - Run the helper on the whole hardware tree
    // ---------------------------------------------------------------------------------------------
    return pickFqdn('cmdb_ci_hardware');
    // -> pickFqdn("cmdb_ci_hardware") searches Hardware and every class beneath it ->
    //    "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c" for the sample; null makes the host continue to rule
    //    300.
})(rule, sourceValue, sourcePayload);
