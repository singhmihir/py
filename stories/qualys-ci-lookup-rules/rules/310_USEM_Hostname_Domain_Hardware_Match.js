/* =================================================================================================
   RULE 310 - USEM Hostname Domain Hardware Match
   =================================================================================================
   PURPOSE
   Match by short hostname plus domain evidence anywhere in the hardware tree. This is the second
   combination stage, for hosts whose CI is classed generically (Server, Computer) or differently
   from the OS.

   SAMPLE PAYLOAD
   One Qualys Host Detection record, used for every example in this script:
   {
     "ID": "35884392",
     "IP": "171.128.140.192",
     "TRACKING_METHOD": "IP",
     "OS": "Ubuntu/Linux",
     "DNS": "lrche01xtrapd01.sdi.corp.bankofamerica.com"
   }

   sourceValue   = the DNS field of that record -> "lrche01xtrapd01.sdi.corp.bankofamerica.com"
   sourcePayload = the whole record above; the rule also reads the IP from it
   rule          = this lookup rule record (name, order, source); the logic does not need it
   Expected outcome for the sample: the hardware CI named "lrche01xtrapd01" whose fqdn is
   "lrche01xtrapd01.sdi.corp.bankofamerica.com" or whose dns_domain is "sdi.corp.bankofamerica.com",
   for example a CI in the generic Server class.

   WHY THIS RULE SITS AT ORDER 310
   Rules run from the lowest order to the highest. The first rule that returns a CI wins and every
   later rule is skipped; a rule that returns null simply passes the host on to the next rule.
   - Before it : 300 tried hostname plus domain inside the class the OS implies (Linux Server for
                 the sample OS "Ubuntu/Linux").
   - Reaches it: hosts whose CI is classed generically (Server, Computer) or differently from the
                 scanned OS, so the class-scoped search found nothing.
   - After it  : 350 (layered DNS records) and 400/410 (short hostname without domain evidence).

   THE STAGES OF THIS SCRIPT
    1. Check that Qualys sent a DNS name
    2. Clean the DNS name and split it into hostname and domain
    3. Note the scanned IP address for tie-breaks
    4. Read the list of CI classes that must never be matched
    5. The helper pickCombo(table)
    6. Run the helper on the whole hardware tree
   ================================================================================================= */
(function process(rule, sourceValue, sourcePayload) {
    // ---------------------------------------------------------------------------------------------
    // STAGE 1 - Check that Qualys sent a DNS name
    // What happens : the rule stops with null when the field is empty. null is the signal "no match
    //                from this rule"; the framework then tries the next rule in order.
    // Why          : a search for an empty value can never identify one machine and would only cost
    //                time on every host that lacks the field.
    // Sample       : sourceValue = "lrche01xtrapd01.sdi.corp.bankofamerica.com" -> not empty -> the
    //                rule carries on.
    // ---------------------------------------------------------------------------------------------
    if (!sourceValue)
        return null;
    // -> for the sample the condition is false and nothing happens; for an empty value the rule
    //    ends here with null.
    // ---------------------------------------------------------------------------------------------
    // STAGE 2 - Clean the DNS name and split it into hostname and domain
    // What happens : '' + sourceValue turns the value into plain text, trim() removes blanks at
    //                both ends, toLowerCase() lowers it. indexOf(".") finds the first dot; the text
    //                before it is the short hostname and the text after it is the domain.
    // Why          : the rule needs both halves: the hostname to find candidate CIs by name, and
    //                the domain to confirm that a candidate really belongs to the scanned domain. A
    //                name without a dot has no domain to confirm, so the rule declines and leaves
    //                it to the hostname rules (400 and above).
    // Sample       : full = "lrche01xtrapd01.sdi.corp.bankofamerica.com"; dot = 15; host =
    //                "lrche01xtrapd01"; domain = "sdi.corp.bankofamerica.com".
    // ---------------------------------------------------------------------------------------------
    var full = ('' + sourceValue).trim().toLowerCase();
    // -> full = "lrche01xtrapd01.sdi.corp.bankofamerica.com".
    var dot = full.indexOf('.');
    // -> dot = 15, the position of the first dot (positions count from 0).
    if (dot < 1)
        return null;
    // -> dot = -1 (no dot) or 0 (the name starts with a dot) -> decline; 15 -> carry on.
    var host = full.substring(0, dot);
    // -> host = "lrche01xtrapd01" (everything before the first dot).
    var domain = full.substring(dot + 1);
    // -> domain = "sdi.corp.bankofamerica.com" (everything after the first dot).
    // ---------------------------------------------------------------------------------------------
    // STAGE 3 - Note the scanned IP address for tie-breaks
    // What happens : copies the IP field of the payload into plain text, or an empty text when the
    //                payload has none.
    // Why          : the IP is not used to search; it is only used later to choose between two CIs
    //                that both carry the scanned name.
    // Sample       : ip = "171.128.140.192".
    // ---------------------------------------------------------------------------------------------
    var ip = sourcePayload.IP ? '' + sourcePayload.IP : '';
    // -> ip = "171.128.140.192" (or "" when the payload has no IP field).
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
    // STAGE 5 - The helper pickCombo(table)
    // What happens : defines the helper used in the next stage. It searches one table for CIs whose
    //                name is the short hostname, and keeps a CI only when the CI's own domain
    //                information agrees with the scanned domain: its fqdn equals the scanned name,
    //                or its dns_domain equals the scanned domain, or its fqdn starts with the
    //                hostname and contains the scanned domain. Then it decides: one confirmed CI ->
    //                that CI; several but exactly one with the scanned IP -> that one; anything
    //                else -> null.
    // Why          : the same short hostname can exist in several domains (a test and a production
    //                machine both called app01). Requiring domain evidence on the CI itself stops
    //                the findings from landing on the namesake in another domain.
    // Sample       : the Server "lrche01xtrapd01" (sys_id 3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c) has
    //                dns_domain = "sdi.corp.bankofamerica.com" -> confirmed -> good =
    //                ["3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c"]; a CI "lrche01xtrapd01" with dns_domain =
    //                "lab.example.net" is skipped -> good.length == 1 -> return
    //                "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c".
    // ---------------------------------------------------------------------------------------------
    function pickCombo(table) {
        var gr = new GlideRecord(table);
        // -> gr = a search on the table given (the class and every class beneath it)
        if (!gr.isValid())
            return null;
        // -> the class does not exist on this instance -> decline rather than fail
        gr.addQuery('name', host);
        // -> condition added: name = "lrche01xtrapd01" (CMDB names compare case-insensitively, so
        //    "LRCHE01XTRAPD01" is found too)
        if (ignore)
            gr.addQuery('sys_class_name', 'NOT IN', ignore);
        // -> condition added: sys_class_name NOT IN (sn_sec_cmn_unmatched_ci, sn_vul_qualys_ci,
        //    cmdb_ci_unclassed_hardware, cmdb_ci_incomplete_ip, cmdb_ci_dns_name)
        gr.query();
        // -> the search has run; every CI named "lrche01xtrapd01" in the table is in the result
        var good = [];
        var ipHits = [];
        // -> two empty lists: good will hold the CIs whose domain evidence agrees, ipHits those of
        //    them that also carry the scanned IP
        while (gr.next()) {
            // -> each pass of the loop looks at one CI named "lrche01xtrapd01"
            var cifqdn = ('' + gr.getValue('fqdn')).toLowerCase();
            // -> cifqdn = the CI's own fqdn in lower case, for example
            //    "lrche01xtrapd01.sdi.corp.bankofamerica.com", or "" when the field is empty
            var cidom = ('' + gr.getValue('dns_domain')).toLowerCase();
            // -> cidom = the CI's own dns_domain in lower case, for example
            //    "sdi.corp.bankofamerica.com", or "" when empty
            if (cifqdn == full || cidom == domain ||
                (cifqdn && cifqdn.indexOf(host + '.') == 0 && cifqdn.indexOf(domain) > 0)) {
                // -> the CI confirms the domain in one of three ways: its fqdn is the scanned name;
                //    its dns_domain is the scanned domain; or its fqdn starts with
                //    "lrche01xtrapd01." and contains "sdi.corp.bankofamerica.com" somewhere after
                //    it.
                good.push(gr.getUniqueValue());
                // -> good = ["3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c"] after the first confirmed CI
                if (ip && gr.getValue('ip_address') == ip)
                    ipHits.push(gr.getUniqueValue());
                // -> ipHits = ["3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c"] when this CI's ip_address is
                //    also "171.128.140.192"
            }
            // -> a CI named "lrche01xtrapd01" whose domain evidence disagrees (another domain, or
            //    no domain at all) is simply skipped
        }
        if (good.length == 1)
            return good[0];
        // -> exactly one CI has the name and the domain -> its sys_id is the answer
        if (good.length > 1 && ipHits.length == 1)
            return ipHits[0];
        // -> several confirmed CIs, and exactly one of them also carries the scanned IP -> that one
        //    is the answer
        return null;
        // -> no confirmed CI, or several without a single IP confirmation -> decline
    }
    // ---------------------------------------------------------------------------------------------
    // STAGE 6 - Run the helper on the whole hardware tree
    // ---------------------------------------------------------------------------------------------
    return pickCombo('cmdb_ci_hardware');
    // -> pickCombo("cmdb_ci_hardware") searches Hardware and every class beneath it ->
    //    "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c" for the sample; null makes the host continue to rule
    //    350.
})(rule, sourceValue, sourcePayload);
