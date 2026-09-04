/* =================================================================================================
   RULE 300 - USEM Hostname Domain Class Match
   =================================================================================================
   PURPOSE
   Match by the combination of short hostname and domain, inside the class the OS implies. It serves
   CIs that are named with the short hostname and carry the domain in another field (dns_domain or
   fqdn) instead of an exact fqdn value.

   SAMPLE PAYLOAD
   One Qualys Host Detection record, used for every example in this script:
   {
     "ID": "35832680",
     "IP": "171.128.225.96",
     "TRACKING_METHOD": "AGENT",
     "OS": "Red Hat Enterprise Linux 9.8",
     "DNS": "ah-1047132-001.sdi.corp.bankofamerica.com",
     "QG_HOSTID": "633769a4-0139-0002-e352-005056bf41ea"
   }

   sourceValue   = the DNS field of that record -> "ah-1047132-001.sdi.corp.bankofamerica.com"
   sourcePayload = the whole record above; the rule also reads the OS and the IP from it
   rule          = this lookup rule record (name, order, source); the logic does not need it
   Expected outcome for the sample: the Linux Server CI named "ah-1047132-001" whose dns_domain is
   "sdi.corp.bankofamerica.com" (or whose fqdn is the scanned name); a namesake in another domain is
   never picked.

   WHY THIS RULE SITS AT ORDER 300
   Rules run from the lowest order to the highest. The first rule that returns a CI wins and every
   later rule is skipped; a rule that returns null simply passes the host on to the next rule.
   - Before it : 250/260 looked for the exact FQDN in the fqdn field.
   - Reaches it: hosts whose CI has no exact fqdn value but is named with the short hostname and
                 shows the domain elsewhere.
   - After it  : 310 repeats the search across all hardware; 350 uses the layered DNS records;
                 400/410 accept a unique short name without any domain evidence.

   THE STAGES OF THIS SCRIPT
    1. Check that Qualys sent a DNS name
    2. Clean the DNS name and split it into hostname and domain
    3. Note the scanned IP address for tie-breaks
    4. Read the list of CI classes that must never be matched
    5. Work out the CMDB class from the scanned operating system
    6. The helper pickCombo(table)
    7. Run the helper inside the class the OS implies
   ================================================================================================= */
(function process(rule, sourceValue, sourcePayload) {
    // ---------------------------------------------------------------------------------------------
    // STAGE 1 - Check that Qualys sent a DNS name
    // What happens : the rule stops with null when the field is empty. null is the signal "no match
    //                from this rule"; the framework then tries the next rule in order.
    // Why          : a search for an empty value can never identify one machine and would only cost
    //                time on every host that lacks the field.
    // Sample       : sourceValue = "ah-1047132-001.sdi.corp.bankofamerica.com" -> not empty -> the
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
    // Sample       : full = "ah-1047132-001.sdi.corp.bankofamerica.com"; dot = 14; host =
    //                "ah-1047132-001"; domain = "sdi.corp.bankofamerica.com".
    // ---------------------------------------------------------------------------------------------
    var full = ('' + sourceValue).trim().toLowerCase();
    // -> full = "ah-1047132-001.sdi.corp.bankofamerica.com".
    var dot = full.indexOf('.');
    // -> dot = 14, the position of the first dot (positions count from 0).
    if (dot < 1)
        return null;
    // -> dot = -1 (no dot) or 0 (the name starts with a dot) -> decline; 14 -> carry on.
    var host = full.substring(0, dot);
    // -> host = "ah-1047132-001" (everything before the first dot).
    var domain = full.substring(dot + 1);
    // -> domain = "sdi.corp.bankofamerica.com" (everything after the first dot).
    // ---------------------------------------------------------------------------------------------
    // STAGE 3 - Note the scanned IP address for tie-breaks
    // What happens : copies the IP field of the payload into plain text, or an empty text when the
    //                payload has none.
    // Why          : the IP is not used to search; it is only used later to choose between two CIs
    //                that both carry the scanned name.
    // Sample       : ip = "171.128.225.96".
    // ---------------------------------------------------------------------------------------------
    var ip = sourcePayload.IP ? '' + sourcePayload.IP : '';
    // -> ip = "171.128.225.96" (or "" when the payload has no IP field).
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
    // STAGE 5 - Work out the CMDB class from the scanned operating system
    // What happens : the helper classFor() reads the operating system text Qualys reports and
    //                returns the CMDB class such a machine is stored in. It lowers the text, gives
    //                up when the text is an unauthenticated multi-guess fingerprint (three or more
    //                guesses separated by "/"), then looks for key words in a fixed order and
    //                returns an empty string when nothing fits. Searching a class also searches
    //                every class beneath it, so cmdb_ci_linux_server covers all Linux flavour
    //                classes.
    // Why          : evidence is only trusted when it lands in a class that agrees with the scanned
    //                OS: a Red Hat host must resolve to a Linux Server CI, never to a Windows
    //                Server that happens to carry the same value.
    // Sample       : classFor("Red Hat Enterprise Linux 9.8"): s = "red hat enterprise linux 9.8";
    //                s.split("/") has 1 part; "esx", "windows", "aix", "solaris", "sunos", "hp-ux",
    //                "netapp", "ontap", "printer", "laserjet" and "jetdirect" are not found; "red
    //                hat" is found -> returns "cmdb_ci_linux_server" (Linux Server).
    // ---------------------------------------------------------------------------------------------
    function classFor(os) {
        if (!os) return '';
        // -> no OS text at all -> "" (no class).
        var s = ('' + os).toLowerCase();
        // -> s = the OS text in lower case, so that "Windows", "WINDOWS" and "windows" all compare
        //    the same.
        if (s.split('/').length > 2) return '';
        // -> "ubuntu / tiny core linux / linux 2.6.x / ibm asm / hp storeonce / f5 networks big-ip
        //    / cisco ios software" splits into 7 parts at the "/" characters -> more than 2 -> an
        //    unauthenticated guess list -> "" (no class).
        if (s.indexOf('esx') != -1) return 'cmdb_ci_esx_server';
        // -> "vmware esxi 7.0.3 build 24723872" contains "esx" -> "cmdb_ci_esx_server" (ESX
        //    Server).
        if (s.indexOf('windows') != -1)
            return s.indexOf('server') != -1 ? 'cmdb_ci_win_server' : 'cmdb_ci_computer';
        // -> "windows server 2016 standard 64 bit edition version 1607" -> "cmdb_ci_win_server"
        //    (Windows Server); "windows 10 enterprise 64 bit edition version 22h2" has no "server"
        //    -> "cmdb_ci_computer" (Computer, a workstation).
        if (s.indexOf('aix') != -1) return 'cmdb_ci_aix_server';
        // -> "aix 7.3 tl3" -> "cmdb_ci_aix_server" (AIX Server).
        if (s.indexOf('solaris') != -1 || s.indexOf('sunos') != -1) return 'cmdb_ci_solaris_server';
        // -> "oracle solaris 11.4" -> "cmdb_ci_solaris_server" (Solaris Server).
        if (s.indexOf('hp-ux') != -1) return 'cmdb_ci_hpux_server';
        // -> "hp-ux b.11.31" -> "cmdb_ci_hpux_server" (HPUX Server).
        if (s.indexOf('netapp') != -1 || s.indexOf('ontap') != -1) return 'cmdb_ci_storage_server';
        // -> "netapp ontap 9.12.1" -> "cmdb_ci_storage_server" (Storage Server).
        if (s.indexOf('printer') != -1 || s.indexOf('laserjet') != -1 || s.indexOf('jetdirect') != -1) return 'cmdb_ci_printer';
        // -> "hp laserjet m507" -> "cmdb_ci_printer" (Printer).
        if (s.indexOf('red hat') != -1 || s.indexOf('linux') != -1 || s.indexOf('centos') != -1 ||
            s.indexOf('ubuntu') != -1 || s.indexOf('suse') != -1 || s.indexOf('debian') != -1 ||
            s.indexOf('fedora') != -1 || s.indexOf('euleros') != -1 ||
            s.indexOf('oracle enterprise') != -1 || s.indexOf('amazon') != -1) return 'cmdb_ci_linux_server';
        // -> "red hat enterprise linux 9.8", "suse linux enterprise server 15 sp5" and "amazon
        //    linux 2023" -> "cmdb_ci_linux_server" (Linux Server).
        if (s.indexOf('nx-os') != -1 || s.indexOf('catos') != -1 || s.indexOf('cisco') != -1) return 'cmdb_ci_netgear';
        // -> "cisco nx-os 9.3(8)" -> "cmdb_ci_netgear" (Network Gear).
        return '';
        // -> anything else, for example "unknown" -> "" (no class).
    }

    var pref = classFor(sourcePayload.OS);
    // -> pref = "cmdb_ci_linux_server" for the sample OS "Red Hat Enterprise Linux 9.8".
    if (!pref)
        return null;
    // -> pref = "" happens for an unknown OS or a multi-guess fingerprint; this rule then declines
    //    so that rule 310 (which searches all hardware without a class) gets its turn.
    // ---------------------------------------------------------------------------------------------
    // STAGE 6 - The helper pickCombo(table)
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
    // Sample       : the Linux Server "ah-1047132-001" (sys_id 3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c)
    //                has dns_domain = "sdi.corp.bankofamerica.com" -> confirmed -> good =
    //                ["3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c"]; a CI "ah-1047132-001" with dns_domain =
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
        // -> condition added: name = "ah-1047132-001" (CMDB names compare case-insensitively, so
        //    "AH-1047132-001" is found too)
        if (ignore)
            gr.addQuery('sys_class_name', 'NOT IN', ignore);
        // -> condition added: sys_class_name NOT IN (sn_sec_cmn_unmatched_ci, sn_vul_qualys_ci,
        //    cmdb_ci_unclassed_hardware, cmdb_ci_incomplete_ip, cmdb_ci_dns_name)
        gr.query();
        // -> the search has run; every CI named "ah-1047132-001" in the table is in the result
        var good = [];
        var ipHits = [];
        // -> two empty lists: good will hold the CIs whose domain evidence agrees, ipHits those of
        //    them that also carry the scanned IP
        while (gr.next()) {
            // -> each pass of the loop looks at one CI named "ah-1047132-001"
            var cifqdn = ('' + gr.getValue('fqdn')).toLowerCase();
            // -> cifqdn = the CI's own fqdn in lower case, for example
            //    "ah-1047132-001.sdi.corp.bankofamerica.com", or "" when the field is empty
            var cidom = ('' + gr.getValue('dns_domain')).toLowerCase();
            // -> cidom = the CI's own dns_domain in lower case, for example
            //    "sdi.corp.bankofamerica.com", or "" when empty
            if (cifqdn == full || cidom == domain ||
                (cifqdn && cifqdn.indexOf(host + '.') == 0 && cifqdn.indexOf(domain) > 0)) {
                // -> the CI confirms the domain in one of three ways: its fqdn is the scanned name;
                //    its dns_domain is the scanned domain; or its fqdn starts with
                //    "ah-1047132-001." and contains "sdi.corp.bankofamerica.com" somewhere after
                //    it.
                good.push(gr.getUniqueValue());
                // -> good = ["3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c"] after the first confirmed CI
                if (ip && gr.getValue('ip_address') == ip)
                    ipHits.push(gr.getUniqueValue());
                // -> ipHits = ["3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c"] when this CI's ip_address is
                //    also "171.128.225.96"
            }
            // -> a CI named "ah-1047132-001" whose domain evidence disagrees (another domain, or no
            //    domain at all) is simply skipped
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
    // STAGE 7 - Run the helper inside the class the OS implies
    // ---------------------------------------------------------------------------------------------
    return pickCombo(pref);
    // -> pickCombo("cmdb_ci_linux_server") -> "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c" for the sample;
    //    that sys_id goes back to the framework, which links the vulnerable item to the Linux
    //    Server "ah-1047132-001" and stops evaluating later rules. null makes the host continue to
    //    rule 310.
})(rule, sourceValue, sourcePayload);
