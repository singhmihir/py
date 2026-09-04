/* =================================================================================================
   RULE 250 - USEM FQDN Class Match
   =================================================================================================
   PURPOSE
   Match a scanned host by its fully qualified domain name (FQDN) stored in the fqdn field of a CI,
   inside the CMDB class the scanned OS implies. An exact FQDN on the CI is the most precise name
   evidence there is, so this is the first name rule after the phone rule.

   SAMPLE PAYLOAD
   One Qualys Host Detection record, used for every example in this script:
   {
     "ID": "83047612",
     "IP": "30.206.199.36",
     "TRACKING_METHOD": "IP",
     "OS": "VMware ESXi 7.0.3 build 24723872",
     "DNS": "vsdnac22xsdi004.sdi.corp.bankofamerica.com"
   }

   sourceValue   = the DNS field of that record -> "vsdnac22xsdi004.sdi.corp.bankofamerica.com"
   sourcePayload = the whole record above; the rule also reads the OS and the IP from it
   rule          = this lookup rule record (name, order, source); the logic does not need it
   Expected outcome for the sample: the ESX Server CI whose fqdn field is
   "vsdnac22xsdi004.sdi.corp.bankofamerica.com"; its sys_id is returned. Two ESX Servers with that
   fqdn are accepted only when exactly one of them also carries the IP 30.206.199.36.

   WHY THIS RULE SITS AT ORDER 250
   Rules run from the lowest order to the highest. The first rule that returns a CI wins and every
   later rule is skipped; a rule that returns null simply passes the host on to the next rule.
   - Before it : 175/180 (serial numbers) and 200 (phone labels) found nothing.
   - Reaches it: every host with a dotted DNS name, which is the bulk of the Qualys feed.
   - After it  : 260 repeats the exact FQDN search across every hardware class; 300 and 310 fall
                 back to hostname plus domain evidence; 400 and 410 to the short hostname alone.

   THE STAGES OF THIS SCRIPT
    1. Check that Qualys sent a DNS name
    2. Clean the DNS name and require a domain part
    3. Note the scanned IP address for tie-breaks
    4. Read the list of CI classes that must never be matched
    5. Work out the CMDB class from the scanned operating system
    6. The helper pickFqdn(table)
    7. Run the helper inside the class the OS implies
   ================================================================================================= */
(function process(rule, sourceValue, sourcePayload) {
    // ---------------------------------------------------------------------------------------------
    // STAGE 1 - Check that Qualys sent a DNS name
    // What happens : the rule stops with null when the field is empty. null is the signal "no match
    //                from this rule"; the framework then tries the next rule in order.
    // Why          : a search for an empty value can never identify one machine and would only cost
    //                time on every host that lacks the field.
    // Sample       : sourceValue = "vsdnac22xsdi004.sdi.corp.bankofamerica.com" -> not empty -> the
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
    // Sample       : fqdn = "vsdnac22xsdi004.sdi.corp.bankofamerica.com"; indexOf(".") finds a dot
    //                -> carry on. A bare label "vsdnac22xsdi004" has no dot -> indexOf(".") = -1 ->
    //                decline.
    // ---------------------------------------------------------------------------------------------
    var fqdn = ('' + sourceValue).trim().toLowerCase();
    // -> fqdn = "vsdnac22xsdi004.sdi.corp.bankofamerica.com".
    if (fqdn.indexOf('.') == -1)
        return null;
    // -> indexOf(".") = 15 for the sample (the position of the first dot) -> not -1 -> carry on.
    // ---------------------------------------------------------------------------------------------
    // STAGE 3 - Note the scanned IP address for tie-breaks
    // What happens : copies the IP field of the payload into plain text, or an empty text when the
    //                payload has none.
    // Why          : the IP is not used to search; it is only used later to choose between two CIs
    //                that both carry the scanned name.
    // Sample       : ip = "30.206.199.36".
    // ---------------------------------------------------------------------------------------------
    var ip = sourcePayload.IP ? '' + sourcePayload.IP : '';
    // -> ip = "30.206.199.36" (or "" when the payload has no IP field).
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
    // Sample       : classFor("VMware ESXi 7.0.3 build 24723872"): s = "vmware esxi 7.0.3 build
    //                24723872"; s.split("/") has 1 part; "esx" is found straight away -> returns
    //                "cmdb_ci_esx_server" (ESX Server).
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
    // -> pref = "cmdb_ci_esx_server" for the sample OS "VMware ESXi 7.0.3 build 24723872".
    if (!pref)
        return null;
    // -> pref = "" happens for an unknown OS or a multi-guess fingerprint; this rule then declines
    //    so that rule 260 (which searches all hardware without a class) gets its turn.
    // ---------------------------------------------------------------------------------------------
    // STAGE 6 - The helper pickFqdn(table)
    // What happens : defines the helper used in the next stage. It searches one table for CIs whose
    //                fqdn field equals the scanned name (ignored classes left out), collects the
    //                sys_id of every CI found, notes which of them also carry the scanned IP
    //                address, and decides: one CI -> that CI; several CIs but exactly one with the
    //                scanned IP -> that one; anything else -> null.
    // Why          : an FQDN is meant to be unique, but CMDBs do carry duplicates: a retired server
    //                and its rebuilt replacement, or a cluster alias loaded on two nodes. The
    //                scanned IP is the second piece of evidence that can safely break such a tie;
    //                without it the rule declines rather than guess.
    // Sample       : the ESX Server "vsdnac22xsdi004" (sys_id 3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c) has
    //                fqdn = "vsdnac22xsdi004.sdi.corp.bankofamerica.com" -> ids =
    //                ["3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c"], ipHits =
    //                ["3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c"] because its ip_address is also
    //                "30.206.199.36" -> ids.length == 1 -> return
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
        // -> condition added: fqdn = "vsdnac22xsdi004.sdi.corp.bankofamerica.com" (exact match,
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
            //    "30.206.199.36"; unchanged otherwise
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
    // STAGE 7 - Run the helper inside the class the OS implies
    // ---------------------------------------------------------------------------------------------
    return pickFqdn(pref);
    // -> pickFqdn("cmdb_ci_esx_server") -> "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c" for the sample; that
    //    sys_id goes back to the framework, which links the vulnerable item to the ESX Server
    //    "vsdnac22xsdi004" and stops evaluating later rules. null makes the host continue to rule
    //    260.
})(rule, sourceValue, sourcePayload);
