/* =================================================================================================
   RULE 400 - USEM Hostname Class Match
   =================================================================================================
   PURPOSE
   Match by the short hostname alone, inside the class the OS implies. This is for CIs that carry
   only a short name and no domain information; the agreement between the CI class and the scanned
   OS replaces the missing domain evidence.

   SAMPLE PAYLOAD
   One Qualys Host Detection record, used for every example in this script:
   {
     "ID": "35850078",
     "IP": "30.143.70.11",
     "TRACKING_METHOD": "IP",
     "OS": "Windows Server 2016 Standard 64 bit Edition Version 1607",
     "DNS": "wsaoi01zeapd1.sdi.corp.bankofamerica.com",
     "NETBIOS": "WSAOI01ZEAPD1"
   }

   sourceValue   = the DNS field of that record -> "wsaoi01zeapd1.sdi.corp.bankofamerica.com"
   sourcePayload = the whole record above; the rule also reads the OS from it
   rule          = this lookup rule record (name, order, source); the logic does not need it
   Expected outcome for the sample: the Windows Server CI named "WSAOI01ZEAPD1" (names compare
   case-insensitively, so "wsaoi01zeapd1" finds it); a second Windows Server with the same name
   makes the rule decline.

   WHY THIS RULE SITS AT ORDER 400
   Rules run from the lowest order to the highest. The first rule that returns a CI wins and every
   later rule is skipped; a rule that returns null simply passes the host on to the next rule.
   - Before it : 250 to 350 needed domain evidence on the CI (fqdn, dns_domain or the layered DNS
                 records).
   - Reaches it: hosts whose CI carries only a short name and no domain information at all.
   - After it  : 410 repeats the short name search across all hardware with a class sanity check;
                 450 handles CIs named with the full FQDN.

   THE STAGES OF THIS SCRIPT
    1. Check that Qualys sent a DNS name
    2. Clean the DNS name and take the short hostname
    3. Read the list of CI classes that must never be matched
    4. Work out the CMDB class from the scanned operating system
    5. Search that class for the short name
    6. Decide: exactly one CI, or decline
   ================================================================================================= */
(function process(rule, sourceValue, sourcePayload) {
    // ---------------------------------------------------------------------------------------------
    // STAGE 1 - Check that Qualys sent a DNS name
    // What happens : the rule stops with null when the field is empty. null is the signal "no match
    //                from this rule"; the framework then tries the next rule in order.
    // Why          : a search for an empty value can never identify one machine and would only cost
    //                time on every host that lacks the field.
    // Sample       : sourceValue = "wsaoi01zeapd1.sdi.corp.bankofamerica.com" -> not empty -> the
    //                rule carries on.
    // ---------------------------------------------------------------------------------------------
    if (!sourceValue)
        return null;
    // -> for the sample the condition is false and nothing happens; for an empty value the rule
    //    ends here with null.
    // ---------------------------------------------------------------------------------------------
    // STAGE 2 - Clean the DNS name and take the short hostname
    // What happens : '' + sourceValue turns the value into plain text, trim() removes blanks at
    //                both ends, toLowerCase() lowers it, and split(".")[0] keeps the text before
    //                the first dot.
    // Why          : CIs without domain information carry only the short name, so the short name is
    //                what has to be compared. A bare label with no dot works as well: split gives
    //                the whole text back.
    // Sample       : full = "wsaoi01zeapd1.sdi.corp.bankofamerica.com"; split(".") =
    //                ["wsaoi01zeapd1", "sdi", "corp", "bankofamerica", "com"]; host =
    //                "wsaoi01zeapd1".
    // ---------------------------------------------------------------------------------------------
    var full = ('' + sourceValue).trim().toLowerCase();
    // -> full = "wsaoi01zeapd1.sdi.corp.bankofamerica.com".
    var host = full.split('.')[0];
    // -> host = "wsaoi01zeapd1".
    if (!host)
        return null;
    // -> host is empty only for a name that starts with a dot -> decline; "wsaoi01zeapd1" -> carry
    //    on.
    // ---------------------------------------------------------------------------------------------
    // STAGE 3 - Read the list of CI classes that must never be matched
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
    // STAGE 4 - Work out the CMDB class from the scanned operating system
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
    // Sample       : classFor("Windows Server 2016 Standard 64 bit Edition Version 1607"): s =
    //                "windows server 2016 standard 64 bit edition version 1607"; s.split("/") has 1
    //                part; "esx" is not found; "windows" is found and "server" is found too ->
    //                returns "cmdb_ci_win_server" (Windows Server).
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
    // -> pref = "cmdb_ci_win_server" for the sample OS "Windows Server 2016 Standard 64 bit Edition
    //    Version 1607".
    if (!pref)
        return null;
    // -> pref = "" happens for an unknown OS or a multi-guess fingerprint; this rule then declines
    //    so that rule 410 (which searches all hardware without a class) gets its turn.
    // ---------------------------------------------------------------------------------------------
    // STAGE 5 - Search that class for the short name
    // What happens : opens a search on the class chosen above (and its sub-classes), keeps only CIs
    //                whose name equals the short hostname, and leaves out every class on the ignore
    //                list.
    // Why          : with no domain to confirm, the class is the only safeguard against a namesake;
    //                inside the agreed class the short name still has to be unique (next stage).
    // Sample       : the search on cmdb_ci_win_server for name = "wsaoi01zeapd1" finds the Windows
    //                Server "WSAOI01ZEAPD1" (sys_id 3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c).
    // ---------------------------------------------------------------------------------------------
    var gr = new GlideRecord(pref);
    // -> gr = a search on the Windows Server class and every class beneath it.
    if (!gr.isValid())
        return null;
    // -> the class does not exist on this instance -> decline rather than fail.
    gr.addQuery('name', host);
    // -> condition added: name = "wsaoi01zeapd1"; CMDB names compare case-insensitively, so
    //    "WSAOI01ZEAPD1" is found.
    if (ignore)
        gr.addQuery('sys_class_name', 'NOT IN', ignore);
    // -> condition added: sys_class_name NOT IN (sn_sec_cmn_unmatched_ci, sn_vul_qualys_ci,
    //    cmdb_ci_unclassed_hardware, cmdb_ci_incomplete_ip, cmdb_ci_dns_name).
    // ---------------------------------------------------------------------------------------------
    // STAGE 6 - Decide: exactly one CI, or decline
    // What happens : runs the search, reads the first CI and accepts it only when there is no
    //                second CI in the result.
    // Why          : every finding of this host will be linked to the CI the rule returns. A wrong
    //                CI sends the findings to the wrong owner, so when two CIs share the value the
    //                rule refuses to guess and answers null; a later rule with different evidence
    //                may still resolve the host, and if none does the host stays unmatched for the
    //                CMDB team to review.
    // Sample       : one CI -> the Windows Server "WSAOI01ZEAPD1" -> return
    //                "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c". No CI -> return null and rule 410 gets its
    //                turn. Two CIs -> two Windows Servers named "WSAOI01ZEAPD1" (for example one
    //                retired and one rebuilt) -> return null.
    // ---------------------------------------------------------------------------------------------
    gr.query();
    // -> the search has run; gr now sits just before the first row of the result (0, 1 or more
    //    CIs).
    if (!gr.next())
        return null;
    // -> next() moves to the first CI and returns true. When the result is empty it returns false
    //    and the rule declines with null.
    var match = gr.getUniqueValue();
    // -> match = the 32-character sys_id of that CI, for example
    //    "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c"; this is the value the framework expects back.
    if (gr.hasNext())
        return null;
    // -> hasNext() is true when a second CI is waiting in the result: two owners of one value is an
    //    ambiguity, so the rule declines.
    return match;
    // -> exactly one CI: its sys_id goes back to the framework, which links the vulnerable item to
    //    it and stops evaluating later rules.
})(rule, sourceValue, sourcePayload);
