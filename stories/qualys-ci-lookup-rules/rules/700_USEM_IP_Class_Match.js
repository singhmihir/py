/* =================================================================================================
   RULE 700 - USEM IP Class Match
   =================================================================================================
   PURPOSE
   Match by IP address, inside the class the OS implies. An address is the least trustworthy
   identifier (addresses move between machines and are shared by load balancers), so it is used only
   when the host has no serial and no usable name, and only when exactly one CI of the agreed class
   carries it.

   SAMPLE PAYLOAD
   One Qualys Host Detection record, used for every example in this script:
   {
     "ID": "83047621",
     "IP": "30.162.178.21",
     "TRACKING_METHOD": "IP",
     "OS": "VMware ESXi 7.0.3 build 24723872"
   }

   sourceValue   = the IP field of that record -> "30.162.178.21"
   sourcePayload = the whole record above; the rule also reads the OS from it
   rule          = this lookup rule record (name, order, source); the logic does not need it
   Expected outcome for the sample: the ESX Server CI whose ip_address is "30.162.178.21", for
   example "vsdnac22xsdi009"; a load balancer or a Windows CI with the same address is outside the
   class and cannot be picked.

   WHY THIS RULE SITS AT ORDER 700
   Rules run from the lowest order to the highest. The first rule that returns a CI wins and every
   later rule is skipped; a rule that returns null simply passes the host on to the next rule.
   - Before it : all serial and name rules (175 to 450). The sample has no DNS name at all, so every
                 name rule declined.
   - Reaches it: DNS-less hosts, typically ESXi management interfaces and appliances (89 of the
                 21,000 hosts in the reference extract).
   - After it  : 705 searches the address across all hardware with extra safety checks; 730 and 740
                 resolve it through adapters and the layered IP records.

   THE STAGES OF THIS SCRIPT
    1. Check that Qualys sent an IP address
    2. Clean the address and reject addresses that identify nothing
    3. Read the list of CI classes that must never be matched
    4. Work out the CMDB class from the scanned operating system
    5. Search that class for the address
    6. Decide: exactly one CI, or decline
   ================================================================================================= */
(function process(rule, sourceValue, sourcePayload) {
    // ---------------------------------------------------------------------------------------------
    // STAGE 1 - Check that Qualys sent an IP address
    // What happens : the rule stops with null when the field is empty. null is the signal "no match
    //                from this rule"; the framework then tries the next rule in order.
    // Why          : a search for an empty value can never identify one machine and would only cost
    //                time on every host that lacks the field.
    // Sample       : sourceValue = "30.162.178.21" -> not empty -> the rule carries on.
    // ---------------------------------------------------------------------------------------------
    if (!sourceValue)
        return null;
    // -> for the sample the condition is false and nothing happens; for an empty value the rule
    //    ends here with null.
    // ---------------------------------------------------------------------------------------------
    // STAGE 2 - Clean the address and reject addresses that identify nothing
    // What happens : '' + sourceValue turns the value into plain text and trim() removes blanks at
    //                both ends. Then the rule refuses loopback addresses (127.x.x.x) and link-local
    //                addresses (169.254.x.x).
    // Why          : every machine answers on 127.0.0.1, and 169.254.x.x addresses are
    //                self-assigned when no network is available, so neither can ever point at one
    //                CI.
    // Sample       : ip = "30.162.178.21" -> neither prefix matches -> carry on.
    // ---------------------------------------------------------------------------------------------
    var ip = ('' + sourceValue).trim();
    // -> ip = "30.162.178.21".
    if (!ip || ip.indexOf('127.') == 0 || ip.indexOf('169.254.') == 0)
        return null;
    // -> indexOf("127.") == 0 would mean the text starts with "127."; for "30.162.178.21" both
    //    indexOf calls return -1 -> the condition is false -> carry on.
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
    //    so that rule 705 (which searches all hardware without a class) gets its turn.
    // ---------------------------------------------------------------------------------------------
    // STAGE 5 - Search that class for the address
    // What happens : opens a search on the class chosen above (and its sub-classes), keeps only CIs
    //                whose ip_address field equals the scanned address, and leaves out every class
    //                on the ignore list.
    // Why          : inside the agreed class an address is reasonably safe: a virtual IP of a load
    //                balancer, or a Windows machine that inherited the address, sits outside the
    //                ESX Server class and never appears.
    // Sample       : the search on cmdb_ci_esx_server for ip_address = "30.162.178.21" finds the
    //                ESX Server "vsdnac22xsdi009" (sys_id 3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c).
    // ---------------------------------------------------------------------------------------------
    var gr = new GlideRecord(pref);
    // -> gr = a search on the ESX Server class and every class beneath it.
    if (!gr.isValid())
        return null;
    // -> the class does not exist on this instance -> decline rather than fail.
    gr.addQuery('ip_address', ip);
    // -> condition added: ip_address = "30.162.178.21" (exact match).
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
    // Sample       : one CI -> the ESX Server "vsdnac22xsdi009" -> return
    //                "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c". No CI -> return null and rule 705 gets its
    //                turn. Two CIs -> two ESX Servers carrying "30.162.178.21" (an address reused
    //                after a rebuild) -> return null.
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
