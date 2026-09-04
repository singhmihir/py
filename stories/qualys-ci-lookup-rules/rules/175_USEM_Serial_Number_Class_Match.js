/* =================================================================================================
   RULE 175 - USEM Serial Number Class Match
   =================================================================================================
   PURPOSE
   Match a scanned host to its CI by serial number, but only inside the CMDB class that the scanned
   operating system implies. A serial number is the strongest identifier a physical or virtual
   machine has, so this is the first USEM rule in the chain.

   SAMPLE PAYLOAD
   One Qualys Host Detection record, used for every example in this script:
   {
     "ID": "35832680",
     "IP": "171.128.225.96",
     "TRACKING_METHOD": "AGENT",
     "OS": "Red Hat Enterprise Linux 9.8",
     "DNS": "ah-1047132-001.sdi.corp.bankofamerica.com",
     "SERIAL_NUMBER": "VMware-42 1a 9c 3f 7d 2e 61 b8-55 04 e2 91 6a 27 c3 08"
   }

   sourceValue   = the SERIAL_NUMBER field of that record -> "VMware-42 1a 9c 3f 7d 2e 61 b8-55 04 e2 91 6a 27 c3 08"
   sourcePayload = the whole record above; the rule also reads the OS from it
   rule          = this lookup rule record (name, order, source); the logic does not need it
   Expected outcome for the sample: the Linux Server CI "ah-1047132-001" whose serial_number field
   holds the same serial; its sys_id is returned. If no Linux Server carries the serial, or two do,
   the rule returns null.

   WHY THIS RULE SITS AT ORDER 175
   Rules run from the lowest order to the highest. The first rule that returns a CI wins and every
   later rule is skipped; a rule that returns null simply passes the host on to the next rule.
   - Before it : nothing custom runs before it. Serial numbers come first because a serial belongs
                 to one machine for its whole life, while names and addresses are reused.
   - Reaches it: every Qualys host that reports a SERIAL_NUMBER. Today only hosts scanned by the
                 authenticated Cloud Agent report one; unauthenticated network scans leave the field
                 empty and those hosts skip straight to the name rules.
   - After it  : 180 repeats the serial search across every hardware class for hosts whose OS gives
                 no class or whose CI is classed differently; 200 and above move on to names and,
                 last of all, addresses.

   THE STAGES OF THIS SCRIPT
    1. Check that Qualys sent a serial number
    2. Clean the serial number
    3. Reject placeholder serial numbers
    4. Read the list of CI classes that must never be matched
    5. Work out the CMDB class from the scanned operating system
    6. Search that class for the serial
    7. Decide: exactly one CI, or decline
   ================================================================================================= */
(function process(rule, sourceValue, sourcePayload) {
    // ---------------------------------------------------------------------------------------------
    // STAGE 1 - Check that Qualys sent a serial number
    // What happens : the rule stops with null when the field is empty. null is the signal "no match
    //                from this rule"; the framework then tries the next rule in order.
    // Why          : a search for an empty value can never identify one machine and would only cost
    //                time on every host that lacks the field.
    // Sample       : sourceValue = "VMware-42 1a 9c 3f 7d 2e 61 b8-55 04 e2 91 6a 27 c3 08" -> not
    //                empty -> the rule carries on.
    // ---------------------------------------------------------------------------------------------
    if (!sourceValue)
        return null;
    // -> for the sample the condition is false and nothing happens; for an empty value the rule
    //    ends here with null.
    // ---------------------------------------------------------------------------------------------
    // STAGE 2 - Clean the serial number
    // What happens : '' + sourceValue turns the platform value into a plain text string and trim()
    //                removes blanks at both ends. Blanks inside the value stay, because they are
    //                part of the serial.
    // Why          : some feeds pad values with blanks; a search for " MXQ13005TC " would not find
    //                "MXQ13005TC".
    // Sample       : serial = "VMware-42 1a 9c 3f 7d 2e 61 b8-55 04 e2 91 6a 27 c3 08".
    // ---------------------------------------------------------------------------------------------
    var serial = ('' + sourceValue).trim();
    // -> serial = "VMware-42 1a 9c 3f 7d 2e 61 b8-55 04 e2 91 6a 27 c3 08" (54 characters).
    // ---------------------------------------------------------------------------------------------
    // STAGE 3 - Reject placeholder serial numbers
    // What happens : the rule keeps a list of placeholder serials that vendors ship on thousands of
    //                machines ("To Be Filled By O.E.M.", "System Serial Number", "0123456789",
    //                "None" and so on) and refuses to search for any of them, or for a serial
    //                shorter than four characters.
    // Why          : a placeholder would match dozens of CIs at once and the tie could never be
    //                broken; declining at once lets the name and address rules do the work instead.
    // Sample       : "vmware-42 1a 9c 3f 7d 2e 61 b8-55 04 e2 91 6a 27 c3 08" is 54 characters long
    //                and is not in the list -> carry on. "N/A" would be found as ",n/a," in the
    //                list -> decline. "12" is shorter than four characters -> decline.
    // ---------------------------------------------------------------------------------------------
    var junk = ',0,none,n/a,na,unknown,empty,not specified,not available,no serial,' +
        'default string,to be filled by o.e.m.,system serial number,chassis serial number,' +
        '0123456789,1234567890,';
    // -> junk = one long text with a comma before and after every placeholder, so that "," + serial
    //    + "," can only be found when the whole serial equals a placeholder (",na," is never found
    //    inside ",not available,").
    if (serial.length < 4 || junk.indexOf(',' + serial.toLowerCase() + ',') != -1)
        return null;
    // -> serial.toLowerCase() = "vmware-42 1a 9c 3f 7d 2e 61 b8-55 04 e2 91 6a 27 c3 08";
    //    junk.indexOf(",vmware-42 1a 9c 3f 7d 2e 61 b8-55 04 e2 91 6a 27 c3 08,") = -1 (not found)
    //    and the length is 54 -> the condition is false -> carry on.
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
    //                s.split("/") has 1 part (not a multi-guess); "esx", "windows", "aix",
    //                "solaris", "sunos", "hp-ux", "netapp", "ontap", "printer", "laserjet" and
    //                "jetdirect" are not found; "red hat" is found -> returns
    //                "cmdb_ci_linux_server" (Linux Server).
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
    //    so that rule 180 (which searches all hardware without a class) gets its turn.
    // ---------------------------------------------------------------------------------------------
    // STAGE 6 - Search that class for the serial
    // What happens : opens a search on the class chosen above (which automatically includes its
    //                sub-classes), keeps only CIs whose serial_number equals the cleaned serial,
    //                and leaves out every class on the ignore list.
    // Why          : the serial must match exactly (no wildcard) and inside the agreed class only,
    //                so class evidence and serial evidence have to agree before the rule trusts the
    //                result.
    // Sample       : the search on cmdb_ci_linux_server for serial_number = "VMware-42 1a 9c 3f 7d
    //                2e 61 b8-55 04 e2 91 6a 27 c3 08" finds the Linux Server "ah-1047132-001"
    //                (sys_id 3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c). A Windows Server with the same
    //                serial is outside the class and never appears in the result.
    // ---------------------------------------------------------------------------------------------
    var gr = new GlideRecord(pref);
    // -> gr = a search on the Linux Server class and every class beneath it; nothing has run yet.
    if (!gr.isValid())
        return null;
    // -> isValid() is false only when the class does not exist on this instance (a plugin not
    //    installed); then the rule declines rather than fail.
    gr.addQuery('serial_number', serial);
    // -> condition added: serial_number = "VMware-42 1a 9c 3f 7d 2e 61 b8-55 04 e2 91 6a 27 c3 08"
    //    (exact match, case-insensitive).
    if (ignore)
        gr.addQuery('sys_class_name', 'NOT IN', ignore);
    // -> condition added: sys_class_name NOT IN (sn_sec_cmn_unmatched_ci, sn_vul_qualys_ci,
    //    cmdb_ci_unclassed_hardware, cmdb_ci_incomplete_ip, cmdb_ci_dns_name), so an ignored class
    //    can never appear in the result.
    // ---------------------------------------------------------------------------------------------
    // STAGE 7 - Decide: exactly one CI, or decline
    // What happens : runs the search, reads the first CI and accepts it only when there is no
    //                second CI in the result.
    // Why          : every finding of this host will be linked to the CI the rule returns. A wrong
    //                CI sends the findings to the wrong owner, so when two CIs share the value the
    //                rule refuses to guess and answers null; a later rule with different evidence
    //                may still resolve the host, and if none does the host stays unmatched for the
    //                CMDB team to review.
    // Sample       : one CI -> the Linux Server "ah-1047132-001" -> return
    //                "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c". No CI -> return null and rule 180 gets its
    //                turn. Two CIs -> "ah-1047132-001" and a second Linux Server loaded twice with
    //                the same serial -> return null.
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
