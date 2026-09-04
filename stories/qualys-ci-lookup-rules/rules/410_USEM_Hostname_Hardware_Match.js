/* =================================================================================================
   RULE 410 - USEM Hostname Hardware Match
   =================================================================================================
   PURPOSE
   Match by the short hostname anywhere in the hardware tree, with a sanity check that the CI found
   does not contradict the scanned OS. This is the second short-name stage, for CIs classed
   generically (Server, Computer, UNIX Server) or differently from the OS.

   SAMPLE PAYLOAD
   One Qualys Host Detection record, used for every example in this script:
   {
     "ID": "80217765",
     "IP": "171.150.219.123",
     "TRACKING_METHOD": "IP",
     "OS": "AIX 7.3 TL3",
     "DNS": "va2ausapabw0.bankofamerica.com",
     "QG_HOSTID": "6337e0dc-007d-0002-c47d-005056a4fcd5"
   }

   sourceValue   = the DNS field of that record -> "va2ausapabw0.bankofamerica.com"
   sourcePayload = the whole record above; the rule also reads the OS from it
   rule          = this lookup rule record (name, order, source); the logic does not need it
   Expected outcome for the sample: the one hardware CI named "va2ausapabw0"; accepted when it is an
   AIX Server or a generically classed Server, rejected when it is, say, a Windows Server (an AIX
   scan cannot belong to a Windows machine).

   WHY THIS RULE SITS AT ORDER 410
   Rules run from the lowest order to the highest. The first rule that returns a CI wins and every
   later rule is skipped; a rule that returns null simply passes the host on to the next rule.
   - Before it : 400 required the short name to be unique inside the class the OS implies.
   - Reaches it: hosts whose CI is classed generically (Server, Computer, UNIX Server) or whose OS
                 gave no class, so 400 found nothing.
   - After it  : 450 (CI named with the full FQDN) and then the IP rules (700 and above) for hosts
                 without a usable name.

   THE STAGES OF THIS SCRIPT
    1. Check that Qualys sent a DNS name
    2. Clean the DNS name and take the short hostname
    3. Read the list of CI classes that must never be matched
    4. Work out the CMDB class from the scanned operating system (a preference, not a requirement)
    5. List the classes that never contradict the scan
    6. Search the whole hardware tree for the short name
    7. Require exactly one owner
    8. Reject an owner whose class contradicts the scanned OS
    9. Return the owner
   ================================================================================================= */
(function process(rule, sourceValue, sourcePayload) {
    // ---------------------------------------------------------------------------------------------
    // STAGE 1 - Check that Qualys sent a DNS name
    // What happens : the rule stops with null when the field is empty. null is the signal "no match
    //                from this rule"; the framework then tries the next rule in order.
    // Why          : a search for an empty value can never identify one machine and would only cost
    //                time on every host that lacks the field.
    // Sample       : sourceValue = "va2ausapabw0.bankofamerica.com" -> not empty -> the rule
    //                carries on.
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
    // Sample       : full = "va2ausapabw0.bankofamerica.com"; split(".") = ["va2ausapabw0",
    //                "bankofamerica", "com"]; host = "va2ausapabw0".
    // ---------------------------------------------------------------------------------------------
    var full = ('' + sourceValue).trim().toLowerCase();
    // -> full = "va2ausapabw0.bankofamerica.com".
    var host = full.split('.')[0];
    // -> host = "va2ausapabw0".
    if (!host)
        return null;
    // -> host is empty only for a name that starts with a dot -> decline; "va2ausapabw0" -> carry
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
    // Sample       : classFor("AIX 7.3 TL3"): s = "aix 7.3 tl3"; s.split("/") has 1 part; "esx" and
    //                "windows" are not found; "aix" is found -> returns "cmdb_ci_aix_server" (AIX
    //                Server).
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
    // -> pref = "cmdb_ci_aix_server" for the sample OS "AIX 7.3 TL3".
    // -> unlike rule 400, an empty pref does not stop this rule: the search below runs without a
    //    class, and stage 8 simply has nothing to check.
    // ---------------------------------------------------------------------------------------------
    // STAGE 5 - List the classes that never contradict the scan
    // What happens : lists the classes that say nothing about the operating system: Hardware,
    //                Computer, Server and UNIX Server. A CI stored in one of these never
    //                contradicts the scan.
    // Why          : many CIs are loaded into the generic Server class before discovery refines
    //                them; rejecting those would leave a large part of the estate unmatched for no
    //                good reason.
    // Sample       : generic["cmdb_ci_server"] = 1 (true), generic["cmdb_ci_win_server"] =
    //                undefined (false).
    // ---------------------------------------------------------------------------------------------
    var generic = {cmdb_ci_hardware: 1, cmdb_ci_computer: 1, cmdb_ci_server: 1,
        cmdb_ci_unix_server: 1};
    // -> generic = a lookup table with the four class names; generic[cls] answers "is this class
    //    generic?".
    // ---------------------------------------------------------------------------------------------
    // STAGE 6 - Search the whole hardware tree for the short name
    // What happens : opens a search on cmdb_ci_hardware, the parent class of every device class,
    //                keeps only CIs whose name equals the short hostname, and leaves out every
    //                class on the ignore list.
    // Why          : the class-scoped search of rule 400 found nothing, so the name is now searched
    //                everywhere; the safety comes from the two checks that follow.
    // Sample       : the search on cmdb_ci_hardware for name = "va2ausapabw0" finds the Server
    //                "va2ausapabw0" (sys_id 3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c, class
    //                cmdb_ci_server).
    // ---------------------------------------------------------------------------------------------
    var gr = new GlideRecord('cmdb_ci_hardware');
    // -> gr = a search on Hardware and every class beneath it.
    gr.addQuery('name', host);
    // -> condition added: name = "va2ausapabw0" (case-insensitive).
    if (ignore)
        gr.addQuery('sys_class_name', 'NOT IN', ignore);
    // -> condition added: sys_class_name NOT IN (sn_sec_cmn_unmatched_ci, sn_vul_qualys_ci,
    //    cmdb_ci_unclassed_hardware, cmdb_ci_incomplete_ip, cmdb_ci_dns_name).
    gr.query();
    // -> the search has run.
    // ---------------------------------------------------------------------------------------------
    // STAGE 7 - Require exactly one owner
    // What happens : reads the first CI, remembers its sys_id and its class, and declines when a
    //                second CI carries the same name.
    // Why          : two hardware CIs with one short name (a test and a production machine, a
    //                retired and a rebuilt one) can never be told apart by the name alone.
    // Sample       : one row -> id = "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c", cls = "cmdb_ci_server".
    //                Two rows -> return null.
    // ---------------------------------------------------------------------------------------------
    if (!gr.next())
        return null;
    // -> no CI has this name -> decline; the host continues to rule 450.
    var id = gr.getUniqueValue();
    // -> id = "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c".
    var cls = '' + gr.getValue('sys_class_name');
    // -> cls = "cmdb_ci_server" (the exact class of the CI found).
    if (gr.hasNext())
        return null;
    // -> a second CI with the same name is waiting in the result -> ambiguous -> decline.
    // ---------------------------------------------------------------------------------------------
    // STAGE 8 - Reject an owner whose class contradicts the scanned OS
    // What happens : when the OS gave a class preference, checks that the CI found sits inside that
    //                class (or one of its sub-classes) or is generically classed; any other class
    //                is a contradiction and the rule declines.
    // Why          : a host scanned as AIX that resolves by name to a Windows Server CI is a
    //                namesake, not the same machine; linking the findings there would send AIX
    //                vulnerabilities to a Windows owner.
    // Sample       : pref = "cmdb_ci_aix_server"; chk.get("3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c") on
    //                the AIX Server class is false because the CI is a plain Server, but
    //                generic["cmdb_ci_server"] is true -> accepted. For a Windows Server CI both
    //                checks fail -> return null.
    // ---------------------------------------------------------------------------------------------
    if (pref) {
        var chk = new GlideRecord(pref);
        // -> chk = a search on the AIX Server class and its sub-classes.
        if (!(chk.isValid() && chk.get(id)) && !generic[cls])
            return null;
        // -> chk.get(id) is true when the CI is an AIX Server; generic[cls] is true when it is
        //    generically classed; when neither holds the CI contradicts the scan -> decline.
    }
    // ---------------------------------------------------------------------------------------------
    // STAGE 9 - Return the owner
    // ---------------------------------------------------------------------------------------------
    return id;
    // -> the sys_id "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c" goes back to the framework, which links the
    //    vulnerable item to the CI and stops evaluating later rules.
})(rule, sourceValue, sourcePayload);
