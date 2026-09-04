/* =================================================================================================
   RULE 705 - USEM IP Hardware Match
   =================================================================================================
   PURPOSE
   Match by IP address anywhere in the hardware tree, with two extra safety checks: the CI must not
   be a load balancer, and its class must not contradict the scanned OS.

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
   Expected outcome for the sample: the one hardware CI whose ip_address is "30.162.178.21",
   accepted when it is an ESX Server or generically classed; rejected when it is a Load Balancer (a
   virtual address answered on behalf of pool members) or a CI of a contradicting class such as
   Windows Server.

   WHY THIS RULE SITS AT ORDER 705
   Rules run from the lowest order to the highest. The first rule that returns a CI wins and every
   later rule is skipped; a rule that returns null simply passes the host on to the next rule.
   - Before it : 700 required the address to belong to one CI of the OS-implied class.
   - Reaches it: DNS-less hosts whose CI is classed generically (Server) or whose OS gave no class.
   - After it  : 730 (address on a network adapter) and 740 (layered IP Address records).

   THE STAGES OF THIS SCRIPT
    1. Check that Qualys sent an IP address
    2. Clean the address and reject addresses that identify nothing
    3. Read the list of CI classes that must never be matched
    4. Work out the CMDB class from the scanned operating system (a preference, not a requirement)
    5. List the classes that never contradict the scan
    6. The helper isLoadBalancer(id)
    7. Search the whole hardware tree for the address
    8. Require exactly one owner
    9. Reject a load balancer
   10. Reject an owner whose class contradicts the scanned OS
   11. Return the owner
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
    // -> an empty pref does not stop this rule: the search below runs without a class, and stage 10
    //    simply has nothing to check.
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
    // STAGE 6 - The helper isLoadBalancer(id)
    // What happens : defines a small helper used later: it reports true when the CI with the given
    //                sys_id is stored in the Load Balancer class (cmdb_ci_lb) or one of its
    //                sub-classes.
    // Why          : a load balancer answers on virtual addresses on behalf of the pool members
    //                behind it; a scanned address that belongs to such a virtual IP describes a
    //                pool member, not the balancer, so the balancer must never be returned.
    // Sample       : isLoadBalancer("8c1d5e2f7a9b4c3d6e0f1a2b3c4d5e6f") = true when that sys_id is
    //                the Load Balancer "lb-sdi-core-01"; false for the ESX Server
    //                "vsdnac22xsdi009".
    // ---------------------------------------------------------------------------------------------
    function isLoadBalancer(id) {
        var lb = new GlideRecord('cmdb_ci_lb');
        // -> lb = a search on the Load Balancer class; isValid() is false when that class is not
        //    installed
        return lb.isValid() && lb.get(id);
        // -> get(id) returns true only when a load balancer with that sys_id exists
    }
    // ---------------------------------------------------------------------------------------------
    // STAGE 7 - Search the whole hardware tree for the address
    // What happens : opens a search on cmdb_ci_hardware, keeps only CIs whose ip_address field
    //                equals the scanned address, and leaves out every class on the ignore list.
    // Why          : the class-scoped search of rule 700 found nothing, so the address is now
    //                searched everywhere; the safety comes from the three checks that follow.
    // Sample       : the search on cmdb_ci_hardware for ip_address = "30.162.178.21" finds the
    //                Server "vsdnac22xsdi009" (sys_id 3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c, class
    //                cmdb_ci_server).
    // ---------------------------------------------------------------------------------------------
    var gr = new GlideRecord('cmdb_ci_hardware');
    // -> gr = a search on Hardware and every class beneath it.
    gr.addQuery('ip_address', ip);
    // -> condition added: ip_address = "30.162.178.21".
    if (ignore)
        gr.addQuery('sys_class_name', 'NOT IN', ignore);
    // -> condition added: sys_class_name NOT IN (sn_sec_cmn_unmatched_ci, sn_vul_qualys_ci,
    //    cmdb_ci_unclassed_hardware, cmdb_ci_incomplete_ip, cmdb_ci_dns_name).
    gr.query();
    // -> the search has run.
    // ---------------------------------------------------------------------------------------------
    // STAGE 8 - Require exactly one owner
    // What happens : reads the first CI, remembers its sys_id and its class, and declines when a
    //                second CI carries the same address.
    // Why          : an address answered by several CIs (a shared virtual IP, an address reused
    //                after a rebuild) is never a safe match.
    // Sample       : one row -> id = "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c", cls = "cmdb_ci_server".
    //                Two rows -> return null.
    // ---------------------------------------------------------------------------------------------
    if (!gr.next())
        return null;
    // -> no CI carries the address -> decline; the host continues to rule 730.
    var id = gr.getUniqueValue();
    // -> id = "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c".
    var cls = '' + gr.getValue('sys_class_name');
    // -> cls = "cmdb_ci_server" (the exact class of the CI found).
    if (gr.hasNext())
        return null;
    // -> a second CI with the same address is waiting in the result -> ambiguous -> decline.
    // ---------------------------------------------------------------------------------------------
    // STAGE 9 - Reject a load balancer
    // What happens : asks the helper whether the single owner is a Load Balancer CI and declines
    //                when it is.
    // Why          : a scanned address that belongs to a virtual IP describes a pool member behind
    //                the balancer, not the balancer; the findings must not land on the balancer.
    // Sample       : isLoadBalancer("3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c") = false for the Server
    //                "vsdnac22xsdi009" -> carry on; true for the Load Balancer "lb-sdi-core-01" ->
    //                return null.
    // ---------------------------------------------------------------------------------------------
    if (isLoadBalancer(id))
        return null;
    // -> for the sample the helper answers false and nothing happens.
    // ---------------------------------------------------------------------------------------------
    // STAGE 10 - Reject an owner whose class contradicts the scanned OS
    // What happens : when the OS gave a class preference, checks that the CI found sits inside that
    //                class (or one of its sub-classes) or is generically classed; any other class
    //                is a contradiction and the rule declines.
    // Why          : an ESXi scan that lands by address on a Windows Server CI is a reused address,
    //                not the same machine.
    // Sample       : pref = "cmdb_ci_esx_server"; chk.get("3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c") on
    //                the ESX Server class is false because the CI is a plain Server, but
    //                generic["cmdb_ci_server"] is true -> accepted. For a Windows Server CI both
    //                checks fail -> return null.
    // ---------------------------------------------------------------------------------------------
    if (pref) {
        var chk = new GlideRecord(pref);
        // -> chk = a search on the ESX Server class and its sub-classes.
        if (!(chk.isValid() && chk.get(id)) && !generic[cls])
            return null;
        // -> chk.get(id) is true when the CI is an ESX Server; generic[cls] is true when it is
        //    generically classed; when neither holds the CI contradicts the scan -> decline.
    }
    // ---------------------------------------------------------------------------------------------
    // STAGE 11 - Return the owner
    // ---------------------------------------------------------------------------------------------
    return id;
    // -> the sys_id "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c" goes back to the framework, which links the
    //    vulnerable item to the CI and stops evaluating later rules.
})(rule, sourceValue, sourcePayload);
