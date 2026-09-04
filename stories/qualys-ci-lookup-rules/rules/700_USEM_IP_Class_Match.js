/* =================================================================================================
   RULE 700 - USEM IP Class Match
   =================================================================================================
   Match by IP address, inside the class the OS implies. An address is the least trustworthy
   identifier (addresses move between machines and are shared by load balancers), so it is used only
   when the host has no serial and no usable name, and only when exactly one CI of the agreed class
   carries it.

   SAMPLE PAYLOAD (one Qualys Host Detection record, used in every example below)
   {
     "ID": "83047621",
     "IP": "30.162.178.21",
     "TRACKING_METHOD": "IP",
     "OS": "VMware ESXi 7.0.3 build 24723872"
   }

   sourceValue   = the IP field -> "30.162.178.21"
   sourcePayload = the whole record; the rule also reads the OS from it
   Expected for the sample: the ESX Server CI whose ip_address is "30.162.178.21", for example
   "vsdnac22xsdi009"; a load balancer or a Windows CI with the same address is outside the class and
   cannot be picked.

   WHY THIS RULE SITS AT ORDER 700
   Rules run from the lowest order to the highest; the first rule that returns a CI wins and the
   later rules are skipped. A rule that returns null passes the host on.
   - Before it : all serial and name rules (175 to 450). The sample has no DNS name, so every name
                 rule declined.
   - Reaches it: DNS-less hosts, typically ESXi management interfaces and appliances (89 of the
                 21,000 hosts in the reference extract).
   - After it  : 705 searches the address across all hardware with extra safety checks; 730 and 740
                 resolve it through adapters and the layered IP records.
   ================================================================================================= */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // nothing to look up -> null = "no match from this rule"
        return null;
    var ip = ('' + sourceValue).trim();           // "30.162.178.21"
    if (!ip || ip.indexOf('127.') == 0 || ip.indexOf('169.254.') == 0)   // loopback and link-local identify nothing
        return null;
    // CI classes that must never be matched (placeholder and technical classes). Administrators
    // keep the list in the property sn_sec_cmn.ignoreCIClass; the framework may pass the same list
    // in as _ignoreClass.
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');
    // -> ignore =
    //    "sn_sec_cmn_unmatched_ci,sn_vul_qualys_ci,cmdb_ci_unclassed_hardware,cmdb_ci_incomplete_ip,cmdb_ci_dns_name"
    // ====== STAGE 1: Work out the CMDB class from the scanned OS =================================
    // What   : classFor() maps the OS text to the class the CI should be in; the search that
    //          follows is limited to that class and its sub-classes.
    // Why    : evidence is trusted only when it lands in a class that agrees with the scanned OS. A
    //          Red Hat host must resolve to a Linux Server CI, never to a Windows Server that
    //          happens to carry the same value.
    // Sample : classFor("VMware ESXi 7.0.3 build 24723872") -> "cmdb_ci_esx_server" (ESX Server).
    //          An unknown or multi-guess OS gives "" and this rule declines so that rule 705 (all
    //          hardware, no class) takes over.
    // =============================================================================================
    // classFor() turns the OS text Qualys reports into the CMDB class the CI lives in. Examples:
    //   "Red Hat Enterprise Linux 9.8"                              -> cmdb_ci_linux_server
    //   "Windows Server 2016 Standard 64 bit Edition Version 1607"  -> cmdb_ci_win_server
    //   "Windows 10 Enterprise 64 bit Edition Version 22H2"         -> cmdb_ci_computer
    //   "VMware ESXi 7.0.3 build 24723872"                          -> cmdb_ci_esx_server
    //   "AIX 7.3 TL3"                                               -> cmdb_ci_aix_server
    //   "Cisco NX-OS 9.3(8)"                                        -> cmdb_ci_netgear
    //   "Ubuntu / Tiny Core Linux / Linux 2.6.x / IBM ASM / HP StoreOnce / F5 Networks Big-IP / Cisco IOS Software"
    //       -> "" : three or more guesses separated by "/" means the unauthenticated scan
    //               could not identify the OS, so no class is chosen
    function classFor(os) {
        if (!os) return '';
        var s = ('' + os).toLowerCase();
        if (s.split('/').length > 2) return '';                  // multi-guess fingerprint
        if (s.indexOf('esx') != -1) return 'cmdb_ci_esx_server';
        if (s.indexOf('windows') != -1)
            return s.indexOf('server') != -1 ? 'cmdb_ci_win_server' : 'cmdb_ci_computer';
        if (s.indexOf('aix') != -1) return 'cmdb_ci_aix_server';
        if (s.indexOf('solaris') != -1 || s.indexOf('sunos') != -1) return 'cmdb_ci_solaris_server';
        if (s.indexOf('hp-ux') != -1) return 'cmdb_ci_hpux_server';
        if (s.indexOf('netapp') != -1 || s.indexOf('ontap') != -1) return 'cmdb_ci_storage_server';
        if (s.indexOf('printer') != -1 || s.indexOf('laserjet') != -1 || s.indexOf('jetdirect') != -1) return 'cmdb_ci_printer';
        if (s.indexOf('red hat') != -1 || s.indexOf('linux') != -1 || s.indexOf('centos') != -1 ||
            s.indexOf('ubuntu') != -1 || s.indexOf('suse') != -1 || s.indexOf('debian') != -1 ||
            s.indexOf('fedora') != -1 || s.indexOf('euleros') != -1 ||
            s.indexOf('oracle enterprise') != -1 || s.indexOf('amazon') != -1) return 'cmdb_ci_linux_server';
        if (s.indexOf('nx-os') != -1 || s.indexOf('catos') != -1 || s.indexOf('cisco') != -1) return 'cmdb_ci_netgear';
        return '';
    }
    var pref = classFor(sourcePayload.OS);
    // -> pref = "cmdb_ci_esx_server"
    if (!pref)
        return null;
    // ====== STAGE 2: Search that class for the address ===========================================
    // What   : opens a search on the class chosen (its sub-classes included), keeps only CIs whose
    //          ip_address equals the scanned address, and leaves out the ignored classes.
    // Why    : inside the agreed class an address is reasonably safe: a virtual IP of a load
    //          balancer, or a Windows machine that inherited the address, sits outside the ESX
    //          Server class and never appears.
    // Sample : the search on cmdb_ci_esx_server for ip_address = "30.162.178.21" finds the ESX
    //          Server "vsdnac22xsdi009".
    // =============================================================================================
    var gr = new GlideRecord(pref);           // the ESX Server class and its sub-classes
    if (!gr.isValid())                            // class not installed -> decline rather than fail
        return null;
    gr.addQuery('ip_address', ip);
    if (ignore)
        gr.addQuery('sys_class_name', 'NOT IN', ignore);
    // ====== STAGE 3: Decide: exactly one CI, or decline ==========================================
    // What   : runs the search, reads the first CI and accepts it only when no second CI is in the
    //          result.
    // Why    : every finding of this host is linked to the CI returned; a wrong CI sends findings
    //          to the wrong owner. Two CIs sharing the value is an ambiguity, so the rule declines
    //          and a later rule with different evidence may still resolve the host.
    // Sample : one CI (the ESX Server "vsdnac22xsdi009") -> return
    //          "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c". No CI -> return null and rule 705 gets its turn.
    //          Two CIs -> two ESX Servers carrying "30.162.178.21" (an address reused after a
    //          rebuild) -> return null.
    // =============================================================================================
    gr.query();
    if (!gr.next())                               // empty result -> decline
        return null;
    var match = gr.getUniqueValue();
    // -> match = "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c", the sys_id of the ESX Server "vsdnac22xsdi009"
    if (gr.hasNext())                             // a second CI carries the same value -> never guess
        return null;
    return match;
    // -> the framework links the vulnerable item to this CI and stops evaluating later rules
})(rule, sourceValue, sourcePayload);
