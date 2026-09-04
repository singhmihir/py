/* =================================================================================================
   RULE 705 - USEM IP Hardware Match
   =================================================================================================
   Match by IP address anywhere in the hardware tree, with two extra safety checks: the CI must not
   be a load balancer, and its class must not contradict the scanned OS.

   SAMPLE PAYLOAD (one Qualys Host Detection record, used in every example below)
   {
     "ID": "83047621",
     "IP": "30.162.178.21",
     "TRACKING_METHOD": "IP",
     "OS": "VMware ESXi 7.0.3 build 24723872"
   }

   sourceValue   = the IP field -> "30.162.178.21"
   sourcePayload = the whole record; the rule also reads the OS from it
   Expected for the sample: the one hardware CI whose ip_address is "30.162.178.21", accepted when
   it is an ESX Server or generically classed; rejected when it is a Load Balancer or a CI of a
   contradicting class such as Windows Server.

   WHY THIS RULE SITS AT ORDER 705
   Rules run from the lowest order to the highest; the first rule that returns a CI wins and the
   later rules are skipped. A rule that returns null passes the host on.
   - Before it : 700 required the address to belong to one CI of the OS-implied class.
   - Reaches it: DNS-less hosts whose CI is classed generically (Server) or whose OS gave no class.
   - After it  : 730 (address on a network adapter) and 740 (layered IP Address records).
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
    // ====== STAGE 1: Work out the class the scanned OS implies (a preference, not a requirement) =
    // What   : classFor() maps the OS text to a class; here it is only used at the end to reject a
    //          CI whose class contradicts the scan.
    // Why    : this rule searches the whole hardware tree, so the class check is the safeguard
    //          against a namesake of a different type.
    // Sample : classFor("VMware ESXi 7.0.3 build 24723872") -> "cmdb_ci_esx_server" (ESX Server);
    //          "" when the OS is unknown, and then no class check is made.
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
    // Classes that say nothing about the OS (a CI loaded as a plain Server before discovery refined
    // it); a CI in one of these never contradicts the scan.
    var generic = {cmdb_ci_hardware: 1, cmdb_ci_computer: 1, cmdb_ci_server: 1,
        cmdb_ci_unix_server: 1};
    // isLoadBalancer(id) is true when the CI is a Load Balancer. A balancer answers on virtual
    // addresses on behalf of its pool members, so it is never the host that was scanned.
    function isLoadBalancer(id) {
        var lb = new GlideRecord('cmdb_ci_lb');
        return lb.isValid() && lb.get(id);
    }
    // ====== STAGE 2: Search the whole hardware tree for the address ==============================
    // What   : opens a search on cmdb_ci_hardware, keeps only CIs whose ip_address equals the
    //          scanned address, and leaves out the ignored classes.
    // Why    : the class-scoped search of rule 700 found nothing, so the address is searched
    //          everywhere; the safety comes from the three checks that follow.
    // Sample : the search on cmdb_ci_hardware for ip_address = "30.162.178.21" finds the Server
    //          "vsdnac22xsdi009" (class cmdb_ci_server).
    // =============================================================================================
    var gr = new GlideRecord('cmdb_ci_hardware');// Hardware and every class beneath it
    gr.addQuery('ip_address', ip);
    if (ignore)
        gr.addQuery('sys_class_name', 'NOT IN', ignore);
    // ====== STAGE 3: Require exactly one owner ===================================================
    // What   : reads the first CI, remembers its sys_id and class, and declines when a second CI
    //          carries the same value.
    // Why    : an address answered by several CIs (a shared virtual IP, an address reused after a
    //          rebuild) is never a safe match.
    // Sample : one row -> id = "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c", cls = "cmdb_ci_server". No row
    //          -> null and rule 730 gets its turn. Two rows -> null.
    // =============================================================================================
    gr.query();
    if (!gr.next())
        return null;
    var id = gr.getUniqueValue();
    var cls = '' + gr.getValue('sys_class_name');   // e.g. "cmdb_ci_server"
    if (gr.hasNext())                             // a second CI carries the same value -> never guess
        return null;
    // ====== STAGE 4: Reject a load balancer ======================================================
    // What   : declines when the single owner is a Load Balancer CI.
    // Why    : a scanned address that belongs to a virtual IP describes a pool member behind the
    //          balancer, not the balancer.
    // Sample : isLoadBalancer("3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c") = false for the Server
    //          "vsdnac22xsdi009" -> carry on; true for the Load Balancer "lb-sdi-core-01" -> null.
    // =============================================================================================
    if (isLoadBalancer(id))
        return null;
    // ====== STAGE 5: Reject an owner whose class contradicts the scanned OS ======================
    // What   : when the OS gave a class, the CI found must sit inside that class (sub-classes
    //          included) or be generically classed; any other class is a contradiction and the rule
    //          declines.
    // Why    : a host that resolves to a Windows Server CI by name or address is a namesake or a
    //          reused address, not the same machine; its findings would go to the wrong owner.
    // Sample : pref = "cmdb_ci_esx_server"; a plain Server passes through
    //          generic["cmdb_ci_server"]; a Windows Server CI fails both checks -> null.
    // =============================================================================================
    if (pref) {
        var chk = new GlideRecord(pref);
        if (!(chk.isValid() && chk.get(id)) && !generic[cls])
            return null;
    }
    return id;
    // -> the framework links the vulnerable item to this CI and stops evaluating later rules
})(rule, sourceValue, sourcePayload);
