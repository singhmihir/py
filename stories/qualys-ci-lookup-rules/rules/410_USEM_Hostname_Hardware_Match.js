/* =================================================================================================
   RULE 410 - USEM Hostname Hardware Match
   =================================================================================================
   Match by the short hostname anywhere in the hardware tree, with a check that the CI found does
   not contradict the scanned OS. Second short-name stage, for CIs classed generically (Server,
   Computer, UNIX Server) or differently from the OS.

   SAMPLE PAYLOAD (one Qualys Host Detection record, used in every example below)
   {
     "ID": "80217765",
     "IP": "171.150.219.123",
     "TRACKING_METHOD": "IP",
     "OS": "AIX 7.3 TL3",
     "DNS": "va2ausapabw0.bankofamerica.com",
     "QG_HOSTID": "6337e0dc-007d-0002-c47d-005056a4fcd5"
   }

   sourceValue   = the DNS field -> "va2ausapabw0.bankofamerica.com"
   sourcePayload = the whole record; the rule also reads the OS from it
   Expected for the sample: the one hardware CI named "va2ausapabw0"; accepted when it is an AIX
   Server or a generically classed Server, rejected when it is, say, a Windows Server.

   WHY THIS RULE SITS AT ORDER 410
   Rules run from the lowest order to the highest; the first rule that returns a CI wins and the
   later rules are skipped. A rule that returns null passes the host on.
   - Before it : 400 required the short name to be unique inside the class the OS implies.
   - Reaches it: hosts whose CI is classed generically (Server, Computer, UNIX Server) or whose OS
                 gave no class.
   - After it  : 450 (CI named with the full FQDN) and then the IP rules (700 and above) for hosts
                 without a usable name.
   ================================================================================================= */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // nothing to look up -> null = "no match from this rule"
        return null;
    var full = ('' + sourceValue).trim().toLowerCase();   // "va2ausapabw0.bankofamerica.com"
    var host = full.split('.')[0];                // "va2ausapabw0"
    if (!host)
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
    // Sample : classFor("AIX 7.3 TL3") -> "cmdb_ci_aix_server" (AIX Server); "" when the OS is
    //          unknown, and then no class check is made.
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
    // -> pref = "cmdb_ci_aix_server"
    // Classes that say nothing about the OS (a CI loaded as a plain Server before discovery refined
    // it); a CI in one of these never contradicts the scan.
    var generic = {cmdb_ci_hardware: 1, cmdb_ci_computer: 1, cmdb_ci_server: 1,
        cmdb_ci_unix_server: 1};
    // ====== STAGE 2: Search the whole hardware tree for the short name ===========================
    // What   : opens a search on cmdb_ci_hardware, keeps only CIs whose name equals the short
    //          hostname, and leaves out the ignored classes.
    // Why    : the class-scoped search of rule 400 found nothing, so the name is searched
    //          everywhere; the safety comes from the two checks that follow.
    // Sample : the search on cmdb_ci_hardware for name = "va2ausapabw0" finds the Server
    //          "va2ausapabw0" (class cmdb_ci_server).
    // =============================================================================================
    var gr = new GlideRecord('cmdb_ci_hardware');// Hardware and every class beneath it
    gr.addQuery('name', host);
    if (ignore)
        gr.addQuery('sys_class_name', 'NOT IN', ignore);
    // ====== STAGE 3: Require exactly one owner ===================================================
    // What   : reads the first CI, remembers its sys_id and class, and declines when a second CI
    //          carries the same value.
    // Why    : two hardware CIs with one short name (a test and a production machine, a retired and
    //          a rebuilt one) can never be told apart by the name alone.
    // Sample : one row -> id = "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c", cls = "cmdb_ci_server". No row
    //          -> null and rule 450 gets its turn. Two rows -> null.
    // =============================================================================================
    gr.query();
    if (!gr.next())
        return null;
    var id = gr.getUniqueValue();
    var cls = '' + gr.getValue('sys_class_name');   // e.g. "cmdb_ci_server"
    if (gr.hasNext())                             // a second CI carries the same value -> never guess
        return null;
    // ====== STAGE 4: Reject an owner whose class contradicts the scanned OS ======================
    // What   : when the OS gave a class, the CI found must sit inside that class (sub-classes
    //          included) or be generically classed; any other class is a contradiction and the rule
    //          declines.
    // Why    : a host that resolves to a Windows Server CI by name or address is a namesake or a
    //          reused address, not the same machine; its findings would go to the wrong owner.
    // Sample : pref = "cmdb_ci_aix_server"; a plain Server passes through
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
