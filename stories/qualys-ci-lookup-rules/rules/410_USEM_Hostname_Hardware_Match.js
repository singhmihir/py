/* =====================================================================
   RULE 410 - USEM Hostname Hardware Match
   =====================================================================
   SAMPLE PAYLOAD (one Qualys Host Detection record) this rule is written for:
   {
     "ID": "80217765",
     "IP": "171.150.219.123",
     "TRACKING_METHOD": "IP",
     "OS": "AIX 7.3 TL3",
     "DNS": "va2ausapabw0.bankofamerica.com",
     "QG_HOSTID": "6337e0dc-007d-0002-c47d-005056a4fcd5"
   }

   sourceValue   = the DNS field  -> "va2ausapabw0.bankofamerica.com"
   sourcePayload = the whole record above (OS is read from it)

   WHY THIS RULE SITS AT ORDER 410
   Rules run from the lowest order to the highest; the first rule that
   returns a CI wins and every later rule is skipped.
   - Before it : 400 required the short name to be unique inside the class the
                 OS implies.
   - Reaches it: hosts whose CI is classed generically (Server, Computer, Unix
                 Server) or whose OS gave no class, so 400 found nothing; the
                 short name is now searched across the whole hardware tree,
                 still requiring a single owner.
   - After it  : 450 (CI named with the full FQDN) and then the IP rules (700+)
                 for hosts without a usable name.
   ===================================================================== */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // payload has no DNS -> nothing to look up
        return null;
    var full = ('' + sourceValue).trim().toLowerCase();   // "va2ausapabw0.bankofamerica.com"
    var host = full.split('.')[0];                // "va2ausapabw0"
    if (!host)
        return null;

    // Classes that must never be matched (for example unclassed or retired CI
    // classes) are listed by the administrators in the system property
    // sn_sec_cmn.ignoreCIClass. The CI identification framework may hand the
    // same list to the script as _ignoreClass; either way it ends up in
    // "ignore", e.g. "cmdb_ci_unclassed,cmdb_ci_ip_address_dns_name".
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');

    // classFor() translates the operating system text Qualys reports into the
    // CMDB class the CI should live in. Examples of what it returns:
    //   "Red Hat Enterprise Linux 9.8"                   -> cmdb_ci_linux_server
    //   "Windows Server 2016 Standard 64 bit Edition"    -> cmdb_ci_win_server
    //   "Windows 10 Enterprise"                          -> cmdb_ci_computer
    //   "VMware ESXi 7.0.3 build 24723872"               -> cmdb_ci_esx_server
    //   "AIX 7.3 TL3"                                    -> cmdb_ci_aix_server
    //   "Cisco IOS-XE / NX-OS"                           -> cmdb_ci_netgear
    //   "Ubuntu / Tiny Core Linux / Linux 2.6.x / F5 ..."-> "" (unauthenticated
    //      scans list several guesses separated by "/"; three or more guesses
    //      mean the OS is unknown, so no class is chosen)
    function classFor(os) {
        if (!os) return '';                                   // no OS reported -> no class
        var s = ('' + os).toLowerCase();                      // "VMware ESXi 7.0.3 ..." -> "vmware esxi 7.0.3 ..."
        if (s.split('/').length > 2) return '';              // "a / b / c" -> multi-guess fingerprint -> no class
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
        return '';                                            // anything else -> no class preference
    }

    var pref = classFor(sourcePayload.OS);        // "AIX 7.3 TL3" -> "cmdb_ci_aix_server"
    // Classes that say nothing about the OS; a CI in one of these never
    // contradicts the scan and is accepted.
    var generic = {cmdb_ci_hardware: 1, cmdb_ci_computer: 1, cmdb_ci_server: 1,
        cmdb_ci_unix_server: 1};

    var gr = new GlideRecord('cmdb_ci_hardware'); // the whole hardware tree
    gr.addQuery('name', host);                    // name = "va2ausapabw0"
    if (ignore)
        gr.addQuery('sys_class_name', 'NOT IN', ignore);
    gr.query();
    if (!gr.next())                               // nobody has this name -> decline
        return null;
    var id = gr.getUniqueValue();                 // the single owner, e.g. an AIX server or a generic "Server" CI
    var cls = '' + gr.getValue('sys_class_name'); // its class, e.g. "cmdb_ci_server"
    if (gr.hasNext())                             // two hardware CIs with the same short name -> never guess
        return null;
    if (pref) {
        // The unique owner must not contradict the scanned OS: it is accepted
        // when it sits inside the OS-implied class (an AIX server for an AIX
        // scan) or when it is only generically classed (a plain "Server").
        // An AIX scan landing on a Windows server is rejected here.
        var chk = new GlideRecord(pref);
        if (!(chk.isValid() && chk.get(id)) && !generic[cls])
            return null;
    }
    return id;
})(rule, sourceValue, sourcePayload);
