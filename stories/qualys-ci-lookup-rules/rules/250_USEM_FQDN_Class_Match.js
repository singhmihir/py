/* =====================================================================
   RULE 250 - USEM FQDN Class Match
   =====================================================================
   SAMPLE PAYLOAD (one Qualys Host Detection record) this rule is written for:
   {
     "ID": "83047612",
     "IP": "30.206.199.36",
     "TRACKING_METHOD": "IP",
     "OS": "VMware ESXi 7.0.3 build 24723872",
     "DNS": "vsdnac22xsdi004.sdi.corp.bankofamerica.com"
   }

   sourceValue   = the DNS field  -> "vsdnac22xsdi004.sdi.corp.bankofamerica.com"
   sourcePayload = the whole record above (OS and IP are read from it)

   WHY THIS RULE SITS AT ORDER 250
   Rules run from the lowest order to the highest; the first rule that
   returns a CI wins and every later rule is skipped.
   - Before it : 175/180 (serial numbers) and 200 (Cisco phone labels) found
                 nothing.
   - Reaches it: every host with a dotted DNS name (a fully qualified domain
                 name) - the bulk of the Qualys feed. This is the first
                 name-based rule because an exact FQDN stored on the CI is the
                 most precise name evidence there is.
   - After it  : 260 repeats the exact-FQDN search across all hardware classes;
                 300+ fall back to hostname + domain, then to the short hostname
                 alone.
   ===================================================================== */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // payload has no DNS -> nothing to look up
        return null;
    var fqdn = ('' + sourceValue).trim().toLowerCase();   // "vsdnac22xsdi004.sdi.corp.bankofamerica.com"
    // A bare label such as "vsdnac22xsdi004" carries no domain; the hostname
    // rules (400 and above) look after those.
    if (fqdn.indexOf('.') == -1)                  // no dot in the name -> decline
        return null;
    var ip = sourcePayload.IP ? '' + sourcePayload.IP : '';   // "30.206.199.36" - used only to break ties

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

    // pickFqdn() searches one table for CIs whose fqdn field equals the scanned
    // name and decides whether the answer is safe to use.
    function pickFqdn(table) {
        var gr = new GlideRecord(table);
        if (!gr.isValid())                        // class missing on this instance -> decline
            return null;
        gr.addQuery('fqdn', fqdn);                // fqdn = "vsdnac22xsdi004.sdi.corp.bankofamerica.com"
        if (ignore)
            gr.addQuery('sys_class_name', 'NOT IN', ignore);
        gr.query();
        var ids = [];                             // every CI carrying this FQDN
        var ipHits = [];                          // those of them whose ip_address is also the scanned IP
        while (gr.next()) {
            ids.push(gr.getUniqueValue());
            if (ip && gr.getValue('ip_address') == ip)
                ipHits.push(gr.getUniqueValue());
        }
        if (ids.length == 1)                      // one CI carries the FQDN -> match
            return ids[0];
        // Two or more CIs carry the same FQDN (a retired and a rebuilt server, a
        // cluster alias ...). Accept only when the scanned IP points at exactly
        // one of them, otherwise decline and let a later rule decide.
        if (ids.length > 1 && ipHits.length == 1)
            return ipHits[0];
        return null;
    }

    var pref = classFor(sourcePayload.OS);        // "VMware ESXi 7.0.3 build 24723872" -> "cmdb_ci_esx_server"
    if (!pref)                                    // no class evidence -> rule 260 (all hardware) takes over
        return null;
    return pickFqdn(pref);                        // exact FQDN inside the ESX server class only
})(rule, sourceValue, sourcePayload);
