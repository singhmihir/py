/* =====================================================================
   RULE 300 - USEM Hostname Domain Class Match
   =====================================================================
   SAMPLE PAYLOAD (one Qualys Host Detection record) this rule is written for:
   {
     "ID": "35832680",
     "IP": "171.128.225.96",
     "TRACKING_METHOD": "AGENT",
     "OS": "Red Hat Enterprise Linux 9.8",
     "DNS": "ah-1047132-001.sdi.corp.bankofamerica.com",
     "QG_HOSTID": "633769a4-0139-0002-e352-005056bf41ea"
   }

   sourceValue   = the DNS field  -> "ah-1047132-001.sdi.corp.bankofamerica.com"
   sourcePayload = the whole record above (OS and IP are read from it)

   WHY THIS RULE SITS AT ORDER 300
   Rules run from the lowest order to the highest; the first rule that
   returns a CI wins and every later rule is skipped.
   - Before it : 250/260 looked for the exact FQDN in the fqdn field of the CI.
   - Reaches it: hosts whose CI does not store the full FQDN but is named with
                 the short hostname and carries the domain elsewhere
                 (dns_domain, or an fqdn built from the same name). The same
                 short name registered in another domain can never be picked.
   - After it  : 310 repeats the search across all hardware; 350 uses the
                 layered DNS records; 400/410 accept a unique short name without
                 any domain evidence.
   ===================================================================== */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // payload has no DNS -> nothing to look up
        return null;
    var full = ('' + sourceValue).trim().toLowerCase();   // "ah-1047132-001.sdi.corp.bankofamerica.com"
    var dot = full.indexOf('.');                  // position of the first dot -> 14
    if (dot < 1)                                  // no dot, or a leading dot -> no domain to check, decline
        return null;
    var host = full.substring(0, dot);            // "ah-1047132-001"
    var domain = full.substring(dot + 1);         // "sdi.corp.bankofamerica.com"
    var ip = sourcePayload.IP ? '' + sourcePayload.IP : '';   // "171.128.225.96" - tie-breaker only

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

    // pickCombo() searches one table for CIs whose name is the short hostname
    // and keeps only those whose own domain information agrees with the
    // scanned domain.
    function pickCombo(table) {
        var gr = new GlideRecord(table);
        if (!gr.isValid())
            return null;
        gr.addQuery('name', host);                // name = "ah-1047132-001" (CMDB names compare case-insensitively)
        if (ignore)
            gr.addQuery('sys_class_name', 'NOT IN', ignore);
        gr.query();
        var good = [];                            // CIs whose domain evidence confirms the scanned domain
        var ipHits = [];                          // those of them that also carry the scanned IP
        while (gr.next()) {
            var cifqdn = ('' + gr.getValue('fqdn')).toLowerCase();        // e.g. "ah-1047132-001.sdi.corp.bankofamerica.com"
            var cidom = ('' + gr.getValue('dns_domain')).toLowerCase();   // e.g. "sdi.corp.bankofamerica.com"
            // The CI confirms the domain when its fqdn equals the scanned name,
            // or its dns_domain equals the scanned domain, or its fqdn starts
            // with "hostname." and contains the scanned domain.
            if (cifqdn == full || cidom == domain ||
                (cifqdn && cifqdn.indexOf(host + '.') == 0 && cifqdn.indexOf(domain) > 0)) {
                good.push(gr.getUniqueValue());
                if (ip && gr.getValue('ip_address') == ip)
                    ipHits.push(gr.getUniqueValue());
            }
        }
        if (good.length == 1)                     // one CI has the name AND the domain -> match
            return good[0];
        if (good.length > 1 && ipHits.length == 1)   // several: accept only the one the scanned IP confirms
            return ipHits[0];
        return null;                              // none, or several without an IP tie-break -> decline
    }

    var pref = classFor(sourcePayload.OS);        // "Red Hat Enterprise Linux 9.8" -> "cmdb_ci_linux_server"
    if (!pref)                                    // no class evidence -> rule 310 (all hardware) takes over
        return null;
    return pickCombo(pref);                       // hostname + domain inside the Linux server class
})(rule, sourceValue, sourcePayload);
