/* =====================================================================
   RULE 400 - USEM Hostname Class Match
   =====================================================================
   SAMPLE PAYLOAD (one Qualys Host Detection record) this rule is written for:
   {
     "ID": "35850078",
     "IP": "30.143.70.11",
     "TRACKING_METHOD": "IP",
     "OS": "Windows Server 2016 Standard 64 bit Edition Version 1607",
     "DNS": "wsaoi01zeapd1.sdi.corp.bankofamerica.com",
     "NETBIOS": "WSAOI01ZEAPD1"
   }

   sourceValue   = the DNS field  -> "wsaoi01zeapd1.sdi.corp.bankofamerica.com"
   sourcePayload = the whole record above (OS is read from it)

   WHY THIS RULE SITS AT ORDER 400
   Rules run from the lowest order to the highest; the first rule that
   returns a CI wins and every later rule is skipped.
   - Before it : 250-350 needed domain evidence on the CI (fqdn, dns_domain or
                 the layered DNS records).
   - Reaches it: hosts whose CI carries only a short name and no domain
                 information at all. Because the domain cannot be checked, the
                 rule compensates by insisting on the class the OS implies and
                 on the name being unique inside that class.
   - After it  : 410 repeats the short-name search across all hardware with a
                 class sanity check; 450 handles CIs named with the full FQDN.
   ===================================================================== */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // payload has no DNS -> nothing to look up
        return null;
    var full = ('' + sourceValue).trim().toLowerCase();   // "wsaoi01zeapd1.sdi.corp.bankofamerica.com"
    var host = full.split('.')[0];                // "wsaoi01zeapd1" (also works for a bare label with no dots)
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

    // Short name inside the OS-implied class only; the class agreement is the
    // safeguard that replaces the missing domain evidence.
    var pref = classFor(sourcePayload.OS);        // "Windows Server 2016 ..." -> "cmdb_ci_win_server"
    if (!pref)                                    // no class evidence -> rule 410 (all hardware) takes over
        return null;
    var gr = new GlideRecord(pref);
    if (!gr.isValid())
        return null;
    // CMDB names compare case-insensitively, so "wsaoi01zeapd1" also finds "WSAOI01ZEAPD1"
    gr.addQuery('name', host);                    // name = "wsaoi01zeapd1"
    if (ignore)
        gr.addQuery('sys_class_name', 'NOT IN', ignore);

    gr.query();                                   // run the search
    if (!gr.next())                               // no CI at all -> this rule declines, the next rule gets its turn
        return null;
    var match = gr.getUniqueValue();              // sys_id of the CI found, e.g. "b5f1c2d3e4f5a6b7c8d9e0f1a2b3c4d5"
    if (gr.hasNext())                             // a second CI carries the same value -> ambiguous, never guess
        return null;
    return match;                                 // exactly one CI -> this is the match
})(rule, sourceValue, sourcePayload);
