/* =====================================================================
   RULE 700 - USEM IP Class Match
   =====================================================================
   SAMPLE PAYLOAD (one Qualys Host Detection record) this rule is written for:
   {
     "ID": "83047621",
     "IP": "30.162.178.21",
     "TRACKING_METHOD": "IP",
     "OS": "VMware ESXi 7.0.3 build 24723872"
   }

   sourceValue   = the IP field  -> "30.162.178.21"
   sourcePayload = the whole record above (OS is read from it)

   WHY THIS RULE SITS AT ORDER 700
   Rules run from the lowest order to the highest; the first rule that
   returns a CI wins and every later rule is skipped.
   - Before it : all serial and name rules (175-450) - an IP address is only
                 used when the host has no serial and no usable DNS name.
   - Reaches it: DNS-less hosts (typically ESXi management interfaces and
                 appliances; 89 of the 21,000 hosts in the reference extract).
                 An address is accepted only when exactly one CI of the
                 OS-implied class carries it.
   - After it  : 705 searches the address across all hardware with extra safety
                 checks, 730/740 resolve it through adapters and the layered IP
                 records.
   ===================================================================== */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // payload has no IP -> nothing to look up
        return null;
    var ip = ('' + sourceValue).trim();           // "30.162.178.21"
    // Loopback (127.x) and link-local (169.254.x) addresses are the same on
    // every machine and can never identify one CI.
    if (!ip || ip.indexOf('127.') == 0 || ip.indexOf('169.254.') == 0)
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

    // IP is the least trustworthy identifier (addresses move between machines),
    // so this first stage insists on the class the OS implies.
    var pref = classFor(sourcePayload.OS);        // "VMware ESXi 7.0.3 ..." -> "cmdb_ci_esx_server"
    if (!pref)                                    // no class evidence -> rule 705 (all hardware) takes over
        return null;
    var gr = new GlideRecord(pref);
    if (!gr.isValid())
        return null;
    gr.addQuery('ip_address', ip);                // ip_address = "30.162.178.21" inside the ESX server class
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
