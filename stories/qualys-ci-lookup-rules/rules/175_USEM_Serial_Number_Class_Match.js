/* =====================================================================
   RULE 175 - USEM Serial Number Class Match
   =====================================================================
   SAMPLE PAYLOAD (one Qualys Host Detection record) this rule is written for:
   {
     "ID": "35832680",
     "IP": "171.128.225.96",
     "TRACKING_METHOD": "AGENT",
     "OS": "Red Hat Enterprise Linux 9.8",
     "DNS": "ah-1047132-001.sdi.corp.bankofamerica.com",
     "SERIAL_NUMBER": "VMware-42 1a 9c 3f 7d 2e 61 b8-55 04 e2 91 6a 27 c3 08"
   }

   sourceValue   = the SERIAL_NUMBER field  -> "VMware-42 1a 9c 3f 7d 2e 61 b8-55 04 e2 91 6a 27 c3 08"
   sourcePayload = the whole record above (OS is read from it)

   WHY THIS RULE SITS AT ORDER 175
   Rules run from the lowest order to the highest; the first rule that
   returns a CI wins and every later rule is skipped.
   - Before it : nothing custom; this is the very first USEM rule because a
                 serial number is the most unique identifier a machine has -
                 stronger than any name or address.
   - Reaches it: every Qualys host that reports a SERIAL_NUMBER (today only
                 hosts scanned by an authenticated agent report one).
   - After it  : 180 tries the same serial across all hardware classes when the
                 OS gives no class or the CI is classed differently; 200 and
                 above move on to names and addresses.
   ===================================================================== */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // payload has no SERIAL_NUMBER -> nothing to look up
        return null;
    var serial = ('' + sourceValue).trim();       // "VMware-42 1a 9c ... c3 08" (spaces at both ends removed)

    // Vendors ship placeholder serials that thousands of machines share. Any of
    // these would match dozens of CIs, so they are rejected before searching:
    var junk = ',0,none,n/a,na,unknown,empty,not specified,not available,no serial,' +
        'default string,to be filled by o.e.m.,system serial number,chassis serial number,' +
        '0123456789,1234567890,';
    // "vmware-42 1a ..." is 52 characters and not in the junk list -> carry on
    // ("N/A" -> ",n/a," is found in the list -> rejected; "12" -> too short -> rejected)
    if (serial.length < 4 || junk.indexOf(',' + serial.toLowerCase() + ',') != -1)
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

    // Stage 1 of serial matching: search only inside the class the OS implies,
    // so the class evidence and the serial evidence must agree.
    var pref = classFor(sourcePayload.OS);        // "Red Hat Enterprise Linux 9.8" -> "cmdb_ci_linux_server"
    if (!pref)                                    // unknown or multi-guess OS -> rule 180 (all hardware) takes over
        return null;
    var gr = new GlideRecord(pref);               // search the Linux server class (and its sub-classes)
    if (!gr.isValid())                            // class does not exist on this instance -> decline
        return null;
    gr.addQuery('serial_number', serial);         // serial_number = "VMware-42 1a 9c ... c3 08"
    if (ignore)
        gr.addQuery('sys_class_name', 'NOT IN', ignore);   // never pick a CI of an ignored class

    gr.query();                                   // run the search
    if (!gr.next())                               // no CI at all -> this rule declines, the next rule gets its turn
        return null;
    var match = gr.getUniqueValue();              // sys_id of the CI found, e.g. "b5f1c2d3e4f5a6b7c8d9e0f1a2b3c4d5"
    if (gr.hasNext())                             // a second CI carries the same value -> ambiguous, never guess
        return null;
    return match;                                 // exactly one CI -> this is the match
})(rule, sourceValue, sourcePayload);
