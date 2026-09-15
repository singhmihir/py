/* USEM Serial Number Class Match
   -------------------------------------------------------------------------------------------------
   Serial number first. A serial stays with a machine for its whole life while names and addresses
   get reused, so it is the strongest identifier Qualys gives us. This rule trusts it only inside
   the CMDB class the scanned OS points at.

   Sample payload (one Qualys host record, used in every note below)
   {
     "ID": "35832680",
     "IP": "171.128.225.96",
     "TRACKING_METHOD": "AGENT",
     "OS": "Red Hat Enterprise Linux 9.8",
     "DNS": "ah-1047132-001.sdi.corp.bankofamerica.com",
     "SERIAL_NUMBER": "VMware-42 1a 9c 3f 7d 2e 61 b8-55 04 e2 91 6a 27 c3 08"
   }
   Input  : sourceValue is the SERIAL_NUMBER field, "VMware-42 1a 9c 3f 7d 2e 61 b8-55 04 e2 91 6a
            27 c3 08"; the rule also reads the OS from sourcePayload.
   Returns: the sys_id of the one CI of that class whose serial_number equals the scanned serial;
            null when none or more than one carries it.
   Sample : the Linux Server CI "ah-1047132-001", whose serial_number holds the same serial; null
            when no Linux Server carries it, or two do.

   Place in the chain (the first rule to return a CI wins; a null hands the host to the next rule)
   Before : nothing custom runs before this rule.
   Reaches: every host that reports a serial. In our feed that is the Cloud Agent hosts; the
            unauthenticated network scans rarely carry one.
   After  : USEM Serial Number Hardware Match repeats the search across the whole hardware tree for
            hosts whose OS gives no class or whose CI is classed differently.
   ------------------------------------------------------------------------------------------------- */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // nothing to look up
        return null;
    var serial = ('' + sourceValue).trim();       // "VMware-42 1a 9c 3f 7d 2e 61 b8-55 04 e2 91 6a 27 c3 08"
    // Placeholder serials that vendors ship on thousands of machines ("To be filled by O.E.M.",
    // "0123456789") would match dozens of CIs, so they are refused, as is anything shorter than
    // four characters. The sample serial is neither, so it goes through.
    var junk = ',0,none,n/a,na,unknown,empty,not specified,not available,no serial,' +
        'default string,to be filled by o.e.m.,system serial number,chassis serial number,' +
        '0123456789,1234567890,';
    if (serial.length < 4 || junk.indexOf(',' + serial.toLowerCase() + ',') != -1)
        return null;
    // Classes that must never be matched (placeholder and technical CIs); the list lives in the
    // property sn_sec_cmn.ignoreCIClass and the framework may pass it in as _ignoreClass.
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');
    // -- Class from the scanned OS ----------------------------------------------------------------
    // The search below stays inside the class the OS points at (sub-classes included), so a Red Hat
    // host can only land on a Linux Server and a Windows Server carrying the same value is never
    // seen. An unknown or multi-guess OS gives no class and the rule declines; the hardware-wide
    // serial match takes over.
    // Sample: classFor("Red Hat Enterprise Linux 9.8") gives Linux Server, so pref is
    //         cmdb_ci_linux_server and the search below runs on that class.
    // classFor() maps the OS text Qualys reports to the CMDB class the CI should be in, e.g. "Red
    // Hat Enterprise Linux 9.8" is a Linux Server, "Windows Server 2016 Standard" a Windows Server
    // and "VMware ESXi 7.0.3" an ESX Server. A string of guesses separated by "/" comes from an
    // unauthenticated scan that could not identify the OS; three or more guesses give no class at
    // all.
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
    if (!pref)
        return null;
    // -- Serial search inside that class, one CI only ---------------------------------------------
    // Exact match on serial_number with the ignored classes left out. The CI is accepted only when
    // it is the single row: two CIs sharing a serial do happen (a cloned virtual machine, a serial
    // typed on the wrong record) and nothing here can tell them apart, so the rule declines and a
    // later rule with different evidence gets its chance.
    // Sample: the search on cmdb_ci_linux_server for serial_number "VMware-42 1a 9c 3f 7d 2e 61
    //         b8-55 04 e2 91 6a 27 c3 08" finds the Linux Server "ah-1047132-001" and no second
    //         row, so its sys_id is returned. A Windows Server with the same serial is outside the
    //         class and never appears.
    var gr = new GlideRecord(pref);           // the class chosen and its sub-classes
    if (!gr.isValid())                            // class not installed here, decline
        return null;
    gr.addQuery('serial_number', serial);
    if (ignore)
        gr.addQuery('sys_class_name', 'NOT IN', ignore);
    gr.query();
    if (!gr.next())
        return null;
    var match = gr.getUniqueValue();
    if (gr.hasNext())                             // a second CI carries the same value, never guess
        return null;
    return match;
})(rule, sourceValue, sourcePayload);
