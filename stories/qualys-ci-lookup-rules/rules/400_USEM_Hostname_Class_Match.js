/* USEM Hostname Class Match
   -------------------------------------------------------------------------------------------------
   The short hostname alone, inside the class the scanned OS points at. For CIs that carry only a
   short name and no domain information; the agreement between CI class and scanned OS stands in for
   the missing domain evidence.

   Input  : sourceValue is the DNS field; the rule also reads the OS from sourcePayload.
   Returns: the sys_id of the one CI of that class named with the short hostname (names compare
            case-insensitively); null when none or two carry it.

   Place in the chain (the first rule to return a CI wins; a null hands the host to the next rule)
   Before : every rule so far needed domain evidence on the CI (fqdn, dns_domain or the discovery
            DNS records).
   Reaches: hosts whose CI carries only a short name and no domain information at all.
   After  : USEM Hostname Hardware Match repeats the short name search across all hardware with a
            class sanity check; USEM FQDN Name Hardware Match handles CIs named with the full FQDN.
   ------------------------------------------------------------------------------------------------- */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // nothing to look up
        return null;
    var full = ('' + sourceValue).trim().toLowerCase();   // e.g. "wsaoi01zeapd1.sdi.corp.bankofamerica.com"
    var host = full.split('.')[0];                // "wsaoi01zeapd1"
    if (!host)
        return null;
    // Classes that must never be matched (placeholder and technical CIs); the list lives in the
    // property sn_sec_cmn.ignoreCIClass and the framework may pass it in as _ignoreClass.
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');
    // -- Class from the scanned OS ----------------------------------------------------------------
    // The search below stays inside the class the OS points at (sub-classes included), so a Red Hat
    // host can only land on a Linux Server and a Windows Server carrying the same value is never
    // seen. "Windows Server 2016 Standard 64 bit Edition Version 1607" gives cmdb_ci_win_server
    // (Windows Server). An unknown or multi-guess OS gives no class and the rule declines; the
    // hardware-wide hostname match takes over.
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
    // -- Short name search inside that class, one CI only -----------------------------------------
    // With no domain to confirm, the class is the only safeguard against a namesake, and inside the
    // class the name still has to be unique: two CIs with the same short name cannot be told apart
    // here and the rule declines.
    var gr = new GlideRecord(pref);           // the class chosen and its sub-classes
    if (!gr.isValid())                            // class not installed here, decline
        return null;
    gr.addQuery('name', host);
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
