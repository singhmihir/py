/* USEM Hostname Hardware Match
   -------------------------------------------------------------------------------------------------
   The short hostname across the whole hardware tree, with a check that the CI found does not
   contradict the scanned OS. For CIs classed generically (Server, Computer, UNIX Server) or
   differently from the OS.

   Input  : sourceValue is the DNS field; the rule also reads the OS from sourcePayload.
   Returns: the sys_id of the one hardware CI named with the short hostname, accepted when its class
            agrees with the scanned OS or is generic; null when the name is shared or the class
            contradicts the scan.

   Place in the chain (the first rule to return a CI wins; a null hands the host to the next rule)
   Before : USEM Hostname Class Match required the short name to be unique inside the class the OS
            implies.
   Reaches: hosts whose CI is classed generically or whose OS gave no class.
   After  : USEM FQDN Name Hardware Match, then the IP address rules for hosts without a usable
            name.
   ------------------------------------------------------------------------------------------------- */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // nothing to look up
        return null;
    var full = ('' + sourceValue).trim().toLowerCase();   // e.g. "va2ausapabw0.bankofamerica.com"
    var host = full.split('.')[0];                // "va2ausapabw0"
    if (!host)
        return null;
    // Classes that must never be matched (placeholder and technical CIs); the list lives in the
    // property sn_sec_cmn.ignoreCIClass and the framework may pass it in as _ignoreClass.
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');
    // -- Class the scanned OS implies, kept as a preference ---------------------------------------
    // This rule searches the whole hardware tree, so the class is not a filter here; it is checked
    // at the end to reject a CI whose class contradicts the scan. "AIX 7.3 TL3" gives
    // cmdb_ci_aix_server (AIX Server); an unknown OS gives no class and then no check is made.
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
    // Classes that say nothing about the OS (a CI loaded as a plain Server before discovery refined
    // it) never contradict the scan.
    var generic = {cmdb_ci_hardware: 1, cmdb_ci_computer: 1, cmdb_ci_server: 1,
        cmdb_ci_unix_server: 1};
    // -- Short name search across the hardware tree -----------------------------------------------
    // Nothing is filtered by class here; the two checks that follow provide the safety.
    var gr = new GlideRecord('cmdb_ci_hardware');// Hardware and every class beneath it
    gr.addQuery('name', host);
    if (ignore)
        gr.addQuery('sys_class_name', 'NOT IN', ignore);
    // -- Exactly one CI carries the value ---------------------------------------------------------
    // The first row is remembered with its class; a second row means two hardware CIs with one
    // short name (a test and a production box, a retired and a rebuilt one), which the name alone
    // cannot tell apart and the rule declines.
    gr.query();
    if (!gr.next())
        return null;
    var id = gr.getUniqueValue();
    var cls = '' + gr.getValue('sys_class_name');
    if (gr.hasNext())
        return null;
    // -- Reject a CI whose class contradicts the scanned OS ---------------------------------------
    // When the OS gave a class, the CI found must sit inside it (sub-classes included) or be
    // generically classed. A host that lands on a Windows Server by name or address is a namesake
    // or a reused address, not the same machine, and its findings would go to the wrong owner.
    if (pref) {
        var chk = new GlideRecord(pref);
        if (!(chk.isValid() && chk.get(id)) && !generic[cls])
            return null;
    }
    return id;
})(rule, sourceValue, sourcePayload);
