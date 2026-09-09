/* USEM FQDN Class Match
   -------------------------------------------------------------------------------------------------
   The first name rule: the scanned DNS name against the fqdn field of a CI, inside the class the
   scanned OS points at. An exact FQDN on the CI is the most precise name evidence we have, so it
   comes before any hostname matching.

   Sample payload (one Qualys host record, used in every note below)
   {
     "ID": "83047612",
     "IP": "30.206.199.36",
     "TRACKING_METHOD": "IP",
     "OS": "VMware ESXi 7.0.3 build 24723872",
     "DNS": "vsdnac22xsdi004.sdi.corp.bankofamerica.com"
   }
   Input  : sourceValue is the DNS field, "vsdnac22xsdi004.sdi.corp.bankofamerica.com"; the rule
            also reads the OS and the IP from sourcePayload.
   Returns: the sys_id of the one CI of that class whose fqdn equals the scanned name; with
            duplicate fqdn values, the one that also carries the scanned IP; null otherwise.
   Sample : the ESX Server CI "vsdnac22xsdi004", whose fqdn is the scanned name; two ESX Servers
            with that fqdn are accepted only when exactly one also carries the IP 30.206.199.36.

   Place in the chain (the first rule to return a CI wins; a null hands the host to the next rule)
   Before : the serial number rules and the IP phone rule found nothing.
   Reaches: every host with a dotted DNS name, which is the bulk of the Qualys feed.
   After  : USEM FQDN Hardware Match repeats the exact FQDN search across every hardware class; the
            hostname-plus-domain rules and then the plain hostname rules follow.
   ------------------------------------------------------------------------------------------------- */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // nothing to look up
        return null;
    var fqdn = ('' + sourceValue).trim().toLowerCase();   // "vsdnac22xsdi004.sdi.corp.bankofamerica.com"
    if (fqdn.indexOf('.') == -1)                  // a bare label is left to the hostname rules
        return null;
    var ip = sourcePayload.IP ? '' + sourcePayload.IP : '';   // "30.206.199.36", only used to break a tie
    // Classes that must never be matched (placeholder and technical CIs); the list lives in the
    // property sn_sec_cmn.ignoreCIClass and the framework may pass it in as _ignoreClass.
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');
    // -- Class from the scanned OS ----------------------------------------------------------------
    // The search below stays inside the class the OS points at (sub-classes included), so a Red Hat
    // host can only land on a Linux Server and a Windows Server carrying the same value is never
    // seen. An unknown or multi-guess OS gives no class and the rule declines; the hardware-wide
    // FQDN match takes over.
    // Sample: classFor("VMware ESXi 7.0.3 build 24723872") gives ESX Server, so pref is
    //         cmdb_ci_esx_server and the search below runs on that class.
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
    // -- Exact FQDN, scanned IP as the tie-break --------------------------------------------------
    // pickFqdn() collects every CI of that class whose fqdn equals the scanned name and notes which
    // of them also carry the scanned IP. One hit is the match. Duplicates do exist in the CMDB (a
    // retired server and its rebuilt replacement, a cluster alias on two nodes); when exactly one
    // of them carries the scanned IP that one is taken, otherwise the rule declines rather than
    // guess.
    // Sample: the ESX Server "vsdnac22xsdi004" has fqdn
    //         "vsdnac22xsdi004.sdi.corp.bankofamerica.com", so ids holds that one CI and its sys_id
    //         is returned. Were a second CI to carry the same fqdn, the one with ip_address
    //         "30.206.199.36" would be taken; if neither or both carried it, the rule would
    //         decline.
    function pickFqdn(table) {
        var gr = new GlideRecord(table);
        if (!gr.isValid())
            return null;
        gr.addQuery('fqdn', fqdn);
        if (ignore)
            gr.addQuery('sys_class_name', 'NOT IN', ignore);
        gr.query();
        var ids = [];                             // every CI carrying the FQDN
        var ipHits = [];                          // those that also carry the scanned IP
        while (gr.next()) {
            ids.push(gr.getUniqueValue());
            if (ip && gr.getValue('ip_address') == ip)
                ipHits.push(gr.getUniqueValue());
        }
        if (ids.length == 1)
            return ids[0];
        if (ids.length > 1 && ipHits.length == 1) // duplicates, one confirmed by the IP
            return ipHits[0];
        return null;                              // none, or a tie nothing can break
    }
    return pickFqdn(pref);                    // exact FQDN inside the class chosen
})(rule, sourceValue, sourcePayload);
