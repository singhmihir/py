/* USEM Hostname Domain Class Match
   -------------------------------------------------------------------------------------------------
   For CIs that are named with the short hostname and carry the domain in another field (dns_domain,
   or an fqdn that was never copied into the name). The short name and the domain are matched
   together, inside the class the scanned OS points at.

   Sample payload (one Qualys host record, used in every note below)
   {
     "ID": "35832680",
     "IP": "171.128.225.96",
     "TRACKING_METHOD": "AGENT",
     "OS": "Red Hat Enterprise Linux 9.8",
     "DNS": "ah-1047132-001.sdi.corp.bankofamerica.com",
     "QG_HOSTID": "633769a4-0139-0002-e352-005056bf41ea"
   }
   Input  : sourceValue is the DNS field, "ah-1047132-001.sdi.corp.bankofamerica.com"; the rule also
            reads the OS and the IP from sourcePayload.
   Returns: the sys_id of the one CI of that class named with the short hostname whose own domain
            information agrees with the scanned domain; a namesake in another domain is never
            picked.
   Sample : the Linux Server CI named "ah-1047132-001" whose dns_domain is
            "sdi.corp.bankofamerica.com".

   Place in the chain (the first rule to return a CI wins; a null hands the host to the next rule)
   Before : the FQDN rules looked for the exact name in the fqdn field and found nothing.
   Reaches: hosts whose CI has no exact fqdn value but is named with the short hostname and shows
            the domain elsewhere.
   After  : USEM Hostname Domain Hardware Match repeats the search across all hardware, USEM Layered
            DNS Match reads the discovery DNS records, and the plain hostname rules accept a unique
            short name without domain evidence.
   ------------------------------------------------------------------------------------------------- */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // nothing to look up
        return null;
    var full = ('' + sourceValue).trim().toLowerCase();   // "ah-1047132-001.sdi.corp.bankofamerica.com"
    var dot = full.indexOf('.');
    if (dot < 1)                                  // a bare label is left to the hostname rules
        return null;
    var host = full.substring(0, dot);            // "ah-1047132-001"
    var domain = full.substring(dot + 1);         // "sdi.corp.bankofamerica.com"
    var ip = sourcePayload.IP ? '' + sourcePayload.IP : '';   // "171.128.225.96", only used to break a tie
    // Classes that must never be matched (placeholder and technical CIs); the list lives in the
    // property sn_sec_cmn.ignoreCIClass and the framework may pass it in as _ignoreClass.
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');
    // -- Class from the scanned OS ----------------------------------------------------------------
    // The search below stays inside the class the OS points at (sub-classes included), so a Red Hat
    // host can only land on a Linux Server and a Windows Server carrying the same value is never
    // seen. An unknown or multi-guess OS gives no class and the rule declines; the hardware-wide
    // hostname-plus-domain match takes over.
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
    // -- Short hostname plus domain evidence, scanned IP as the tie-break -------------------------
    // pickCombo() looks for CIs of that class named with the short hostname and keeps one only when
    // its own record agrees with the scanned domain: fqdn equal to the scanned name, dns_domain
    // equal to the scanned domain, or an fqdn that starts with the hostname and contains the
    // domain. The same short name lives in several domains (a test and a production box both called
    // app01), and this check is what keeps the findings off the namesake. One confirmed CI is the
    // match; several with exactly one carrying the scanned IP gives that one; anything else
    // declines.
    // Sample: the Linux Server is named "ah-1047132-001" and its dns_domain is
    //         "sdi.corp.bankofamerica.com", so it lands in good as the only entry and its sys_id is
    //         returned. A CI "ah-1047132-001" with dns_domain "lab.example.net" would be skipped;
    //         two confirmed CIs would be resolved by ip_address "171.128.225.96" or declined.
    function pickCombo(table) {
        var gr = new GlideRecord(table);
        if (!gr.isValid())
            return null;
        gr.addQuery('name', host);                // name compares case-insensitively
        if (ignore)
            gr.addQuery('sys_class_name', 'NOT IN', ignore);
        gr.query();
        var good = [];                            // CIs whose domain evidence agrees
        var ipHits = [];                          // those that also carry the scanned IP
        while (gr.next()) {
            var cifqdn = ('' + gr.getValue('fqdn')).toLowerCase();
            var cidom = ('' + gr.getValue('dns_domain')).toLowerCase();
            if (cifqdn == full || cidom == domain ||
                (cifqdn && cifqdn.indexOf(host + '.') == 0 && cifqdn.indexOf(domain) > 0)) {
                good.push(gr.getUniqueValue());
                if (ip && gr.getValue('ip_address') == ip)
                    ipHits.push(gr.getUniqueValue());
            }
        }
        if (good.length == 1)
            return good[0];
        if (good.length > 1 && ipHits.length == 1) // several, one confirmed by the IP
            return ipHits[0];
        return null;                              // none, or a tie nothing can break
    }
    return pickCombo(pref);                   // hostname plus domain inside the class chosen
})(rule, sourceValue, sourcePayload);
