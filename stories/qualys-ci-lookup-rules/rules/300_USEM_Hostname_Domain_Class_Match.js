/* =================================================================================================
   RULE 300 - USEM Hostname Domain Class Match
   =================================================================================================
   Match by the combination of short hostname and domain, inside the class the OS implies. Serves
   CIs named with the short hostname that carry the domain in another field (dns_domain or fqdn)
   instead of an exact fqdn value.

   SAMPLE PAYLOAD (one Qualys Host Detection record, used in every example below)
   {
     "ID": "35832680",
     "IP": "171.128.225.96",
     "TRACKING_METHOD": "AGENT",
     "OS": "Red Hat Enterprise Linux 9.8",
     "DNS": "ah-1047132-001.sdi.corp.bankofamerica.com",
     "QG_HOSTID": "633769a4-0139-0002-e352-005056bf41ea"
   }

   sourceValue   = the DNS field -> "ah-1047132-001.sdi.corp.bankofamerica.com"
   sourcePayload = the whole record; the rule also reads the OS and the IP from it
   Expected for the sample: the Linux Server CI named "ah-1047132-001" whose dns_domain is
   "sdi.corp.bankofamerica.com" (or whose fqdn is the scanned name); a namesake in another domain is
   never picked.

   WHY THIS RULE SITS AT ORDER 300
   Rules run from the lowest order to the highest; the first rule that returns a CI wins and the
   later rules are skipped. A rule that returns null passes the host on.
   - Before it : 250/260 looked for the exact FQDN in the fqdn field.
   - Reaches it: hosts whose CI has no exact fqdn value but is named with the short hostname and
                 shows the domain elsewhere.
   - After it  : 310 repeats the search across all hardware; 350 uses the layered DNS records;
                 400/410 accept a unique short name without domain evidence.
   ================================================================================================= */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // nothing to look up -> null = "no match from this rule"
        return null;
    var full = ('' + sourceValue).trim().toLowerCase();   // "ah-1047132-001.sdi.corp.bankofamerica.com"
    var dot = full.indexOf('.');                  // 14, position of the first dot
    if (dot < 1)                                  // no domain part -> the hostname rules (400+) handle bare labels
        return null;
    var host = full.substring(0, dot);            // "ah-1047132-001"
    var domain = full.substring(dot + 1);         // "sdi.corp.bankofamerica.com"
    var ip = sourcePayload.IP ? '' + sourcePayload.IP : '';   // "171.128.225.96", used only to break ties
    // CI classes that must never be matched (placeholder and technical classes). Administrators
    // keep the list in the property sn_sec_cmn.ignoreCIClass; the framework may pass the same list
    // in as _ignoreClass.
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');
    // -> ignore =
    //    "sn_sec_cmn_unmatched_ci,sn_vul_qualys_ci,cmdb_ci_unclassed_hardware,cmdb_ci_incomplete_ip,cmdb_ci_dns_name"
    // ====== STAGE 1: Work out the CMDB class from the scanned OS =================================
    // What   : classFor() maps the OS text to the class the CI should be in; the search that
    //          follows is limited to that class and its sub-classes.
    // Why    : evidence is trusted only when it lands in a class that agrees with the scanned OS. A
    //          Red Hat host must resolve to a Linux Server CI, never to a Windows Server that
    //          happens to carry the same value.
    // Sample : classFor("Red Hat Enterprise Linux 9.8") -> "cmdb_ci_linux_server" (Linux Server).
    //          An unknown or multi-guess OS gives "" and this rule declines so that rule 310 (all
    //          hardware, no class) takes over.
    // =============================================================================================
    // classFor() turns the OS text Qualys reports into the CMDB class the CI lives in. Examples:
    //   "Red Hat Enterprise Linux 9.8"                              -> cmdb_ci_linux_server
    //   "Windows Server 2016 Standard 64 bit Edition Version 1607"  -> cmdb_ci_win_server
    //   "Windows 10 Enterprise 64 bit Edition Version 22H2"         -> cmdb_ci_computer
    //   "VMware ESXi 7.0.3 build 24723872"                          -> cmdb_ci_esx_server
    //   "AIX 7.3 TL3"                                               -> cmdb_ci_aix_server
    //   "Cisco NX-OS 9.3(8)"                                        -> cmdb_ci_netgear
    //   "Ubuntu / Tiny Core Linux / Linux 2.6.x / IBM ASM / HP StoreOnce / F5 Networks Big-IP / Cisco IOS Software"
    //       -> "" : three or more guesses separated by "/" means the unauthenticated scan
    //               could not identify the OS, so no class is chosen
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
    // -> pref = "cmdb_ci_linux_server"
    if (!pref)
        return null;
    // ====== STAGE 2: Hostname plus domain evidence, with the scanned IP as tie-break (pickCombo) =
    // What   : pickCombo() searches one table for CIs named with the short hostname and keeps a CI
    //          only when its own domain information agrees with the scanned domain: its fqdn equals
    //          the scanned name, or its dns_domain equals the scanned domain, or its fqdn starts
    //          with the hostname and contains the domain. One confirmed CI -> match. Several but
    //          exactly one with the scanned IP -> that one. Anything else -> null.
    // Why    : the same short hostname can exist in several domains (a test and a production
    //          machine both called app01). Domain evidence on the CI itself stops the findings from
    //          landing on the namesake in another domain.
    // Sample : the Linux Server "ah-1047132-001" has dns_domain "sdi.corp.bankofamerica.com" ->
    //          confirmed -> good = ["3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c"] -> return
    //          "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c". A CI "ah-1047132-001" with dns_domain
    //          "lab.example.net" is skipped.
    // =============================================================================================
    function pickCombo(table) {
        var gr = new GlideRecord(table);
        if (!gr.isValid())
            return null;
        gr.addQuery('name', host);                // name = "ah-1047132-001" (case-insensitive)
        if (ignore)
            gr.addQuery('sys_class_name', 'NOT IN', ignore);
        gr.query();
        var good = [];                            // CIs whose domain evidence agrees
        var ipHits = [];                          // those that also carry the scanned IP
        while (gr.next()) {
            var cifqdn = ('' + gr.getValue('fqdn')).toLowerCase();        // e.g. "ah-1047132-001.sdi.corp.bankofamerica.com"
            var cidom = ('' + gr.getValue('dns_domain')).toLowerCase();   // e.g. "sdi.corp.bankofamerica.com"
            if (cifqdn == full || cidom == domain ||
                (cifqdn && cifqdn.indexOf(host + '.') == 0 && cifqdn.indexOf(domain) > 0)) {
                good.push(gr.getUniqueValue());
                if (ip && gr.getValue('ip_address') == ip)
                    ipHits.push(gr.getUniqueValue());
            }
        }
        // -> good = ["3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c"], ipHits =
        //    ["3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c"] for the sample
        if (good.length == 1)                     // one confirmed CI -> match
            return good[0];
        if (good.length > 1 && ipHits.length == 1) // several, one confirmed by the IP -> that one
            return ipHits[0];
        return null;                              // none, or an unresolved tie -> decline
    }
    return pickCombo(pref);                   // hostname + domain inside the Linux Server class
})(rule, sourceValue, sourcePayload);
