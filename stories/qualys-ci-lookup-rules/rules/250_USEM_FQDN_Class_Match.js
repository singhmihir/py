/* =================================================================================================
   RULE 250 - USEM FQDN Class Match
   =================================================================================================
   Match a scanned host by its fully qualified domain name (FQDN) stored in the fqdn field of a CI,
   inside the class the scanned OS implies. An exact FQDN on the CI is the most precise name
   evidence there is, so this is the first name rule after the phone rule.

   SAMPLE PAYLOAD (one Qualys Host Detection record, used in every example below)
   {
     "ID": "83047612",
     "IP": "30.206.199.36",
     "TRACKING_METHOD": "IP",
     "OS": "VMware ESXi 7.0.3 build 24723872",
     "DNS": "vsdnac22xsdi004.sdi.corp.bankofamerica.com"
   }

   sourceValue   = the DNS field -> "vsdnac22xsdi004.sdi.corp.bankofamerica.com"
   sourcePayload = the whole record; the rule also reads the OS and the IP from it
   Expected for the sample: the ESX Server CI whose fqdn is
   "vsdnac22xsdi004.sdi.corp.bankofamerica.com". Two ESX Servers with that fqdn are accepted only
   when exactly one also carries the IP 30.206.199.36.

   WHY THIS RULE SITS AT ORDER 250
   Rules run from the lowest order to the highest; the first rule that returns a CI wins and the
   later rules are skipped. A rule that returns null passes the host on.
   - Before it : 175/180 (serial numbers) and 200 (phone labels) found nothing.
   - Reaches it: every host with a dotted DNS name, which is the bulk of the Qualys feed.
   - After it  : 260 repeats the exact FQDN search across every hardware class; 300/310 fall back to
                 hostname plus domain evidence; 400/410 to the short hostname alone.
   ================================================================================================= */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // nothing to look up -> null = "no match from this rule"
        return null;
    var fqdn = ('' + sourceValue).trim().toLowerCase();   // "vsdnac22xsdi004.sdi.corp.bankofamerica.com"
    if (fqdn.indexOf('.') == -1)                  // no domain part -> the hostname rules (400+) handle bare labels
        return null;
    var ip = sourcePayload.IP ? '' + sourcePayload.IP : '';   // "30.206.199.36", used only to break ties
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
    // Sample : classFor("VMware ESXi 7.0.3 build 24723872") -> "cmdb_ci_esx_server" (ESX Server).
    //          An unknown or multi-guess OS gives "" and this rule declines so that rule 260 (all
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
    // -> pref = "cmdb_ci_esx_server"
    if (!pref)
        return null;
    // ====== STAGE 2: Exact FQDN search with the scanned IP as tie-break (pickFqdn) ===============
    // What   : pickFqdn() searches one table for CIs whose fqdn field equals the scanned name,
    //          collects every hit and notes which of them also carry the scanned IP. One hit ->
    //          match. Several hits but exactly one with the scanned IP -> that one. Anything else
    //          -> null.
    // Why    : an FQDN should be unique, but CMDBs carry duplicates (a retired server and its
    //          rebuilt replacement, a cluster alias on two nodes). The scanned IP is the second
    //          piece of evidence that breaks such a tie safely; without it the rule declines.
    // Sample : the ESX Server "vsdnac22xsdi004" has fqdn
    //          "vsdnac22xsdi004.sdi.corp.bankofamerica.com" and ip_address "30.206.199.36" -> ids =
    //          ["3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c"], ipHits = ["3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c"]
    //          -> return "3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c".
    // =============================================================================================
    function pickFqdn(table) {
        var gr = new GlideRecord(table);
        if (!gr.isValid())
            return null;
        gr.addQuery('fqdn', fqdn);                // fqdn = "vsdnac22xsdi004.sdi.corp.bankofamerica.com"
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
        // -> ids = ["3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c"], ipHits =
        //    ["3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c"] for the sample; a duplicate would give ids =
        //    ["3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c", "8c1d5e2f7a9b4c3d6e0f1a2b3c4d5e6f"]
        if (ids.length == 1)                      // one CI -> match
            return ids[0];
        if (ids.length > 1 && ipHits.length == 1) // duplicates, one confirmed by the IP -> that one
            return ipHits[0];
        return null;                              // none, or an unresolved tie -> decline
    }
    return pickFqdn(pref);                    // exact FQDN inside the ESX Server class only
})(rule, sourceValue, sourcePayload);
