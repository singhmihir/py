/* USEM IP Class Match
   -------------------------------------------------------------------------------------------------
   The first address rule. An address is the least trustworthy identifier we get: addresses move
   between machines and are shared by load balancers. It is used only for hosts without a serial and
   without a usable name, inside the class the scanned OS points at, and only when exactly one CI of
   that class carries it.

   Sample payload (one Qualys host record, used in every note below)
   {
     "ID": "83047621",
     "IP": "30.162.178.21",
     "TRACKING_METHOD": "IP",
     "OS": "VMware ESXi 7.0.3 build 24723872"
   }
   Input  : sourceValue is the IP field, "30.162.178.21"; the rule also reads the OS from
            sourcePayload.
   Returns: the sys_id of the one CI of that class whose ip_address equals the scanned address,
            named with the scanned hostname when the scan carries one; null when none or two carry
            it or the name differs.
   Sample : the ESX Server CI "vsdnesxm21", whose ip_address is "30.162.178.21"; a load balancer or
            a Windows CI on the same address is outside the class and cannot be picked.

   Place in the chain (the first rule to return a CI wins; a null hands the host to the next rule)
   Before : all serial and name rules. The sample has no DNS name, so every name rule declined.
   Reaches: DNS-less hosts, a small group in the feed, mostly ESXi management interfaces and
            appliances.
   After  : USEM IP Hardware Match searches the address across all hardware with extra safety
            checks; the adapter and layered address rules follow.
   ------------------------------------------------------------------------------------------------- */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // nothing to look up
        return null;
    var ip = ('' + sourceValue).trim();           // "30.162.178.21"
    if (!ip || ip.indexOf('127.') == 0 || ip.indexOf('169.254.') == 0)   // loopback and link-local identify nothing
        return null;
    // Classes that must never be matched (placeholder and technical CIs); the list lives in the
    // property sn_sec_cmn.ignoreCIClass and the framework may pass it in as _ignoreClass.
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');
    // nameAgrees() checks the CI found against the name the scan carries. With no DNS in the
    // payload there is nothing to check. Otherwise the first label of the CI name must be the
    // scanned label, or the scanned label must be that name plus an interface tail ("<name>-mgmt"),
    // or the CI name must be the label plus a tail. A CI named differently sits on a reused address
    // (a lease that moved, a decommissioned machine whose address was handed on) and is not the
    // scanned host, whatever its class.
    function nameAgrees(ciId) {
        var label = ('' + (sourcePayload.DNS || '')).trim().toLowerCase().split('.')[0];
        if (!label)
            return true;
        var ci = new GlideRecord('cmdb_ci');
        ci.get(ciId);
        var name = ('' + ci.getValue('name')).trim().toLowerCase().split('.')[0];
        if (!name)
            return true;
        return name == label || label.indexOf(name + '-') == 0 || name.indexOf(label + '-') == 0;
    }
    // -- Class from the scanned OS ----------------------------------------------------------------
    // The search below stays inside the class the OS points at (sub-classes included), so a Red Hat
    // host can only land on a Linux Server and a Windows Server carrying the same value is never
    // seen. An unknown or multi-guess OS gives no class and the rule declines; the hardware-wide
    // address match takes over.
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
    // -- Address search inside that class, one CI only --------------------------------------------
    // Inside the agreed class an address is reasonably safe: a virtual IP of a load balancer or a
    // Windows machine that inherited the address sits outside the class and never appears. Two CIs
    // of the class on one address (an address reused after a rebuild) still make the rule decline.
    // Sample: the search on cmdb_ci_esx_server for ip_address "30.162.178.21" finds the ESX Server
    //         "vsdnesxm21" and no second row, so its sys_id is returned.
    var gr = new GlideRecord(pref);           // the class chosen and its sub-classes
    if (!gr.isValid())                            // class not installed here, decline
        return null;
    gr.addQuery('ip_address', ip);
    if (ignore)
        gr.addQuery('sys_class_name', 'NOT IN', ignore);
    gr.query();
    if (!gr.next())
        return null;
    var match = gr.getUniqueValue();
    if (gr.hasNext())                             // a second CI carries the same value, never guess
        return null;
    // -- The CI must carry the scanned name -------------------------------------------------------
    // An address alone is not enough when the scan also carries a hostname: the CI found must be
    // named with it, or with it minus an interface tail. This keeps a finding scanned as one host
    // off a record named after another, which is what a reused address produces.
    // Sample: the sample carries no DNS, so nothing is checked and the sys_id of "vsdnesxm21" is
    //         returned. A host scanned as "vk1660790" whose address leads to a CI named "vk1448212"
    //         would be declined here: the address has been reused.
    if (!nameAgrees(match))
        return null;
    return match;
})(rule, sourceValue, sourcePayload);
