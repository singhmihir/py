/* USEM IP Layered Match
   -------------------------------------------------------------------------------------------------
   Newer discovery writes each address as its own IP Address record linked to the adapter, and the
   adapter record itself may carry no address. This rule reads those records: IP Address -> Network
   Adapter -> CI.

   Sample payload (one Qualys host record, used in every note below)
   {
     "ID": "83047623",
     "IP": "30.162.178.23",
     "TRACKING_METHOD": "IP",
     "OS": "Ubuntu / Tiny Core Linux / Linux 2.6.x / IBM ASM / HP StoreOnce / F5 Networks Big-IP / Cisco IOS Software"
   }
   Input  : sourceValue is the IP field, "30.162.178.23".
   Returns: the sys_id of the CI at the end of the chain IP Address -> adapter -> CI, its class
            agreeing with the scanned OS when one is known and its name the scanned hostname when
            the scan carries one; null for several owners, a load balancer or a differing name.
   Sample : the Server at the end of the chain IP Address "30.162.178.23" -> adapter "eth0" -> CI;
            neither the Server record nor the adapter record carries the address itself.

   Place in the chain (the first rule to return a CI wins; a null hands the host to the next rule)
   Before : USEM IP Adapter Match looked for the address on the adapter records, which hold nothing
            for the sample.
   Reaches: hosts whose address exists only as an IP Address record.
   After  : USEM FQDN Name Broad Match, and after that the out-of-box Qualys rules.
   ------------------------------------------------------------------------------------------------- */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // nothing to look up
        return null;
    var ip = ('' + sourceValue).trim();           // "30.162.178.23"
    if (!ip || ip.indexOf('127.') == 0 || ip.indexOf('169.254.') == 0)   // loopback and link-local identify nothing
        return null;
    // Classes that must never be matched (placeholder and technical CIs); the list lives in the
    // property sn_sec_cmn.ignoreCIClass and the framework may pass it in as _ignoreClass.
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');
    // -- Class the scanned OS implies, kept as a preference ---------------------------------------
    // This rule follows discovery records rather than searching a class, so the class is not a
    // filter; it is used to leave out a CI at the end of the chain whose class contradicts the
    // scan. An unknown or multi-guess OS gives no class and then nothing is left out.
    // Sample: classFor("Ubuntu / Tiny Core Linux / Linux 2.6.x / IBM ASM / HP StoreOnce / F5
    //         Networks Big-IP / Cisco IOS Software") gives no class, so pref is "".
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
    // agrees() decides whether a CI of class cls can be the scanned host once the OS gave a class:
    // the same class, one of its sub-classes, or one of its parents (a Cisco IOS host may be kept
    // as a plain Network Gear or Hardware record). Any other class is a different kind of machine:
    // a Computer named or addressed like a router is a namesake or a reused address, never the
    // router. With no class from the OS nothing is refused.
    function parentsOf(table) {                   // the class and every class above it
        var out = [table];
        var db = new GlideRecord('sys_db_object');
        db.addQuery('name', table);
        db.query();
        while (db.next() && db.getValue('super_class')) {
            var parent = '' + db.super_class.name;
            out.push(parent);
            db = new GlideRecord('sys_db_object');
            db.addQuery('name', parent);
            db.query();
        }
        return out;
    }
    function agrees(cls) {
        if (!pref || cls == pref)
            return true;
        if (parentsOf(cls).indexOf(pref) != -1)     // cls is a sub-class of pref
            return true;
        return parentsOf(pref).indexOf(cls) != -1;   // cls is a parent of pref
    }
    // A load balancer answers on virtual addresses for the servers behind it, so it is never the
    // host that was scanned.
    function isLoadBalancer(id) {
        var lb = new GlideRecord('cmdb_ci_lb');
        return lb.isValid() && lb.get(id);
    }
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
    // -- IP Address records carrying the address --------------------------------------------------
    // nic.cmdb_ci reaches the CI two links away; the record must belong to an adapter that belongs
    // to a CI outside the ignored classes.
    // Sample: the IP Address record "30.162.178.23" belongs to the adapter "eth0", which belongs to
    //         a Server; that is the one row the query returns.
    var ipGr = new GlideRecord('cmdb_ci_ip_address');
    if (!ipGr.isValid())                          // layered model not installed here, decline
        return null;
    ipGr.addQuery('ip_address', ip);              // "30.162.178.23"
    ipGr.addNotNullQuery('nic.cmdb_ci');          // the chain must end on a CI
    if (ignore)
        ipGr.addQuery('nic.cmdb_ci.sys_class_name', 'NOT IN', ignore);
    ipGr.query();
    // -- One owning CI whose class agrees, not a load balancer, carrying the scanned name ---------
    // An owner whose class contradicts the scanned OS is skipped: the address record then belongs
    // to a different kind of machine, most often a stale or misattributed discovery record. Each
    // remaining owner is counted once, so one device with two address records counts once and two
    // devices count twice. Two different owners cannot be told apart by the address and the rule
    // declines; a single owner that is a load balancer is refused too, because the address is then
    // a virtual IP and the scanned host sits behind it; and when the scan carries a hostname the
    // owner must be named with it, otherwise the address has been reused by another machine.
    // Sample: pref is empty for the sample, so every owner counts; one record, one owner: count is
    //         1, the owner is not a Load Balancer, the sample carries no DNS so no name is checked,
    //         and the sys_id of the Server is returned. A scan carrying the name "vk1660790" whose
    //         address record belongs to a Server named "vk1448212" would be declined. With OS
    //         "Cisco IOS 15.9", pref would be cmdb_ci_netgear and a record owned by a Computer
    //         would be skipped.
    var owners = {};
    var count = 0, first = null;
    while (ipGr.next()) {
        var owner = '' + ipGr.nic.cmdb_ci;
        if (!agrees('' + ipGr.nic.cmdb_ci.sys_class_name))              // a class the OS rules out is not counted
            continue;
        if (!owners[owner]) {
            owners[owner] = true;
            count++;
            if (count == 1)
                first = owner;
        }
    }
    if (count == 1 && !isLoadBalancer(first) && nameAgrees(first))
        return first;
    return null;
})(rule, sourceValue, sourcePayload);
