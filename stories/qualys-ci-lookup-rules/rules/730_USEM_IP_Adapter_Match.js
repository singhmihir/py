/* USEM IP Adapter Match
   -------------------------------------------------------------------------------------------------
   Discovery stores one Network Adapter record per network card, and a multi-homed server keeps its
   addresses there rather than on the CI record. This rule finds the adapter carrying the scanned
   address and takes its owning CI.

   Sample payload (one Qualys host record, used in every note below)
   {
     "ID": "83047622",
     "IP": "30.162.178.22",
     "TRACKING_METHOD": "IP",
     "OS": "Ubuntu / Tiny Core Linux / Linux 2.6.x / IBM ASM / HP StoreOnce / F5 Networks Big-IP / Cisco IOS Software"
   }
   Input  : sourceValue is the IP field, "30.162.178.22".
   Returns: the sys_id of the CI that owns the adapter carrying the scanned address, when its class
            agrees with the scanned OS and its name with the scanned host name; null when adapters
            of two different CIs carry it, the owner is a load balancer or the name differs.
   Sample : the Server that owns the adapter "eth0" carrying "30.162.178.22"; the address is not
            written on the Server record itself.

   Place in the chain (the first rule to return a CI wins; a null hands the host to the next rule)
   Before : the address rules so far read the ip_address field of the CI record, which holds nothing
            for the sample.
   Reaches: hosts whose address is recorded on an adapter only.
   After  : USEM IP Layered Match and then the broad name rule.
   ------------------------------------------------------------------------------------------------- */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // nothing to look up
        return null;
    var ip = ('' + sourceValue).trim();           // "30.162.178.22"
    // loopback and link-local identify nothing
    if (!ip || ip.indexOf('127.') == 0 || ip.indexOf('169.254.') == 0)
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
    //
    // classFor() maps the OS text Qualys reports to the CMDB class the CI should be in, e.g. "Red
    // Hat Enterprise Linux 9.8" is a Linux Server, "Windows Server 2016 Standard" a Windows Server
    // and "VMware ESXi 7.0.3" an ESX Server. A string of guesses separated by "/" comes from an
    // unauthenticated scan that could not identify the OS; three or more guesses give no class at
    // all.
    function classFor(os) {
        if (!os) return '';
        var s = ('' + os).toLowerCase();
        if (s.split('/').length > 2) return '';   // multi-guess fingerprint
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
        if (parentsOf(cls).indexOf(pref) != -1)   // cls is a sub-class of pref
            return true;
        return parentsOf(pref).indexOf(cls) != -1;  // cls is a parent of pref
    }

    // A load balancer answers on virtual addresses for the servers behind it, so it is never the
    // host that was scanned.
    function isLoadBalancer(id) {
        var lb = new GlideRecord('cmdb_ci_lb');
        return lb.isValid() && lb.get(id);
    }

    // nameAgrees() checks the CI found against the host name the scan carries. Nothing is checked
    // when the payload has no DNS or the CI has no name. Otherwise the first label of the CI name
    // must equal the scanned label, or one must be the other plus a hyphenated tail ("<name>-mgmt"
    // for a management interface, "<name>-a" for a node). A CI named after another machine sits on
    // a reused address (a lease that moved, a decommissioned host whose address was handed on) and
    // is not the scanned host, whatever its class.
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

    // -- Adapters carrying the address ------------------------------------------------------------
    // Adapters with the scanned address that belong to a CI outside the ignored classes.
    // Sample: the adapter "eth0" with ip_address "30.162.178.22" belongs to a Server; that is the
    //         one row the query returns.
    var nic = new GlideRecord('cmdb_ci_network_adapter');
    nic.addQuery('ip_address', ip);               // "30.162.178.22"
    nic.addNotNullQuery('cmdb_ci');               // the adapter must belong to a CI
    if (ignore)
        nic.addQuery('cmdb_ci.sys_class_name', 'NOT IN', ignore);
    nic.query();

    // -- One owning CI: class agreeing, not a load balancer, named as scanned ---------------------
    // An owner whose class contradicts the scanned OS is skipped: its address record then belongs
    // to a different kind of machine, most often a stale or misattributed discovery record. Each
    // remaining owner is counted once, so one server with two adapters on the address counts once
    // and two servers count twice. Two different owners cannot be told apart by the address, so the
    // rule declines. One owner that is a load balancer is refused, because the address is then a
    // virtual IP and the scanned host sits behind it. One owner named after another machine is
    // refused, because the address has been reused.
    // Sample: pref is empty and the sample carries no DNS, so every owner counts and no name is
    //         checked; one adapter, one owner, not a Load Balancer: the sys_id of the Server is
    //         returned. A second server with an adapter on "30.162.178.22" would make the rule
    //         decline, and so would a scan named "vk1660790" whose adapter belongs to a Server
    //         named "vk1448212"; with OS "Cisco IOS 15.9" an adapter owned by a Computer would be
    //         skipped.
    var owners = {};
    var count = 0, first = null;
    while (nic.next()) {
        var owner = nic.getValue('cmdb_ci');
        if (!agrees('' + nic.cmdb_ci.sys_class_name))  // a class the OS rules out is not counted
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
