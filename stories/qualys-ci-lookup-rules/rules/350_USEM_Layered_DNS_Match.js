/* USEM Layered DNS Match
   -------------------------------------------------------------------------------------------------
   Discovery keeps names and addresses as their own records linked to the device: a DNS Name record
   is tied to an IP Address record, the IP Address record belongs to a Network Adapter, and the
   adapter belongs to the CI. This rule follows that chain, which is the only way to find a host
   whose name is not written on the CI record at all, and it resolves aliases to the real machine. A
   CI at the end of the chain whose class contradicts the scanned OS is left out, because the
   discovery records then describe a different kind of machine.

   Sample payload (one Qualys host record, used in every note below)
   {
     "ID": "42773078",
     "IP": "167.202.60.26",
     "TRACKING_METHOD": "IP",
     "OS": "Red Hat Enterprise Linux Server 7.9",
     "DNS": "hklvteqoradbp3.hk.baml.com",
     "QG_HOSTID": "6337dede-02e7-0002-ad2c-0050569765df"
   }
   Input  : sourceValue is the DNS field, "hklvteqoradbp3.hk.baml.com"; the rule also reads the OS
            and the IP from sourcePayload.
   Returns: the sys_id of the CI at the end of the chain DNS Name -> IP Address -> adapter -> CI,
            its class agreeing with the scanned OS when one is known (a Linux fingerprint agrees
            with Network Gear, Load Balancer and Storage Server records too); when several CIs
            answer to the name, the one whose chain runs through the scanned IP; null otherwise.
   Sample : the Linux Server "hklvteqoradbp3", reached through DNS Name "hklvteqoradbp3.hk.baml.com"
            -> IP Address "167.202.60.26" -> adapter "eth0".

   Place in the chain (the first rule to return a CI wins; a null hands the host to the next rule)
   Before : the FQDN and hostname-plus-domain rules looked at name fields stored on the CI record
            itself.
   Reaches: hosts whose name lives only in the discovery DNS records, and aliases that point at an
            address of the device.
   After  : the plain hostname rules and USEM FQDN Name Hardware Match.
   ------------------------------------------------------------------------------------------------- */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // nothing to look up
        return null;
    var fqdn = ('' + sourceValue).trim().toLowerCase();  // "hklvteqoradbp3.hk.baml.com"
    if (fqdn.indexOf('.') == -1)                  // a bare label is left to the hostname rules
        return null;
    // "167.202.60.26", only used to break a tie
    var ip = sourcePayload.IP ? '' + sourcePayload.IP : '';

    // Classes that must never be matched (placeholder and technical CIs); the list lives in the
    // property sn_sec_cmn.ignoreCIClass and the framework may pass it in as _ignoreClass.
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');

    // -- Class the scanned OS implies, kept as a preference ---------------------------------------
    // This rule follows discovery records rather than searching a class, so the class is not a
    // filter; it is used to leave out a CI at the end of the chain whose class contradicts the
    // scan. An unknown or multi-guess OS gives no class and then nothing is left out.
    // Sample: classFor("Red Hat Enterprise Linux Server 7.9") gives Linux Server, so pref is
    //         cmdb_ci_linux_server.
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
    // a Windows Server named like the scanned Linux host is a namesake, never the host. With no
    // class from the OS nothing is refused.
    //
    // A Linux fingerprint is also accepted against Network Gear, Load Balancer and Storage Server
    // records: switches, balancers and storage nodes run Linux underneath and Qualys reports that
    // kernel, so the fingerprint says nothing against those classes.
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
        var above = parentsOf(cls);
        var appliance = above.indexOf('cmdb_ci_netgear') != -1 ||
            above.indexOf('cmdb_ci_lb') != -1 || above.indexOf('cmdb_ci_storage_server') != -1;
        if (pref == 'cmdb_ci_linux_server' && appliance)  // an appliance reporting its Linux
            return true;
        if (above.indexOf(pref) != -1)            // cls is a sub-class of pref
            return true;
        return parentsOf(pref).indexOf(cls) != -1;  // cls is a parent of pref
    }

    // -- Follow the chain DNS Name -> IP Address -> adapter -> CI ---------------------------------
    // cmdb_ip_address_dns_name ties one DNS Name record to one IP Address record; dot-walking
    // reaches the rest: dns_name.name is the name on the DNS Name record and ip_address.nic.cmdb_ci
    // is the CI owning the adapter that holds the address. Because the chain ends on whatever
    // device holds the address, an alias resolves to the real machine.
    // Sample: the DNS Name record "hklvteqoradbp3.hk.baml.com" is linked to the IP Address record
    //         "167.202.60.26", which belongs to the adapter "eth0" of the Linux Server
    //         "hklvteqoradbp3"; that is the one row the query returns.
    var gr = new GlideRecord('cmdb_ip_address_dns_name');
    if (!gr.isValid())                            // layered model not installed here, decline
        return null;
    gr.addQuery('dns_name.name', fqdn);           // "hklvteqoradbp3.hk.baml.com"
    gr.addNotNullQuery('ip_address.nic.cmdb_ci');  // the chain must end on a CI
    if (ignore)
        gr.addQuery('ip_address.nic.cmdb_ci.sys_class_name', 'NOT IN', ignore);
    gr.query();

    // -- One CI at the end of the chain, class agreeing, scanned IP as the tie-break --------------
    // A CI whose class contradicts the scanned OS is skipped: a Computer at the end of the chain
    // for a Cisco IOS host is a stale or misattributed discovery record, not the router. Each
    // remaining CI is counted once, and the CIs reached through the scanned address are noted. One
    // CI is the match. A name that resolves to two devices (an alias moved between hosts, an old
    // and a new record) is taken only when exactly one of them is reached through the scanned IP;
    // otherwise the rule declines.
    // Sample: the chain ends on a Linux Server, the class pref holds, so it is counted: count is 1
    //         and the sys_id of "hklvteqoradbp3" is returned. A Computer at the end of the chain
    //         would also count (a parent of Linux Server), and so would an IP Switch or a Load
    //         Balancer, appliances that report the Linux they run on; a Windows Server would be
    //         skipped. Were the name also linked to an address of a second Linux Server, ipOwners
    //         would hold only the CI reached through "167.202.60.26" and that one would be
    //         returned.
    var owners = {}, ipOwners = {};
    var count = 0, first = null;
    while (gr.next()) {
        var owner = '' + gr.ip_address.nic.cmdb_ci;
        // a class the OS rules out is not counted
        if (!agrees('' + gr.ip_address.nic.cmdb_ci.sys_class_name))
            continue;
        if (!owners[owner]) {
            owners[owner] = true;
            count++;
            if (count == 1)
                first = owner;
        }
        if (ip && ('' + gr.ip_address.ip_address) == ip)  // this chain runs through the scanned IP
            ipOwners[owner] = true;
    }
    if (count == 1)
        return first;
    if (count > 1) {
        var confirmed = Object.keys(ipOwners);
        if (confirmed.length == 1)
            return confirmed[0];
    }
    return null;
})(rule, sourceValue, sourcePayload);
