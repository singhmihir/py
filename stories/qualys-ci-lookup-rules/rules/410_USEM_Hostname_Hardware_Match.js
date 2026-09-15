/* USEM Hostname Hardware Match
   -------------------------------------------------------------------------------------------------
   The short hostname across the whole hardware tree, with a check that the CI found does not
   contradict the scanned OS. For CIs kept in a parent class (Server, Computer, Hardware) or in a
   different class than the OS suggests.

   Sample payload (one Qualys host record, used in every note below)
   {
     "ID": "80217765",
     "IP": "171.150.219.123",
     "TRACKING_METHOD": "IP",
     "OS": "AIX 7.3 TL3",
     "DNS": "va2ausapabw0.bankofamerica.com",
     "QG_HOSTID": "6337e0dc-007d-0002-c47d-005056a4fcd5"
   }
   Input  : sourceValue is the DNS field, "va2ausapabw0.bankofamerica.com"; the rule also reads the
            OS from sourcePayload.
   Returns: the sys_id of the one hardware CI named with the short hostname, accepted when its class
            is the one the OS implies, a sub-class of it or a parent of it, or an appliance class
            (Network Gear, Load Balancer, Storage Server) for a Linux fingerprint; null when the
            name is shared or the class contradicts the scan.
   Sample : the CI named "va2ausapabw0" in the plain Server class, a parent of AIX Server; it would
            also be accepted as an AIX Server, and rejected as, say, a Windows Server or an IP
            Router.

   Place in the chain (the first rule to return a CI wins; a null hands the host to the next rule)
   Before : USEM Hostname Class Match required the short name to be unique inside the class the OS
            implies (AIX Server) and found nothing there.
   Reaches: hosts whose CI is kept in a parent class or whose OS gave no class.
   After  : USEM FQDN Name Hardware Match, then the IP address rules for hosts without a usable
            name.
   ------------------------------------------------------------------------------------------------- */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // nothing to look up
        return null;
    var full = ('' + sourceValue).trim().toLowerCase();  // "va2ausapabw0.bankofamerica.com"
    var host = full.split('.')[0];                // "va2ausapabw0"
    if (!host)
        return null;

    // Classes that must never be matched (placeholder and technical CIs); the list lives in the
    // property sn_sec_cmn.ignoreCIClass and the framework may pass it in as _ignoreClass.
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');

    // -- Class the scanned OS implies, kept as a preference ---------------------------------------
    // This rule searches the whole hardware tree, so the class is not a filter here; it is checked
    // at the end to reject a CI whose class contradicts the scan. An unknown OS gives no class and
    // then no check is made.
    // Sample: classFor("AIX 7.3 TL3") gives AIX Server, so pref is cmdb_ci_aix_server; it is only
    //         used in the last stage.
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

    // -- Short name search across the hardware tree -----------------------------------------------
    // Nothing is filtered by class here; the two checks that follow provide the safety.
    // Sample: the search on cmdb_ci_hardware for name "va2ausapabw0" finds the Server
    //         "va2ausapabw0", class cmdb_ci_server.
    var gr = new GlideRecord('cmdb_ci_hardware');  // Hardware and every class beneath it
    gr.addQuery('name', host);
    if (ignore)
        gr.addQuery('sys_class_name', 'NOT IN', ignore);

    // -- Exactly one CI carries the value ---------------------------------------------------------
    // The first row is remembered with its class; a second row means two hardware CIs with one
    // short name (a test and a production box, a retired and a rebuilt one), which the name alone
    // cannot tell apart and the rule declines.
    // Sample: one row, so id is the sys_id of "va2ausapabw0" and cls is "cmdb_ci_server". A second
    //         CI with that name would end the rule here.
    gr.query();
    if (!gr.next())
        return null;
    var id = gr.getUniqueValue();
    var cls = '' + gr.getValue('sys_class_name');
    if (gr.hasNext())
        return null;

    // -- Reject a CI whose class contradicts the scanned OS ---------------------------------------
    // When the OS gave a class, the CI found must be of that class, of a sub-class of it, or of a
    // parent of it. A host that lands on a Windows Server by name or address is a namesake or a
    // reused address, not the same machine, and its findings would go to the wrong owner.
    // Sample: pref is cmdb_ci_aix_server and cls is cmdb_ci_server, a parent of AIX Server, so
    //         agrees() is true and the sys_id is returned. A Windows Server or an IP Router named
    //         "va2ausapabw0" is neither a sub-class nor a parent of AIX Server and the rule would
    //         decline. An IP Switch named "cncnshasd03sae0002" scanned as "Ubuntu/Linux" is
    //         accepted: the switch reports the Linux it runs on.
    if (!agrees(cls))
        return null;
    return id;
})(rule, sourceValue, sourcePayload);
