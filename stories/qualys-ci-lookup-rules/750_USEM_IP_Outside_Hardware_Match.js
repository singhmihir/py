/* USEM IP Outside Hardware Match
   -------------------------------------------------------------------------------------------------
   Some addresses belong to CIs the CMDB keeps outside the Hardware tree: a vCenter (an Application
   class), a cluster virtual IP, an IP Phone or an Imaging Hardware device (scanners and the like).
   The address rules search hardware records, adapters and IP Address records only, so a host
   scanned on such an address stays unmatched. This rule looks the scanned address up in exactly
   those four classes, as the Discovery status enrichment (Shazzam) does for its "IP in CMDB"
   column: the one CI found on the address is the match, and a cluster virtual IP stands for its
   cluster.

   Sample payload (one Qualys host record, used in every note below)
   {
     "ID": "91402286",
     "IP": "10.44.18.25",
     "TRACKING_METHOD": "IP",
     "DNS": "sqlclu01.bankofamerica.com",
     "OS": "Windows Server 2019 Standard 64 bit Edition Version 1809"
   }
   Input  : sourceValue is the IP field, "10.44.18.25"; the rule also reads the OS from
            sourcePayload.
   Returns: the sys_id of the one vCenter, IP Phone or Imaging Hardware CI carrying the address, or
            of the cluster whose virtual IP carries it; null when none or two different CIs carry
            it, when a virtual IP names no cluster, or when a server or desktop OS is scanned on a
            phone or imaging address.
   Sample : the cluster "SQLCLU01": its virtual IP record "SQLCLU01-VIP" carries "10.44.18.25"; the
            Windows Server fingerprint is the node answering on the address and rules nothing out
            for a cluster.

   Place in the chain (the first rule to return a CI wins; a null hands the host to the next rule)
   Before : USEM IP Layered Match and the other address rules found no hardware record, adapter or
            IP Address record carrying the address (or declined what they found), and every name
            rule before them declined.
   Reaches: hosts whose address is carried only by a vCenter, a cluster virtual IP, an IP phone or
            an imaging device; phones and scanners named in DNS were already taken by USEM Device
            Name Match.
   After  : USEM FQDN Name Broad Match, then the platform's own rules.
   ------------------------------------------------------------------------------------------------- */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // nothing to look up
        return null;
    var ip = ('' + sourceValue).trim();           // "10.44.18.25"
    // loopback and link-local identify nothing
    if (!ip || ip.indexOf('127.') == 0 || ip.indexOf('169.254.') == 0)
        return null;

    // Classes that must never be matched (placeholder and technical CIs); the list lives in the
    // property sn_sec_cmn.ignoreCIClass and the framework may pass it in as _ignoreClass.
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');

    // -- The scanned OS may rule out a phone or an imaging device ---------------------------------
    // A phone or a scanner reports no OS to an unauthenticated scan, or an embedded Linux kernel,
    // "Unknown OS" or a vendor name. An OS that clearly names a server or desktop system (Windows,
    // ESXi, AIX, Solaris, HP-UX) scanned on a phone or imaging address means the address now
    // belongs to another machine, so those two classes are not counted; a Linux kernel fingerprint
    // and anything mentioning a phone are accepted, as in USEM Device Name Match. A vCenter and a
    // cluster answer with the OS of the machine behind the address, so the OS rules nothing out for
    // them.
    // Sample: the sample reports Windows Server 2019, which would rule out a phone or an imaging
    //         device on "10.44.18.25"; the virtual IP found there is still counted.
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
    var os = ('' + (sourcePayload.OS || '')).toLowerCase();
    var pref = classFor(os);
    var notDevice = !!pref && pref != 'cmdb_ci_linux_server' && os.indexOf('phone') == -1;

    // -- Search the four classes outside the Hardware tree on the address -------------------------
    // Each class is searched on ip_address, sub-classes included, with the ignored classes left
    // out. A vCenter, a phone or an imaging device is the CI itself; a cluster virtual IP stands
    // for the cluster it names, because the node answering on a virtual address changes with every
    // failover while the cluster does not. A virtual IP that names no cluster leaves the address
    // unexplained and the rule declines.
    // Sample: cmdb_ci_cluster_vip holds "SQLCLU01-VIP" on "10.44.18.25" naming the cluster
    //         "SQLCLU01", so found holds that cluster; the vCenter, phone and imaging classes hold
    //         nothing on the address.
    // viaCluster: the record stands for its cluster; device: phone or imaging
    var classes = [
        {table: 'cmdb_ci_vcenter', viaCluster: false, device: false},
        {table: 'cmdb_ci_cluster_vip', viaCluster: true, device: false},
        {table: 'cmdb_ci_ip_phone', viaCluster: false, device: true},
        {table: 'cmdb_ci_imaging_hardware', viaCluster: false, device: true}
    ];
    var found = [], unnamed = false;
    for (var i = 0; i < classes.length; i++) {
        if (classes[i].device && notDevice)       // a server or desktop OS on a device address
            continue;
        var gr = new GlideRecord(classes[i].table);
        if (!gr.isValid())                        // class not installed here, try the next one
            continue;
        gr.addQuery('ip_address', ip);
        if (ignore)
            gr.addQuery('sys_class_name', 'NOT IN', ignore);
        gr.query();
        while (gr.next()) {
            var id = classes[i].viaCluster ? (gr.getValue('cluster') || '') : gr.getUniqueValue();
            if (!id)
                unnamed = true;
            else if (found.indexOf(id) == -1)
                found.push(id);
        }
    }

    // -- Exactly one CI on the address, or none ---------------------------------------------------
    // One CI is the match, however many records led to it (two virtual IP records of one cluster
    // name the same cluster). Two different CIs on one address, a virtual IP without a cluster, or
    // a cluster of an ignored class leave the address ambiguous and the rule declines, so nothing
    // is guessed.
    // Sample: found holds the one cluster "SQLCLU01", which is not an ignored class, so its sys_id
    //         is returned. Were a vCenter also on "10.44.18.25", found would hold two CIs and the
    //         rule would decline.
    if (unnamed || found.length != 1)
        return null;
    var ci = new GlideRecord('cmdb_ci');
    ci.addQuery('sys_id', found[0]);
    if (ignore)
        ci.addQuery('sys_class_name', 'NOT IN', ignore);
    ci.query();
    return ci.next() ? found[0] : null;
})(rule, sourceValue, sourcePayload);
