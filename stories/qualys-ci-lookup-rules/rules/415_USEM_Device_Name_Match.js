/* USEM Device Name Match
   -------------------------------------------------------------------------------------------------
   Two device classes sit outside the Hardware tree of the CMDB: IP Phone extends the base CI class
   directly and Scanner sits under Imaging Hardware. The hardware-wide name rules never see those
   records, and the class rules need an OS that a phone or a scanner does not report to an
   unauthenticated scan. This rule looks for the scanned host name in exactly those classes: one
   device carrying the name is the match, and when the name is shared the scanned address breaks the
   tie.

   Sample payload (one Qualys host record, used in every note below)
   {
     "ID": "753026617",
     "IP": "10.190.29.132",
     "TRACKING_METHOD": "IP",
     "DNS": "avxdd008a.cc.bofa.com"
   }
   Input  : sourceValue is the DNS field, "avxdd008a.cc.bofa.com"; the rule also reads the OS and
            the IP from sourcePayload.
   Returns: the sys_id of the one IP Phone or Imaging Hardware CI named with the host name; when
            several carry it, the one whose ip_address is the scanned address; null otherwise, and
            null when the scanned OS names a server or desktop system.
   Sample : the IP Phone CI "AVXDD008A" (an Avaya station named "avx" plus the tail of its MAC
            address), whose ip_address is also "10.190.29.132".

   Place in the chain (the first rule to return a CI wins; a null hands the host to the next rule)
   Before : USEM Hostname Hardware Match searched the Hardware tree for the plain host name; the
            phone and scanner classes are not in that tree, so it declined, and every earlier rule
            needed an OS class, a serial or a Cisco phone label.
   Reaches: phones and scanners named in DNS, which in our feed scan without an OS; in the
            contact-centre domain cc.bofa.com nearly every host is such a phone.
   After  : USEM Management Interface Match, then the interface, service and address rules.
   ------------------------------------------------------------------------------------------------- */
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // nothing to look up
        return null;
    var full = ('' + sourceValue).trim().toLowerCase();  // "avxdd008a.cc.bofa.com"
    var host = full.split('.')[0];                // "avxdd008a"
    if (!host)
        return null;
    // "10.190.29.132", only used to break a tie
    var ip = sourcePayload.IP ? '' + sourcePayload.IP : '';

    // Classes that must never be matched (placeholder and technical CIs); the list lives in the
    // property sn_sec_cmn.ignoreCIClass and the framework may pass it in as _ignoreClass.
    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');

    // -- The scanned OS must not name a different kind of machine ---------------------------------
    // A phone or a scanner reports no OS to an unauthenticated scan, or a guess such as an embedded
    // Linux kernel, "Unknown OS" or a vendor name. Only an OS that clearly names a server or
    // desktop system (Windows, ESXi, AIX, Solaris, HP-UX) rules the device out; a Linux kernel
    // fingerprint is what an appliance shows and is accepted, and so is anything that mentions a
    // phone.
    // Sample: the sample carries no OS, so nothing rules the device out; "Foundry Networks",
    //         "Unknown OS" or "Linux 2.x" on a phone would pass too, "Windows 10 Enterprise" would
    //         end the rule here.
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
    if (pref && pref != 'cmdb_ci_linux_server' && os.indexOf('phone') == -1)
        return null;

    // -- Search the device classes outside the Hardware tree --------------------------------------
    // Each class is searched by name, sub-classes included, with the ignored classes left out. The
    // classes are listed here rather than derived because they are exactly the device classes the
    // CMDB keeps outside the Hardware tree; a scanner or phone record loaded elsewhere is not the
    // concern of this rule.
    // Sample: cmdb_ci_ip_phone holds one record named "AVXDD008A" (the query is not case-sensitive)
    //         with ip_address "10.190.29.132"; cmdb_ci_imaging_hardware holds none, so found has
    //         one entry and onAddress the same one.
    // IP phones; scanners and other imaging devices
    var classes = ['cmdb_ci_ip_phone', 'cmdb_ci_imaging_hardware'];
    var found = [], onAddress = [];
    for (var i = 0; i < classes.length; i++) {
        var gr = new GlideRecord(classes[i]);
        if (!gr.isValid())                        // class not installed here, try the next one
            continue;
        gr.addQuery('name', host);
        if (ignore)
            gr.addQuery('sys_class_name', 'NOT IN', ignore);
        gr.query();
        while (gr.next()) {
            found.push(gr.getUniqueValue());
            if (ip && ('' + gr.getValue('ip_address')) == ip)
                onAddress.push(gr.getUniqueValue());
        }
    }

    // -- One device carrying the name, the scanned address as the tie-break -----------------------
    // One device named with the host is the match: a phone name is built from its MAC address and a
    // scanner name from its asset label, so the name alone identifies the device even after its
    // DHCP address has changed. When the name is shared (a phone re-registered under a new record,
    // a scanner loaded twice) the one whose ip_address is the scanned address is taken, and only
    // when exactly one carries it; otherwise the rule declines.
    // Sample: found holds the one IP Phone "AVXDD008A", so its sys_id is returned. Were a second
    //         phone named "avxdd008a", only the one on "10.190.29.132" would be taken; two phones
    //         on that address would make the rule decline.
    if (found.length == 1)
        return found[0];
    if (found.length > 1 && onAddress.length == 1)
        return onAddress[0];
    return null;
})(rule, sourceValue, sourcePayload);
