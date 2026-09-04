// {"id": "3e1ba9f493e6c754e3aef0aefaba10cb", "name": "USEM Serial Number Class Match", "order": "175", "active": "true", "scope": "undefined", "created_by": "ZK5LG9V", "updated": "2026-08-10 14:42:01", "source_field": "SERIAL_NUMBER", "target_table_product_model": "cmdb_application_product_model", "description": "Serial number resolved strictly inside the CI class implied by the scanned OS. Junk serials filtered; unique owner required.", "source": "Qualys Cloud Platform [ed44bdc453220300e8f9f745911c0801]", "type": "Custom [custom]", "reapply_version": "3", "lookup_target": "Configuration item [ci]", "table": "sn_vul_qualys_host_attrb", "method": "Script [script]", "reapply": "true [1]"}
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)
        return null;
    var serial = ('' + sourceValue).trim();
    var junk = ',0,none,n/a,na,unknown,empty,not specified,not available,no serial,' +
        'default string,to be filled by o.e.m.,system serial number,chassis serial number,' +
        '0123456789,1234567890,';
    if (serial.length < 4 || junk.indexOf(',' + serial.toLowerCase() + ',') != -1)
        return null;

    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');

    function classFor(os) {
        if (!os) return '';
        var s = ('' + os).toLowerCase();
        if (s.split('/').length > 2) return ''; // unauthenticated multi-guess fingerprint
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

    // stage 1 of serial matching: resolve only inside the CI class implied by
    // the scanned OS, so class evidence and serial evidence must agree
    var pref = classFor(sourcePayload.OS);
    if (!pref)
        return null; // no reliable OS fingerprint -> hardware-stage rule takes over
    var gr = new GlideRecord(pref);
    if (!gr.isValid())
        return null;
    gr.addQuery('serial_number', serial);
    if (ignore)
        gr.addQuery('sys_class_name', 'NOT IN', ignore);
    gr.setLimit(3);
    gr.query();
    var hit = null, n = 0;
    while (gr.next()) {
        n++;
        if (n == 1)
            hit = gr.getUniqueValue();
    }
    return n == 1 ? hit : null;

    /* Targeted payload sample (Qualys Host Detection):
       {"ID":"35832680","IP":"171.128.225.96","TRACKING_METHOD":"AGENT",
        "OS":"Red Hat Enterprise Linux 9.8",
        "DNS":"ah-1047132-001.sdi.corp.bankofamerica.com",
        "SERIAL_NUMBER":"VMware-42 1a 9c 3f 7d 2e 61 b8-55 04 e2 91 6a 27 c3 08"}
       OS maps to cmdb_ci_linux_server; the serial must belong to exactly one
       Linux server CI. SERIAL_NUMBER is absent from the current Host Detection
       extract (0 of 21,000 hosts) and arrives once Qualys asset inventory
       (CSAM) data is enabled in the feed. */
})(rule, sourceValue, sourcePayload);