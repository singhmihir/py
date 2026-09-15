// {"id": "816a0136932a4310e3aef0aefaba10bc", "name": "USEM Hostname Class Match", "order": "400", "active": "true", "scope": "undefined", "created_by": "ZK5LG9V", "updated": "2026-08-10 14:42:01", "source_field": "DNS", "target_table_product_model": "cmdb_application_product_model", "description": "Unique short hostname inside the OS-implied class, for CIs without FQDN/domain data.", "source": "Qualys Cloud Platform [ed44bdc453220300e8f9f745911c0801]", "type": "Custom [custom]", "reapply_version": "2", "lookup_target": "Configuration item [ci]", "table": "sn_vul_qualys_host_attrb", "method": "Script [script]", "reapply": "true [1]"}
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)
        return null;
    var full = ('' + sourceValue).trim().toLowerCase();
    var host = full.split('.')[0];
    if (!host)
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

    // short-name match inside the OS-implied class only; class agreement is
    // implicit, so no further guard is needed at this stage
    var pref = classFor(sourcePayload.OS);
    if (!pref)
        return null; // no class evidence -> hardware-stage rule takes over
    var gr = new GlideRecord(pref);
    if (!gr.isValid())
        return null;
    gr.addQuery('name', host);
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
    return n == 1 ? hit : null; // never guess between same-named CIs

    /* Targeted payload sample (Qualys Host Detection):
       {"ID":"35850078","IP":"30.143.70.11","TRACKING_METHOD":"IP",
        "OS":"Windows Server 2016 Standard 64 bit Edition Version 1607",
        "DNS":"wsaoi01zeapd1.sdi.corp.bankofamerica.com",
        "NETBIOS":"WSAOI01ZEAPD1"}
       When no CI carries FQDN or domain fields, the short name
       "wsaoi01zeapd1" must be unique within cmdb_ci_win_server (name matching
       is case-insensitive, so upper-case CMDB names match). */
})(rule, sourceValue, sourcePayload);