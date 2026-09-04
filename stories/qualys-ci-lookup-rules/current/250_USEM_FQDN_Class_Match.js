// {"id": "b3f9e0a493a60754e3aef0aefaba102f", "name": "USEM FQDN Class Match", "order": "250", "active": "true", "scope": "undefined", "created_by": "ZK5LG9V", "updated": "2026-08-10 14:42:01", "source_field": "DNS", "target_table_product_model": "cmdb_application_product_model", "description": "Exact FQDN inside the OS-implied class; duplicate FQDNs resolve only when the scanned IP corroborates a single candidate.", "source": "Qualys Cloud Platform [ed44bdc453220300e8f9f745911c0801]", "type": "Custom [custom]", "reapply_version": "4", "lookup_target": "Configuration item [ci]", "table": "sn_vul_qualys_host_attrb", "method": "Script [script]", "reapply": "true [1]", "lookup_script": "DNS [89269effc3120300a1cedb1122d3ae79]"}
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)
        return null;
    var fqdn = ('' + sourceValue).trim().toLowerCase();
    if (fqdn.indexOf('.') == -1)
        return null; // bare labels are handled by the hostname rules
    var ip = sourcePayload.IP ? '' + sourcePayload.IP : '';

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

    function pickFqdn(table) {
        var gr = new GlideRecord(table);
        if (!gr.isValid())
            return null;
        gr.addQuery('fqdn', fqdn);
        if (ignore)
            gr.addQuery('sys_class_name', 'NOT IN', ignore);
        gr.setLimit(10);
        gr.query();
        var ids = [], ipHits = [];
        while (gr.next()) {
            ids.push(gr.getUniqueValue());
            if (ip && gr.getValue('ip_address') == ip)
                ipHits.push(gr.getUniqueValue());
        }
        if (ids.length == 1)
            return ids[0];
        // several CIs carry this FQDN: accept only when the scanned IP
        // corroborates exactly one of them, otherwise defer down the chain
        if (ids.length > 1 && ipHits.length == 1)
            return ipHits[0];
        return null;
    }

    var pref = classFor(sourcePayload.OS);
    if (!pref)
        return null; // no class evidence -> hardware-stage rule takes over
    return pickFqdn(pref);

    /* Targeted payload sample (Qualys Host Detection):
       {"ID":"83047612","IP":"30.206.199.36","TRACKING_METHOD":"IP",
        "OS":"VMware ESXi 7.0.3 build 24723872",
        "DNS":"vsdnac22xsdi004.sdi.corp.bankofamerica.com"}
       OS maps to cmdb_ci_esx_server; the exact FQDN must resolve to a single
       ESX server CI (scanned IP breaks duplicate-FQDN ties). A same-FQDN CI
       in another class can never be picked by this stage. */
})(rule, sourceValue, sourcePayload);