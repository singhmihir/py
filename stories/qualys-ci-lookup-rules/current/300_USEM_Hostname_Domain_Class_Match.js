// {"id": "b3f9e0a493a60754e3aef0aefaba103f", "name": "USEM Hostname Domain Class Match", "order": "300", "active": "true", "scope": "undefined", "created_by": "ZK5LG9V", "updated": "2026-08-10 14:42:01", "source_field": "DNS", "target_table_product_model": "cmdb_application_product_model", "description": "Combination match inside the OS-implied class: CI name = hostname AND fqdn/dns_domain confirms the domain. Scanned IP breaks ties.", "source": "Qualys Cloud Platform [ed44bdc453220300e8f9f745911c0801]", "type": "Custom [custom]", "reapply_version": "5", "lookup_target": "Configuration item [ci]", "table": "sn_vul_qualys_host_attrb", "method": "Script [script]", "reapply": "true [1]"}
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)
        return null;
    var full = ('' + sourceValue).trim().toLowerCase();
    var dot = full.indexOf('.');
    if (dot < 1)
        return null; // needs hostname + domain
    var host = full.substring(0, dot);
    var domain = full.substring(dot + 1);
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

    function pickCombo(table) {
        var gr = new GlideRecord(table);
        if (!gr.isValid())
            return null;
        gr.addQuery('name', host);
        if (ignore)
            gr.addQuery('sys_class_name', 'NOT IN', ignore);
        gr.setLimit(10);
        gr.query();
        var good = [], ipHits = [];
        while (gr.next()) {
            // combination match: short name plus domain evidence on the CI
            var cifqdn = ('' + gr.getValue('fqdn')).toLowerCase();
            var cidom = ('' + gr.getValue('dns_domain')).toLowerCase();
            if (cifqdn == full || cidom == domain ||
                (cifqdn && cifqdn.indexOf(host + '.') == 0 && cifqdn.indexOf(domain) > 0)) {
                good.push(gr.getUniqueValue());
                if (ip && gr.getValue('ip_address') == ip)
                    ipHits.push(gr.getUniqueValue());
            }
        }
        if (good.length == 1)
            return good[0];
        if (good.length > 1 && ipHits.length == 1)
            return ipHits[0];
        return null;
    }

    var pref = classFor(sourcePayload.OS);
    if (!pref)
        return null; // no class evidence -> hardware-stage rule takes over
    return pickCombo(pref);

    /* Targeted payload sample (Qualys Host Detection):
       {"ID":"35832680","IP":"171.128.225.96","TRACKING_METHOD":"AGENT",
        "OS":"Red Hat Enterprise Linux 9.8",
        "DNS":"ah-1047132-001.sdi.corp.bankofamerica.com",
        "QG_HOSTID":"633769a4-0139-0002-e352-005056bf41ea"}
       Splits into hostname "ah-1047132-001" + domain
       "sdi.corp.bankofamerica.com"; matches a cmdb_ci_linux_server whose name
       is the hostname AND whose fqdn/dns_domain confirms the domain. The same
       short name registered in another domain can never be picked. */
})(rule, sourceValue, sourcePayload);