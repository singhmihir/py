// {"id": "1bff4d7e936a4310e3aef0aefaba105f", "name": "USEM Hostname Domain Hardware Match", "order": "310", "active": "true", "scope": "undefined", "created_by": "ZK5LG9V", "updated": "2026-08-10 14:42:02", "source_field": "DNS", "target_table_product_model": "cmdb_application_product_model", "description": "Combination match (name + domain evidence) across the cmdb_ci_hardware subtree for generically classed CIs. Scanned IP breaks ties.", "source": "Qualys Cloud Platform [ed44bdc453220300e8f9f745911c0801]", "type": "Custom [custom]", "reapply_version": "1", "lookup_target": "Configuration item [ci]", "table": "sn_vul_qualys_host_attrb", "method": "Script [script]", "reapply": "true [1]"}
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

    return pickCombo('cmdb_ci_hardware');

    /* Targeted payload sample (Qualys Host Detection):
       {"ID":"35884392","IP":"171.128.140.192","TRACKING_METHOD":"IP",
        "OS":"Ubuntu/Linux",
        "DNS":"lrche01xtrapd01.sdi.corp.bankofamerica.com"}
       Hostname "lrche01xtrapd01" + domain evidence resolved across the whole
       cmdb_ci_hardware subtree -- covers CIs classed generically (Server,
       Computer) or differently than the scanned OS suggests. */
})(rule, sourceValue, sourcePayload);