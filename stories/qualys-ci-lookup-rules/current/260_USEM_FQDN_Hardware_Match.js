// {"id": "97ff4d7e936a4310e3aef0aefaba1010", "name": "USEM FQDN Hardware Match", "order": "260", "active": "true", "scope": "undefined", "created_by": "ZK5LG9V", "updated": "2026-08-10 14:42:02", "source_field": "DNS", "target_table_product_model": "cmdb_application_product_model", "description": "Exact FQDN across the cmdb_ci_hardware subtree; duplicate FQDNs resolve only when the scanned IP corroborates a single candidate.", "source": "Qualys Cloud Platform [ed44bdc453220300e8f9f745911c0801]", "type": "Custom [custom]", "reapply_version": "1", "lookup_target": "Configuration item [ci]", "table": "sn_vul_qualys_host_attrb", "method": "Script [script]", "reapply": "true [1]"}
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)
        return null;
    var fqdn = ('' + sourceValue).trim().toLowerCase();
    if (fqdn.indexOf('.') == -1)
        return null; // bare labels are handled by the hostname rules
    var ip = sourcePayload.IP ? '' + sourcePayload.IP : '';

    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');

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

    return pickFqdn('cmdb_ci_hardware');

    /* Targeted payload sample (Qualys Host Detection, unauthenticated scan):
       {"ID":"35920204","IP":"171.135.28.125","TRACKING_METHOD":"IP",
        "OS":"Ubuntu / Tiny Core Linux / Linux 2.6.x / IBM ASM / HP StoreOnce / F5 Networks Big-IP / Cisco IOS Software",
        "DNS":"txr9gxcenah031.sdi.corp.bankofamerica.com"}
       No usable class preference from the OS fingerprint, so the exact FQDN is
       resolved across the cmdb_ci_hardware subtree -- still requiring a unique
       (or IP-corroborated) owner. */
})(rule, sourceValue, sourcePayload);