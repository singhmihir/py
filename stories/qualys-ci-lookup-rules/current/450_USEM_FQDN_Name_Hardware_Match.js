// {"id": "a34a4df2932a4310e3aef0aefaba1089", "name": "USEM FQDN Name Hardware Match", "order": "450", "active": "true", "scope": "undefined", "created_by": "ZK5LG9V", "updated": "2026-08-10 14:42:02", "source_field": "DNS", "target_table_product_model": "cmdb_application_product_model", "description": "CI named with the full FQDN string, hardware subtree only; unique owner required.", "source": "Qualys Cloud Platform [ed44bdc453220300e8f9f745911c0801]", "type": "Custom [custom]", "reapply_version": "2", "lookup_target": "Configuration item [ci]", "table": "sn_vul_qualys_host_attrb", "method": "Script [script]", "reapply": "true [1]"}
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)
        return null;
    var fqdn = ('' + sourceValue).trim().toLowerCase();
    if (fqdn.indexOf('.') == -1)
        return null;

    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');

    // some CMDB sources name the CI with the full FQDN string
    var gr = new GlideRecord('cmdb_ci_hardware');
    gr.addQuery('name', fqdn);
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
       {"ID":"71973166","IP":"164.91.209.12","TRACKING_METHOD":"AGENT",
        "OS":"Red Hat Enterprise Linux 8.10",
        "DNS":"lva40bneehcs01.ecomm.devicenp.rpg",
        "QG_HOSTID":"633781ed-019b-0002-2f2f-0050569d20ff"}
       The .rpg appliance domains are commonly loaded with the full FQDN as the
       CI name; matches name = "lva40bneehcs01.ecomm.devicenp.rpg" within the
       cmdb_ci_hardware subtree, requiring a unique owner. */
})(rule, sourceValue, sourcePayload);