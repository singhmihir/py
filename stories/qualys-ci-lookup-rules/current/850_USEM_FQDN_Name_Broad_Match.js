// {"id": "abff4d7e936a4310e3aef0aefaba1076", "name": "USEM FQDN Name Broad Match", "order": "850", "active": "true", "scope": "undefined", "created_by": "ZK5LG9V", "updated": "2026-08-10 14:42:03", "source_field": "DNS", "target_table_product_model": "cmdb_application_product_model", "description": "The single deliberately-late broad fallback: CI named with the full FQDN anywhere outside the ignored classes; unique owner required.", "source": "Qualys Cloud Platform [ed44bdc453220300e8f9f745911c0801]", "type": "Custom [custom]", "reapply_version": "1", "lookup_target": "Configuration item [ci]", "table": "sn_vul_qualys_host_attrb", "method": "Script [script]", "reapply": "true [1]"}
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)
        return null;
    var fqdn = ('' + sourceValue).trim().toLowerCase();
    if (fqdn.indexOf('.') == -1)
        return null;

    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');

    // deliberate late-stage fallback: the only rule that searches the broad
    // CI table by name, kept at the end of the custom chain so every scoped
    // rule gets the first chance. Still requires a unique, non-ignored owner.
    var gr = new GlideRecord('cmdb_ci');
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
       Fires only when every hardware-scoped rule has declined -- e.g. the CI
       named with this FQDN exists outside the hardware subtree. Broad cmdb_ci
       matching is confined to this one explicitly-late rule. */
})(rule, sourceValue, sourcePayload);