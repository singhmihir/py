// {"id": "97ff4d7e936a4310e3aef0aefaba106d", "name": "USEM IP Adapter Match", "order": "730", "active": "true", "scope": "undefined", "created_by": "ZK5LG9V", "updated": "2026-08-10 14:42:02", "source_field": "IP", "target_table_product_model": "cmdb_application_product_model", "description": "Last-resort IP matching, stage 3: address resolved through the network adapter to a single owning CI; VIPs rejected.", "source": "Qualys Cloud Platform [ed44bdc453220300e8f9f745911c0801]", "type": "Custom [custom]", "reapply_version": "1", "lookup_target": "Configuration item [ci]", "table": "sn_vul_qualys_host_attrb", "method": "Script [script]", "reapply": "true [1]"}
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)
        return null;
    var ip = ('' + sourceValue).trim();
    if (!ip || ip.indexOf('127.') == 0 || ip.indexOf('169.254.') == 0)
        return null;

    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');

    function isLoadBalancer(id) {
        var lb = new GlideRecord('cmdb_ci_lb');
        return lb.isValid() && lb.get(id);
    }

    // the address may live on a network adapter rather than the CI record
    var nic = new GlideRecord('cmdb_ci_network_adapter');
    nic.addQuery('ip_address', ip);
    nic.addNotNullQuery('cmdb_ci');
    if (ignore)
        nic.addQuery('cmdb_ci.sys_class_name', 'NOT IN', ignore);
    nic.setLimit(10);
    nic.query();
    var owners = {}, count = 0, first = null;
    while (nic.next()) {
        var o = nic.getValue('cmdb_ci');
        if (!owners[o]) {
            owners[o] = true;
            count++;
            if (count == 1)
                first = o;
        }
    }
    if (count == 1 && !isLoadBalancer(first))
        return first;
    return null;

    /* Targeted payload sample (Qualys Host Detection):
       {"ID":"83047621","IP":"30.162.178.21","TRACKING_METHOD":"IP",
        "OS":"VMware ESXi 7.0.3 build 24723872"}
       Resolves the scanned address through cmdb_ci_network_adapter to its
       owning CI when the address is tracked on the adapter instead of the CI
       record. Exactly one distinct owner required; VIPs rejected. */
})(rule, sourceValue, sourcePayload);