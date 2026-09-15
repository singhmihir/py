// {"id": "23ff4d7e936a4310e3aef0aefaba1072", "name": "USEM IP Layered Match", "order": "740", "active": "true", "scope": "undefined", "created_by": "ZK5LG9V", "updated": "2026-08-10 14:42:03", "source_field": "IP", "target_table_product_model": "cmdb_application_product_model", "description": "Last-resort IP matching, stage 4: address resolved through the layered IP model (IP record -> adapter -> owning CI); VIPs rejected.", "source": "Qualys Cloud Platform [ed44bdc453220300e8f9f745911c0801]", "type": "Custom [custom]", "reapply_version": "1", "lookup_target": "Configuration item [ci]", "table": "sn_vul_qualys_host_attrb", "method": "Script [script]", "reapply": "true [1]"}
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

    // layered IP model: IP address record -> adapter -> owning CI
    var ipGr = new GlideRecord('cmdb_ci_ip_address');
    if (!ipGr.isValid())
        return null;
    ipGr.addQuery('ip_address', ip);
    ipGr.addNotNullQuery('nic.cmdb_ci');
    if (ignore)
        ipGr.addQuery('nic.cmdb_ci.sys_class_name', 'NOT IN', ignore);
    ipGr.setLimit(10);
    ipGr.query();
    var owners = {}, count = 0, first = null;
    while (ipGr.next()) {
        var o = '' + ipGr.nic.cmdb_ci;
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
       Final IP stage: resolves through the discovery data model
       (cmdb_ci_ip_address -> adapter -> owning CI). Exactly one distinct
       owner required; VIPs rejected. */
})(rule, sourceValue, sourcePayload);