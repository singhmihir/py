// {"id": "ef4a4df2932a4310e3aef0aefaba1066", "name": "USEM Layered DNS Match", "order": "350", "active": "true", "scope": "undefined", "created_by": "ZK5LG9V", "updated": "2026-08-10 14:17:12", "source_field": "DNS", "target_table_product_model": "cmdb_application_product_model", "description": "Resolves the scanned DNS name through the layered CMDB model (DNS name -> IP address -> adapter -> owning CI) so aliases land on the device that answers on that name.", "source": "Qualys Cloud Platform [ed44bdc453220300e8f9f745911c0801]", "type": "Custom [custom]", "reapply_version": "1", "lookup_target": "Configuration item [ci]", "table": "sn_vul_qualys_host_attrb", "method": "Script [script]", "reapply": "true [1]"}
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)
        return null;
    var fqdn = ('' + sourceValue).trim().toLowerCase();
    if (fqdn.indexOf('.') == -1)
        return null;
    var ip = sourcePayload.IP ? '' + sourcePayload.IP : '';

    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');

    // layered DNS model: DNS name -> IP address record -> adapter -> owning CI.
    // This is the record chain CMDB discovery maintains, so a match here lands
    // on the device that actually answers on that name (aliases included).
    var gr = new GlideRecord('cmdb_ip_address_dns_name');
    if (!gr.isValid())
        return null;
    gr.addQuery('dns_name.name', fqdn);
    gr.addNotNullQuery('ip_address.nic.cmdb_ci');
    if (ignore)
        gr.addQuery('ip_address.nic.cmdb_ci.sys_class_name', 'NOT IN', ignore);
    gr.setLimit(10);
    gr.query();
    var owners = {}, ipOwners = {}, count = 0, first = null;
    while (gr.next()) {
        var owner = '' + gr.ip_address.nic.cmdb_ci;
        if (!owners[owner]) {
            owners[owner] = true;
            count++;
            if (count == 1)
                first = owner;
        }
        if (ip && ('' + gr.ip_address.ip_address) == ip)
            ipOwners[owner] = true;
    }
    if (count == 1)
        return first;
    if (count > 1) {
        var confirmed = Object.keys(ipOwners);
        if (confirmed.length == 1)
            return confirmed[0];
    }
    return null;

    /* Targeted payload sample (Qualys Host Detection):
       {"ID":"42773078","IP":"167.202.60.26","TRACKING_METHOD":"IP",
        "OS":"Red Hat Enterprise Linux Server 7.9",
        "DNS":"hklvteqoradbp3.hk.baml.com",
        "QG_HOSTID":"6337dede-02e7-0002-ad2c-0050569765df"}
       Resolves "hklvteqoradbp3.hk.baml.com" through
       cmdb_ip_address_dns_name -> cmdb_ci_ip_address -> adapter -> owning CI,
       with the scanned IP as tie-breaker when several owners share the name. */
})(rule, sourceValue, sourcePayload);