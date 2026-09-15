// {"id": "321b2db4932ac754e3aef0aefaba1052", "name": "USEM Cisco IP Phone MAC", "order": "200", "active": "true", "scope": "undefined", "created_by": "ZK5LG9V", "updated": "2026-08-10 14:17:11", "source_field": "DNS", "target_table_product_model": "cmdb_application_product_model", "description": "Cisco Unified CM phones report SEP<MAC> as their DNS label. Derives the MAC and matches strictly within cmdb_ci_ip_phone (adapter, mac_address, or SEP device name).", "source": "Qualys Cloud Platform [ed44bdc453220300e8f9f745911c0801]", "type": "Custom [custom]", "reapply_version": "2", "lookup_target": "Configuration item [ci]", "table": "sn_vul_qualys_host_attrb", "method": "Script [script]", "reapply": "true [1]"}
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)
        return null;
    // Cisco Unified CM registers phones as SEP<MAC>; Qualys reports that label
    // as the DNS hostname. Scope strictly to IP phone CIs so a MAC collision
    // can never pull a server or network device.
    var label = ('' + sourceValue).split('.')[0].toLowerCase();
    var m = label.match(/^sep([0-9a-f]{12})$/);
    if (!m)
        return null;
    var hex = m[1];
    var pairs = [];
    for (var i = 0; i < 12; i += 2)
        pairs.push(hex.substr(i, 2));
    var colon = pairs.join(':');
    var candidates = [colon.toUpperCase(), colon, hex.toUpperCase(), hex];

    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');

    // adapter owned by an IP phone CI
    var nic = new GlideRecord('cmdb_ci_network_adapter');
    nic.addQuery('mac_address', 'IN', candidates.join(','));
    nic.addNotNullQuery('cmdb_ci');
    nic.setLimit(10);
    nic.query();
    var phones = {}, count = 0, first = null;
    while (nic.next()) {
        var owner = nic.getValue('cmdb_ci');
        var phone = new GlideRecord('cmdb_ci_ip_phone');
        if (phone.get(owner) && !phones[owner]) {
            phones[owner] = true;
            count++;
            if (count == 1)
                first = owner;
        }
    }
    if (count == 1)
        return first;

    // MAC held directly on the phone CI
    var ph = new GlideRecord('cmdb_ci_ip_phone');
    ph.addQuery('mac_address', 'IN', candidates.join(','));
    if (ignore)
        ph.addQuery('sys_class_name', 'NOT IN', ignore);
    ph.setLimit(3);
    ph.query();
    var hit = null, n = 0;
    while (ph.next()) {
        n++;
        if (n == 1)
            hit = ph.getUniqueValue();
    }
    if (n == 1)
        return hit;

    // phone named by its SEP label (Unified CM device name)
    var byName = new GlideRecord('cmdb_ci_ip_phone');
    byName.addQuery('name', label.toUpperCase());
    if (ignore)
        byName.addQuery('sys_class_name', 'NOT IN', ignore);
    byName.setLimit(3);
    byName.query();
    hit = null;
    n = 0;
    while (byName.next()) {
        n++;
        if (n == 1)
            hit = byName.getUniqueValue();
    }
    return n == 1 ? hit : null;

    /* Targeted payload sample (Qualys Host Detection, map/unauthenticated scan):
       {"ID":"41277345","IP":"30.144.62.108","TRACKING_METHOD":"IP",
        "OS":"Cisco IP Phone","DNS":"sep64f69dd5c9b0.voip.bankofamerica.com"}
       Label "sep64f69dd5c9b0" -> MAC 64:F6:9D:D5:C9:B0 -> unique
       cmdb_ci_ip_phone (via its network adapter, its mac_address field, or its
       SEP device name). Phones do not appear in the current server-focused
       extract; the rule is scoped ahead of the DNS rules so phone records can
       never be consumed by hostname matching. */
})(rule, sourceValue, sourcePayload);