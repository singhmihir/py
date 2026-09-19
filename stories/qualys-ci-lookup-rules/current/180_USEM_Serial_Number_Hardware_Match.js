// {"id": "d7ff4d7e936a4310e3aef0aefaba100b", "name": "USEM Serial Number Hardware Match", "order": "180", "active": "true", "scope": "undefined", "created_by": "ZK5LG9V", "updated": "2026-08-10 14:42:02", "source_field": "SERIAL_NUMBER", "target_table_product_model": "cmdb_application_product_model", "description": "Serial number resolved across the cmdb_ci_hardware subtree when the OS gives no usable class. Junk serials filtered; unique owner required.", "source": "Qualys Cloud Platform [ed44bdc453220300e8f9f745911c0801]", "type": "Custom [custom]", "reapply_version": "1", "lookup_target": "Configuration item [ci]", "table": "sn_vul_qualys_host_attrb", "method": "Script [script]", "reapply": "true [1]"}
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)
        return null;
    var serial = ('' + sourceValue).trim();
    var junk = ',0,none,n/a,na,unknown,empty,not specified,not available,no serial,' +
        'default string,to be filled by o.e.m.,system serial number,chassis serial number,' +
        '0123456789,1234567890,';
    if (serial.length < 4 || junk.indexOf(',' + serial.toLowerCase() + ',') != -1)
        return null;

    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');

    // stage 2 of serial matching: the OS gave no usable class (or the CI is
    // classed differently) -- accept a unique serial owner anywhere in hardware
    var gr = new GlideRecord('cmdb_ci_hardware');
    gr.addQuery('serial_number', serial);
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

    /* Targeted payload sample (Qualys Host Detection, unauthenticated scan):
       {"ID":"35920204","IP":"171.135.28.125","TRACKING_METHOD":"IP",
        "OS":"Ubuntu / Tiny Core Linux / Linux 2.6.x / IBM ASM / HP StoreOnce / F5 Networks Big-IP / Cisco IOS Software",
        "DNS":"txr9gxcenah031.sdi.corp.bankofamerica.com",
        "SERIAL_NUMBER":"MXQ13005TC"}
       The multi-guess OS fingerprint gives no class preference, so a unique
       serial owner is accepted from the whole cmdb_ci_hardware subtree. */
})(rule, sourceValue, sourcePayload);