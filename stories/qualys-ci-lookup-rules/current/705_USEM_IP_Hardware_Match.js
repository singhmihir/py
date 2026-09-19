// {"id": "1fff4d7e936a4310e3aef0aefaba1068", "name": "USEM IP Hardware Match", "order": "705", "active": "true", "scope": "undefined", "created_by": "ZK5LG9V", "updated": "2026-08-10 14:42:02", "source_field": "IP", "target_table_product_model": "cmdb_application_product_model", "description": "Last-resort IP matching, stage 2: unique owner across cmdb_ci_hardware; load-balancer VIPs and OS-contradicting owners rejected.", "source": "Qualys Cloud Platform [ed44bdc453220300e8f9f745911c0801]", "type": "Custom [custom]", "reapply_version": "1", "lookup_target": "Configuration item [ci]", "table": "sn_vul_qualys_host_attrb", "method": "Script [script]", "reapply": "true [1]"}
(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)
        return null;
    var ip = ('' + sourceValue).trim();
    if (!ip || ip.indexOf('127.') == 0 || ip.indexOf('169.254.') == 0)
        return null;

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

    function isLoadBalancer(id) {
        var lb = new GlideRecord('cmdb_ci_lb');
        return lb.isValid() && lb.get(id);
    }

    var pref = classFor(sourcePayload.OS);
    var generic = {cmdb_ci_hardware: 1, cmdb_ci_computer: 1, cmdb_ci_server: 1,
        cmdb_ci_unix_server: 1};
    var gr = new GlideRecord('cmdb_ci_hardware');
    gr.addQuery('ip_address', ip);
    if (ignore)
        gr.addQuery('sys_class_name', 'NOT IN', ignore);
    gr.setLimit(3);
    gr.query();
    var n = 0, id = null, cls = '';
    while (gr.next()) {
        n++;
        if (n == 1) {
            id = gr.getUniqueValue();
            cls = '' + gr.getValue('sys_class_name');
        }
    }
    if (n != 1)
        return null; // an address answered by several CIs is never a safe match
    if (isLoadBalancer(id))
        return null; // a VIP answering for a pool member is not the host
    if (pref) {
        var chk = new GlideRecord(pref);
        if (!(chk.isValid() && chk.get(id)) && !generic[cls])
            return null; // owner class contradicts the scanned OS
    }
    return id;

    /* Targeted payload sample (Qualys Host Detection):
       {"ID":"83047621","IP":"30.162.178.21","TRACKING_METHOD":"IP",
        "OS":"VMware ESXi 7.0.3 build 24723872"}
       Hardware-wide stage for DNS-less hosts whose CI is classed generically
       (e.g. Server). Requires a unique owner, rejects load-balancer VIPs, and
       rejects owners whose class contradicts the scanned OS. */
})(rule, sourceValue, sourcePayload);