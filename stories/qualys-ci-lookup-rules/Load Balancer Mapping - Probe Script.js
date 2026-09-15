/* Load balancer mapping probe (read-only)
   -------------------------------------------------------------------------------------------------
   Paste the virtual addresses to check into VIPS and run as a background script. For each address it
   prints what the CMDB holds: the discovered items scanned on it, the Load Balancer Service records
   on the address or the name with their pool and pool members, the load balancer devices carrying
   it, the DNS Name and IP Address records tied to it, the relationships around those records and
   the servers carrying each pool member address. Nothing is written.
   ------------------------------------------------------------------------------------------------- */
var VIPS = ['171.203.142.26', '164.91.236.18'];
var LIMIT = 20;                                   // rows printed per list

var out = [];
function line(s) { out.push(s); }
function label(gr) {
    return gr.getValue('name') + ' [' + ('' + gr.getValue('sys_class_name')).replace('cmdb_ci_', '') +
        (gr.getValue('install_status') == '7' ? ', retired' : '') + '] ' + gr.getUniqueValue();
}
function ciLabel(id) {
    var c = new GlideRecord('cmdb_ci');
    if (!id || !c.get(id))
        return '(none)';
    return label(c);
}
function relationships(id) {
    var rel = new GlideRecord('cmdb_rel_ci');
    rel.addQuery('parent', id).addOrCondition('child', id);
    rel.setLimit(LIMIT);
    rel.query();
    var n = 0;
    while (rel.next()) {
        n++;
        line('      rel: ' + ciLabel(rel.getValue('parent')) + ' --' + rel.type.getDisplayValue() + '--> ' + ciLabel(rel.getValue('child')));
    }
    if (!n)
        line('      rel: none');
}
function serversOn(ip) {
    var found = [];
    var hw = new GlideRecord('cmdb_ci_hardware');
    hw.addQuery('ip_address', ip);
    hw.setLimit(LIMIT);
    hw.query();
    while (hw.next())
        found.push('device ' + label(hw));
    var nic = new GlideRecord('cmdb_ci_network_adapter');
    nic.addQuery('ip_address', ip);
    nic.addNotNullQuery('cmdb_ci');
    nic.setLimit(LIMIT);
    nic.query();
    while (nic.next())
        found.push('adapter ' + nic.getValue('name') + ' of ' + ciLabel(nic.getValue('cmdb_ci')));
    var ipr = new GlideRecord('cmdb_ci_ip_address');
    if (ipr.isValid()) {
        ipr.addQuery('ip_address', ip);
        ipr.addNotNullQuery('nic.cmdb_ci');
        ipr.setLimit(LIMIT);
        ipr.query();
        while (ipr.next())
            found.push('IP Address record on adapter ' + ipr.nic.name + ' of ' + ciLabel('' + ipr.nic.cmdb_ci));
    }
    return found;
}
function members(pool) {
    var m = new GlideRecord('cmdb_ci_lb_pool_member');
    if (!m.isValid())
        return line('      (no pool member table)');
    m.addQuery('pool', pool.getUniqueValue());
    m.setLimit(LIMIT);
    m.query();
    var n = 0;
    while (m.next()) {
        n++;
        line('      member ' + label(m) + ' address ' + m.getValue('ip_address') + ' port ' + m.getValue('service_port'));
        var servers = serversOn(m.getValue('ip_address'));
        for (var s = 0; s < servers.length; s++)
            line('         real server: ' + servers[s]);
        if (!servers.length)
            line('         real server: nothing carries ' + m.getValue('ip_address'));
        relationships(m.getUniqueValue());
    }
    if (!n)
        line('      members: none');
}
function pools(service) {
    var seen = {};
    var ids = [];
    if (service.getValue('pool'))
        ids.push(service.getValue('pool'));
    var byService = new GlideRecord('cmdb_ci_lb_pool');
    if (byService.isValid()) {
        byService.addQuery('service', service.getUniqueValue());
        byService.query();
        while (byService.next())
            ids.push(byService.getUniqueValue());
    }
    for (var i = 0; i < ids.length; i++) {
        if (seen[ids[i]])
            continue;
        seen[ids[i]] = true;
        var pool = new GlideRecord('cmdb_ci_lb_pool');
        if (!pool.get(ids[i]))
            continue;
        line('    pool ' + label(pool) + ' on ' + ciLabel(pool.getValue('load_balancer')));
        members(pool);
    }
    if (!ids.length)
        line('    pool: none');
}
for (var v = 0; v < VIPS.length; v++) {
    var vip = VIPS[v];
    line('');
    line('=== ' + vip + ' ===');
    var names = {};
    var di = new GlideRecord('sn_sec_cmn_src_ci');
    di.addQuery('source_data', 'CONTAINS', '"' + vip + '"');
    di.setLimit(LIMIT);
    di.query();
    var n = 0;
    while (di.next()) {
        n++;
        var p = {};
        try { p = JSON.parse('' + di.getValue('source_data')); } catch (e) {}
        if (p.DNS)
            names[('' + p.DNS).toLowerCase()] = true;
        line('  discovered item ' + di.getValue('number') + ' | DNS ' + (p.DNS || '-') + ' | OS ' + (p.OS || '-') + ' | ' + di.getValue('state') + ' | CI today ' + ciLabel(di.getValue('cmdb_ci')));
    }
    if (!n)
        line('  discovered items: none scanned on this address');
    var svc = new GlideRecord('cmdb_ci_lb_service');
    if (svc.isValid()) {
        var q = svc.addQuery('ip_address', vip);
        for (var nm in names) {
            q.addOrCondition('fqdn', nm);
            q.addOrCondition('name', nm);
            q.addOrCondition('name', nm.split('.')[0]);
        }
        svc.setLimit(LIMIT);
        svc.query();
        var ns = 0;
        while (svc.next()) {
            ns++;
            line('  service ' + label(svc) + ' | fqdn ' + (svc.getValue('fqdn') || '-') + ' | address ' + svc.getValue('ip_address') + ' port ' + svc.getValue('port') + ' | device ' + ciLabel(svc.getValue('load_balancer')));
            pools(svc);
            relationships(svc.getUniqueValue());
        }
        if (!ns)
            line('  service: none on the address or the name');
    } else
        line('  service: table not installed');
    var lb = new GlideRecord('cmdb_ci_lb');
    lb.addQuery('ip_address', vip);
    lb.setLimit(LIMIT);
    lb.query();
    var nl = 0;
    while (lb.next()) {
        nl++;
        line('  load balancer device on the address: ' + label(lb));
        relationships(lb.getUniqueValue());
    }
    if (!nl)
        line('  load balancer device on the address: none');
    var chain = new GlideRecord('cmdb_ip_address_dns_name');
    if (chain.isValid()) {
        chain.addQuery('ip_address.ip_address', vip);
        chain.setLimit(LIMIT);
        chain.query();
        var nc = 0;
        while (chain.next()) {
            nc++;
            line('  DNS chain: ' + chain.dns_name.name + ' -> IP Address ' + chain.ip_address.ip_address + ' -> adapter ' + (chain.ip_address.nic.name || '(none)') + ' -> ' + ciLabel('' + chain.ip_address.nic.cmdb_ci));
        }
        if (!nc)
            line('  DNS chain: no DNS Name record tied to this address');
    }
    var others = serversOn(vip);
    for (var o = 0; o < others.length; o++)
        line('  also carrying the address: ' + others[o]);
}
gs.print(out.join('\n'));
