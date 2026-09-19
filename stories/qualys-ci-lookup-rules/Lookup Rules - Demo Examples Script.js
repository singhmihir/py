/* Qualys lookup rules, demo examples (read-only)
   -------------------------------------------------------------------------------------------------
   For every active scripted lookup rule of the Qualys source, in chain order, prints how many
   discovered items the rule has matched on this instance and a few of those items, each with the
   scanned values the rule read and the CI it returned. Nothing is created or updated. Paste into
   Scripts - Background (global scope), run, and copy the whole output.
   ------------------------------------------------------------------------------------------------- */
var PER_RULE = 3;        // examples printed per rule
var POOL = 80;           // newest matched items looked at per rule when choosing the examples
var DAYS = 0;            // only items updated in the last DAYS days; 0 = any age

var started = new Date().getTime();
var hasRuleField = new GlideRecord('sn_sec_cmn_src_ci').isValidField('ci_lookup_rule');
if (!hasRuleField) {
    gs.print('sn_sec_cmn_src_ci has no ci_lookup_rule field on this instance; nothing to report.');
} else {
    var rules = [];
    var rl = new GlideRecord('sn_sec_cmn_ci_lookup_rule');
    rl.addQuery('source.name', 'CONTAINS', 'Qualys');
    rl.addQuery('method', 'script');
    rl.addActiveQuery();
    rl.orderBy('order');
    rl.query();
    while (rl.next())
        rules.push({ id: rl.getUniqueValue(), order: '' + rl.getValue('order'), name: '' + rl.getValue('name'), field: '' + rl.getValue('source_field') });

    function text(gr, field) {
        return gr.isValidField(field) ? '' + (gr.getValue(field) || '') : '';
    }
    function label(gr, field) {
        return gr.isValidField(field) ? '' + gr.getDisplayValue(field) : '';
    }
    function ciFacts(id) {
        var base = new GlideRecord('cmdb_ci');
        if (!id || !base.get(id))
            return null;
        var ci = new GlideRecord('' + base.getValue('sys_class_name'));
        if (!ci.get(id))
            ci = base;
        var out = { sys_id: id, name: text(ci, 'name'), cls: text(ci, 'sys_class_name'), cls_label: label(ci, 'sys_class_name'),
            fqdn: text(ci, 'fqdn'), dns_domain: text(ci, 'dns_domain'), host_name: text(ci, 'host_name'), ip_address: text(ci, 'ip_address'),
            serial_number: text(ci, 'serial_number'), mac_address: text(ci, 'mac_address'), os: text(ci, 'os'), model: label(ci, 'model_id'),
            install_status: label(ci, 'install_status'), operational_status: label(ci, 'operational_status'), discovery_source: text(ci, 'discovery_source') };
        if (out.cls == 'cmdb_ci_lb_service') {
            out.load_balancer = label(ci, 'load_balancer');
            out.pools = poolsOf(id);
        }
        return out;
    }
    function poolsOf(serviceId) {
        var pools = [];
        var pool = new GlideRecord('cmdb_ci_lb_pool');
        pool.addQuery('load_balancer_service', serviceId);
        pool.query();
        while (pool.next()) {
            var members = [];
            var m = new GlideRecord('cmdb_ci_lb_pool_member');
            m.addQuery('load_balancer_pool', pool.getUniqueValue());
            m.query();
            while (m.next())
                members.push({ name: text(m, 'name'), ip: text(m, 'ip_address'), port: text(m, 'port'), sys_id: m.getUniqueValue() });
            pools.push({ name: text(pool, 'name'), sys_id: pool.getUniqueValue(), members: members });
        }
        return pools;
    }
    function servicesOn(ip) {
        var list = [];
        if (!ip) return list;
        var s = new GlideRecord('cmdb_ci_lb_service');
        s.addQuery('ip_address', ip);
        s.query();
        while (s.next())
            list.push({ sys_id: s.getUniqueValue(), name: text(s, 'name'), fqdn: text(s, 'fqdn'), load_balancer: label(s, 'load_balancer'),
                install_status: label(s, 'install_status'), pools: poolsOf(s.getUniqueValue()) });
        return list;
    }

    var lines = [], total = 0;
    for (var r = 0; r < rules.length; r++) {
        var rule = rules[r];
        var count = new GlideAggregate('sn_sec_cmn_src_ci');
        count.addQuery('ci_lookup_rule', rule.id);
        count.addQuery('state', 'matched');
        count.addAggregate('COUNT');
        count.query();
        var matched = count.next() ? parseInt(count.getAggregate('COUNT')) : 0;
        lines.push('== ' + rule.order + ' ' + rule.name + ' (' + rule.field + '): ' + matched + ' matched items on this instance');
        var di = new GlideRecord('sn_sec_cmn_src_ci');
        di.addQuery('ci_lookup_rule', rule.id);
        di.addQuery('state', 'matched');
        di.addNotNullQuery('cmdb_ci');
        if (DAYS > 0) di.addQuery('sys_updated_on', '>', gs.daysAgoStart(DAYS));
        di.orderByDesc('sys_updated_on');
        di.setLimit(POOL);
        di.query();
        var picks = [], seenClass = {}, seenOs = {}, spare = [];
        while (di.next()) {
            var p;
            try { p = JSON.parse('' + di.getValue('source_data')); } catch (e) { continue; }
            var ci = ciFacts('' + di.getValue('cmdb_ci'));
            if (!ci) continue;
            var ex = { rule: rule.order, rule_name: rule.name,
                item: { number: '' + di.getValue('number'), sys_id: di.getUniqueValue(), dns: '' + (p.DNS || ''), ip: '' + (p.IP || ''), os: '' + (p.OS || ''),
                    netbios: '' + (p.NETBIOS || ''), serial: '' + (p.SERIAL_NUMBER || ''), tracking: '' + (p.TRACKING_METHOD || ''), qualys_id: '' + (p.ID || ''),
                    matching_type: '' + di.getValue('matching_type'), updated: '' + di.getValue('sys_updated_on') },
                ci: ci };
            if (rule.name.indexOf('Load Balancer') != -1)
                ex.services_on_address = servicesOn(ex.item.ip);
            var key = ci.cls, osKey = ('' + p.OS).toLowerCase().split(' ')[0];
            if (!seenClass[key]) { seenClass[key] = true; seenOs[osKey] = true; picks.push(ex); }
            else if (!seenOs[osKey]) { seenOs[osKey] = true; picks.push(ex); }
            else spare.push(ex);
            if (picks.length >= PER_RULE) break;
        }
        while (picks.length < PER_RULE && spare.length)
            picks.push(spare.shift());
        for (var i = 0; i < picks.length; i++) {
            var x = picks[i];
            lines.push('  ' + x.item.number + ' | ' + (x.item.dns || '(no name)') + ' | ' + x.item.ip + ' | ' + x.item.os + ' -> ' + x.ci.name + ' [' + x.ci.cls + ']');
            lines.push('  EX ' + JSON.stringify(x));
            total++;
        }
        if (!picks.length)
            lines.push('  (no matched item carries this rule)');
    }
    gs.print('=== Qualys lookup rules, demo examples, read-only ===\nrules: ' + rules.length + ' | examples: ' + total + ' | elapsed: ' + Math.round((new Date().getTime() - started) / 1000) + ' s\n' + lines.join('\n'));
}
