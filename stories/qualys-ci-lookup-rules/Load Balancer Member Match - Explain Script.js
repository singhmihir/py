/* Load Balancer Member Match, explained per discovered item (read-only)
   -------------------------------------------------------------------------------------------------
   Replays the walk of the Load Balancer Member Match rule for the discovered items listed in ITEMS
   and prints every hop: the VIP sign, the service search clue by clue, the pools found by each of
   the three paths, the members with their addresses, the candidate servers found through each of
   the four places, the real-server check on each candidate, the answer the rule gives today, and the
   CI the item holds. SURVEY_DAYS > 0 adds a survey of every unmatched item of the Qualys source
   updated in the last SURVEY_DAYS days that shows a VIP sign, grouped by the reason the two load
   balancer rules decline it. Nothing is written.
   ------------------------------------------------------------------------------------------------- */
var ITEMS = ['SDI000003028419', 'SDI000002993687', 'SDI000002923588', 'SDI000002418623', 'SDI000002411394', 'SDI000002375027',
             'SDI000002418687', 'SDI000002411359', 'SDI000002364705', 'SDI000002924018', 'SDI000002923857', 'SDI000002923742'];
var SURVEY_DAYS = 3;                              // 0 = no survey
var SURVEY_LIMIT = 40;                            // items listed per reason

var out = [];
function line(s) { out.push(s); }
function label(id) {
    var c = new GlideRecord('cmdb_ci');
    if (!id || !c.get(id))
        return '(none)';
    return c.getValue('name') + ' [' + ('' + c.getValue('sys_class_name')).replace('cmdb_ci_', '') + (c.getValue('install_status') == '7' ? ', retired' : '') + '] ip ' + (c.getValue('ip_address') || '-');
}
var ignore = gs.getProperty('sn_sec_cmn.ignoreCIClass', '');
function isMarker(segment, words) {
    for (var i = 0; i < words.length; i++) {
        var w = words[i];
        if (segment == w) return true;
        if (segment.indexOf(w) == 0 && /^[0-9]+$/.test(segment.substring(w.length))) return true;
        if (w.length >= 3 && segment.length > w.length && segment.substring(segment.length - w.length) == w) return true;
    }
    return false;
}
function vipSign(p) {
    var os = ('' + (p.OS || '')).toLowerCase();
    var label0 = ('' + (p.DNS || '')).trim().toLowerCase().split('.')[0];
    var osMarkers = ['f5', 'big-ip', 'big ip', 'netscaler'], labelMarkers = ['vip', 'vs'];
    var hits = [];
    for (var m = 0; m < osMarkers.length; m++) if (os.indexOf(osMarkers[m]) != -1) hits.push('OS has "' + osMarkers[m] + '"');
    var segments = label0 ? label0.split('-') : [];
    for (var s = 0; s < segments.length; s++) if (isMarker(segments[s], labelMarkers)) hits.push('label segment "' + segments[s] + '"');
    return hits;
}
function serviceSearch(p) {                       // the four clues, as in both rules
    var ip = ('' + (p.IP || '')).trim();
    var dns = ('' + (p.DNS || '')).trim().toLowerCase();
    var label0 = dns.split('.')[0];
    var steps = [['fqdn', dns], ['name', dns], ['name', label0], ['ip_address', ip]];
    var result = { service: null, stopped: false, trace: [] };
    for (var t = 0; t < steps.length; t++) {
        if (!steps[t][1]) { result.trace.push('clue ' + (t + 1) + ' ' + steps[t][0] + ': value empty, skipped'); continue; }
        var gr = new GlideRecord('cmdb_ci_lb_service');
        gr.addQuery(steps[t][0], steps[t][1]);
        if (ignore) gr.addQuery('sys_class_name', 'NOT IN', ignore);
        gr.query();
        var rows = [];
        while (gr.next() && rows.length < 5) rows.push(gr.getValue('name') + ' on ' + gr.getValue('ip_address') + ' (' + gr.load_balancer.getDisplayValue() + ', ' + gr.getUniqueValue() + ')');
        var n = gr.getRowCount();
        result.trace.push('clue ' + (t + 1) + ' ' + steps[t][0] + ' = "' + steps[t][1] + '": ' + n + ' row(s)' + (rows.length ? ' -> ' + rows.join(' | ') : ''));
        if (n > 1) { result.stopped = true; result.trace.push('   two or more services carry the value: both rules stop here (never guess)'); return result; }
        if (n == 1) { gr.query(); gr.next(); result.service = gr.getUniqueValue(); return result; }
    }
    result.trace.push('no clue found a service: both rules stop here');
    return result;
}
function related(id, table) {
    var found = [];
    var rel = new GlideRecord('cmdb_rel_ci');
    rel.addQuery('parent', id).addOrCondition('child', id);
    rel.query();
    while (rel.next()) {
        var other = rel.getValue('parent') == id ? rel.getValue('child') : rel.getValue('parent');
        var g = new GlideRecord(table);
        if (g.isValid() && g.get(other)) found.push({ id: other, via: rel.type.getDisplayValue() });
    }
    return found;
}
function isRealServer(id) {
    var hw = new GlideRecord('cmdb_ci_hardware');
    if (!hw.get(id)) return 'not in the Hardware tree';
    var cls = ',' + hw.getValue('sys_class_name') + ',';
    if (ignore && (',' + ignore + ',').indexOf(cls) != -1) return 'ignored class';
    var lb = new GlideRecord('cmdb_ci_lb');
    if (lb.isValid() && lb.get(id)) return 'a load balancer device';
    return 'real server';
}
function explain(p, itemLabel) {
    line(''); line('=== ' + itemLabel);
    line('  payload: IP ' + (p.IP || '-') + ' | DNS ' + (p.DNS || '-') + ' | OS ' + (p.OS || '-'));
    var sign = vipSign(p);
    line('  VIP sign: ' + (sign.length ? sign.join(', ') : 'NONE, neither rule runs'));
    if (!sign.length) return;
    var s = serviceSearch(p);
    for (var i = 0; i < s.trace.length; i++) line('  ' + s.trace[i]);
    if (!s.service) return;
    var svc = new GlideRecord('cmdb_ci_lb_service'); svc.get(s.service);
    line('  service: ' + svc.getValue('name') + ' | address ' + svc.getValue('ip_address') + ' port ' + svc.getValue('port') + ' | balancer ' + svc.load_balancer.getDisplayValue() + ' | pool field -> ' + (svc.getValue('pool') ? svc.pool.getDisplayValue() : '(empty)'));
    var pools = {};
    if (svc.getValue('pool')) pools[svc.getValue('pool')] = 'the pool field of the service';
    var byService = new GlideRecord('cmdb_ci_lb_pool'); byService.addQuery('service', s.service); byService.query();
    while (byService.next()) if (!pools[byService.getUniqueValue()]) pools[byService.getUniqueValue()] = 'a pool whose service field points at the service';
    var relPools = related(s.service, 'cmdb_ci_lb_pool');
    for (var r1 = 0; r1 < relPools.length; r1++) if (!pools[relPools[r1].id]) pools[relPools[r1].id] = 'a pool related to the service (' + relPools[r1].via + ')';
    var poolIds = Object.keys(pools);
    if (!poolIds.length) { line('  pools: NONE -> Member Match declines; Service Match attaches the service ' + svc.getValue('name')); return; }
    var members = {};
    for (var pi = 0; pi < poolIds.length; pi++) {
        var pg = new GlideRecord('cmdb_ci_lb_pool'); pg.get(poolIds[pi]);
        line('  pool: ' + pg.getValue('name') + ' (' + pools[poolIds[pi]] + ')');
        var mem = new GlideRecord('cmdb_ci_lb_pool_member'); mem.addQuery('pool', poolIds[pi]); mem.query();
        while (mem.next()) { members[mem.getUniqueValue()] = { ip: '' + (mem.getValue('ip_address') || ''), name: mem.getValue('name'), how: 'pool field' }; }
        var relMembers = related(poolIds[pi], 'cmdb_ci_lb_pool_member');
        for (var r2 = 0; r2 < relMembers.length; r2++) if (!members[relMembers[r2].id]) { var mg = new GlideRecord('cmdb_ci_lb_pool_member'); mg.get(relMembers[r2].id); members[relMembers[r2].id] = { ip: '' + (mg.getValue('ip_address') || ''), name: mg.getValue('name'), how: 'relationship ' + relMembers[r2].via }; }
    }
    var memberIds = Object.keys(members);
    if (!memberIds.length) { line('  members: NONE -> Member Match declines; Service Match attaches the service'); return; }
    var servers = {};
    for (var k = 0; k < memberIds.length; k++) {
        var m = members[memberIds[k]];
        line('  member: ' + m.name + ' | address ' + (m.ip || '(empty)') + ' | found through ' + m.how);
        var cands = [];
        if (m.ip) {
            var hw = new GlideRecord('cmdb_ci_hardware'); hw.addQuery('ip_address', m.ip); hw.query(); while (hw.next()) cands.push({ id: hw.getUniqueValue(), via: 'device record' });
            var nic = new GlideRecord('cmdb_ci_network_adapter'); nic.addQuery('ip_address', m.ip); nic.addNotNullQuery('cmdb_ci'); nic.query(); while (nic.next()) cands.push({ id: nic.getValue('cmdb_ci'), via: 'network adapter ' + nic.getValue('name') });
            var ipr = new GlideRecord('cmdb_ci_ip_address'); if (ipr.isValid()) { ipr.addQuery('ip_address', m.ip); ipr.addNotNullQuery('nic.cmdb_ci'); ipr.query(); while (ipr.next()) cands.push({ id: '' + ipr.nic.cmdb_ci, via: 'IP Address record on adapter ' + ipr.nic.name }); }
        }
        var relServers = related(memberIds[k], 'cmdb_ci_hardware');
        for (var r3 = 0; r3 < relServers.length; r3++) cands.push({ id: relServers[r3].id, via: 'relationship ' + relServers[r3].via });
        if (!cands.length) line('     candidates: none (no record carries ' + (m.ip || 'an address') + ', no relationship to hardware)');
        for (var c = 0; c < cands.length; c++) { var verdict = isRealServer(cands[c].id); line('     candidate via ' + cands[c].via + ': ' + label(cands[c].id) + ' -> ' + verdict); if (verdict == 'real server') servers[cands[c].id] = true; }
    }
    var ids = Object.keys(servers);
    line('  distinct real servers: ' + ids.length + (ids.length ? ' -> ' + ids.map(label).join(' ; ') : ''));
    line('  ANSWER: ' + (ids.length == 1 ? 'Member Match returns ' + label(ids[0]) : 'Member Match declines (' + (ids.length ? 'several servers' : 'no server') + '); Service Match attaches ' + svc.getValue('name')));
}
for (var i = 0; i < ITEMS.length; i++) {
    var di = new GlideRecord('sn_sec_cmn_src_ci'); di.addQuery('number', ITEMS[i]); di.query();
    if (!di.next()) { line(''); line('=== ' + ITEMS[i] + ': no such discovered item'); continue; }
    var p = {}; try { p = JSON.parse('' + di.getValue('source_data')); } catch (e) {}
    explain(p, ITEMS[i] + ' | state ' + di.getValue('state') + ' | CI today ' + label(di.getValue('cmdb_ci')) + ' | rule today ' + di.ci_lookup_rule.getDisplayValue() + ' | updated ' + di.getValue('sys_updated_on'));
}
if (SURVEY_DAYS > 0) {
    line(''); line('=== survey: unmatched items with a VIP sign, last ' + SURVEY_DAYS + ' days');
    var reasons = {}, lists = {};
    var u = new GlideRecord('sn_sec_cmn_src_ci'); u.addQuery('source.name', 'CONTAINS', 'Qualys'); u.addQuery('state', 'unmatched'); u.addQuery('sys_updated_on', '>=', gs.daysAgoStart(SURVEY_DAYS)); u.query();
    var seen = 0;
    while (u.next()) {
        var q = {}; try { q = JSON.parse('' + u.getValue('source_data')); } catch (e2) { continue; }
        if (!vipSign(q).length) continue;
        seen++;
        var r = serviceSearch(q); var reason;
        if (r.stopped) { var last = r.trace[r.trace.length - 2] || ''; reason = 'two or more services carry the value' + (last.indexOf('ip_address') != -1 ? ' (on the address)' : ' (on the name)'); }
        else if (!r.service) reason = 'no service carries the name or the address';
        else reason = 'a service exists but the item is unmatched (evaluated before the rules?)';
        reasons[reason] = (reasons[reason] || 0) + 1;
        lists[reason] = lists[reason] || [];
        if (lists[reason].length < SURVEY_LIMIT) lists[reason].push(u.getValue('number') + ' | ' + (q.DNS || '-') + ' | ' + q.IP + ' | ' + ('' + (q.OS || '')).substring(0, 30) + ' | updated ' + u.getValue('sys_updated_on'));
    }
    line('  unmatched items with a VIP sign: ' + seen);
    for (var rk in reasons) { line('  ' + reasons[rk] + '  ' + rk); for (var li = 0; li < lists[rk].length; li++) line('      ' + lists[rk][li]); }
}
gs.print(out.join('\n'));
