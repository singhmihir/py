/* Qualys lookup rules, demo evidence (read-only)
   -------------------------------------------------------------------------------------------------
   For every active scripted lookup rule of the Qualys source, in chain order: counts the discovered
   items the rule has matched on this instance, replays the rule on the newest of them, records what
   each step of the script found (the records carrying the serial, MAC, name, fqdn or address, the
   adapter and address records walked, the pool behind a virtual server, the flags that decided) and
   prints a few examples chosen so that they show different paths through the rule. One readable
   line and one EX line per example. Nothing is created or updated. Paste into Scripts - Background
   (global scope), run, and attach the whole output as a text file.
   ------------------------------------------------------------------------------------------------- */
var PER_RULE = 3;        // examples printed per rule
var POOL = 100;          // newest matched items replayed per rule when choosing the examples
var LB_POOL = 40;        // the same for the two load balancer rules, whose walk costs more
var DAYS = 0;            // only items updated in the last DAYS days; 0 = any age
var ROWS = 6;            // records listed per search step
var ONLY = [];           // rule orders to run, e.g. ['450', '705', '740']; empty = every rule
var PREFER_NAMED = true; // choose items that carry a DNS name before items that do not
var REQUIRE_ROWS = true; // choose items whose trace found at least one record over items where it found none

var started = new Date().getTime();
var ignore = gs.getProperty('sn_sec_cmn.ignoreCIClass', '');
var out = [];

// ---------------------------------------------------------------- helpers shared with the rules
function text(gr, f) { return gr.isValidField(f) ? '' + (gr.getValue(f) || '') : ''; }
function disp(gr, f) { return gr.isValidField(f) ? '' + gr.getDisplayValue(f) : ''; }
function classFor(os) {
    if (!os) return '';
    var s = ('' + os).toLowerCase();
    if (s.split('/').length > 2) return '';
    if (s.indexOf('esx') != -1) return 'cmdb_ci_esx_server';
    if (s.indexOf('windows') != -1) return s.indexOf('server') != -1 ? 'cmdb_ci_win_server' : 'cmdb_ci_computer';
    if (s.indexOf('aix') != -1) return 'cmdb_ci_aix_server';
    if (s.indexOf('solaris') != -1 || s.indexOf('sunos') != -1) return 'cmdb_ci_solaris_server';
    if (s.indexOf('hp-ux') != -1) return 'cmdb_ci_hpux_server';
    if (s.indexOf('netapp') != -1 || s.indexOf('ontap') != -1) return 'cmdb_ci_storage_server';
    if (s.indexOf('printer') != -1 || s.indexOf('laserjet') != -1 || s.indexOf('jetdirect') != -1) return 'cmdb_ci_printer';
    if (s.indexOf('red hat') != -1 || s.indexOf('linux') != -1 || s.indexOf('centos') != -1 || s.indexOf('ubuntu') != -1 || s.indexOf('suse') != -1 ||
        s.indexOf('debian') != -1 || s.indexOf('fedora') != -1 || s.indexOf('euleros') != -1 || s.indexOf('oracle enterprise') != -1 || s.indexOf('amazon') != -1)
        return 'cmdb_ci_linux_server';
    if (s.indexOf('nx-os') != -1 || s.indexOf('catos') != -1 || s.indexOf('cisco') != -1) return 'cmdb_ci_netgear';
    return '';
}
var parentCache = {};
function parentsOf(table) {
    if (parentCache[table]) return parentCache[table];
    var chain = [table], db = new GlideRecord('sys_db_object');
    db.addQuery('name', table); db.query();
    while (db.next() && db.getValue('super_class')) {
        var parent = '' + db.super_class.name;
        chain.push(parent);
        db = new GlideRecord('sys_db_object'); db.addQuery('name', parent); db.query();
    }
    return (parentCache[table] = chain);
}
function agrees(cls, pref, appliances) {
    if (!pref || !cls || cls == pref) return true;
    var up = parentsOf(cls);
    if (appliances && pref == 'cmdb_ci_linux_server' && (up.indexOf('cmdb_ci_netgear') != -1 || up.indexOf('cmdb_ci_lb') != -1 || up.indexOf('cmdb_ci_storage_server') != -1)) return true;
    return up.indexOf(pref) != -1 || parentsOf(pref).indexOf(cls) != -1;
}
function retired(gr) {
    return text(gr, 'install_status') == '7' || text(gr, 'operational_status') == '6' || (gr.isValidField('life_cycle_stage_status') && '' + gr.life_cycle_stage_status.getDisplayValue() == 'Retired');
}
function isLB(id) { var lb = new GlideRecord('cmdb_ci_lb'); return lb.isValid() && lb.get(id); }
function shortClass(cls) { return ('' + cls).replace('cmdb_ci_', ''); }
function ciRow(gr) {
    return { id: gr.getUniqueValue(), name: text(gr, 'name'), cls: text(gr, 'sys_class_name'), ip: text(gr, 'ip_address'), fqdn: text(gr, 'fqdn'),
        dns_domain: text(gr, 'dns_domain'), serial: text(gr, 'serial_number'), status: disp(gr, 'install_status'), live: !retired(gr) };
}
function rowsOf(table, field, value, byClass) {
    var r = { table: table, field: field, value: value, n: 0, rows: [], valid: true };
    if (!value) return r;
    var gr = new GlideRecord(table);
    if (!gr.isValid()) { r.valid = false; return r; }
    gr.addQuery(field, value);
    if (ignore) gr.addQuery(byClass || 'sys_class_name', 'NOT IN', ignore);
    gr.query();
    while (gr.next()) { r.n++; if (r.rows.length < ROWS) r.rows.push(ciRow(gr)); }
    return r;
}
function ciFacts(id) {
    var base = new GlideRecord('cmdb_ci');
    if (!id || !base.get(id)) return null;
    var ci = new GlideRecord('' + base.getValue('sys_class_name'));
    if (!ci.get(id)) ci = base;
    var f = ciRow(ci);
    f.cls_label = disp(ci, 'sys_class_name'); f.host_name = text(ci, 'host_name'); f.mac = text(ci, 'mac_address'); f.model = disp(ci, 'model_id');
    f.operational = disp(ci, 'operational_status'); f.load_balancer = disp(ci, 'load_balancer'); f.os = text(ci, 'os');
    return f;
}
function nameAgrees(id, dns) {
    var lbl = ('' + (dns || '')).trim().toLowerCase().split('.')[0];
    if (!lbl) return true;
    var ci = new GlideRecord('cmdb_ci'); if (!ci.get(id)) return false;
    var nm = ('' + ci.getValue('name')).trim().toLowerCase().split('.')[0];
    if (!nm) return true;
    return nm == lbl || lbl.indexOf(nm + '-') == 0 || nm.indexOf(lbl + '-') == 0;
}
function isMarker(segment, words) {
    for (var i = 0; i < words.length; i++) {
        var w = words[i];
        if (segment == w) return true;
        if (segment.indexOf(w) == 0 && /^[0-9]+$/.test(segment.substring(w.length))) return true;
        if (w.length >= 3 && segment.length > w.length && segment.substring(segment.length - w.length) == w) return true;
    }
    return false;
}
function rowText(x) { return x.name + ' [' + shortClass(x.cls) + (x.live ? '' : ', retired') + ']' + (x.ip ? ' ip ' + x.ip : ''); }
function listText(r) {
    var s = r.n + ' record' + (r.n == 1 ? '' : 's');
    if (!r.valid) return 'table ' + r.table + ' not on this instance';
    if (r.rows.length) s += ': ' + r.rows.map(rowText).join(' ; ') + (r.n > r.rows.length ? ' ; ...' : '');
    return s;
}
function step(steps, title, detail) { steps.push({ title: title, detail: detail }); }

// ---------------------------------------------------------------- the load balancer walk (as the member rule does it)
function vipSign(p) {
    var os = ('' + (p.OS || '')).toLowerCase(), lbl = ('' + (p.DNS || '')).trim().toLowerCase().split('.')[0];
    var osMarkers = ['f5', 'big-ip', 'big ip', 'netscaler'], labelMarkers = ['vip', 'vs'], hits = [];
    for (var m = 0; m < osMarkers.length; m++) if (os.indexOf(osMarkers[m]) != -1) hits.push('OS has "' + osMarkers[m] + '"');
    var segments = lbl ? lbl.split('-') : [];
    for (var s = 0; s < segments.length; s++) if (isMarker(segments[s], labelMarkers)) hits.push('label segment "' + segments[s] + '"');
    return hits;
}
function narrow(list, flag) { var o = []; for (var i = 0; i < list.length; i++) if (list[i][flag]) o.push(list[i]); return o.length ? o : list; }
function serviceSearch(p, steps) {
    var ip = ('' + (p.IP || '')).trim(), dns = ('' + (p.DNS || '')).trim().toLowerCase(), lbl = dns.split('.')[0];
    var clues = [['fqdn', dns], ['name', dns], ['name', lbl], ['ip_address', ip]];
    var res = { twins: [], service: null, stopped: false, clue: '', names: 0, rows: 0 };
    for (var t = 0; t < clues.length; t++) {
        if (!clues[t][1]) continue;
        var gr = new GlideRecord('cmdb_ci_lb_service');
        if (!gr.isValid()) { step(steps, 'Service search', 'cmdb_ci_lb_service is not on this instance'); return res; }
        gr.addQuery(clues[t][0], clues[t][1]);
        if (ignore) gr.addQuery('sys_class_name', 'NOT IN', ignore);
        gr.query();
        var all = [], names = {}, shown = [];
        while (gr.next()) {
            var here = text(gr, 'ip_address') == ip, live = !retired(gr);
            names[text(gr, 'name').trim().toLowerCase()] = true;
            all.push({ id: gr.getUniqueValue(), here: here, live: live, name: text(gr, 'name'), ip: text(gr, 'ip_address'), lb: disp(gr, 'load_balancer') });
            if (shown.length < ROWS) shown.push(text(gr, 'name') + ' on ' + text(gr, 'ip_address') + ' (' + disp(gr, 'load_balancer') + (live ? '' : ', retired') + ')');
        }
        if (!all.length) { step(steps, 'Clue ' + (t + 1) + ': ' + clues[t][0] + ' = "' + clues[t][1] + '"', 'no service record; next clue'); continue; }
        res.clue = clues[t][0]; res.names = Object.keys(names).length; res.rows = all.length;
        step(steps, 'Clue ' + (t + 1) + ': ' + clues[t][0] + ' = "' + clues[t][1] + '"', all.length + ' service record' + (all.length == 1 ? '' : 's') + ': ' + shown.join(' ; '));
        if (res.names > 1) { res.stopped = true; step(steps, 'Two differently named services', 'both load balancer rules stop here, never guess'); return res; }
        var kept = narrow(all, 'here'), afterLive = kept.length > 1 ? narrow(kept, 'live') : kept;
        res.twins = afterLive;
        res.service = afterLive.length == 1 ? afterLive[0] : null;
        if (all.length > 1) step(steps, 'Twins', all.length + ' records of one name are one virtual server recorded more than once: ' + kept.length + ' kept on the scanned address' + (afterLive.length < kept.length ? ', then ' + afterLive.length + ' live' : '') + '; the member rule walks the pools of all ' + afterLive.length + ', the service rule ' + (res.service ? 'has one record left' : 'declines on ' + afterLive.length + ' live records'));
        return res;
    }
    step(steps, 'Service search', 'no clue found a service record');
    return res;
}
function related(id, table) {
    var found = [], rel = new GlideRecord('cmdb_rel_ci');
    rel.addQuery('parent', id).addOrCondition('child', id); rel.query();
    while (rel.next()) {
        var other = rel.getValue('parent') == id ? rel.getValue('child') : rel.getValue('parent');
        var g = new GlideRecord(table);
        if (g.isValid() && g.get(other)) found.push(other);
    }
    return found;
}
function isRealServer(id) {
    var hw = new GlideRecord('cmdb_ci_hardware');
    if (!hw.get(id)) return 'not in the Hardware tree';
    if (ignore && (',' + ignore + ',').indexOf(',' + hw.getValue('sys_class_name') + ',') != -1) return 'ignored class';
    if (isLB(id)) return 'a load balancer device';
    return 'real server';
}
function memberWalk(p, steps, shape) {
    var s = serviceSearch(p, steps);
    if (!s.twins.length) { shape.push('no service'); return; }
    var pools = {}, poolNames = [];
    for (var w = 0; w < s.twins.length; w++) {
        var tw = new GlideRecord('cmdb_ci_lb_service'); tw.get(s.twins[w].id);
        if (text(tw, 'pool') && !pools[text(tw, 'pool')]) pools[text(tw, 'pool')] = 'pool field';
        var byService = new GlideRecord('cmdb_ci_lb_pool'); byService.addQuery('service', s.twins[w].id); byService.query();
        while (byService.next()) if (!pools[byService.getUniqueValue()]) pools[byService.getUniqueValue()] = 'service field of the pool';
        var relPools = related(s.twins[w].id, 'cmdb_ci_lb_pool');
        for (var r1 = 0; r1 < relPools.length; r1++) if (!pools[relPools[r1]]) pools[relPools[r1]] = 'relationship';
    }
    var poolIds = Object.keys(pools);
    if (!poolIds.length) { step(steps, 'Pools', 'none behind the virtual server: the member rule declines, the service rule decides'); shape.push('no pool'); return; }
    var members = {};
    for (var pi = 0; pi < poolIds.length; pi++) {
        var pg = new GlideRecord('cmdb_ci_lb_pool'); pg.get(poolIds[pi]); poolNames.push(text(pg, 'name') + ' (' + pools[poolIds[pi]] + ')');
        var mem = new GlideRecord('cmdb_ci_lb_pool_member'); mem.addQuery('pool', poolIds[pi]); mem.query();
        while (mem.next()) members[mem.getUniqueValue()] = { ip: text(mem, 'ip_address'), name: text(mem, 'name') };
        var relMembers = related(poolIds[pi], 'cmdb_ci_lb_pool_member');
        for (var r2 = 0; r2 < relMembers.length; r2++) if (!members[relMembers[r2]]) { var mg = new GlideRecord('cmdb_ci_lb_pool_member'); mg.get(relMembers[r2]); members[relMembers[r2]] = { ip: text(mg, 'ip_address'), name: text(mg, 'name') }; }
    }
    step(steps, 'Pools', poolIds.length + ': ' + poolNames.join(' ; '));
    var memberIds = Object.keys(members);
    if (!memberIds.length) { step(steps, 'Members', 'none: the member rule declines'); shape.push('no members'); return; }
    var servers = {}, serverNames = {}, unresolved = 0, memberLines = [];
    for (var k = 0; k < memberIds.length; k++) {
        var m = members[memberIds[k]], cands = [], led = false;
        if (m.ip) {
            var hw = new GlideRecord('cmdb_ci_hardware'); hw.addQuery('ip_address', m.ip); hw.query(); while (hw.next()) cands.push({ id: hw.getUniqueValue(), via: 'device record' });
            var nic = new GlideRecord('cmdb_ci_network_adapter'); nic.addQuery('ip_address', m.ip); nic.addNotNullQuery('cmdb_ci'); nic.query(); while (nic.next()) cands.push({ id: nic.getValue('cmdb_ci'), via: 'adapter' });
            var ipr = new GlideRecord('cmdb_ci_ip_address'); if (ipr.isValid()) { ipr.addQuery('ip_address', m.ip); ipr.addNotNullQuery('nic.cmdb_ci'); ipr.query(); while (ipr.next()) cands.push({ id: '' + ipr.nic.cmdb_ci, via: 'IP Address record' }); }
        }
        var relServers = related(memberIds[k], 'cmdb_ci_hardware');
        for (var r3 = 0; r3 < relServers.length; r3++) cands.push({ id: relServers[r3], via: 'relationship' });
        var placed = [];
        for (var c = 0; c < cands.length; c++) {
            var verdict = isRealServer(cands[c].id);
            if (verdict == 'real server') {
                led = true;
                if (servers[cands[c].id] === undefined) { var hwc = new GlideRecord('cmdb_ci_hardware'); hwc.get(cands[c].id); serverNames[cands[c].id] = text(hwc, 'name'); servers[cands[c].id] = serverNames[cands[c].id].trim().toLowerCase().split('.')[0] || cands[c].id; }
                if (placed.length < 3) placed.push(serverNames[cands[c].id] + ' via ' + cands[c].via);
            }
        }
        if (!led) unresolved++;
        if (memberLines.length < ROWS) memberLines.push(m.name + ' ' + (m.ip || '(no address)') + (led ? ' -> ' + placed.join(', ') : ' -> no server the CMDB can place'));
    }
    step(steps, 'Members', memberIds.length + ': ' + memberLines.join(' ; '));
    var ids = Object.keys(servers), machines = {};
    for (var n = 0; n < ids.length; n++) machines[servers[ids[n]]] = (machines[servers[ids[n]]] || []).concat(ids[n]);
    var labels = Object.keys(machines);
    var decision;
    if (unresolved) decision = unresolved + ' member(s) the CMDB cannot place: the member rule declines';
    else if (labels.length != 1) decision = labels.length + ' machines behind the virtual server: the member rule declines';
    else if (machines[labels[0]].length == 1) decision = 'one machine, one record: the member rule returns it';
    else { var liveN = 0; for (var f = 0; f < machines[labels[0]].length; f++) { var ci = new GlideRecord('cmdb_ci_hardware'); ci.get(machines[labels[0]][f]); if (!retired(ci)) liveN++; }
        decision = 'one machine recorded ' + machines[labels[0]].length + ' times, ' + liveN + ' live: ' + (liveN == 1 ? 'the live record stands for it' : 'the member rule declines'); }
    step(steps, 'Decision', memberIds.length + ' member(s), ' + ids.length + ' server record(s), ' + labels.length + ' machine(s) by name; ' + decision);
    shape.push(s.rows > 1 ? 'twins' : 'one service', memberIds.length + ' member' + (memberIds.length == 1 ? '' : 's'), labels.length + ' machine' + (labels.length == 1 ? '' : 's'));
}

// ---------------------------------------------------------------- the trace per rule family
function trace(kind, p) {
    var steps = [], shape = [];
    var dns = ('' + (p.DNS || '')).trim().toLowerCase(), lbl = dns.split('.')[0], domain = dns.indexOf('.') != -1 ? dns.substring(dns.indexOf('.') + 1) : '';
    var ip = ('' + (p.IP || '')).trim(), os = '' + (p.OS || ''), pref = classFor(os), serial = ('' + (p.SERIAL_NUMBER || '')).trim();
    var clsLine = pref ? 'OS "' + os + '" gives the class ' + shortClass(pref) : 'OS "' + (os || 'not reported') + '" gives no class';
    function one(r) { return r.n == 1 ? 'exactly one, accepted' : r.n == 0 ? 'none' : r.n + ' records, the rule declines'; }
    if (kind == 'Serial Number Class Match' || kind == 'Serial Number Hardware Match') {
        step(steps, 'Serial read', '"' + serial + '"' + (serial.length < 4 ? ' (shorter than four characters, refused)' : ''));
        var table = kind.indexOf('Class') != -1 ? pref : 'cmdb_ci_hardware';
        step(steps, 'Class', kind.indexOf('Class') != -1 ? clsLine : 'the whole hardware tree, the OS is not read');
        var r = rowsOf(table, 'serial_number', serial);
        step(steps, 'Records carrying the serial', listText(r) + ' -> ' + one(r));
        shape.push(kind.indexOf('Class') != -1 ? shortClass(pref) : (r.rows[0] ? shortClass(r.rows[0].cls) : 'none'), r.n + ' rows');
    } else if (kind == 'Cisco IP Phone MAC') {
        var m = /^sep([0-9a-f]{12})$/.exec(lbl);
        step(steps, 'Phone label', '"' + lbl + '"' + (m ? ' matches sep plus twelve hex characters' : ' does not match sep plus twelve hex characters'));
        if (m) {
            var hex = m[1], pairs = []; for (var i = 0; i < 12; i += 2) pairs.push(hex.substr(i, 2));
            var colon = pairs.join(':'), cands = [colon.toUpperCase(), colon, hex.toUpperCase(), hex];
            step(steps, 'MAC rebuilt', cands.join(', '));
            var a = new GlideRecord('cmdb_ci_network_adapter'); a.addQuery('mac_address', 'IN', cands.join(',')); a.addNotNullQuery('cmdb_ci'); a.query();
            var owners = [], phoneOwners = 0, n1 = 0;
            while (a.next()) { n1++; var ph = new GlideRecord('cmdb_ci_ip_phone'); var isPhone = ph.get(a.getValue('cmdb_ci')); if (isPhone) phoneOwners++; if (owners.length < ROWS) owners.push(text(a, 'name') + ' on ' + disp(a, 'cmdb_ci') + (isPhone ? ' [IP Phone]' : ' [not a phone]')); }
            step(steps, 'Attempt 1: adapter with the MAC', n1 + ' adapter' + (n1 == 1 ? '' : 's') + (owners.length ? ': ' + owners.join(' ; ') : '') + ' -> ' + (phoneOwners == 1 ? 'one IP Phone owner, accepted' : phoneOwners + ' phone owners, next attempt'));
            var r2 = { n: 0, rows: [], valid: true };
            var g2 = new GlideRecord('cmdb_ci_ip_phone'); g2.addQuery('mac_address', 'IN', cands.join(',')); if (ignore) g2.addQuery('sys_class_name', 'NOT IN', ignore); g2.query(); while (g2.next()) { r2.n++; if (r2.rows.length < ROWS) r2.rows.push(ciRow(g2)); }
            step(steps, 'Attempt 2: phone record with the MAC', listText(r2) + ' -> ' + one(r2));
            var r3 = rowsOf('cmdb_ci_ip_phone', 'name', lbl.toUpperCase());
            step(steps, 'Attempt 3: Unified CM device name', listText(r3) + ' -> ' + one(r3));
            shape.push(phoneOwners == 1 ? 'adapter' : r2.n == 1 ? 'phone mac' : r3.n == 1 ? 'device name' : 'none');
        } else shape.push('no label');
    } else if (kind == 'FQDN Class Match' || kind == 'FQDN Hardware Match') {
        var table2 = kind.indexOf('Class') != -1 ? pref : 'cmdb_ci_hardware';
        step(steps, 'Name', '"' + dns + '"' + (dns.indexOf('.') == -1 ? ' (no dot, refused)' : '') + '; ' + (kind.indexOf('Class') != -1 ? clsLine : 'the whole hardware tree'));
        var rf = rowsOf(table2, 'fqdn', dns), onIp = 0;
        for (var q = 0; q < rf.rows.length; q++) if (ip && rf.rows[q].ip == ip) onIp++;
        step(steps, 'Records carrying the fqdn', listText(rf) + ' -> ' + (rf.n == 1 ? 'exactly one, accepted' : rf.n == 0 ? 'none' : rf.n + ' records, ' + onIp + ' on the scanned address ' + ip + (onIp == 1 ? ': that one is accepted' : ': the rule declines')));
        shape.push(kind.indexOf('Class') != -1 ? shortClass(pref) : (rf.rows[0] ? shortClass(rf.rows[0].cls) : 'none'), rf.n == 1 ? 'one row' : 'tie by address');
    } else if (kind == 'Hostname Domain Class Match' || kind == 'Hostname Domain Hardware Match') {
        var table3 = kind.indexOf('Class') != -1 ? pref : 'cmdb_ci_hardware';
        step(steps, 'Split', 'host "' + lbl + '", domain "' + domain + '"; ' + (kind.indexOf('Class') != -1 ? clsLine : 'the whole hardware tree'));
        var rn = rowsOf(table3, 'name', lbl), good = 0, ipHits = 0, lines = [];
        for (var q2 = 0; q2 < rn.rows.length; q2++) { var x = rn.rows[q2], f1 = x.fqdn.toLowerCase(), d1 = x.dns_domain.toLowerCase();
            var ok = f1 == dns || d1 == domain || (f1.indexOf(lbl + '.') == 0 && f1.indexOf(domain) > 0); if (ok) good++; if (ok && ip && x.ip == ip) ipHits++;
            lines.push(rowText(x) + ' domain "' + (x.dns_domain || x.fqdn || '-') + '" ' + (ok ? 'agrees' : 'differs')); }
        step(steps, 'Records carrying the host name', rn.n + ': ' + lines.join(' ; ') + ' -> ' + good + ' agree on the domain' + (good > 1 ? ', ' + ipHits + ' on the scanned address' : ''));
        shape.push(kind.indexOf('Class') != -1 ? shortClass(pref) : (rn.rows[0] ? shortClass(rn.rows[0].cls) : 'none'), rn.n == 0 ? 'no row' : rn.n == 1 ? 'one row' : good == 1 ? 'domain separates' : 'tie by address');
    } else if (kind == 'Layered DNS Match') {
        step(steps, 'Name', '"' + dns + '"; ' + clsLine + ' (agreement includes appliances for a Linux fingerprint)');
        var link = new GlideRecord('cmdb_ip_address_dns_name'), owners2 = {}, ipOwners = {}, rowsL = [], nL = 0;
        if (!link.isValid()) step(steps, 'Link table', 'cmdb_ip_address_dns_name is not on this instance');
        else {
            link.addQuery('dns_name.name', dns); link.addNotNullQuery('ip_address.nic.cmdb_ci'); if (ignore) link.addQuery('ip_address.nic.cmdb_ci.sys_class_name', 'NOT IN', ignore); link.query();
            while (link.next()) { nL++; var ow = '' + link.ip_address.nic.cmdb_ci, oc = '' + link.ip_address.nic.cmdb_ci.sys_class_name, addr = '' + link.ip_address.ip_address;
                var ag = agrees(oc, pref, true); if (ag) { owners2[ow] = true; if (ip && addr == ip) ipOwners[ow] = true; }
                if (rowsL.length < ROWS) rowsL.push('address ' + addr + ' -> adapter ' + link.ip_address.nic.getDisplayValue() + ' -> ' + link.ip_address.nic.cmdb_ci.getDisplayValue() + ' [' + shortClass(oc) + (ag ? '' : ', class disagrees') + ']'); }
            var cnt = Object.keys(owners2).length, conf = Object.keys(ipOwners).length;
            step(steps, 'DNS Name -> IP Address -> adapter -> CI', nL + ' row' + (nL == 1 ? '' : 's') + (rowsL.length ? ': ' + rowsL.join(' ; ') : ''));
            step(steps, 'Decision', cnt + ' agreeing CI' + (cnt == 1 ? '' : 's') + (cnt > 1 ? ', ' + conf + ' reached through the scanned address' : '') + (cnt == 1 && isLB(Object.keys(owners2)[0]) ? '; it is a load balancer device: refused' : ''));
            shape.push(cnt == 1 ? 'one owner' : 'tie by address', nL + ' rows');
        }
    } else if (kind == 'Hostname Class Match' || kind == 'Hostname Hardware Match') {
        var table4 = kind.indexOf('Class') != -1 ? pref : 'cmdb_ci_hardware';
        step(steps, 'Host name', '"' + lbl + '"; ' + (kind.indexOf('Class') != -1 ? clsLine : 'the whole hardware tree, the OS class kept as a preference'));
        var rh = rowsOf(table4, 'name', lbl);
        var agr = kind.indexOf('Hardware') != -1 && rh.n == 1 ? (agrees(rh.rows[0].cls, pref, true) ? '; class ' + shortClass(rh.rows[0].cls) + ' agrees with the OS' : '; class ' + shortClass(rh.rows[0].cls) + ' disagrees with the OS, refused') : '';
        step(steps, 'Records carrying the name', listText(rh) + ' -> ' + one(rh) + agr);
        shape.push(rh.rows[0] ? shortClass(rh.rows[0].cls) : 'none', rh.n + ' rows');
    } else if (kind == 'Device Name Match') {
        var lower = os.toLowerCase(), guard = pref && pref != 'cmdb_ci_linux_server' && lower.indexOf('phone') == -1;
        step(steps, 'OS guard', clsLine + (guard ? ': a server or desktop class, the rule declines' : ': no server or desktop class, the search runs'));
        var found = [], onAddr = 0, tables = ['cmdb_ci_ip_phone', 'cmdb_ci_imaging_hardware'], seen = [];
        for (var ti = 0; ti < tables.length; ti++) { var rd = rowsOf(tables[ti], 'name', lbl); if (!rd.valid) continue; for (var q3 = 0; q3 < rd.rows.length; q3++) { found.push(rd.rows[q3]); if (ip && rd.rows[q3].ip == ip) onAddr++; } seen.push(tables[ti] + ': ' + listText(rd)); }
        step(steps, 'Name searched in IP Phone and Imaging Hardware', seen.join(' | '));
        step(steps, 'Decision', found.length == 1 ? 'one device, accepted' : found.length == 0 ? 'no device' : found.length + ' devices, ' + onAddr + ' on the scanned address ' + ip + (onAddr == 1 ? ': that one is accepted' : ': the rule declines'));
        shape.push(found[0] ? shortClass(found[0].cls) : 'none', found.length == 1 ? 'one row' : 'tie by address');
    } else if (kind == 'Management Interface Match') {
        var suffixes = ['ilo', 'ilom', 'idrac', 'drac', 'ipmi', 'bmc', 'oob', 'mgmt', 'imm', 'cimc', 'rmm', 'con'], markers = ['ilo', 'ilom', 'idrac', 'drac', 'remote access controller', 'imm', 'cimc', 'bmc', 'ipmi', 'lights out'];
        var dash = lbl.lastIndexOf('-'), tail = dash > 0 ? lbl.substring(dash + 1) : '', base = '', why = '';
        if (dash > 0 && suffixes.indexOf(tail) != -1) { base = lbl.substring(0, dash); why = 'suffix "-' + tail + '"'; }
        else { for (var mk = 0; mk < markers.length; mk++) if (os.toLowerCase().indexOf(markers[mk]) != -1) { base = dash > 0 ? lbl.substring(0, dash) : ''; why = 'OS word "' + markers[mk] + '"'; break; } }
        step(steps, 'Controller sign', why ? why + ' on "' + lbl + '"; server name "' + base + '"' : 'none on "' + lbl + '"');
        if (base) { var rb = rowsOf('cmdb_ci_hardware', 'name', base); step(steps, 'Records carrying the server name', listText(rb) + ' -> ' + one(rb) + (rb.n == 1 && isLB(rb.rows[0].id) ? '; a load balancer device, refused' : '')); shape.push(why.indexOf('suffix') == 0 ? 'suffix ' + tail : 'os word', rb.rows[0] ? shortClass(rb.rows[0].cls) : 'none'); }
        else shape.push('no sign');
    } else if (kind == 'Network Interface Name Match') {
        var words = ['vlan', 'v', 'hsrp', 'vrrp', 'po', 'eth', 'gi', 'te', 'lo', 'mgmt', 'aom', 'vs', 'fab'], segs = lbl ? lbl.split('-') : [], ev = [];
        if (dns.indexOf('.network.') != -1) ev.push('domain ".network."');
        for (var si = 1; si < segs.length; si++) if (isMarker(segs[si], words)) ev.push('segment "' + segs[si] + '"');
        step(steps, 'Interface sign', ev.length ? ev.join(', ') : 'none: the rule declines');
        var tried = [], answer = '';
        for (var k2 = segs.length - 1; k2 >= 1 && ev.length; k2--) {
            var base2 = segs.slice(0, k2).join('-'), hits = [];
            var tabs = ['cmdb_ci_netgear', 'cmdb_ci_lb'];
            for (var tb = 0; tb < tabs.length; tb++) { var rr = rowsOf(tabs[tb], 'name', base2); if (rr.valid) for (var q4 = 0; q4 < rr.rows.length && hits.length < 2; q4++) hits.push(rr.rows[q4]); if (rr.n > rr.rows.length) hits.push({ name: '...', cls: '', live: true, ip: '' }); }
            tried.push('"' + base2 + '": ' + (hits.length ? hits.map(rowText).join(' ; ') : 'nothing'));
            if (hits.length) { answer = hits.length == 1 ? 'one device at prefix "' + base2 + '", accepted' : 'two devices at prefix "' + base2 + '", the rule declines'; shape.push('prefix depth ' + k2, hits[0].cls ? shortClass(hits[0].cls) : 'tie'); break; }
        }
        if (ev.length) step(steps, 'Prefixes tried, longest first, on Network Gear and Load Balancer', tried.join(' | ') + (answer ? ' -> ' + answer : ' -> nothing at any prefix'));
        if (!shape.length) shape.push(ev.length ? 'no prefix' : 'no sign');
    } else if (kind == 'FQDN Name Hardware Match' || kind == 'FQDN Name Broad Match') {
        var table5 = kind.indexOf('Broad') != -1 ? 'cmdb_ci' : 'cmdb_ci_hardware';
        step(steps, 'Name', '"' + dns + '" searched on the name field of ' + (kind.indexOf('Broad') != -1 ? 'every CI class' : 'the whole hardware tree'));
        var r5 = rowsOf(table5, 'name', dns);
        step(steps, 'Records named with the whole fqdn', listText(r5) + ' -> ' + one(r5));
        shape.push(r5.rows[0] ? shortClass(r5.rows[0].cls) : 'none', r5.n + ' rows');
    } else if (kind == 'Load Balancer Member Match') {
        var sign = vipSign(p);
        step(steps, 'VIP sign', sign.length ? sign.join(', ') : 'none: neither load balancer rule runs');
        if (sign.length) memberWalk(p, steps, shape); else shape.push('no sign');
    } else if (kind == 'Load Balancer Service Match') {
        var sign2 = vipSign(p);
        step(steps, 'VIP sign', sign2.length ? sign2.join(', ') : 'none: neither load balancer rule runs');
        if (sign2.length) { var ss = serviceSearch(p, steps); step(steps, 'Decision', ss.service ? 'one live virtual server record left, attached (the pool is not read)' : ss.stopped ? 'two names, declined' : ss.twins.length > 1 ? ss.twins.length + ' live records compete, declined' : 'no service record'); shape.push(ss.clue || 'no clue', ss.rows > 1 ? 'twins' : 'one record'); }
        else shape.push('no sign');
    } else if (kind == 'IP Class Match' || kind == 'IP Hardware Match') {
        var table6 = kind.indexOf('Class') != -1 ? pref : 'cmdb_ci_hardware';
        step(steps, 'Address', '"' + ip + '"; ' + (kind.indexOf('Class') != -1 ? clsLine : 'the whole hardware tree, the OS class kept as a preference'));
        var ri = rowsOf(table6, 'ip_address', ip), notes = [];
        if (ri.n == 1) { if (kind.indexOf('Hardware') != -1) { notes.push(isLB(ri.rows[0].id) ? 'a load balancer device, refused' : 'not a load balancer device'); notes.push(agrees(ri.rows[0].cls, pref, false) ? 'class agrees with the OS' : 'class disagrees with the OS, refused'); }
            notes.push(nameAgrees(ri.rows[0].id, dns) ? 'name agrees with the scanned label "' + lbl + '"' : 'name differs from the scanned label "' + lbl + '", refused'); }
        step(steps, 'Records carrying the address', listText(ri) + ' -> ' + one(ri) + (notes.length ? '; ' + notes.join('; ') : ''));
        shape.push(ri.rows[0] ? shortClass(ri.rows[0].cls) : 'none', ri.n + ' rows');
    } else if (kind == 'IP Adapter Match' || kind == 'IP Layered Match') {
        step(steps, 'Address', '"' + ip + '"; ' + clsLine + ' (a preference for class agreement)');
        var ownersA = {}, rowsA = [], nA = 0;
        if (kind == 'IP Adapter Match') {
            var nicA = new GlideRecord('cmdb_ci_network_adapter'); nicA.addQuery('ip_address', ip); nicA.addNotNullQuery('cmdb_ci'); if (ignore) nicA.addQuery('cmdb_ci.sys_class_name', 'NOT IN', ignore); nicA.query();
            while (nicA.next()) { nA++; var oA = '' + nicA.getValue('cmdb_ci'), cA = '' + nicA.cmdb_ci.sys_class_name, agA = agrees(cA, pref, false); if (agA) ownersA[oA] = true; if (rowsA.length < ROWS) rowsA.push('adapter ' + text(nicA, 'name') + ' -> ' + nicA.cmdb_ci.getDisplayValue() + ' [' + shortClass(cA) + (agA ? '' : ', class disagrees') + ']'); }
            step(steps, 'Adapter records on the address', nA + (rowsA.length ? ': ' + rowsA.join(' ; ') : ''));
        } else {
            var ipA = new GlideRecord('cmdb_ci_ip_address');
            if (!ipA.isValid()) step(steps, 'IP Address records', 'cmdb_ci_ip_address is not on this instance');
            else { ipA.addQuery('ip_address', ip); ipA.addNotNullQuery('nic.cmdb_ci'); if (ignore) ipA.addQuery('nic.cmdb_ci.sys_class_name', 'NOT IN', ignore); ipA.query();
                while (ipA.next()) { nA++; var oB = '' + ipA.nic.cmdb_ci, cB = '' + ipA.nic.cmdb_ci.sys_class_name, agB = agrees(cB, pref, false); if (agB) ownersA[oB] = true; if (rowsA.length < ROWS) rowsA.push('IP Address record -> adapter ' + ipA.nic.getDisplayValue() + ' -> ' + ipA.nic.cmdb_ci.getDisplayValue() + ' [' + shortClass(cB) + (agB ? '' : ', class disagrees') + ']'); }
                step(steps, 'IP Address records on the address', nA + (rowsA.length ? ': ' + rowsA.join(' ; ') : '')); }
        }
        var ownA = Object.keys(ownersA), noteA = [];
        if (ownA.length == 1) { noteA.push(isLB(ownA[0]) ? 'a load balancer device, refused' : 'not a load balancer device'); noteA.push(nameAgrees(ownA[0], dns) ? 'name agrees with "' + lbl + '"' : 'name differs from "' + lbl + '", refused'); }
        step(steps, 'Decision', ownA.length + ' distinct owning CI' + (ownA.length == 1 ? '' : 's') + (ownA.length == 1 ? '; ' + noteA.join('; ') : ownA.length ? ': the rule declines' : ''));
        shape.push(nA + ' records', ownA.length + ' owners');
    } else {
        step(steps, 'Rule', 'no evidence trace for this rule name');
        shape.push('other');
    }
    return { steps: steps, shape: shape.join(' / ') };
}

// ---------------------------------------------------------------- run the real rule for the verdict
function runRule(rec, field, p) {
    var v = p[field];
    if (!v) return '';
    var ev = new GlideScopedEvaluator();
    ev.putVariable('rule', rec); ev.putVariable('sourceValue', '' + v); ev.putVariable('sourcePayload', p);
    try { var r = ev.evaluateScript(rec, 'script', null); return r ? '' + r : ''; } catch (e) { return 'error: ' + e; }
}

// ---------------------------------------------------------------- rules, items, examples
var rules = [], rl = new GlideRecord('sn_sec_cmn_ci_lookup_rule');
rl.addQuery('source.name', 'CONTAINS', 'Qualys'); rl.addQuery('method', 'script'); rl.addActiveQuery(); rl.orderBy('order'); rl.query();
while (rl.next()) { var rec = new GlideRecord('sn_sec_cmn_ci_lookup_rule'); rec.get(rl.getUniqueValue()); rules.push({ id: rl.getUniqueValue(), order: '' + rl.getValue('order'), name: '' + rl.getValue('name'), field: '' + rl.getValue('source_field'), rec: rec }); }
var hasRuleField = new GlideRecord('sn_sec_cmn_src_ci').isValidField('ci_lookup_rule'), total = 0;
if (!hasRuleField) out.push('sn_sec_cmn_src_ci has no ci_lookup_rule field on this instance; nothing to report.');
for (var r = 0; r < rules.length && hasRuleField; r++) {
    var rule = rules[r], kind = rule.name.replace(/^(USEM|BOFA)\s+/, ''), custom = /^(USEM|BOFA)\s/.test(rule.name);
    var count = new GlideAggregate('sn_sec_cmn_src_ci'); count.addQuery('ci_lookup_rule', rule.id); count.addQuery('state', 'matched'); count.addAggregate('COUNT'); count.query();
    var matched = count.next() ? parseInt(count.getAggregate('COUNT')) : 0;
    if (ONLY.length && ONLY.indexOf(rule.order) == -1) continue;
    out.push('== ' + rule.order + ' ' + rule.name + ' (' + rule.field + '): ' + matched + ' matched items on this instance' + (custom ? '' : ' (platform rule, no examples)'));
    if (!custom) continue;
    var di = new GlideRecord('sn_sec_cmn_src_ci');
    di.addQuery('ci_lookup_rule', rule.id); di.addQuery('state', 'matched'); di.addNotNullQuery('cmdb_ci');
    if (DAYS > 0) di.addQuery('sys_updated_on', '>', gs.daysAgoStart(DAYS));
    di.orderByDesc('sys_updated_on'); di.setLimit(kind.indexOf('Load Balancer') != -1 ? LB_POOL : POOL); di.query();
    var picks = [], spare = [], shapes = {}, looked = 0;
    while (di.next()) {
        var p; try { p = JSON.parse('' + di.getValue('source_data')); } catch (e) { continue; }
        looked++;
        var ciId = '' + di.getValue('cmdb_ci'), facts = ciFacts(ciId);
        if (!facts) continue;
        var t = trace(kind, p), verdict = runRule(rule.rec, rule.field, p);
        var ex = { rule: rule.order, rule_name: rule.name, shape: t.shape, steps: t.steps,
            item: { number: '' + di.getValue('number'), sys_id: di.getUniqueValue(), dns: '' + (p.DNS || ''), ip: '' + (p.IP || ''), os: '' + (p.OS || ''), netbios: '' + (p.NETBIOS || ''), serial: '' + (p.SERIAL_NUMBER || ''), tracking: '' + (p.TRACKING_METHOD || ''), qualys_id: '' + (p.ID || ''), updated: '' + di.getValue('sys_updated_on') },
            ci: facts, verdict: { ci: verdict, same_as_today: verdict == ciId, ci_label: verdict && verdict.indexOf('error') != 0 ? (ciFacts(verdict) || { name: '?' }).name : '' } };
        var key = t.shape + (verdict == ciId ? '' : ' / differs today');
        var weak = (PREFER_NAMED && !ex.item.dns) || (REQUIRE_ROWS && t.shape.indexOf('none') == 0);
        if (verdict == ciId && facts.live && !weak && !shapes[key]) { shapes[key] = true; picks.push(ex); } else spare.push(ex);
        if (picks.length >= PER_RULE) break;
    }
    spare.sort(function(a, b) {
        function score(x) { return (x.verdict.same_as_today ? 4 : 0) + (x.item.dns ? 2 : 0) + (x.shape.indexOf('none') == 0 ? 0 : 1); }
        return score(b) - score(a);
    });
    while (picks.length < PER_RULE && spare.length) picks.push(spare.shift());
    for (var i = 0; i < picks.length; i++) {
        var x = picks[i];
        out.push('  ' + x.item.number + ' | ' + (x.item.dns || '(no name)') + ' | ' + x.item.ip + ' | ' + x.item.os + ' -> ' + x.ci.name + ' [' + x.ci.cls + '] | path: ' + x.shape + (x.verdict.same_as_today ? '' : ' | replay differs: ' + (x.verdict.ci ? x.verdict.ci_label || x.verdict.ci : 'declines')));
        out.push('  EX ' + JSON.stringify(x));
        total++;
    }
    if (!picks.length) out.push('  (no matched item carries this rule)');
    out.push('  looked at ' + looked + ' item(s)');
}
gs.print('=== Qualys lookup rules, demo evidence, read-only ===\nrules: ' + rules.length + ' | examples: ' + total + ' | elapsed: ' + Math.round((new Date().getTime() - started) / 1000) + ' s\n' + out.join('\n'));
