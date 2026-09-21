/* Qualys lookup rules, demo record trace (read-only)
   -------------------------------------------------------------------------------------------------
   For each discovered item shown in the CMDB team demo deck (the list below), replays the rule that
   matched it step by step and records every record the script touched on the way: the item, the
   records carrying the serial, name, fqdn or address, the DNS Name, IP Address and Network Adapter
   records walked, the virtual server, pool, members and servers behind a load balancer address, and
   what every earlier rule's own search finds for the same item, each record with its table and sys_id
   so the deck can link to it. Nothing is created or updated. Paste into Scripts - Background (global
   scope), run, and attach the whole output as a text file.
   ------------------------------------------------------------------------------------------------- */
var ROWS = 12;           // records listed per search
var ITEMS = [
    {"r": "175", "n": "SDI000002148411", "id": "fdf0ab42ebb6c714017ff4d7cad0cd9f", "k": "USEM Serial Number Class Match"},
    {"r": "175", "n": "SDI000002148409", "id": "b5f0ab42ebb6c714017ff4d7cad0cd9e", "k": "USEM Serial Number Class Match"},
    {"r": "175", "n": "SDI000002148406", "id": "6df0ab42ebb6c714017ff4d7cad0cd9c", "k": "USEM Serial Number Class Match"},
    {"r": "180", "n": "SDI000002368092", "id": "1de8581e93fa4b549110fe584dba10f7", "k": "USEM Serial Number Hardware Match"},
    {"r": "180", "n": "SDI000002326199", "id": "6d5c8c16eb3ec710577bf284dad0cde0", "k": "USEM Serial Number Hardware Match"},
    {"r": "180", "n": "SDI000002390879", "id": "a41d909a3b760f942fcecefe23e45a2d", "k": "USEM Serial Number Hardware Match"},
    {"r": "200", "n": "SDI000002627752", "id": "b2998da6eb7ecb14017ff4d7cad0cd60", "k": "USEM Cisco IP Phone MAC"},
    {"r": "200", "n": "SDI000002617321", "id": "59c04526ebfe8b10577bf284dad0cdda", "k": "USEM Cisco IP Phone MAC"},
    {"r": "200", "n": "SDI000002619434", "id": "75520da63bbe43180e435c8a04e45a2d", "k": "USEM Cisco IP Phone MAC"},
    {"r": "250", "n": "SDI000002151366", "id": "3251e706ebb6c714017ff4d7cad0cd1c", "k": "USEM FQDN Class Match"},
    {"r": "250", "n": "SDI000003676655", "id": "c2ece9493b1307d02fcecefe23e45aa6", "k": "USEM FQDN Class Match"},
    {"r": "250", "n": "SDI000003129659", "id": "b1eccbb22b7a4758a277fab2f291bf76", "k": "USEM FQDN Class Match"},
    {"r": "260", "n": "SDI000003651953", "id": "f4137e33930fcb909110fe584dba108f", "k": "USEM FQDN Hardware Match"},
    {"r": "260", "n": "SDI000003438418", "id": "f9548099eb8303d0577bf284dad0cd24", "k": "USEM FQDN Hardware Match"},
    {"r": "260", "n": "SDI000003444611", "id": "874c945d3b8747102fcecefe23e45a11", "k": "USEM FQDN Hardware Match"},
    {"r": "300", "n": "SDI000003576701", "id": "9635d6563b47039c9289d164c3e45ad7", "k": "USEM Hostname Domain Class Match"},
    {"r": "300", "n": "SDI000003576699", "id": "9a35d6563b47039c9289d164c3e45ad0", "k": "USEM Hostname Domain Class Match"},
    {"r": "300", "n": "SDI000003576697", "id": "d635d6563b47039c9289d164c3e45abd", "k": "USEM Hostname Domain Class Match"},
    {"r": "310", "n": "SDI000003576283", "id": "f8059a962bcf0350a277fab2f291bf8c", "k": "USEM Hostname Domain Hardware Match"},
    {"r": "310", "n": "SDI000003669773", "id": "76912eb8935b4798cfcebc5a7bba10ab", "k": "USEM Hostname Domain Hardware Match"},
    {"r": "310", "n": "SDI000003669770", "id": "9a916ab8935b4798cfcebc5a7bba100a", "k": "USEM Hostname Domain Hardware Match"},
    {"r": "350", "n": "SDI000003582887", "id": "bc6c5e5a9303cb14cfcebc5a7bba10c0", "k": "USEM Layered DNS Match"},
    {"r": "350", "n": "SDI000003052286", "id": "f17bde363b3e4f180e435c8a04e45a33", "k": "USEM Layered DNS Match"},
    {"r": "350", "n": "SDI000003085182", "id": "a48172b2eb7ecf14017ff4d7cad0cdf3", "k": "USEM Layered DNS Match"},
    {"r": "400", "n": "SDI000003129664", "id": "d2eccbb22b7a4758a277fab2f291bfca", "k": "USEM Hostname Class Match"},
    {"r": "400", "n": "SDI000003576309", "id": "0e05da962bcf0350a277fab2f291bf72", "k": "USEM Hostname Class Match"},
    {"r": "400", "n": "SDI000003129660", "id": "caeccbb22b7a4758a277fab2f291bf9d", "k": "USEM Hostname Class Match"},
    {"r": "410", "n": "SDI000003650853", "id": "b3646affeb4b4350017ff4d7cad0cda0", "k": "USEM Hostname Hardware Match"},
    {"r": "410", "n": "SDI000003605570", "id": "5af3a6963bc7039c9289d164c3e45aef", "k": "USEM Hostname Hardware Match"},
    {"r": "410", "n": "SDI000003650834", "id": "5344eebfeb4b4350017ff4d7cad0cd28", "k": "USEM Hostname Hardware Match"},
    {"r": "415", "n": "SDI000003799341", "id": "6714e30c2bebc710a277fab2f291bf41", "k": "USEM Device Name Match"},
    {"r": "415", "n": "SDI000003799352", "id": "e024670c2bebc710a277fab2f291bf2a", "k": "USEM Device Name Match"},
    {"r": "415", "n": "SDI000003799469", "id": "39e867883b6b47102fcecefe23e45a7f", "k": "USEM Device Name Match"},
    {"r": "420", "n": "SDI000002647592", "id": "918911a23bbe83180e435c8a04e45a8d", "k": "USEM Management Interface Match"},
    {"r": "420", "n": "SDI000002530819", "id": "1957cc663b3ecf942fcecefe23e45aef", "k": "USEM Management Interface Match"},
    {"r": "420", "n": "SDI000003103867", "id": "bc3e32beebfecf14017ff4d7cad0cdc9", "k": "USEM Management Interface Match"},
    {"r": "430", "n": "SDI000003800077", "id": "8d6b274c93a747109110fe584dba104b", "k": "USEM Network Interface Name Match"},
    {"r": "430", "n": "SDI000003800075", "id": "d74a274493a747109110fe584dba10f9", "k": "USEM Network Interface Name Match"},
    {"r": "430", "n": "SDI000003799353", "id": "9b646b8c2bebc710a277fab2f291bfa0", "k": "USEM Network Interface Name Match"},
    {"r": "450", "n": "SDI000003103157", "id": "e8ddba3a93fec310cfcebc5a7bba10fc", "k": "USEM FQDN Name Hardware Match"},
    {"r": "455", "n": "SDI000002993687", "id": "deb3b97a3bfe4b189289d164c3e45a59", "k": "USEM Load Balancer Member Match"},
    {"r": "455", "n": "SDI000003786277", "id": "eac78dafebdb47d0577bf284dad0cd8f", "k": "USEM Load Balancer Member Match"},
    {"r": "455", "n": "SDI000002418623", "id": "9f78729e3bf28f942fcecefe23e45a40", "k": "USEM Load Balancer Member Match"},
    {"r": "460", "n": "SDI000003055580", "id": "28ad5e36933283949110fe584dba108d", "k": "USEM Load Balancer Service Match"},
    {"r": "460", "n": "SDI000003036490", "id": "e8d1123e3bf647d42fcecefe23e45a89", "k": "USEM Load Balancer Service Match"},
    {"r": "460", "n": "SDI000003008717", "id": "dd4eb5ba3bb60f180e435c8a04e45a29", "k": "USEM Load Balancer Service Match"},
    {"r": "700", "n": "SDI000003093964", "id": "ff38b63a93bec310cfcebc5a7bba10bf", "k": "USEM IP Class Match"},
    {"r": "700", "n": "SDI000003093886", "id": "dc38f23a93bec310cfcebc5a7bba10af", "k": "USEM IP Class Match"},
    {"r": "700", "n": "SDI000003070780", "id": "a858ea3a933ec310cfcebc5a7bba1094", "k": "USEM IP Class Match"},
    {"r": "705", "n": "SDI000003007215", "id": "614df97e3b328b189289d164c3e45a44", "k": "USEM IP Hardware Match"},
    {"r": "705", "n": "SDI000003054392", "id": "81dc16f23b3a8b189289d164c3e45aeb", "k": "USEM IP Hardware Match"},
    {"r": "705", "n": "SDI000002907396", "id": "f17dac323bb64b189289d164c3e45a6f", "k": "USEM IP Hardware Match"},
    {"r": "730", "n": "SDI000002813895", "id": "c6ab93a293724750a2b4f91e1dba10a8", "k": "USEM IP Adapter Match"},
    {"r": "730", "n": "SDI000002578917", "id": "f17624e23b7e03180e435c8a04e45a79", "k": "USEM IP Adapter Match"},
    {"r": "730", "n": "SDI000002582383", "id": "139824a23b3287189289d164c3e45a8f", "k": "USEM IP Adapter Match"},
    {"r": "740", "n": "SDI000002376737", "id": "795ad412933a8b10a2b4f91e1dba10be", "k": "USEM IP Layered Match"},
    {"r": "740", "n": "SDI000002354915", "id": "a0e4dc9693ba4b549110fe584dba10bc", "k": "USEM IP Layered Match"},
    {"r": "740", "n": "SDI000002962461", "id": "20f991fe93b643949110fe584dba10c6", "k": "USEM IP Layered Match"},
    {"r": "850", "n": "SDI000003669791", "id": "4da1e6f8935b4798cfcebc5a7bba1022", "k": "USEM FQDN Name Broad Match"},
    {"r": "850", "n": "SDI000003670195", "id": "b424a6bc2b9fcfd0a277fab2f291bfcc", "k": "USEM FQDN Name Broad Match"},
    {"r": "850", "n": "SDI000003670186", "id": "5c2426bc2b9fcfd0a277fab2f291bfe4", "k": "USEM FQDN Name Broad Match"}
];
var started = new Date().getTime();
var ignore = gs.getProperty('sn_sec_cmn.ignoreCIClass', '');
var out = [], TOUCH = [];

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
    var cls = text(gr, 'sys_class_name') || gr.getTableName();
    return { table: cls, id: gr.getUniqueValue(), name: text(gr, 'name'), cls: cls, ip: text(gr, 'ip_address'), fqdn: text(gr, 'fqdn'),
        dns_domain: text(gr, 'dns_domain'), serial: text(gr, 'serial_number'), status: disp(gr, 'install_status'), live: !retired(gr) };
}
// every search the walk makes: the table, the filter (without the ignore clause) and the records found, kept for the step
function touch(table, q, rows, n) { TOUCH.push({ table: table, q: q, n: n === undefined ? rows.length : n, rows: rows }); }
function nameOf(table, id) { var g = new GlideRecord(table); return g.get(id) ? text(g, 'name') : ''; }
function classOf(id) { var g = new GlideRecord('cmdb_ci'); return g.get(id) ? text(g, 'sys_class_name') : ''; }
function rowsOf(table, field, value, byClass) {
    var r = { table: table, field: field, value: value, n: 0, rows: [], valid: true };
    if (!table) { r.valid = false; r.table = '(no class)'; return r; }
    if (!value) return r;
    var gr = new GlideRecord(table);
    if (!gr.isValid()) { r.valid = false; return r; }
    gr.addQuery(field, value);
    if (ignore) gr.addQuery(byClass || 'sys_class_name', 'NOT IN', ignore);
    gr.query();
    while (gr.next()) { r.n++; if (r.rows.length < ROWS) r.rows.push(ciRow(gr)); }
    touch(table, field + '=' + value, r.rows, r.n);
    return r;
}
function ciFacts(id) {
    var base = new GlideRecord('cmdb_ci');
    if (!id || !base.get(id)) return null;
    var ci = new GlideRecord('' + base.getValue('sys_class_name'));
    if (!ci.get(id)) ci = base;
    var f = ciRow(ci);
    f.cls_label = disp(ci, 'sys_class_name'); f.host_name = text(ci, 'host_name'); f.mac = text(ci, 'mac_address'); f.model = disp(ci, 'model_id');
    f.operational = disp(ci, 'operational_status'); f.load_balancer = disp(ci, 'load_balancer'); f.load_balancer_id = text(ci, 'load_balancer'); f.os = text(ci, 'os');
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
// a step of the walk takes the searches made since the previous step
function step(steps, title, detail) { steps.push({ title: title, detail: detail, searches: TOUCH.splice(0, TOUCH.length) }); }

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
        var all = [], names = {}, shown = [], rows = [];
        while (gr.next()) {
            var here = text(gr, 'ip_address') == ip, live = !retired(gr);
            names[text(gr, 'name').trim().toLowerCase()] = true;
            all.push({ id: gr.getUniqueValue(), here: here, live: live, name: text(gr, 'name'), ip: text(gr, 'ip_address'), lb: disp(gr, 'load_balancer') });
            if (rows.length < ROWS) rows.push({ table: 'cmdb_ci_lb_service', id: gr.getUniqueValue(), name: text(gr, 'name'), cls: text(gr, 'sys_class_name'), ip: text(gr, 'ip_address'), live: live, on_address: here,
                port: text(gr, 'port'), lb_id: text(gr, 'load_balancer'), lb: disp(gr, 'load_balancer'), lb_cls: classOf(text(gr, 'load_balancer')), pool_id: text(gr, 'pool'), pool: disp(gr, 'pool'), fqdn: text(gr, 'fqdn') });
            if (shown.length < ROWS) shown.push(text(gr, 'name') + ' on ' + text(gr, 'ip_address') + ' (' + disp(gr, 'load_balancer') + (live ? '' : ', retired') + ')');
        }
        touch('cmdb_ci_lb_service', clues[t][0] + '=' + clues[t][1], rows, all.length);
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
    var found = [], rows = [], rel = new GlideRecord('cmdb_rel_ci');
    rel.addQuery('parent', id).addOrCondition('child', id); rel.query();
    while (rel.next()) {
        var other = rel.getValue('parent') == id ? rel.getValue('child') : rel.getValue('parent');
        var g = new GlideRecord(table);
        if (g.isValid() && g.get(other)) { found.push(other); if (rows.length < ROWS) rows.push({ table: text(g, 'sys_class_name') || table, id: other, name: text(g, 'name'), cls: text(g, 'sys_class_name'), rel_id: rel.getUniqueValue(), rel_type: disp(rel, 'type') }); }
    }
    touch('cmdb_rel_ci', 'parent=' + id + '^ORchild=' + id, rows, found.length);
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
        var bsRows = [];
        while (byService.next()) { if (!pools[byService.getUniqueValue()]) pools[byService.getUniqueValue()] = 'service field of the pool'; if (bsRows.length < ROWS) bsRows.push({ table: 'cmdb_ci_lb_pool', id: byService.getUniqueValue(), name: text(byService, 'name'), cls: 'cmdb_ci_lb_pool' }); }
        touch('cmdb_ci_lb_pool', 'service=' + s.twins[w].id, bsRows);
        var relPools = related(s.twins[w].id, 'cmdb_ci_lb_pool');
        for (var r1 = 0; r1 < relPools.length; r1++) if (!pools[relPools[r1]]) pools[relPools[r1]] = 'relationship';
    }
    var poolIds = Object.keys(pools), poolRows = [];
    for (var pr = 0; pr < poolIds.length; pr++) { var pgr = new GlideRecord('cmdb_ci_lb_pool'); pgr.get(poolIds[pr]); poolRows.push({ table: 'cmdb_ci_lb_pool', id: poolIds[pr], name: text(pgr, 'name'), cls: 'cmdb_ci_lb_pool', via: pools[poolIds[pr]], lb: disp(pgr, 'load_balancer') }); }
    touch('cmdb_ci_lb_pool', 'sys_idIN' + poolIds.join(','), poolRows);
    if (!poolIds.length) { step(steps, 'Pools', 'none behind the virtual server: the member rule declines, the service rule decides'); shape.push('no pool'); return; }
    var members = {};
    for (var pi = 0; pi < poolIds.length; pi++) {
        var pg = new GlideRecord('cmdb_ci_lb_pool'); pg.get(poolIds[pi]); poolNames.push(text(pg, 'name') + ' (' + pools[poolIds[pi]] + ')');
        var mem = new GlideRecord('cmdb_ci_lb_pool_member'); mem.addQuery('pool', poolIds[pi]); mem.query();
        var memRows = [];
        while (mem.next()) { members[mem.getUniqueValue()] = { ip: text(mem, 'ip_address'), name: text(mem, 'name') }; if (memRows.length < ROWS) memRows.push({ table: 'cmdb_ci_lb_pool_member', id: mem.getUniqueValue(), name: text(mem, 'name'), cls: 'cmdb_ci_lb_pool_member', ip: text(mem, 'ip_address'), port: text(mem, 'port') }); }
        touch('cmdb_ci_lb_pool_member', 'pool=' + poolIds[pi], memRows);
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
            var hw = new GlideRecord('cmdb_ci_hardware'); hw.addQuery('ip_address', m.ip); hw.query(); var hwRows = [];
            while (hw.next()) { cands.push({ id: hw.getUniqueValue(), via: 'device record' }); if (hwRows.length < ROWS) hwRows.push(ciRow(hw)); }
            touch('cmdb_ci_hardware', 'ip_address=' + m.ip, hwRows);
            var nic = new GlideRecord('cmdb_ci_network_adapter'); nic.addQuery('ip_address', m.ip); nic.addNotNullQuery('cmdb_ci'); nic.query(); var nicRows = [];
            while (nic.next()) { cands.push({ id: nic.getValue('cmdb_ci'), via: 'adapter' }); if (nicRows.length < ROWS) nicRows.push({ table: 'cmdb_ci_network_adapter', id: nic.getUniqueValue(), name: text(nic, 'name'), cls: 'cmdb_ci_network_adapter', ip: m.ip, owner_id: '' + nic.getValue('cmdb_ci'), owner: disp(nic, 'cmdb_ci'), owner_cls: '' + nic.cmdb_ci.sys_class_name }); }
            touch('cmdb_ci_network_adapter', 'ip_address=' + m.ip, nicRows);
            var ipr = new GlideRecord('cmdb_ci_ip_address'); var iprRows = [];
            if (ipr.isValid()) { ipr.addQuery('ip_address', m.ip); ipr.addNotNullQuery('nic.cmdb_ci'); ipr.query();
                while (ipr.next()) { cands.push({ id: '' + ipr.nic.cmdb_ci, via: 'IP Address record' }); if (iprRows.length < ROWS) iprRows.push({ table: 'cmdb_ci_ip_address', id: ipr.getUniqueValue(), name: text(ipr, 'name'), cls: 'cmdb_ci_ip_address', ip: m.ip, nic_id: '' + ipr.getValue('nic'), nic: disp(ipr, 'nic'), owner_id: '' + ipr.nic.cmdb_ci, owner: '' + ipr.nic.cmdb_ci.getDisplayValue(), owner_cls: '' + ipr.nic.cmdb_ci.sys_class_name }); }
                touch('cmdb_ci_ip_address', 'ip_address=' + m.ip, iprRows); }
        }
        var relServers = related(memberIds[k], 'cmdb_ci_hardware');
        for (var r3 = 0; r3 < relServers.length; r3++) cands.push({ id: relServers[r3], via: 'relationship' });
        var placed = [], verdicts = [];
        for (var c = 0; c < cands.length; c++) {
            var verdict = isRealServer(cands[c].id);
            verdicts.push({ table: classOf(cands[c].id) || 'cmdb_ci', id: cands[c].id, name: nameOf('cmdb_ci', cands[c].id), cls: classOf(cands[c].id), via: cands[c].via, verdict: verdict });
            if (verdict == 'real server') {
                led = true;
                if (servers[cands[c].id] === undefined) { var hwc = new GlideRecord('cmdb_ci_hardware'); hwc.get(cands[c].id); serverNames[cands[c].id] = text(hwc, 'name'); servers[cands[c].id] = serverNames[cands[c].id].trim().toLowerCase().split('.')[0] || cands[c].id; }
                if (placed.length < 3) placed.push(serverNames[cands[c].id] + ' via ' + cands[c].via);
            }
        }
        touch('candidates', 'member=' + memberIds[k], verdicts);
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
    var serverRows = []; for (var sr = 0; sr < ids.length; sr++) { var sg = new GlideRecord('cmdb_ci_hardware'); sg.get(ids[sr]); serverRows.push(ciRow(sg)); }
    touch('servers', 'distinct', serverRows);
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
    TOUCH.length = 0;
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
            var owners = [], phoneOwners = 0, n1 = 0, aRows = [];
            while (a.next()) { n1++; var ph = new GlideRecord('cmdb_ci_ip_phone'); var isPhone = ph.get(a.getValue('cmdb_ci')); if (isPhone) phoneOwners++; if (owners.length < ROWS) owners.push(text(a, 'name') + ' on ' + disp(a, 'cmdb_ci') + (isPhone ? ' [IP Phone]' : ' [not a phone]'));
                if (aRows.length < ROWS) aRows.push({ table: 'cmdb_ci_network_adapter', id: a.getUniqueValue(), name: text(a, 'name'), cls: 'cmdb_ci_network_adapter', mac: text(a, 'mac_address'), owner_id: '' + a.getValue('cmdb_ci'), owner: disp(a, 'cmdb_ci'), owner_cls: '' + a.cmdb_ci.sys_class_name, phone: !!isPhone }); }
            touch('cmdb_ci_network_adapter', 'mac_addressIN' + cands.join(','), aRows, n1);
            step(steps, 'Attempt 1: adapter with the MAC', n1 + ' adapter' + (n1 == 1 ? '' : 's') + (owners.length ? ': ' + owners.join(' ; ') : '') + ' -> ' + (phoneOwners == 1 ? 'one IP Phone owner, accepted' : phoneOwners + ' phone owners, next attempt'));
            var r2 = { n: 0, rows: [], valid: true };
            var g2 = new GlideRecord('cmdb_ci_ip_phone'); g2.addQuery('mac_address', 'IN', cands.join(',')); if (ignore) g2.addQuery('sys_class_name', 'NOT IN', ignore); g2.query(); while (g2.next()) { r2.n++; if (r2.rows.length < ROWS) r2.rows.push(ciRow(g2)); }
            touch('cmdb_ci_ip_phone', 'mac_addressIN' + cands.join(','), r2.rows, r2.n);
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
            var ok = f1 == dns || d1 == domain || (f1.indexOf(lbl + '.') == 0 && f1.indexOf(domain) > 0); x.agrees = ok; if (ok) good++; if (ok && ip && x.ip == ip) ipHits++;
            lines.push(rowText(x) + ' domain "' + (x.dns_domain || x.fqdn || '-') + '" ' + (ok ? 'agrees' : 'differs')); }
        step(steps, 'Records carrying the host name', rn.n + ': ' + lines.join(' ; ') + ' -> ' + good + ' agree on the domain' + (good > 1 ? ', ' + ipHits + ' on the scanned address' : ''));
        shape.push(kind.indexOf('Class') != -1 ? shortClass(pref) : (rn.rows[0] ? shortClass(rn.rows[0].cls) : 'none'), rn.n == 0 ? 'no row' : rn.n == 1 ? 'one row' : good == 1 ? 'domain separates' : 'tie by address');
    } else if (kind == 'Layered DNS Match') {
        step(steps, 'Name', '"' + dns + '"; ' + clsLine + ' (agreement includes appliances for a Linux fingerprint)');
        var link = new GlideRecord('cmdb_ip_address_dns_name'), owners2 = {}, ipOwners = {}, rowsL = [], nL = 0, linkRows = [];
        if (!link.isValid()) step(steps, 'Link table', 'cmdb_ip_address_dns_name is not on this instance');
        else {
            link.addQuery('dns_name.name', dns); link.addNotNullQuery('ip_address.nic.cmdb_ci'); if (ignore) link.addQuery('ip_address.nic.cmdb_ci.sys_class_name', 'NOT IN', ignore); link.query();
            while (link.next()) { nL++; var ow = '' + link.ip_address.nic.cmdb_ci, oc = '' + link.ip_address.nic.cmdb_ci.sys_class_name, addr = '' + link.ip_address.ip_address;
                var ag = agrees(oc, pref, true); if (ag) { owners2[ow] = true; if (ip && addr == ip) ipOwners[ow] = true; }
                if (rowsL.length < ROWS) rowsL.push('address ' + addr + ' -> adapter ' + link.ip_address.nic.getDisplayValue() + ' -> ' + link.ip_address.nic.cmdb_ci.getDisplayValue() + ' [' + shortClass(oc) + (ag ? '' : ', class disagrees') + ']');
                if (linkRows.length < ROWS) linkRows.push({ table: 'cmdb_ip_address_dns_name', id: link.getUniqueValue(), name: '' + link.dns_name.getDisplayValue(), cls: 'cmdb_ip_address_dns_name', dns_name_id: '' + link.getValue('dns_name'), dns_name: '' + link.dns_name.name,
                    ip_id: '' + link.getValue('ip_address'), ip: addr, nic_id: '' + link.ip_address.nic, nic: '' + link.ip_address.nic.getDisplayValue(), owner_id: ow, owner: '' + link.ip_address.nic.cmdb_ci.getDisplayValue(), owner_cls: oc, agrees: ag, on_address: !!(ip && addr == ip) }); }
            touch('cmdb_ip_address_dns_name', 'dns_name.name=' + dns, linkRows, nL);
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
            step(steps, 'Prefix "' + base2 + '"', hits.length ? hits.map(rowText).join(' ; ') : 'nothing on Network Gear or Load Balancer');
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
        var ownersA = {}, rowsA = [], nA = 0, recA = [];
        if (kind == 'IP Adapter Match') {
            var nicA = new GlideRecord('cmdb_ci_network_adapter'); nicA.addQuery('ip_address', ip); nicA.addNotNullQuery('cmdb_ci'); if (ignore) nicA.addQuery('cmdb_ci.sys_class_name', 'NOT IN', ignore); nicA.query();
            while (nicA.next()) { nA++; var oA = '' + nicA.getValue('cmdb_ci'), cA = '' + nicA.cmdb_ci.sys_class_name, agA = agrees(cA, pref, false); if (agA) ownersA[oA] = true; if (rowsA.length < ROWS) rowsA.push('adapter ' + text(nicA, 'name') + ' -> ' + nicA.cmdb_ci.getDisplayValue() + ' [' + shortClass(cA) + (agA ? '' : ', class disagrees') + ']');
                if (recA.length < ROWS) recA.push({ table: 'cmdb_ci_network_adapter', id: nicA.getUniqueValue(), name: text(nicA, 'name'), cls: 'cmdb_ci_network_adapter', ip: ip, mac: text(nicA, 'mac_address'), owner_id: oA, owner: '' + nicA.cmdb_ci.getDisplayValue(), owner_cls: cA, agrees: agA }); }
            touch('cmdb_ci_network_adapter', 'ip_address=' + ip, recA, nA);
            step(steps, 'Adapter records on the address', nA + (rowsA.length ? ': ' + rowsA.join(' ; ') : ''));
        } else {
            var ipA = new GlideRecord('cmdb_ci_ip_address');
            if (!ipA.isValid()) step(steps, 'IP Address records', 'cmdb_ci_ip_address is not on this instance');
            else { ipA.addQuery('ip_address', ip); ipA.addNotNullQuery('nic.cmdb_ci'); if (ignore) ipA.addQuery('nic.cmdb_ci.sys_class_name', 'NOT IN', ignore); ipA.query();
                while (ipA.next()) { nA++; var oB = '' + ipA.nic.cmdb_ci, cB = '' + ipA.nic.cmdb_ci.sys_class_name, agB = agrees(cB, pref, false); if (agB) ownersA[oB] = true; if (rowsA.length < ROWS) rowsA.push('IP Address record -> adapter ' + ipA.nic.getDisplayValue() + ' -> ' + ipA.nic.cmdb_ci.getDisplayValue() + ' [' + shortClass(cB) + (agB ? '' : ', class disagrees') + ']');
                    if (recA.length < ROWS) recA.push({ table: 'cmdb_ci_ip_address', id: ipA.getUniqueValue(), name: text(ipA, 'name'), cls: 'cmdb_ci_ip_address', ip: ip, nic_id: '' + ipA.getValue('nic'), nic: '' + ipA.nic.getDisplayValue(), owner_id: oB, owner: '' + ipA.nic.cmdb_ci.getDisplayValue(), owner_cls: cB, agrees: agB }); }
                touch('cmdb_ci_ip_address', 'ip_address=' + ip, recA, nA);
                step(steps, 'IP Address records on the address', nA + (rowsA.length ? ': ' + rowsA.join(' ; ') : '')); }
        }
        var ownA = Object.keys(ownersA), noteA = [];
        if (ownA.length == 1) { noteA.push(isLB(ownA[0]) ? 'a load balancer device, refused' : 'not a load balancer device'); noteA.push(nameAgrees(ownA[0], dns) ? 'name agrees with "' + lbl + '"' : 'name differs from "' + lbl + '", refused'); }
        step(steps, 'Decision', ownA.length + ' distinct owning CI' + (ownA.length == 1 ? '' : 's') + (ownA.length == 1 ? '; ' + noteA.join('; ') : ownA.length ? ': the rule declines' : ''));
        shape.push(nA + ' records', ownA.length + ' owners');
    } else {
        step(steps, 'Rule', 'no trace for this rule name');
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

// ---------------------------------------------------------------- what every earlier rule's search finds for the item
function junkSerial(s) {
    var junk = ['0', 'none', 'n/a', 'na', 'unknown', 'empty', 'not specified', 'not available', 'no serial', 'default string', 'to be filled by o.e.m.', 'system serial number', 'chassis serial number', '0123456789', '1234567890'];
    return !s || s.length < 4 || junk.indexOf(s) != -1;
}
function finding(kind, p) {
    var dns = ('' + (p.DNS || '')).trim().toLowerCase(), lbl = dns.split('.')[0], domain = dns.indexOf('.') != -1 ? dns.substring(dns.indexOf('.') + 1) : '';
    var ip = ('' + (p.IP || '')).trim(), os = '' + (p.OS || ''), pref = classFor(os), serial = ('' + (p.SERIAL_NUMBER || '')).trim();
    function n(table, field, value) { var r = rowsOf(table, field, value); return r.valid ? r.n + ' record' + (r.n == 1 ? '' : 's') : 'table not on this instance'; }
    function named(table) {
        var r = rowsOf(table, 'name', lbl), good = 0;
        for (var q = 0; q < r.rows.length; q++) { var f1 = r.rows[q].fqdn.toLowerCase(), d1 = r.rows[q].dns_domain.toLowerCase(); var ok = f1 == dns || d1 == domain || (f1.indexOf(lbl + '.') == 0 && f1.indexOf(domain) > 0); r.rows[q].agrees = ok; if (ok) good++; }
        return r.n + ' record' + (r.n == 1 ? '' : 's') + ' named "' + lbl + '", ' + good + ' with the domain "' + domain + '"';
    }
    function keep(st) { for (var i = 0; i < st.length; i++) for (var j = 0; j < st[i].searches.length; j++) TOUCH.push(st[i].searches[j]); }
    var noClass = 'OS "' + (os || 'not reported') + '" gives no class: not searched';
    switch (kind) {
        case 'Serial Number Class Match': return junkSerial(serial.toLowerCase()) ? (serial ? 'serial "' + serial + '" is a placeholder: not searched' : 'no serial reported: not searched') : !pref ? noClass : n(pref, 'serial_number', serial) + ' in ' + shortClass(pref) + ' carry the serial';
        case 'Serial Number Hardware Match': return junkSerial(serial.toLowerCase()) ? (serial ? 'serial "' + serial + '" is a placeholder: not searched' : 'no serial reported: not searched') : n('cmdb_ci_hardware', 'serial_number', serial) + ' in the hardware tree carry the serial';
        case 'Cisco IP Phone MAC': return /^sep[0-9a-f]{12}$/.test(lbl) ? 'label carries a MAC: searched' : 'label "' + lbl + '" is not sep plus twelve hex characters: not searched';
        case 'FQDN Class Match': return dns.indexOf('.') == -1 ? 'no dot in the name: not searched' : !pref ? noClass : n(pref, 'fqdn', dns) + ' in ' + shortClass(pref) + ' carry the fqdn';
        case 'FQDN Hardware Match': return dns.indexOf('.') == -1 ? 'no dot in the name: not searched' : n('cmdb_ci_hardware', 'fqdn', dns) + ' in the hardware tree carry the fqdn';
        case 'Hostname Domain Class Match': return !domain ? 'no domain in the name: not searched' : !pref ? noClass : named(pref) + ' in ' + shortClass(pref);
        case 'Hostname Domain Hardware Match': return !domain ? 'no domain in the name: not searched' : named('cmdb_ci_hardware') + ' in the hardware tree';
        case 'Layered DNS Match': { var link = new GlideRecord('cmdb_ip_address_dns_name'); if (!link.isValid()) return 'table not on this instance'; link.addQuery('dns_name.name', dns); link.addNotNullQuery('ip_address.nic.cmdb_ci'); link.query(); var k = 0, lr = []; while (link.next()) { k++; if (lr.length < ROWS) lr.push({ table: 'cmdb_ip_address_dns_name', id: link.getUniqueValue(), name: '' + link.dns_name.name, cls: 'cmdb_ip_address_dns_name', ip: '' + link.ip_address.ip_address, owner_id: '' + link.ip_address.nic.cmdb_ci, owner: '' + link.ip_address.nic.cmdb_ci.getDisplayValue(), owner_cls: '' + link.ip_address.nic.cmdb_ci.sys_class_name }); } touch('cmdb_ip_address_dns_name', 'dns_name.name=' + dns, lr, k); return k + ' DNS Name record' + (k == 1 ? '' : 's') + ' for "' + dns + '" lead to a CI'; }
        case 'Hostname Class Match': return !pref ? noClass : n(pref, 'name', lbl) + ' in ' + shortClass(pref) + ' named "' + lbl + '"';
        case 'Hostname Hardware Match': { var r = rowsOf('cmdb_ci_hardware', 'name', lbl); return r.n + ' record' + (r.n == 1 ? '' : 's') + ' in the hardware tree named "' + lbl + '"' + (r.n == 1 ? (agrees(r.rows[0].cls, pref, true) ? ' (class agrees)' : ' (class ' + shortClass(r.rows[0].cls) + ' disagrees with the OS)') : ''); }
        case 'Device Name Match': { var guard = pref && pref != 'cmdb_ci_linux_server' && os.toLowerCase().indexOf('phone') == -1; if (guard) return 'OS gives the class ' + shortClass(pref) + ': not searched'; var a = rowsOf('cmdb_ci_ip_phone', 'name', lbl), b = rowsOf('cmdb_ci_imaging_hardware', 'name', lbl); return (a.valid ? a.n : 0) + ' IP Phone and ' + (b.valid ? b.n : 0) + ' Imaging Hardware records named "' + lbl + '"'; }
        case 'Management Interface Match': { var suffixes = ['ilo', 'ilom', 'idrac', 'drac', 'ipmi', 'bmc', 'oob', 'mgmt', 'imm', 'cimc', 'rmm', 'con'], markers = ['ilo', 'ilom', 'idrac', 'drac', 'remote access controller', 'imm', 'cimc', 'bmc', 'ipmi', 'lights out'];
            var dash = lbl.lastIndexOf('-'), tail = dash > 0 ? lbl.substring(dash + 1) : '', sign = dash > 0 && suffixes.indexOf(tail) != -1 ? 'suffix "-' + tail + '"' : '';
            if (!sign) for (var mk = 0; mk < markers.length; mk++) if (os.toLowerCase().indexOf(markers[mk]) != -1) { sign = 'OS word "' + markers[mk] + '"'; break; }
            if (!sign) return 'no controller suffix or OS word: not searched';
            var base = dash > 0 ? lbl.substring(0, dash) : ''; return sign + '; ' + (base ? n('cmdb_ci_hardware', 'name', base) + ' named "' + base + '"' : 'no server name before a hyphen'); }
        case 'Network Interface Name Match': { var words = ['vlan', 'v', 'hsrp', 'vrrp', 'po', 'eth', 'gi', 'te', 'lo', 'mgmt', 'aom', 'vs', 'fab'], segs = lbl ? lbl.split('-') : [], sign2 = dns.indexOf('.network.') != -1;
            for (var si = 1; si < segs.length && !sign2; si++) if (isMarker(segs[si], words)) sign2 = true;
            if (!sign2) return 'no interface domain or marker: not searched';
            var hits = 0; for (var k2 = segs.length - 1; k2 >= 1; k2--) { var base2 = segs.slice(0, k2).join('-'); var h1 = rowsOf('cmdb_ci_netgear', 'name', base2), h2 = rowsOf('cmdb_ci_lb', 'name', base2); hits = h1.n + (h2.valid ? h2.n : 0); if (hits) return hits + ' device' + (hits == 1 ? '' : 's') + ' at the prefix "' + base2 + '"'; }
            return 'interface sign present; no device at any prefix'; }
        case 'FQDN Name Hardware Match': return n('cmdb_ci_hardware', 'name', dns) + ' in the hardware tree named "' + dns + '"';
        case 'FQDN Name Broad Match': return n('cmdb_ci', 'name', dns) + ' in any class named "' + dns + '"';
        case 'Load Balancer Member Match': { if (!vipSign(p).length) return 'no VIP sign: not searched'; var st = [], sh = []; memberWalk(p, st, sh); keep(st); return st.length ? st[st.length - 1].title + ': ' + st[st.length - 1].detail : 'no service record'; }
        case 'Load Balancer Service Match': { if (!vipSign(p).length) return 'no VIP sign: not searched'; var st2 = [], ss = serviceSearch(p, st2); keep(st2); return ss.service ? 'one live virtual server record: ' + ss.service.name : ss.stopped ? 'two names, declined' : ss.twins.length > 1 ? ss.twins.length + ' live records compete, declined' : 'no service record'; }
        case 'IP Class Match': return !pref ? noClass : n(pref, 'ip_address', ip) + ' in ' + shortClass(pref) + ' carry the address';
        case 'IP Hardware Match': { var ri = rowsOf('cmdb_ci_hardware', 'ip_address', ip); return ri.n + ' record' + (ri.n == 1 ? '' : 's') + ' in the hardware tree carry the address' + (ri.n == 1 ? (isLB(ri.rows[0].id) ? ' (a load balancer device, refused)' : !agrees(ri.rows[0].cls, pref, false) ? ' (class disagrees with the OS)' : !nameAgrees(ri.rows[0].id, dns) ? ' (name differs from the scanned label)' : '') : ''); }
        case 'IP Adapter Match': { var nic = new GlideRecord('cmdb_ci_network_adapter'); nic.addQuery('ip_address', ip); nic.addNotNullQuery('cmdb_ci'); nic.query(); var owners = {}, na = 0, nr = []; while (nic.next()) { na++; owners['' + nic.getValue('cmdb_ci')] = true; if (nr.length < ROWS) nr.push({ table: 'cmdb_ci_network_adapter', id: nic.getUniqueValue(), name: text(nic, 'name'), cls: 'cmdb_ci_network_adapter', ip: ip, owner_id: '' + nic.getValue('cmdb_ci'), owner: disp(nic, 'cmdb_ci'), owner_cls: '' + nic.cmdb_ci.sys_class_name }); } touch('cmdb_ci_network_adapter', 'ip_address=' + ip, nr, na); return na + ' adapter record' + (na == 1 ? '' : 's') + ' on the address, ' + Object.keys(owners).length + ' owning CI' + (Object.keys(owners).length == 1 ? '' : 's'); }
        case 'IP Layered Match': { var ipr = new GlideRecord('cmdb_ci_ip_address'); if (!ipr.isValid()) return 'table not on this instance'; ipr.addQuery('ip_address', ip); ipr.addNotNullQuery('nic.cmdb_ci'); ipr.query(); var ow = {}, nb = 0, pr = []; while (ipr.next()) { nb++; ow['' + ipr.nic.cmdb_ci] = true; if (pr.length < ROWS) pr.push({ table: 'cmdb_ci_ip_address', id: ipr.getUniqueValue(), name: text(ipr, 'name'), cls: 'cmdb_ci_ip_address', ip: ip, nic_id: '' + ipr.getValue('nic'), nic: disp(ipr, 'nic'), owner_id: '' + ipr.nic.cmdb_ci, owner: '' + ipr.nic.cmdb_ci.getDisplayValue(), owner_cls: '' + ipr.nic.cmdb_ci.sys_class_name }); } touch('cmdb_ci_ip_address', 'ip_address=' + ip, pr, nb); return nb + ' IP Address record' + (nb == 1 ? '' : 's') + ' on the address, ' + Object.keys(ow).length + ' owning CI' + (Object.keys(ow).length == 1 ? '' : 's'); }
    }
    return '';
}

// ---------------------------------------------------------------- rules, property, items
var rules = [], byOrder = {}, rl = new GlideRecord('sn_sec_cmn_ci_lookup_rule');
rl.addQuery('source.name', 'CONTAINS', 'Qualys'); rl.addQuery('method', 'script'); rl.addActiveQuery(); rl.orderBy('order'); rl.query();
while (rl.next()) { var rec = new GlideRecord('sn_sec_cmn_ci_lookup_rule'); rec.get(rl.getUniqueValue()); var ru = { id: rl.getUniqueValue(), order: '' + rl.getValue('order'), name: '' + rl.getValue('name'), field: '' + rl.getValue('source_field'), rec: rec, custom: /^(USEM|BOFA)\s/.test('' + rl.getValue('name')), updated: '' + rl.getValue('sys_updated_on') }; rules.push(ru); if (ru.custom) byOrder[ru.order] = ru; }
out.push('RULES ' + JSON.stringify(rules.map(function(x) { return { id: x.id, order: x.order, name: x.name, field: x.field, custom: x.custom, updated: x.updated }; })));
var prop = new GlideRecord('sys_properties'); prop.addQuery('name', 'sn_sec_cmn.ignoreCIClass'); prop.query();
out.push('PROP ' + JSON.stringify(prop.next() ? { id: prop.getUniqueValue(), value: '' + prop.getValue('value') } : { id: '', value: ignore }));
var done = 0, failed = 0;
for (var it = 0; it < ITEMS.length; it++) {
    var item = ITEMS[it], line;
    try {
        var di = new GlideRecord('sn_sec_cmn_src_ci');
        if (!di.get(item.id)) { di = new GlideRecord('sn_sec_cmn_src_ci'); di.addQuery('number', item.n); di.query(); if (!di.next()) { out.push('TR ' + JSON.stringify({ rule: item.r, number: item.n, error: 'discovered item not found' })); failed++; continue; } }
        var p; try { p = JSON.parse('' + di.getValue('source_data')); } catch (e1) { out.push('TR ' + JSON.stringify({ rule: item.r, number: item.n, error: 'source data is not JSON' })); failed++; continue; }
        var rule = byOrder[item.r], kind = (rule ? rule.name : item.k).replace(/^(USEM|BOFA)\s+/, '');
        var t = trace(kind, p);
        var verdict = rule ? runRule(rule.rec, rule.field, p) : '';
        var earlier = [];
        for (var b = 0; b < rules.length; b++) {
            if (!rules[b].custom || parseInt(rules[b].order) >= parseInt(item.r)) continue;
            TOUCH.length = 0;
            var f = finding(rules[b].name.replace(/^(USEM|BOFA)\s+/, ''), p);
            earlier.push({ order: rules[b].order, rule: rules[b].name, id: rules[b].id, found: f, searches: TOUCH.splice(0, TOUCH.length) });
        }
        var currentCi = '' + (di.getValue('cmdb_ci') || '');
        line = { rule: item.r, rule_id: rule ? rule.id : '', rule_name: rule ? rule.name : item.k, kind: kind, shape: t.shape, steps: t.steps, earlier: earlier,
            item: { number: '' + di.getValue('number'), sys_id: di.getUniqueValue(), dns: '' + (p.DNS || ''), ip: '' + (p.IP || ''), os: '' + (p.OS || ''), netbios: '' + (p.NETBIOS || ''), serial: '' + (p.SERIAL_NUMBER || ''), tracking: '' + (p.TRACKING_METHOD || ''), qualys_id: '' + (p.ID || ''), updated: '' + di.getValue('sys_updated_on'),
                state: '' + di.getValue('state'), matching_type: disp(di, 'matching_type'), rule_today: disp(di, 'ci_lookup_rule'), rule_today_id: '' + (di.getValue('ci_lookup_rule') || ''), ci_today: currentCi },
            ci: ciFacts(currentCi) || { id: currentCi, name: '?' }, verdict: { ci: verdict, same_as_today: verdict == currentCi, facts: verdict && verdict.indexOf('error') != 0 ? ciFacts(verdict) : null } };
        out.push('TR ' + JSON.stringify(line)); done++;
    } catch (e) { out.push('TR ' + JSON.stringify({ rule: item.r, number: item.n, error: '' + e })); failed++; }
}
gs.print('=== Qualys lookup rules, demo record trace, read-only ===\nrules: ' + rules.length + ' | items: ' + ITEMS.length + ' | traced: ' + done + ' | failed: ' + failed + ' | elapsed: ' + Math.round((new Date().getTime() - started) / 1000) + ' s\n' + out.join('\n'));
