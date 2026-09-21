// Step-by-step pages with record links for every example: what the script does at each step, what it found for this
// item, and a link to every record and every filter (as in the load balancer walkthrough document).
const fs = require('fs');
const path = require('path');
const T = JSON.parse(fs.readFileSync(path.join(__dirname, 'trace_data.json'), 'utf8'));
const HOST = 'https://bofasecopsdev.service-now.com';
const rec = (table, id) => `${HOST}/${table}.do?sys_id=${id}`;
const enc = (q) => q.replace(/%/g, '%25').replace(/=/g, '%3D').replace(/\^/g, '%5E').replace(/ /g, '%20').replace(/#/g, '%23').replace(/&/g, '%26');
const list = (table, q) => `${HOST}/${table}_list.do?sysparm_query=${enc(q)}`;
const RULE_ID = {}; (T.rules || []).forEach(r => { RULE_ID[r.order] = r.id; });
const PROP_URL = T.prop && T.prop.id ? rec('sys_properties', T.prop.id) : list('sys_properties', 'name=sn_sec_cmn.ignoreCIClass');

function classLine(kind, tr) {
  const os = tr.item.os || 'not reported';
  return kind.indexOf('Class') !== -1 ? `classFor(sourcePayload.OS) turns the OS text "${os}" into the CMDB class the search is limited to, sub-classes included; no class means null.`
    : 'The search covers the whole Hardware tree (cmdb_ci_hardware and every sub-class).';
}
// what the script does at a step, from the step title and the rule family
function explain(kind, title, tr) {
  const hw = kind.indexOf('Hardware') !== -1;
  if (/^Serial read/.test(title)) return 'Reads the scanned serial (sourceValue), trims it, and refuses an empty value, one shorter than four characters or a vendor placeholder from the list in the script.';
  if (title === 'Class') return classLine(kind, tr);
  if (/^Records carrying the serial/.test(title)) return 'One query: serial_number equal to the serial, the ignored classes (property sn_sec_cmn.ignoreCIClass) left out. next() then hasNext(): exactly one row is returned; none, or two or more, give null.';
  if (/^Phone label/.test(title)) return 'Lower-cases the DNS label before the first dot and tests it against "sep" plus twelve hex characters; any other shape returns null.';
  if (/^MAC rebuilt/.test(title)) return 'Rebuilds the MAC address from the twelve hex characters in the four spellings the CMDB uses: colon-separated and plain, upper and lower case.';
  if (/^Attempt 1/.test(title)) return 'Network Adapter records whose mac_address is one of the four spellings and that belong to a CI; the rule accepts when exactly one owning CI is an IP Phone record.';
  if (/^Attempt 2/.test(title)) return 'IP Phone records whose own mac_address is one of the four spellings, ignored classes left out; exactly one is returned.';
  if (/^Attempt 3/.test(title)) return 'IP Phone records named with the label in upper case, the Unified CM device name; exactly one is returned.';
  if (title === 'Name' && /^FQDN (Class|Hardware) Match$/.test(kind)) return 'Lower-cases and trims the DNS name; a name without a dot is refused. ' + classLine(kind, tr);
  if (title === 'Name' && kind === 'Layered DNS Match') return 'Lower-cases the DNS name. classFor(OS) is kept as a preference: the CI reached must sit in that class or a parent of it; a Linux fingerprint also accepts network gear, load balancers and storage.';
  if (title === 'Name' && /FQDN Name/.test(kind)) return 'The whole DNS name, dots included, is searched on the name field of ' + (kind.indexOf('Broad') !== -1 ? 'every CI class (cmdb_ci).' : 'the whole Hardware tree.');
  if (/^Records carrying the fqdn/.test(title)) return 'One query: fqdn equal to the DNS name, ignored classes left out. One row is returned; among several rows the one whose ip_address equals the scanned IP is taken when exactly one does, else null.';
  if (/^Split/.test(title)) return 'Splits the DNS name at the first dot into the host label and the domain; no domain means null. ' + classLine(kind, tr);
  if (/^Records carrying the host name/.test(title)) return 'One query: name equal to the label, ignored classes left out. A row agrees when its fqdn equals the DNS name, its dns_domain equals the domain, or its fqdn starts with the label and holds the domain. One agreeing row is returned; among several the one on the scanned address; else null.';
  if (/^DNS Name -> IP Address/.test(title)) return 'Reads the link table cmdb_ip_address_dns_name for the DNS Name record named like the host and follows IP Address -> Network Adapter -> CI, ignored classes left out; the owners whose class agrees with the OS are kept.';
  if (/^Link table/.test(title)) return 'The link table cmdb_ip_address_dns_name must exist; without it the rule returns null.';
  if (title === 'Host name') return 'Lower-cases the DNS name and takes the label before the first dot. ' + (hw ? 'The search covers the whole Hardware tree; classFor(OS) is kept as a preference.' : classLine(kind, tr));
  if (/^Records carrying the name/.test(title)) return 'One query: name equal to the label, ignored classes left out. Exactly one row is returned' + (hw ? ', and its class must agree with the OS class when the OS gives one (a Linux fingerprint also accepts appliances)' : '') + '; none or several give null.';
  if (/^OS guard/.test(title)) return 'classFor(OS): a server or desktop class means the host is a computer and the rule declines; a phone word in the OS, a Linux fingerprint or no class lets the search run.';
  if (/^Name searched in IP Phone/.test(title)) return 'Two queries: name equal to the label on IP Phone (cmdb_ci_ip_phone) and on Imaging Hardware (cmdb_ci_imaging_hardware), ignored classes left out.';
  if (/^Controller sign/.test(title)) return 'Cuts the label at its last hyphen: a controller suffix (ilo, ilom, idrac, drac, ipmi, bmc, oob, mgmt, imm, cimc, rmm, con) or a controller word in the OS text marks a management interface; the part before the hyphen is the server name.';
  if (/^Records carrying the server name/.test(title)) return 'One query on the Hardware tree: name equal to the server name, ignored classes left out; exactly one row is returned, a load balancer device is refused.';
  if (/^Interface sign/.test(title)) return 'An interface is recognised by the domain ".network." or by a label segment after the first that is an interface word (vlan, v, hsrp, vrrp, po, eth, gi, te, lo, mgmt, aom, vs, fab), alone or followed by digits.';
  if (/^Prefix "/.test(title)) return 'Drops the last segment and searches Network Gear (cmdb_ci_netgear) and Load Balancer (cmdb_ci_lb) for a device named with the remaining prefix, ignored classes left out.';
  if (/^Prefixes tried/.test(title)) return 'Prefixes are tried from the longest down: the first prefix with exactly one device is returned; a prefix with two devices ends the rule with null.';
  if (/^Records named with the whole fqdn/.test(title)) return 'One query: name equal to the whole DNS name, ignored classes left out; exactly one row is returned.';
  if (/^VIP sign/.test(title)) return 'The OS text is searched for f5, big-ip, big ip and netscaler, and the label segments for vip or vs (the word, the word plus digits, or a longer word ending in it); without a sign the rule returns null.';
  if (/^Clue (\d)/.test(title)) { const f = /: (\w+) =/.exec(title); return 'One query on Load Balancer Service (cmdb_ci_lb_service): ' + (f ? f[1] : 'the field') + ' equal to the value, ignored classes left out. Nothing found hands over to the next clue; one record settles the search; records of two different names end the rule.'; }
  if (/^Twins/.test(title)) return 'Records of one name are one virtual server recorded more than once: the ones on the scanned address are kept, then the live ones.';
  if (/^Two differently named/.test(title)) return 'Two names mean two virtual servers: neither load balancer rule guesses.';
  if (/^Service search/.test(title)) return 'No clue found a service record: the rule returns null.';
  if (/^Pools/.test(title)) return 'Reads the Pool field of each service record kept, the pools whose Service field points at it, and the pools related to it through cmdb_rel_ci; no pool means the member rule declines.';
  if (/^Members/.test(title)) return 'Collects the Pool Member records of every pool (Pool field and relationships) with their addresses, and looks each address up on Hardware records, Network Adapters and IP Address records; only a real server counts: in the Hardware tree, not a load balancer device, not an ignored class.';
  if (title === 'Address') return 'Trims the scanned IP (sourceValue); loopback and link-local addresses are refused. ' + (kind === 'IP Class Match' ? classLine(kind, tr) : 'The OS class is kept as a preference for class agreement.');
  if (/^Records carrying the address/.test(title)) return 'One query: ip_address equal to the scanned IP, ignored classes left out. Exactly one row is returned when ' + (hw ? 'it is not a load balancer device, its class agrees with the OS class and ' : '') + 'its name agrees with the scanned label (equal, or one a hyphenated extension of the other).';
  if (/^Adapter records on the address/.test(title)) return 'Network Adapter records (cmdb_ci_network_adapter) whose ip_address is the scanned IP and that belong to a CI, ignored classes left out; the owning CIs whose class agrees with the OS are kept.';
  if (/^IP Address records/.test(title)) return 'IP Address records (cmdb_ci_ip_address) on the scanned IP whose adapter belongs to a CI, ignored classes left out; the owning CIs whose class agrees with the OS are kept.';
  if (title === 'Decision') {
    if (kind === 'Layered DNS Match') return 'Exactly one agreeing CI is returned; several are narrowed to the ones reached through the scanned address; a load balancer device is refused.';
    if (kind === 'Device Name Match') return 'One device is returned; several fall back to the one on the scanned address; none, or a tie, give null.';
    if (kind === 'Load Balancer Member Match') return 'Counts the distinct machines behind the virtual server (server records grouped by name): one machine with one live record is returned; a member the CMDB cannot place, two machines or two live records decline.';
    if (kind === 'Load Balancer Service Match') return 'The one live service record left is attached as the CI; two names or two live records decline. The pool is not read: that is the member rule\'s job.';
    return 'The distinct owning CIs are counted: exactly one is returned when it is not a load balancer device and its name agrees with the scanned label (equal, or one a hyphenated extension of the other).';
  }
  return '';
}
const tableLabel = (t) => ({ cmdb_ci_lb_service: 'Load Balancer Service', cmdb_ci_lb_pool: 'Load Balancer Pool', cmdb_ci_lb_pool_member: 'Pool Member', cmdb_ci_network_adapter: 'Network Adapter', cmdb_ci_ip_address: 'IP Address', cmdb_ip_address_dns_name: 'DNS Name link', cmdb_rel_ci: 'CI relationship', cmdb_ci_hardware: 'Hardware', cmdb_ci: 'CI', cmdb_ci_ip_phone: 'IP Phone', cmdb_ci_imaging_hardware: 'Imaging Hardware', cmdb_ci_netgear: 'Network Gear', cmdb_ci_lb: 'Load Balancer' }[t] || t.replace(/^cmdb_ci_/, '').replace(/_/g, ' '));

// runs for the "for this item" cell: the detail, then one line per search with its filter link and record links
function itemRuns(step, NAVY, INK, MUTED) {
  const runs = [{ text: step.detail, options: { color: INK } }];
  const L = (text, url) => ({ text, options: { color: NAVY, underline: { style: 'sng' }, hyperlink: { url, tooltip: url } } });
  const P = (text) => ({ text, options: { color: MUTED } });
  (step.searches || []).forEach(sr => {
    if (sr.table === 'candidates' || sr.table === 'servers') {
      if (!sr.rows.length) return;
      runs.push({ text: '', options: { breakLine: true } });
      runs.push(P(sr.table === 'servers' ? 'Distinct servers: ' : 'Candidates for member: '));
      sr.rows.forEach((w, i) => { if (i) runs.push(P(' · ')); runs.push(L(w.name || w.id, rec(w.table || 'cmdb_ci', w.id))); if (w.via) runs.push(P(' via ' + w.via + (w.verdict ? ', ' + w.verdict : ''))); });
      return;
    }
    runs.push({ text: '', options: { breakLine: true } });
    runs.push(P('Filter '));
    runs.push(L(tableLabel(sr.table) + ': ' + sr.q, list(sr.table, sr.q)));
    runs.push(P(' (' + sr.n + ' row' + (sr.n === 1 ? '' : 's') + ')'));
    sr.rows.forEach(w => {
      runs.push(P('  →  '));
      runs.push(L(w.name || w.ip || w.id, rec(w.table || sr.table, w.id)));
      if (w.live === false) runs.push(P(' (retired)'));
      if (w.nic_id) { runs.push(P(' → adapter ')); runs.push(L(w.nic || w.nic_id, rec('cmdb_ci_network_adapter', w.nic_id))); }
      if (w.owner_id) { runs.push(P(' → ')); runs.push(L(w.owner || w.owner_id, rec(w.owner_cls || 'cmdb_ci', w.owner_id))); runs.push(P(' [' + (w.owner_cls || '').replace(/^cmdb_ci_/, '') + (w.agrees === false ? ', class disagrees' : '') + (w.phone === true ? ', IP Phone' : w.phone === false ? ', not a phone' : '') + ']')); }
      if (w.dns_name_id) { runs.push(P(' (DNS Name ')); runs.push(L(w.dns_name || 'record', rec('cmdb_ci_dns_name', w.dns_name_id))); runs.push(P(', IP Address ')); runs.push(L(w.ip || 'record', rec('cmdb_ci_ip_address', w.ip_id))); runs.push(P(')')); }
      if (w.pool_id) { runs.push(P(' → pool ')); runs.push(L(w.pool || w.pool_id, rec('cmdb_ci_lb_pool', w.pool_id))); }
      if (w.lb_id) { runs.push(P(' on balancer ')); runs.push(L(w.lb || w.lb_id, rec(w.lb_cls || 'cmdb_ci_lb', w.lb_id))); }
      if (w.via) runs.push(P(' (' + w.via + ')'));
      if (w.agrees === false && !w.owner_id) runs.push(P(' (domain differs)'));
    });
  });
  return runs;
}
function findingRuns(e, NAVY, INK, MUTED) {
  const runs = [{ text: e.found, options: { color: INK } }];
  const L = (text, url) => ({ text, options: { color: NAVY, underline: { style: 'sng' }, hyperlink: { url, tooltip: url } } });
  const P = (text) => ({ text, options: { color: MUTED } });
  (e.searches || []).forEach(sr => {
    if (sr.table === 'candidates' || sr.table === 'servers' || sr.table === '(no class)') return;
    runs.push(P('  ·  ')); runs.push(L(tableLabel(sr.table) + ' filter', list(sr.table, sr.q))); runs.push(P(' (' + sr.n + ')'));
    sr.rows.slice(0, 4).forEach(w => { runs.push(P(' → ')); runs.push(L(w.name || w.ip || w.id, rec(w.table || sr.table, w.id))); if (w.owner_id) { runs.push(P(' → ')); runs.push(L(w.owner || w.owner_id, rec(w.owner_cls || 'cmdb_ci', w.owner_id))); } });
  });
  return runs;
}
module.exports = { T, rec, list, RULE_ID, PROP_URL, explain, itemRuns, findingRuns };
