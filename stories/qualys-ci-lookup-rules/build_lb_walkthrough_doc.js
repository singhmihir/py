// Word document: how discovered items scanned on load balancer addresses reached their CI on the
// development instance, record by record and line by line, with clickable links for every step.
const fs = require('fs');
const { Document, Packer, Paragraph, TextRun, ExternalHyperlink, PageBreak, HeadingLevel, Table, TableRow, TableCell,
        WidthType, BorderStyle, ShadingType, TableLayoutType, PageNumber, Footer, AlignmentType } = require('docx');
const FONT = 'Calibri', SZ = 22, MUTED = '595959', LINK = '0563C1', HEAD = 'E7ECF2', CODE = 'F3F4F6';
const HOST = 'https://bofasecopsdev.service-now.com';
const HAIR = { style: BorderStyle.SINGLE, size: 4, color: 'BFC5CC' };
const rec = (table, id) => `${HOST}/${table}.do?sys_id=${id}`;
const enc = (q) => q.replace(/=/g, '%3D').replace(/\^/g, '%5E').replace(/ /g, '%20');
const list = (table, q) => `${HOST}/${table}_list.do?sysparm_query=${enc(q)}`;
const t = (text, o) => { o = o || {}; return new TextRun({ text, font: o.mono ? 'Consolas' : FONT, size: o.size || (o.mono ? 19 : SZ), bold: o.bold, italics: o.italics, color: o.color }); };
const link = (text, url, o) => { o = o || {}; return new ExternalHyperlink({ children: [new TextRun({ text, font: FONT, size: o.size || SZ, color: LINK, underline: {} })], link: url }); };
const p = (runs, o) => { o = o || {}; return new Paragraph({ children: Array.isArray(runs) ? runs : [runs], spacing: { before: o.before || 0, after: o.after == null ? 140 : o.after, line: o.line || 300 }, indent: o.indent ? { left: o.indent } : undefined, shading: o.fill ? { type: ShadingType.CLEAR, fill: o.fill } : undefined, keepNext: o.keepNext }); };
const lab = (label, runs) => p([t(label + '  ', { bold: true })].concat(Array.isArray(runs) ? runs : [runs]));
const ln = (label, text, url) => p([t(label + '  ', { color: MUTED }), link(text, url)], { indent: 360, after: 100 });
const h1 = (text) => new Paragraph({ text, heading: HeadingLevel.HEADING_1, spacing: { before: 360, after: 200 } });
const h2 = (text) => new Paragraph({ text, heading: HeadingLevel.HEADING_2, spacing: { before: 280, after: 160 } });
const h3 = (text) => new Paragraph({ children: [t(text, { bold: true, size: 23, color: '1F3864' })], spacing: { before: 200, after: 100, line: 300 }, keepNext: true });
const brk = () => new Paragraph({ children: [new PageBreak()] });
const code = (lines) => lines.map((l, i) => p(t(l, { mono: true }), { after: i == lines.length - 1 ? 140 : 0, line: 260, fill: CODE, indent: 200 }));
const cell = (children, w, fill) => new TableCell({ children, width: { size: w, type: WidthType.DXA }, shading: fill ? { type: ShadingType.CLEAR, fill } : undefined, margins: { top: 60, bottom: 60, left: 110, right: 110 } });
const num = (i) => p(t(String(i) + '.'), { after: 0, line: 260 });
function kv(rows) {
  return new Table({ rows: rows.map(r => new TableRow({ cantSplit: true, children: [cell([p(t(r[0], { bold: true }), { after: 0 })], 2600, HEAD), cell([p(t(r[1]), { after: 0 })], 6760)] })),
    width: { size: 9360, type: WidthType.DXA }, columnWidths: [2600, 6760], layout: TableLayoutType.FIXED,
    borders: { top: HAIR, bottom: HAIR, left: HAIR, right: HAIR, insideHorizontal: HAIR, insideVertical: HAIR } });
}
// the walk table: step number, what the script does, what it finds for this item (runs, may hold links)
function walk(rows) {
  const head = new TableRow({ tableHeader: true, children: [cell([p(t('No.', { bold: true }), { after: 0 })], 700, HEAD), cell([p(t('What the script does', { bold: true }), { after: 0 })], 4000, HEAD), cell([p(t('For this item', { bold: true }), { after: 0 })], 4660, HEAD)] });
  const body = rows.map((r, i) => new TableRow({ cantSplit: true, children: [cell([num(i + 1)], 700), cell([p(t(r[0]), { after: 0, line: 260 })], 4000), cell(r[1].map(runs => p(runs, { after: 40, line: 260 })), 4660)] }));
  return new Table({ rows: [head].concat(body), width: { size: 9360, type: WidthType.DXA }, columnWidths: [700, 4000, 4660], layout: TableLayoutType.FIXED,
    borders: { top: HAIR, bottom: HAIR, left: HAIR, right: HAIR, insideHorizontal: HAIR, insideVertical: HAIR } });
}
const gap = () => p(t(''), { after: 60 });
const RULE_455 = list('sn_sec_cmn_ci_lookup_rule', 'name=BOFA Load Balancer Member Match');
const RULE_460 = list('sn_sec_cmn_ci_lookup_rule', 'name=BOFA Load Balancer Service Match');
const PROP = list('sys_properties', 'name=sn_sec_cmn.ignoreCIClass');
const K = [];

K.push(new Paragraph({ children: [t('Qualys CI Matching for Load Balancer Addresses', { bold: true, size: 36 })], spacing: { after: 120, line: 440 } }));
K.push(p(t('How discovered items reach their CI through the Load Balancer Member Match and Load Balancer Service Match rules, record by record and line by line', { color: MUTED, size: 24 }), { after: 60 }));
K.push(p(t('Development instance, 17 September 2026', { color: MUTED }), { after: 300 }));

K.push(h1('What both rules receive'));
K.push(p(t('Every Qualys host record arrives as a Discovered Item (table sn_sec_cmn_src_ci). Its source data carries the scanned IP, the DNS name Qualys resolved for it, when there is one, and the operating system text of whatever answered the scan. A virtual IP has no serial number, no CI carries its DNS name, and the address rules deliberately refuse a load balancer device, so a virtual IP reaches the two load balancer rules with nothing matched.')));
K.push(p(t('Both rules are CI lookup rules on the Qualys source. They run in this order: Load Balancer Member Match first, Load Balancer Service Match next, and the first rule to return a CI wins.')));
K.push(ln('Rule record:', 'BOFA Load Balancer Member Match', RULE_455));
K.push(ln('Rule record:', 'BOFA Load Balancer Service Match', RULE_460));
K.push(h3('The lines every evaluation starts with'));
K.push(p(t('Each rule receives the scanned IP as sourceValue and the whole host record as sourcePayload. The first lines take the values apart and read the list of CI classes that must never be matched:')));
K.push(...code(["var ip = ('' + sourceValue).trim();", "if (!ip || ip.indexOf('127.') == 0 || ip.indexOf('169.254.') == 0)", '    return null;',
                "var dns = ('' + (sourcePayload.DNS || '')).trim().toLowerCase();", "var label = dns.split('.')[0];", "var os = ('' + (sourcePayload.OS || '')).toLowerCase();",
                "var ignore = gs.getProperty('sn_sec_cmn.ignoreCIClass', '');"]));
K.push(p([t('A loopback or link-local address identifies nothing, so the rule stops there. The label is the DNS name before the first dot. The ignore list is the property '), link('sn_sec_cmn.ignoreCIClass', PROP), t(', read at run time; every search below leaves those classes out.')]));
K.push(h3('The virtual IP sign'));
K.push(p(t('Both rules go on only when the host record shows a virtual IP sign. The two lists are declared in the script:')));
K.push(...code(["var osMarkers = ['f5', 'big-ip', 'big ip', 'netscaler'];", "var labelMarkers = ['vip', 'vs'];"]));
K.push(p(t('The operating system text is searched for each product word. The label is split at hyphens, and a segment counts as a marker when it is the word itself (vip), the word followed by digits only (vip1, vip2, vs1), or a longer word ending in it (multihostvip). One hit of either kind is enough. Without a sign the rule returns null: a Load Balancer Service must never be attached to an ordinary server that happens to share an address with a virtual IP.')));
K.push(h3('The four clues'));
K.push(p(t('With a sign, both rules search the Load Balancer Service table (cmdb_ci_lb_service, the virtual server) with four clues, in this order:')));
K.push(...code(["var steps = [['fqdn', dns], ['name', dns], ['name', label], ['ip_address', ip]];"]));
K.push(p(t('Each clue is one query on cmdb_ci_lb_service: the field equal to the value, ignored classes left out. A clue whose value is empty is skipped. A clue that finds nothing hands over to the next. A clue that finds exactly one record settles the search. A clue that finds two records ends the rule without a match, because a weaker clue could otherwise pick a different service.')));
K.push(p(t('On our instance the service records are named after the F5 object (for example /Common/ait73074-rvcpbt1-ctuapi-pb-443-vip) and carry no fqdn, so the first three clues find nothing and the fourth, the IP address, is the one that identifies the virtual server in every example in this document. Each example below carries the filter links for the clues, so the empty result of the name clues and the single result of the address clue can be seen on the instance.')));
K.push(brk());

// ---------------------------------------------------------------- 455
K.push(h1('BOFA Load Balancer Member Match'));
K.push(p([t('Purpose. A virtual server usually fronts several real servers, but many front exactly one. When the CMDB holds the pool behind the virtual server and exactly one real server sits in it, the findings scanned on the virtual address belong to that server. This rule returns that server. Rule record: '), link('BOFA Load Balancer Member Match', RULE_455), t('.')]));
K.push(p(t('After the sign and the four clues, the script walks the platform\'s own load balancer model:')));
const steps455 = [
  'Reads the Pool field of the service record. It also takes any Load Balancer Pool (cmdb_ci_lb_pool) whose Service field points at the service, and any pool tied to the service by a CI relationship (cmdb_rel_ci, either direction). Without a pool the rule returns null.',
  'Collects the Load Balancer Pool Member records (cmdb_ci_lb_pool_member) whose Pool field points at one of those pools, plus members tied to a pool by a relationship, each with its IP address. Without members the rule returns null.',
  'Looks each member address up in three places: the IP Address field of the server records (cmdb_ci_hardware), the Network Adapter records (their owning CI), and the IP Address records (their adapter\'s CI). A member tied to a server by a relationship counts as well.',
  'Keeps only real servers: a record in the Hardware tree that is neither a load balancer device (cmdb_ci_lb and its sub-classes) nor of a class on the ignore list.',
  'Counts the distinct servers found. Exactly one is returned; none, or two or more, and the rule returns null, leaving the host to the service rule.',
];
steps455.forEach((s, i) => K.push(p([t((i + 1) + '.  ', { bold: true }), t(s)], { indent: 360, after: 100 })));
K.push(p(t('The discovered item then carries the server as its CI, the rule as its CI lookup rule and "matched by CI lookup" as its matching type: never the load balancer device, and not the virtual server record.'), { before: 80 }));
K.push(p(t('Five items matched by this rule follow, one per page. Each page shows the source data, the sign, the walk step by step with the record found at every hop, and a link for each record and each filter the script used.')));
K.push(brk());

function ex455(n, o) {
  const dns = o.dns, label = dns.split('.')[0], segs = label.split('-');
  K.push(h2(`Example ${n}: ${o.num}`));
  K.push(lab('Discovered item', link(o.num, list('sn_sec_cmn_src_ci', 'number=' + o.num))));
  K.push(lab('Source data received', t('')));
  K.push(kv([['IP', o.ip], ['DNS', o.dns], ['OS', o.os]]));
  K.push(gap());
  K.push(lab('Virtual IP sign', t(o.sign)));
  K.push(lab('Result', t(`The rule returned ${o.server} (${o.serverClass}), and the discovered item carries that server as its CI. ${o.note}`)));
  K.push(h3('How the script walks this item'));
  const rows = [
    ['Takes the scanned IP and checks it is not loopback or link-local.', [[t(`ip = "${o.ip}", accepted.`)]]],
    ['Lower-cases the DNS name, cuts the label before the first dot, lower-cases the OS text.', [[t(`dns = "${dns}", label = "${label}", os = "${o.os.toLowerCase()}".`)]]],
    ['Reads the ignore list from the property.', [[t('sn_sec_cmn.ignoreCIClass: '), link('open the property', PROP)]]],
    ['Searches the OS text for the product words and the label segments for the markers.', [[t(o.signWalk)]]],
    ['Clue 1, fqdn equal to the DNS name.', [[t('No service record carries this fqdn: '), link('filter on fqdn', list('cmdb_ci_lb_service', 'fqdn=' + dns)), t(' (empty). Next clue.')]]],
    ['Clue 2, name equal to the DNS name; clue 3, name equal to the label.', [[t('No service record is named this way: '), link('filter on the label', list('cmdb_ci_lb_service', 'name=' + label)), t(' (empty). Next clue.')]]],
    ['Clue 4, ip_address equal to the scanned IP.', [[t('Exactly one record: '), link(o.svcLinkText, o.svcLink), t(o.svcTail)], [t('Check: '), link('services on ' + o.ip, list('cmdb_ci_lb_service', 'ip_address=' + o.ip)), t(' (one row).')]]],
    ['Reads the Pool field of the service record; also looks for pools whose Service field points at it and pools related to it.', [[t(o.poolText + ' ')].concat(o.poolLink ? [link(o.poolName, o.poolLink)] : [])]
        .concat(o.svcId ? [[t('Pools by Service field: '), link('filter', list('cmdb_ci_lb_pool', 'service=' + o.svcId)), t('; related records: '), link('filter', list('cmdb_rel_ci', 'parent=' + o.svcId + '^ORchild=' + o.svcId)), t('.')]] : [])],
    ['Collects the Pool Member records whose Pool field points at the pool, with their IP addresses.', [[t(o.memberText + ' '), link(o.memberLinkText, o.memberLink)]]],
    ['Looks the member address up on server records, on network adapters and on IP Address records.', [[t(`${o.memberIp} is the IP Address field of the server record ${o.server}: `), link('servers on ' + o.memberIp, list('cmdb_ci_hardware', 'ip_address=' + o.memberIp))], [t('Adapters: '), link('filter', list('cmdb_ci_network_adapter', 'ip_address=' + o.memberIp)), t('; IP Address records: '), link('filter', list('cmdb_ci_ip_address', 'ip_address=' + o.memberIp)), t('. Whichever of the three places holds the address, the owning CI is the same server, counted once.')]]],
    ['Keeps the record only if it is a real server: in the Hardware tree, not a load balancer device, not an ignored class.', [[t(`${o.server} is a ${o.serverClass} record, so it is kept.`)]]],
    ['Counts the distinct servers and returns the one sys_id.', [[t('One server. Returned: '), link(o.server, rec(o.serverTable, o.serverId))]]],
    ['The platform writes the result on the discovered item.', [[t('CI = ' + o.server + ', CI lookup rule = BOFA Load Balancer Member Match, matching type = matched by CI lookup, state = matched.')]]],
  ];
  K.push(walk(rows));
  K.push(brk());
}
ex455(1, { num: 'SDI000002418623', ip: '10.143.52.217', dns: 'ccgw-l7-vip2.sit1.gwimnp.rpg', os: 'F5 Networks Big-IP',
  sign: 'The OS text contains "f5" and "big-ip"; the label segment "vip2" is a marker as well.',
  signWalk: '"f5 networks big-ip" contains "f5" and "big-ip". Segments ccgw, l7, vip2: "vip2" is "vip" followed by digits. Sign present.',
  svcLinkText: '/Common/ihscore-sit1-ccgw-6011-vip', svcLink: rec('cmdb_ci_lb_service', 'be381f963bfd2e50489ce5d964e45a84'), svcId: 'be381f963bfd2e50489ce5d964e45a84', svcTail: ' (port 6011, on balancer svedpz1rp4lb10).',
  poolText: 'The Pool field points at', poolName: '/Common/ihscore-sit1-ccgw-6011-pool', poolLink: rec('cmdb_ci_lb_pool', '36381f963bfd2e50489ce5d964e45a84'),
  memberText: 'The members of this pool carry one address, 10.143.72.200:', memberLinkText: 'pool members', memberLink: list('cmdb_ci_lb_pool_member', 'pool=36381f963bfd2e50489ce5d964e45a84'),
  memberIp: '10.143.72.200', server: 'lva71pwbolcc01v', serverClass: 'Linux Server', serverTable: 'cmdb_ci_linux_server', serverId: 'ddcdddf02b462294d50dffbdbe91bf9b',
  note: 'The balancer svedpz1rp4lb10 is a separate CI and is never returned.' });
ex455(2, { num: 'SDI000002411394', ip: '10.143.52.163', dns: 'ccgw-l7-vip2.dev.gwimnp.rpg', os: 'F5 Networks Big-IP',
  sign: 'The OS text contains "f5" and "big-ip"; the label segment "vip2" is a marker as well.',
  signWalk: '"f5 networks big-ip" contains "f5" and "big-ip". Segments ccgw, l7, vip2: "vip2" is "vip" followed by digits. Sign present.',
  svcLinkText: '/Common/ihscore-dev-ccgw-6011-vip', svcLink: rec('cmdb_ci_lb_service', 'b2381f963bfd2e50489ce5d964e45a86'), svcId: 'b2381f963bfd2e50489ce5d964e45a86', svcTail: ' (port 6011, on balancer svedpz1rp4lb10).',
  poolText: 'The Pool field points at', poolName: '/Common/ihscore-dev-ccgw-6011-pool', poolLink: rec('cmdb_ci_lb_pool', '3a381f963bfd2e50489ce5d964e45a85'),
  memberText: 'The members of this pool carry one address, 10.143.72.198:', memberLinkText: 'pool members', memberLink: list('cmdb_ci_lb_pool_member', 'pool=3a381f963bfd2e50489ce5d964e45a85'),
  memberIp: '10.143.72.198', server: 'lva68pwbolcc01v', serverClass: 'Linux Server', serverTable: 'cmdb_ci_linux_server', serverId: 'd78e25b82b8e2294d50dffbdbe91bf32',
  note: 'The same application as example 1 in the development environment: a different virtual server, a different pool, a different server.' });
ex455(3, { num: 'SDI000002375027', ip: '10.143.52.154', dns: 'multi-benefits-l7-vip2.dev.gwimnp.rpg', os: 'F5 Networks Big-IP',
  sign: 'The OS text contains "f5" and "big-ip"; the label segment "vip2" is a marker as well.',
  signWalk: '"f5 networks big-ip" contains "f5" and "big-ip". Segments multi, benefits, l7, vip2: "vip2" is "vip" followed by digits. Sign present.',
  svcLinkText: '/Common/ihscore-dev-multilang_benefits-6011-vip', svcLink: rec('cmdb_ci_lb_service', 'be381f963bfd2e50489ce5d964e45a1d'), svcId: 'be381f963bfd2e50489ce5d964e45a1d', svcTail: ' (port 6011, on balancer svedpz1rp4lb10).',
  poolText: 'The Pool field points at', poolName: '/Common/ihscore-dev-multilang_benefits-6011-pool', poolLink: rec('cmdb_ci_lb_pool', '36381f963bfd2e50489ce5d964e45a1d'),
  memberText: 'The members of this pool carry one address, 10.143.72.171:', memberLinkText: 'pool members', memberLink: list('cmdb_ci_lb_pool_member', 'pool=36381f963bfd2e50489ce5d964e45a1d'),
  memberIp: '10.143.72.171', server: 'wva68pwbolts51v', serverClass: 'Windows Server', serverTable: 'cmdb_ci_win_server', serverId: '813bd5383b0e6254a052e71864e45a35',
  note: 'The class of the server plays no part: the rule takes what the pool points at, here a Windows Server.' });
ex455(4, { num: 'SDI000002993687', ip: '10.143.53.96', dns: 'boluiv4-dev2-benefits-l7-vip1.dev.gwimnp.rpg', os: 'F5 Networks Big-IP',
  sign: 'The OS text contains "f5" and "big-ip"; the label segment "vip1" is a marker as well.',
  signWalk: '"f5 networks big-ip" contains "f5" and "big-ip". Segments boluiv4, dev2, benefits, l7, vip1: "vip1" is "vip" followed by digits. Sign present.',
  svcLinkText: '/Common/ihscore-dev2-boluiv4_benefits-6011-vip', svcLink: rec('cmdb_ci_lb_service', 'a966482d3b68c710ae0c4047f4e45ab3'), svcId: 'a966482d3b68c710ae0c4047f4e45ab3', svcTail: ' (port 6011, on balancer svedpz1rp1lb12).',
  poolText: 'The Pool field points at', poolName: '/Common/ihscore-dev2-boluiv4_benefits-6011-pool', poolLink: rec('cmdb_ci_lb_pool', '3066482d3b68c710ae0c4047f4e45aac'),
  memberText: 'The members of this pool carry one address, 171.184.193.14:', memberLinkText: 'pool members', memberLink: list('cmdb_ci_lb_pool_member', 'pool=3066482d3b68c710ae0c4047f4e45aac'),
  memberIp: '171.184.193.14', server: 'lva62pwbolws51v', serverClass: 'Linux Server', serverTable: 'cmdb_ci_linux_server', serverId: 'f2130b8693966a107fb5f842ed03d653',
  note: 'The member address sits on a different network from the virtual address, which is normal: the pool member address is the server\'s own address, the virtual address belongs to the balancer.' });
ex455(5, { num: 'SDI000003028419', ip: '171.159.246.91', dns: 'turbotmt-tx.pt2.pt2.gwimnp.rpg', os: 'F5 Networks Big-IP',
  sign: 'The OS text contains "f5" and "big-ip". The label turbotmt-tx carries no marker; the OS text alone qualifies the host.',
  signWalk: '"f5 networks big-ip" contains "f5" and "big-ip". Segments turbotmt, tx: neither is a marker; the OS words carry the sign.',
  svcLinkText: 'the service record on 171.159.246.91', svcLink: list('cmdb_ci_lb_service', 'ip_address=171.159.246.91'), svcId: '', svcTail: ' (open it through the address filter; the Pool field on it points at the pool walked next).',
  poolText: 'The Pool field of that record points at its pool; open the record above and follow the field.', poolName: '', poolLink: '',
  memberText: 'The members of that pool carry one address, 171.128.217.213; the list filtered on that address shows them with their pool:', memberLinkText: 'pool members carrying 171.128.217.213', memberLink: list('cmdb_ci_lb_pool_member', 'ip_address=171.128.217.213'),
  memberIp: '171.128.217.213', server: 'wva41bwtmtas01v', serverClass: 'Windows Server', serverTable: 'cmdb_ci_win_server', serverId: '602822843bcc8710ef3892e643e45a97',
  note: '' });

// ---------------------------------------------------------------- 460
K.push(h1('BOFA Load Balancer Service Match'));
K.push(p([t('Purpose. A virtual IP answered by a load balancer is not the balancer, and the hardware rules refuse the balancer device on purpose. When the member rule has not named a server, the host belongs to the Load Balancer Service CI that models the virtual IP, and this rule attaches that record. It runs on the IP field, so virtual IPs without a DNS name are covered too. Rule record: '), link('BOFA Load Balancer Service Match', RULE_460), t('.')]));
K.push(p(t('The script is the sign and the four clues described at the start, and nothing else:')));
const steps460 = [
  'Takes the scanned IP, the DNS name, the label and the OS text apart, and reads the ignore list.',
  'Checks the virtual IP sign. Without a sign it returns null.',
  'Runs the four clues in order on cmdb_ci_lb_service. The first clue that finds exactly one record ends the search, and that record\'s sys_id is returned. Two records on one clue return null; no record on any clue returns null.',
];
steps460.forEach((s, i) => K.push(p([t((i + 1) + '.  ', { bold: true }), t(s)], { indent: 360, after: 100 })));
K.push(p(t('The rule reads nothing beyond the service record itself: the load balancer device, the pool and the pool members play no part in it. The discovered item then carries the Load Balancer Service as its CI, the rule as its CI lookup rule and "matched by CI lookup" as its matching type.'), { before: 80 }));
K.push(p(t('Six items matched by this rule follow, one per page, chosen for the different shapes the sign can take: a host with no DNS name, a host whose OS text and label both carry the sign, a host whose label carries no marker, two hosts whose OS text names a Linux distribution and whose label carries the marker, and a host whose OS text names a Windows product behind the balancer. In every case the record found sits on the scanned address and is the only service record there.')));
K.push(brk());

function ex460(n, o) {
  const dns = o.dns || '', label = dns.split('.')[0];
  K.push(h2(`Example ${n}: ${o.num}`));
  K.push(lab('Discovered item', link(o.num, list('sn_sec_cmn_src_ci', 'number=' + o.num))));
  K.push(lab('Source data received', t('')));
  K.push(kv([['IP', o.ip], ['DNS', o.dns || '(none)'], ['OS', o.os || '(none)']]));
  K.push(gap());
  K.push(lab('Virtual IP sign', t(o.sign)));
  K.push(lab('Result', t(`The rule returned ${o.svc}, and the discovered item carries that Load Balancer Service as its CI. Its IP address equals the scanned address and it is the only service record on that address: the record is the virtual server that answered the scan. ${o.note}`)));
  K.push(h3('How the script walks this item'));
  const nameRows = dns ? [
    ['Clue 1, fqdn equal to the DNS name.', [[t('No service record carries this fqdn: '), link('filter on fqdn', list('cmdb_ci_lb_service', 'fqdn=' + dns)), t(' (empty). Next clue.')]]],
    ['Clue 2, name equal to the DNS name; clue 3, name equal to the label.', [[t('No service record is named this way: '), link('filter on the label', list('cmdb_ci_lb_service', 'name=' + label)), t(' (empty). Next clue.')]]],
  ] : [
    ['Clues 1 to 3 need the DNS name or the label.', [[t('The host record has no DNS name, so dns and label are empty and the three clues are skipped without a query.')]]],
  ];
  const rows = [
    ['Takes the scanned IP and checks it is not loopback or link-local.', [[t(`ip = "${o.ip}", accepted.`)]]],
    ['Lower-cases the DNS name, cuts the label before the first dot, lower-cases the OS text.', [[t(`dns = "${dns}", label = "${label}", os = "${(o.os || '').toLowerCase()}".`)]]],
    ['Reads the ignore list from the property.', [[t('sn_sec_cmn.ignoreCIClass: '), link('open the property', PROP)]]],
    ['Searches the OS text for the product words and the label segments for the markers.', [[t(o.signWalk)]]],
  ].concat(nameRows).concat([
    ['Clue 4, ip_address equal to the scanned IP.', [[t('Exactly one record: '), link(o.svc, rec('cmdb_ci_lb_service', o.svcId)), t(` (port ${o.port}, on balancer `), link(o.lb, list('cmdb_ci_lb', 'name=' + o.lb)), t(').')], [t('Check: '), link('services on ' + o.ip, list('cmdb_ci_lb_service', 'ip_address=' + o.ip)), t(' (one row).')]]],
    ['Returns that record\'s sys_id.', [[t('The search stops at the first clue that found one record; nothing after the service record is read.')]]],
    ['The platform writes the result on the discovered item.', [[t('CI = ' + o.svc + ', CI lookup rule = BOFA Load Balancer Service Match, matching type = matched by CI lookup, state = matched.')]]],
  ]);
  K.push(walk(rows));
  K.push(brk());
}
ex460(1, { num: 'SDI000003028240', ip: '171.159.246.128', dns: '', os: 'F5 Networks Big-IP', sign: 'The OS text contains "f5" and "big-ip". There is no DNS name, so the sign comes from the OS text alone.',
  signWalk: '"f5 networks big-ip" contains "f5" and "big-ip". No label, no segments. Sign present.',
  svc: '/Common/ait71454-pt1-mlonefeeui-443-vip', svcId: 'a029dc43931183d03854f05ea903d6b7', port: '443', lb: 'sveqbt1rp1lb02b', note: 'Without a DNS name only the address clue can run, which is why the rule works on the IP field.' });
ex460(2, { num: 'SDI000003069763', ip: '171.159.246.4', dns: 'prsapp-va-vip.pt1.gwimnp.rpg', os: 'F5 Networks Big-IP', sign: 'The OS text contains "f5" and "big-ip"; the label segment "vip" is a marker as well.',
  signWalk: '"f5 networks big-ip" contains "f5" and "big-ip". Segments prsapp, va, vip: "vip" is the marker itself. Sign present.',
  svc: '/Common/ait71551-pt1-prsapp-443-vip', svcId: '917ce0282f9e87103819983fafa4e37e', port: '443', lb: 'sveqbt1rp1lb02b', note: 'The DNS name prsapp-va-vip.pt1.gwimnp.rpg is not on the record; the F5 object name is, and the address is what ties the two together.' });
ex460(3, { num: 'SDI000003069406', ip: '171.176.215.217', dns: 'lki-nao-flash-svc-tt-mw.ecnp.bankofamerica.com', os: 'F5 Networks Big-IP', sign: 'The OS text contains "f5" and "big-ip". The label lki-nao-flash-svc-tt-mw carries no marker, so the OS text alone qualifies the host.',
  signWalk: '"f5 networks big-ip" contains "f5" and "big-ip". Segments lki, nao, flash, svc, tt, mw: none is a marker ("svc" is not "vs"). The OS words carry the sign.',
  svc: '/Common/LKI-NAO-FLASH-SVC-TT-443', svcId: '31ccec6c2f56871006a8a93fafa4e397', port: '443', lb: 'rtxqbt1conlb03a', note: 'The record name is written in capitals on the balancer; the name clues compare case-insensitively, and it makes no difference here because the address clue is the one that finds it.' });
ex460(4, { num: 'SDI000003727785', ip: '167.202.147.155', dns: 'gwmhcache-sync-wc-vip.dif.dqcnp.rpg', os: 'CentOS', sign: 'The OS text names no load balancer product; the label segment "vip" is a marker, so the host qualifies through the name.',
  signWalk: '"centos" contains none of the product words. Segments gwmhcache, sync, wc, vip: "vip" is the marker itself. Sign present.',
  svc: '/Common/ait71504-dif-gwmhcache-sync-wc-3306-vip', svcId: '85bdd4c32b9903d05371f1f5d891bf88', port: '3306', lb: 'svedbt1gw3lb01a', note: 'The Linux fingerprint belongs to whatever answered on the virtual address; the marker in the name is what identifies the host as a virtual IP.' });
ex460(5, { num: 'SDI000003069445', ip: '171.159.246.6', dns: 'prsmqlx-va-vip.pt1.gwimnp.rpg', os: 'Ubuntu/Linux', sign: 'The OS text names no load balancer product; the label segment "vip" is a marker, so the host qualifies through the name.',
  signWalk: '"ubuntu/linux" contains none of the product words. Segments prsmqlx, va, vip: "vip" is the marker itself. Sign present.',
  svc: '/Common/ait71551-pt1-prsmqlx-1414-vip', svcId: '3e6c286c2f52c710a9e3b44bcfa4e3b5', port: '1414', lb: 'sveqbt1rp1lb02b', note: 'A queue manager virtual server on port 1414; the port plays no part in the match, the address does.' });
ex460(6, { num: 'SDI000003069510', ip: '171.159.246.5', dns: 'prsrpt-va-vip.pt1.gwimnp.rpg', os: 'Windows Vista / Windows 2008 behind F5 Networks Big-IP', sign: 'The OS text contains "f5" and "big-ip" inside a longer fingerprint; the label segment "vip" is a marker as well.',
  signWalk: '"windows vista / windows 2008 behind f5 networks big-ip" contains "f5" and "big-ip". Segments prsrpt, va, vip: "vip" is the marker itself. Sign present.',
  svc: '/Common/ait71551-pt1-prsrpt-443-vip', svcId: 'ac7ce0282f9e87103819983fafa4e37a', port: '443', lb: 'sveqbt1rp1lb02b', note: 'Qualys saw a Windows service behind the balancer and reported both; the load balancer words in the text are enough for the sign.' });

// ---------------------------------------------------------------- how to check
K.push(h1('Checking any item yourself'));
K.push(p(t('For the member rule:')));
['Open the discovered item and read IP, DNS and OS in its source data. Confirm the sign: a load balancer word in the OS text, or a vip / vs segment in the label.',
 'Open the Load Balancer Service list filtered on that IP address. Exactly one record must come back.',
 'Open the record and follow its Pool field to the pool. Open the Pool Member list filtered on that pool and note each member address.',
 'Open the server list (cmdb_ci_hardware) filtered on each member address. One server across all members is the CI the item carries.'].forEach((s, i) => K.push(p([t((i + 1) + '.  ', { bold: true }), t(s)], { indent: 360, after: 100 })));
K.push(p(t('For the service rule:'), { before: 120 }));
['Open the discovered item and confirm the sign in the same way.',
 'Open the Load Balancer Service list filtered on the scanned IP address. Exactly one record must come back, and its IP address equals the scanned address. That record is the CI the item carries.'].forEach((s, i) => K.push(p([t((i + 1) + '.  ', { bold: true }), t(s)], { indent: 360, after: 100 })));
K.push(p([t('Reference records: '), link('the member rule', RULE_455), t(', '), link('the service rule', RULE_460), t(', '), link('the ignore-class property', PROP), t('.')], { before: 160 }));

const doc = new Document({
  creator: 'Mihir Singh', title: 'Qualys CI Matching for Load Balancer Addresses',
  styles: { default: { document: { run: { font: FONT, size: SZ } } },
    paragraphStyles: [
      { id: 'Heading1', name: 'Heading 1', basedOn: 'Normal', next: 'Normal', quickFormat: true, run: { font: 'Calibri Light', size: 34, bold: true, color: '1F3864' }, paragraph: { spacing: { before: 360, after: 200 }, outlineLevel: 0 } },
      { id: 'Heading2', name: 'Heading 2', basedOn: 'Normal', next: 'Normal', quickFormat: true, run: { font: 'Calibri Light', size: 28, bold: true, color: '2E5C8A' }, paragraph: { spacing: { before: 280, after: 160 }, outlineLevel: 1 } },
    ] },
  sections: [{ properties: { page: { margin: { top: 1300, bottom: 1300, left: 1300, right: 1300 } } },
    footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ font: FONT, size: 18, color: MUTED, children: ['Page ', PageNumber.CURRENT] })] })] }) },
    children: K }],
});
Packer.toBuffer(doc).then(buf => { fs.writeFileSync(__dirname + '/Load Balancer Rules - Matching Walkthrough.docx', buf); console.log('written', buf.length, 'bytes'); });
