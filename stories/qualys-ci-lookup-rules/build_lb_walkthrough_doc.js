// Word document: how discovered items scanned on load balancer addresses reached their CI on the
// development instance, record by record, with clickable links for every step.
const fs = require('fs');
const { Document, Packer, Paragraph, TextRun, ExternalHyperlink, PageBreak, HeadingLevel, Table, TableRow, TableCell,
        WidthType, BorderStyle, ShadingType, TableLayoutType, PageNumber, Footer, AlignmentType } = require('docx');
const FONT = 'Calibri', SZ = 22, MUTED = '595959', LINK = '0563C1', HEAD = 'E7ECF2';
const HOST = 'https://bofasecopsdev.service-now.com';
const HAIR = { style: BorderStyle.SINGLE, size: 4, color: 'BFC5CC' };
const rec = (table, id) => `${HOST}/${table}.do?sys_id=${id}`;
const enc = (q) => q.replace(/=/g, '%3D').replace(/\^/g, '%5E');
const list = (table, q) => `${HOST}/${table}_list.do?sysparm_query=${enc(q)}`;
const t = (text, o) => { o = o || {}; return new TextRun({ text, font: FONT, size: o.size || SZ, bold: o.bold, italics: o.italics, color: o.color }); };
const link = (text, url) => new ExternalHyperlink({ children: [new TextRun({ text, font: FONT, size: SZ, color: LINK, underline: {} })], link: url });
const p = (runs, o) => { o = o || {}; return new Paragraph({ children: Array.isArray(runs) ? runs : [runs], spacing: { before: o.before || 0, after: o.after == null ? 140 : o.after, line: 300 }, indent: o.indent ? { left: o.indent } : undefined }); };
const lab = (label, runs) => p([t(label + '  ', { bold: true })].concat(Array.isArray(runs) ? runs : [runs]));
const ln = (label, text, url) => p([t(label + '  ', { color: MUTED }), link(text, url)], { indent: 360, after: 100 });
const h1 = (text) => new Paragraph({ text, heading: HeadingLevel.HEADING_1, spacing: { before: 360, after: 200 } });
const h2 = (text) => new Paragraph({ text, heading: HeadingLevel.HEADING_2, spacing: { before: 280, after: 160 } });
const brk = () => new Paragraph({ children: [new PageBreak()] });
const cell = (children, w, fill) => new TableCell({ children, width: { size: w, type: WidthType.DXA }, shading: fill ? { type: ShadingType.CLEAR, fill } : undefined, margins: { top: 60, bottom: 60, left: 110, right: 110 } });
function kv(rows) {
  return new Table({ rows: rows.map(r => new TableRow({ cantSplit: true, children: [cell([p(t(r[0], { bold: true }), { after: 0 })], 2600, HEAD), cell([p(t(r[1]), { after: 0 })], 6760)] })),
    width: { size: 9360, type: WidthType.DXA }, columnWidths: [2600, 6760], layout: TableLayoutType.FIXED,
    borders: { top: HAIR, bottom: HAIR, left: HAIR, right: HAIR, insideHorizontal: HAIR, insideVertical: HAIR } });
}
const gap = () => p(t(''), { after: 60 });
const K = [];

K.push(new Paragraph({ children: [t('Qualys CI Matching for Load Balancer Addresses', { bold: true, size: 36 })], spacing: { after: 120, line: 440 } }));
K.push(p(t('How discovered items reach their CI through the Load Balancer Member Match and Load Balancer Service Match rules, record by record', { color: MUTED, size: 24 }), { after: 60 }));
K.push(p(t('Development instance, 17 September 2026', { color: MUTED }), { after: 300 }));

K.push(h1('What both rules receive'));
K.push(p(t('Every Qualys host record arrives as a Discovered Item (table sn_sec_cmn_src_ci). Its source data carries the scanned IP, the DNS name Qualys resolved for it, when there is one, and the operating system text of whatever answered the scan. A virtual IP has no serial number, no CI carries its DNS name, and the address rules deliberately refuse a load balancer device, so a virtual IP reaches the two load balancer rules with nothing matched.')));
K.push(p(t('Both rules run only when the host record shows a virtual IP sign:')));
K.push(p(t('the operating system text contains a load balancer product: f5, big-ip, big ip or netscaler; or'), { indent: 360, after: 60 }));
K.push(p(t('a segment of the host label (the DNS name before the first dot, split at hyphens) is a marker: vip or vs, on its own, followed by digits (vip1, vip2, vs1), or as the end of a longer word (multihostvip).'), { indent: 360 }));
K.push(p(t('With a sign, both rules search the Load Balancer Service table (cmdb_ci_lb_service, the virtual server) with four clues in order: fqdn equal to the DNS name, name equal to the DNS name, name equal to the host label, and ip_address equal to the scanned IP. A clue that finds exactly one record settles the search; a clue that finds two records ends the rule without a match; a clue that finds nothing hands over to the next.')));
K.push(p(t('On our instance the service records are named after the F5 object (for example /Common/ait73074-rvcpbt1-ctuapi-pb-443-vip) and carry no fqdn, so the three name clues find nothing and the fourth clue, the IP address, is the one that identifies the virtual server in every example in this document.')));
K.push(p(t('The rules run in this order: Load Balancer Member Match first, Load Balancer Service Match next. The member rule is described first below, then the service rule.')));
K.push(brk());

// ---------------------------------------------------------------- 455
K.push(h1('BOFA Load Balancer Member Match'));
K.push(p(t('Purpose. A virtual server usually fronts several real servers, but many front exactly one. When the CMDB holds the pool behind the virtual server and exactly one real server sits in it, the findings scanned on the virtual address belong to that server. This rule returns that server.')));
K.push(p(t('What it does, step by step:')));
const steps455 = [
  'Checks the virtual IP sign (operating system word or label marker). Without a sign the rule does not run.',
  'Finds the one Load Balancer Service record with the four clues; on our instance the ip_address clue finds it.',
  'Reads the Pool field of that service record, and also takes any Load Balancer Pool (cmdb_ci_lb_pool) whose Service field points at the service, and any pool related to it through a CI relationship.',
  'Collects the Load Balancer Pool Member records (cmdb_ci_lb_pool_member) whose Pool field points at one of those pools, plus members related to a pool, each with its IP address.',
  'Looks each member address up in three places: the IP Address field of the server records (cmdb_ci_hardware), the Network Adapter records (their owning CI), and the IP Address records (their adapter\'s CI). A member related to a server through a CI relationship counts as well.',
  'Keeps only real servers: a record in the Hardware tree that is neither a load balancer device nor a placeholder class.',
  'Counts the distinct servers found. Exactly one is the match and is returned; none, or two or more, and the rule declines, leaving the host to the service rule.',
];
steps455.forEach((s, i) => K.push(p([t((i + 1) + '.  ', { bold: true }), t(s)], { indent: 360, after: 100 })));
K.push(p(t('The discovered item then carries the server as its CI: never the load balancer device, and not the virtual server record.'), { before: 80 }));
K.push(brk());

function ex455(n, o) {
  K.push(h2(`Example ${n}: ${o.num}`));
  K.push(lab('Discovered item', link(o.num, list('sn_sec_cmn_src_ci', 'number=' + o.num))));
  K.push(lab('Source data received', t('')));
  K.push(kv([['IP', o.ip], ['DNS', o.dns], ['OS', o.os]]));
  K.push(gap());
  K.push(lab('Virtual IP sign', t(o.sign)));
  K.push(lab('Clue that found the virtual server', t(`The fqdn and name clues find nothing (the record is named after the F5 object). ip_address = ${o.ip} finds exactly one Load Balancer Service.`)));
  K.push(lab('Load Balancer Service found', t(o.svcText)));
  K.push(ln('Open:', o.svcLinkText, o.svcLink));
  K.push(lab('Pool', t(o.poolText)));
  if (o.poolLink) K.push(ln('Open:', o.poolName, o.poolLink));
  K.push(lab('Pool members', t(o.memberText)));
  K.push(ln('Open:', o.memberLinkText, o.memberLink));
  K.push(lab('Server found', t(`The member address ${o.memberIp} is the IP Address field of the server record ${o.server} (${o.serverClass}).`)));
  K.push(ln('Open:', o.server, rec(o.serverTable, o.serverId)));
  K.push(lab('Result', t(`One member address, one server. The rule returned ${o.server}, and the discovered item carries that server as its CI. ${o.note}`)));
  K.push(brk());
}
ex455(1, { num: 'SDI000002418623', ip: '10.143.52.217', dns: 'ccgw-l7-vip2.sit1.gwimnp.rpg', os: 'F5 Networks Big-IP',
  sign: 'The OS text contains "f5" and "big-ip"; the label segment "vip2" is a marker as well.',
  svcText: '/Common/ihscore-sit1-ccgw-6011-vip, IP address 10.143.52.217, port 6011, on balancer svedpz1rp4lb10.', svcLinkText: '/Common/ihscore-sit1-ccgw-6011-vip', svcLink: rec('cmdb_ci_lb_service', 'be381f963bfd2e50489ce5d964e45a84'),
  poolText: 'The Pool field of the service record points at /Common/ihscore-sit1-ccgw-6011-pool.', poolName: '/Common/ihscore-sit1-ccgw-6011-pool', poolLink: rec('cmdb_ci_lb_pool', '36381f963bfd2e50489ce5d964e45a84'),
  memberText: 'The Pool Member records whose Pool field points at this pool carry one address, 10.143.72.200.', memberLinkText: 'Pool members of /Common/ihscore-sit1-ccgw-6011-pool', memberLink: list('cmdb_ci_lb_pool_member', 'pool=36381f963bfd2e50489ce5d964e45a84'),
  memberIp: '10.143.72.200', server: 'lva71pwbolcc01v', serverClass: 'Linux Server', serverTable: 'cmdb_ci_linux_server', serverId: 'ddcdddf02b462294d50dffbdbe91bf9b',
  note: 'The balancer svedpz1rp4lb10 is a separate CI and is never returned.' });
ex455(2, { num: 'SDI000002411394', ip: '10.143.52.163', dns: 'ccgw-l7-vip2.dev.gwimnp.rpg', os: 'F5 Networks Big-IP',
  sign: 'The OS text contains "f5" and "big-ip"; the label segment "vip2" is a marker as well.',
  svcText: '/Common/ihscore-dev-ccgw-6011-vip, IP address 10.143.52.163, port 6011, on balancer svedpz1rp4lb10.', svcLinkText: '/Common/ihscore-dev-ccgw-6011-vip', svcLink: rec('cmdb_ci_lb_service', 'b2381f963bfd2e50489ce5d964e45a86'),
  poolText: 'The Pool field of the service record points at /Common/ihscore-dev-ccgw-6011-pool.', poolName: '/Common/ihscore-dev-ccgw-6011-pool', poolLink: rec('cmdb_ci_lb_pool', '3a381f963bfd2e50489ce5d964e45a85'),
  memberText: 'The Pool Member records whose Pool field points at this pool carry one address, 10.143.72.198.', memberLinkText: 'Pool members of /Common/ihscore-dev-ccgw-6011-pool', memberLink: list('cmdb_ci_lb_pool_member', 'pool=3a381f963bfd2e50489ce5d964e45a85'),
  memberIp: '10.143.72.198', server: 'lva68pwbolcc01v', serverClass: 'Linux Server', serverTable: 'cmdb_ci_linux_server', serverId: 'd78e25b82b8e2294d50dffbdbe91bf32',
  note: 'The same application as example 1 in the development environment: a different virtual server, a different pool, a different server.' });
ex455(3, { num: 'SDI000002375027', ip: '10.143.52.154', dns: 'multi-benefits-l7-vip2.dev.gwimnp.rpg', os: 'F5 Networks Big-IP',
  sign: 'The OS text contains "f5" and "big-ip"; the label segment "vip2" is a marker as well.',
  svcText: '/Common/ihscore-dev-multilang_benefits-6011-vip, IP address 10.143.52.154, port 6011, on balancer svedpz1rp4lb10.', svcLinkText: '/Common/ihscore-dev-multilang_benefits-6011-vip', svcLink: rec('cmdb_ci_lb_service', 'be381f963bfd2e50489ce5d964e45a1d'),
  poolText: 'The Pool field of the service record points at /Common/ihscore-dev-multilang_benefits-6011-pool.', poolName: '/Common/ihscore-dev-multilang_benefits-6011-pool', poolLink: rec('cmdb_ci_lb_pool', '36381f963bfd2e50489ce5d964e45a1d'),
  memberText: 'The Pool Member records whose Pool field points at this pool carry one address, 10.143.72.171.', memberLinkText: 'Pool members of /Common/ihscore-dev-multilang_benefits-6011-pool', memberLink: list('cmdb_ci_lb_pool_member', 'pool=36381f963bfd2e50489ce5d964e45a1d'),
  memberIp: '10.143.72.171', server: 'wva68pwbolts51v', serverClass: 'Windows Server', serverTable: 'cmdb_ci_win_server', serverId: '813bd5383b0e6254a052e71864e45a35',
  note: 'The class of the server plays no part: the rule takes what the pool points at, here a Windows Server.' });
ex455(4, { num: 'SDI000002993687', ip: '10.143.53.96', dns: 'boluiv4-dev2-benefits-l7-vip1.dev.gwimnp.rpg', os: 'F5 Networks Big-IP',
  sign: 'The OS text contains "f5" and "big-ip"; the label segment "vip1" is a marker as well.',
  svcText: '/Common/ihscore-dev2-boluiv4_benefits-6011-vip, IP address 10.143.53.96, port 6011, on balancer svedpz1rp1lb12.', svcLinkText: '/Common/ihscore-dev2-boluiv4_benefits-6011-vip', svcLink: rec('cmdb_ci_lb_service', 'a966482d3b68c710ae0c4047f4e45ab3'),
  poolText: 'The Pool field of the service record points at /Common/ihscore-dev2-boluiv4_benefits-6011-pool.', poolName: '/Common/ihscore-dev2-boluiv4_benefits-6011-pool', poolLink: rec('cmdb_ci_lb_pool', '3066482d3b68c710ae0c4047f4e45aac'),
  memberText: 'The Pool Member records whose Pool field points at this pool carry one address, 171.184.193.14.', memberLinkText: 'Pool members of /Common/ihscore-dev2-boluiv4_benefits-6011-pool', memberLink: list('cmdb_ci_lb_pool_member', 'pool=3066482d3b68c710ae0c4047f4e45aac'),
  memberIp: '171.184.193.14', server: 'lva62pwbolws51v', serverClass: 'Linux Server', serverTable: 'cmdb_ci_linux_server', serverId: 'f2130b8693966a107fb5f842ed03d653',
  note: 'The member address sits on a different network from the virtual address, which is normal: the pool member address is the server\'s own address, the virtual address belongs to the balancer.' });
ex455(5, { num: 'SDI000003028419', ip: '171.159.246.91', dns: 'turbotmt-tx.pt2.pt2.gwimnp.rpg', os: 'F5 Networks Big-IP',
  sign: 'The OS text contains "f5" and "big-ip". The label turbotmt-tx carries no marker; the OS text alone qualifies the host.',
  svcText: 'The one Load Balancer Service record on 171.159.246.91; the list below is filtered on that address and shows it.', svcLinkText: 'Load Balancer Services on 171.159.246.91', svcLink: list('cmdb_ci_lb_service', 'ip_address=171.159.246.91'),
  poolText: 'The Pool field of that service record points at its pool; open the record and follow the field.', poolName: '', poolLink: '',
  memberText: 'The Pool Member records of that pool carry one address, 171.128.217.213; the list below is filtered on that address and shows them with their pool.', memberLinkText: 'Pool members carrying 171.128.217.213', memberLink: list('cmdb_ci_lb_pool_member', 'ip_address=171.128.217.213'),
  memberIp: '171.128.217.213', server: 'wva41bwtmtas01v', serverClass: 'Windows Server', serverTable: 'cmdb_ci_win_server', serverId: '602822843bcc8710ef3892e643e45a97',
  note: '' });

// ---------------------------------------------------------------- 460
K.push(h1('BOFA Load Balancer Service Match'));
K.push(p(t('Purpose. A virtual IP answered by a load balancer is not the balancer, and the hardware rules refuse the balancer device on purpose. When the member rule has not named a server, the host belongs to the Load Balancer Service CI that models the virtual IP, and this rule attaches that record. It runs on the IP field, so virtual IPs without a DNS name are covered too.')));
K.push(p(t('What it does, step by step:')));
const steps460 = [
  'Checks the virtual IP sign (operating system word or label marker). Without a sign the rule does not run: a Load Balancer Service must never be attached to an ordinary server that happens to share an address with a virtual IP.',
  'Searches the Load Balancer Service table with the four clues in order: fqdn = DNS name, name = DNS name, name = host label, ip_address = scanned IP. Each clue must find exactly one record.',
  'Returns that record. The discovered item then carries the Load Balancer Service as its CI.',
  'Two records carrying the same value end the rule without a match, because a weaker clue could otherwise pick a different service; no record at all leaves the host to the address rules that follow.',
];
steps460.forEach((s, i) => K.push(p([t((i + 1) + '.  ', { bold: true }), t(s)], { indent: 360, after: 100 })));
K.push(p(t('The rule reads nothing beyond the service record itself: the load balancer device and the pool behind the virtual server play no part in it.'), { before: 80 }));
K.push(brk());

function ex460(n, o) {
  K.push(h2(`Example ${n}: ${o.num}`));
  K.push(lab('Discovered item', link(o.num, list('sn_sec_cmn_src_ci', 'number=' + o.num))));
  K.push(lab('Source data received', t('')));
  K.push(kv([['IP', o.ip], ['DNS', o.dns], ['OS', o.os]]));
  K.push(gap());
  K.push(lab('Virtual IP sign', t(o.sign)));
  K.push(lab('Clue that found the virtual server', t(`The fqdn and name clues find nothing (the record is named after the F5 object). ip_address = ${o.ip} finds exactly one Load Balancer Service.`)));
  K.push(lab('Load Balancer Service found', t(`${o.svc}, IP address ${o.ip}, port ${o.port}, on balancer ${o.lb}.`)));
  K.push(ln('Open:', o.svc, rec('cmdb_ci_lb_service', o.svcId)));
  K.push(ln('Balancer:', o.lb, list('cmdb_ci_lb', 'name=' + o.lb)));
  K.push(lab('Result', t(`The rule returned ${o.svc}, and the discovered item carries that Load Balancer Service as its CI. Its IP address equals the scanned address: the record is the virtual server that answered the scan. ${o.note}`)));
  K.push(brk());
}
ex460(1, { num: 'SDI000003028240', ip: '171.159.246.128', dns: '(none)', os: 'F5 Networks Big-IP', sign: 'The OS text contains "f5" and "big-ip". There is no DNS name, so the sign comes from the OS text alone.',
  svc: '/Common/ait71454-pt1-mlonefeeui-443-vip', svcId: 'a029dc43931183d03854f05ea903d6b7', port: '443', lb: 'sveqbt1rp1lb02b', note: 'Without a DNS name only the address clue can run, which is why the rule works on the IP field.' });
ex460(2, { num: 'SDI000003726690', ip: '158.171.194.200', dns: 'ctuapi-pb-va1-vip.gwim.rpg', os: 'F5 Networks Big-IP', sign: 'The OS text contains "f5" and "big-ip"; the label segment "vip" is a marker as well.',
  svc: '/Common/ait73074-rvcpbt1-ctuapi-pb-443-vip', svcId: '4a676071933d4b504cbaf137a803d6a2', port: '443', lb: 'svedbt1gwmlb01a', note: 'The DNS name ctuapi-pb-va1-vip.gwim.rpg is not on the record; the F5 object name is, and the address is what ties the two together.' });
ex460(3, { num: 'SDI000003506195', ip: '165.40.145.228', dns: 'sgcpbt1utigb01b-lsn1.asia.bankofamerica.com', os: 'F5 Big IP', sign: 'The OS text contains "f5" and "big ip" (the spelling without the hyphen is on the list too). The label sgcpbt1utigb01b-lsn1 carries no marker.',
  svc: '/Common/vs_165_40_145_228_53_gtm_0', svcId: '262557de93f9e65007a4f84958373c9f', port: '53', lb: 'sgcpbt1utigb01b', note: 'A DNS listener on a GTM device: the virtual server record is the CI that models this address.' });
ex460(4, { num: 'SDI000002395438', ip: '165.47.76.142', dns: 'caypap1pxylb12-vs1.network.emea.bankofamerica.com', os: '(none)', sign: 'The scan reported no operating system. The label segment "vs1" is a marker ("vs" followed by digits), so the host qualifies through the name alone.',
  svc: '/Common/exp-pxy-vip', svcId: '0c6c8b523b3d2e50489ce5d964e45aee', port: '8080', lb: 'caypap1pxylb12', note: 'A record of the same name, /Common/exp-pxy-vip, exists on caypap1pxylb11 at 165.47.76.141 (item SDI000002393798); the address clue keeps the two apart, and each item lands on the record of its own address.' });
ex460(5, { num: 'SDI000003727785', ip: '167.202.147.155', dns: 'gwmhcache-sync-wc-vip.dif.dqcnp.rpg', os: 'CentOS', sign: 'The OS text names no load balancer product; the label segment "vip" is a marker, so the host qualifies through the name.',
  svc: '/Common/ait71504-dif-gwmhcache-sync-wc-3306-vip', svcId: '85bdd4c32b9903d05371f1f5d891bf88', port: '3306', lb: 'svedbt1gw3lb01a', note: 'The Linux fingerprint belongs to whatever answered on the virtual address; the marker in the name is what identifies the host as a virtual IP.' });
ex460(6, { num: 'SDI000003069510', ip: '171.159.246.5', dns: 'prsrpt-va-vip.pt1.gwimnp.rpg', os: 'Windows Vista / Windows 2008 behind F5 Networks Big-IP', sign: 'The OS text contains "f5" and "big-ip" inside a longer fingerprint; the label segment "vip" is a marker as well.',
  svc: '/Common/ait71551-pt1-prsrpt-443-vip', svcId: 'ac7ce0282f9e87103819983fafa4e37a', port: '443', lb: 'sveqbt1rp1lb02b', note: 'Qualys saw a Windows service behind the balancer and reported both; the load balancer word in the text is enough for the sign.' });

// ---------------------------------------------------------------- how to check
K.push(h1('Checking any item yourself'));
K.push(p(t('For the member rule:')));
['Open the discovered item and read IP, DNS and OS in its source data. Confirm the sign: a load balancer word in the OS text, or a vip / vs segment in the label.',
 'Open the Load Balancer Service list filtered on that IP address. Exactly one record must come back.',
 'Open the record and follow its Pool field to the pool. Open the Pool Member list filtered on that pool and note each member address.',
 'Search the server records (cmdb_ci_hardware) on each member address. One server across all members is the CI the item carries.'].forEach((s, i) => K.push(p([t((i + 1) + '.  ', { bold: true }), t(s)], { indent: 360, after: 100 })));
K.push(p(t('For the service rule:'), { before: 120 }));
['Open the discovered item and confirm the sign in the same way.',
 'Open the Load Balancer Service list filtered on the scanned IP address. Exactly one record must come back, and its IP address equals the scanned address. That record is the CI the item carries.'].forEach((s, i) => K.push(p([t((i + 1) + '.  ', { bold: true }), t(s)], { indent: 360, after: 100 })));

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
