// Builds "Shazzam Logic and the Qualys CI Lookup Rules.docx": what the Discovery status enrichment (Shazzam) works out
// for each address, how its "IP in CMDB" lookup compares with the Qualys CI lookup chain, and the rule 750 built for
// the lookups the chain did not cover. Usage: NODE_MODULES=<dir with docx> node build_shazzam_doc.js
const fs = require('fs');
const path = require('path');
const H = require('../1639-vamp-inbound/doc_helpers.js');
const { Document, Packer, Paragraph } = H.D;
const { NAVY, RED, t, p, body, h1, h2, bullet, numbered, rec, table } = H;
const m = (s) => t(s, { mono: true });
const numbered2 = (runs) => new Paragraph({ children: runs, numbering: { reference: 'steps2', level: 0 }, spacing: { after: 100, line: 260 } });

const children = [];
children.push(new Paragraph({ children: [t('Shazzam Logic and the Qualys CI Lookup Rules', { size: 38, bold: true, color: NAVY })], spacing: { after: 60 } }));
children.push(new Paragraph({ children: [t('What the Discovery status enrichment works out, what the lookup chain already covers, and rule 750', { size: 23, color: RED })], spacing: { after: 60 } }));
children.push(body('Prepared 28 September 2026. High-level explanation of the business rule "Discovery - Async Shazzam Status Update" and of the new Qualys CI lookup rule 750 USEM IP Outside Hardware Match built from it.', { size: 18 }));

children.push(h1('1. What the Shazzam rule is'));
children.push(p([t('A business rule of the BOFA Discovery application ('), rec('sys_script', 'cfe9b9b4eb122ed06fcdf979bad0cd41', 'Discovery - Async Shazzam Status Update'), t('). It runs asynchronously after a row is inserted in the Shazzam status table, where Discovery records each address its Shazzam probe scanned, and enriches that row with what the platform knows about the address.')]));
children.push(bullet([t('Runs only when the property '), m('bofa.shazzam.br_enabled'), t(' is true, and only for rows where the targeted list, the IP in CMDB or the subnet DDI is still empty.')]));
children.push(bullet([t('Loops stop once the time budget in '), m('bofa.shazzam.execution_seconds'), t(' (1 second by default) is used up.')]));
children.push(bullet('Writes the row back without running other rules on it; one error line is logged when anything fails.'));

children.push(h1('2. What it works out for each address'));
children.push(table(['Column filled', 'How it is found'], [
  ['Targeted list', 'The active Discovery schedule (discovering CIs, not an ad-hoc run) whose range items carry the address.'],
  ['IP in CMDB', 'The CI that owns the address, looked up in seven steps (section 3). This is the part that overlaps with the Qualys CI lookup rules.'],
  ['Excluded', 'The first active Discovery IP exclusion whose address list, range or subnet contains the address.'],
  ['Subnet DDI, DDI location, Location', 'The BCAT DDI subnet record whose CIDR contains the address, with its region and location.'],
  ['Tech domain, Tech sub domain', 'The CMDB key values tech_domain and tech_sub_domain of the CI found as IP in CMDB.'],
  ['Investigate, Task', 'When no CI owns the address and Discovery found no host, a subnet discrepancy task is created or updated (unless the address is excluded); when a CI appears later, the open task gets a resolution code.'],
], [26, 74]));

children.push(h1('3. How "IP in CMDB" is found'));
children.push(body('Each step runs only when the previous one found nothing; every search takes the first record it finds.'));
[
  [t('Hardware ('), m('cmdb_ci_hardware'), t(') carrying the address.')],
  [t('vCenter ('), m('cmdb_ci_vcenter'), t(', an Application class) carrying the address.')],
  [t('Cluster virtual IP ('), m('cmdb_ci_cluster_vip'), t(') carrying the address: the server of the node the VIP names, otherwise the cluster.')],
  [t('Imaging hardware ('), m('cmdb_ci_imaging_hardware'), t(', scanners and similar devices) carrying the address.')],
  [t('IP phone ('), m('cmdb_ci_ip_phone'), t(') carrying the address.')],
  [t('IP Address record ('), m('cmdb_ci_ip_address'), t(') with the address whose network adapter belongs to a CI: that CI.')],
  [t('The first label of the DNS name, as the name of a hardware record. The line meant to strip "-vip" from the name has no effect (its result is not kept).')],
].forEach((r) => children.push(numbered(r)));

children.push(h1('4. What the Qualys lookup chain already covers'));
children.push(body('The Qualys chain works name first, then address, and every USEM rule accepts a CI only when exactly one record qualifies; the address rules also require the CI class to agree with the scanned OS, refuse load balancer devices and, when the scan carries a DNS name, require the CI name to agree with it.'));
children.push(table(['Shazzam step', 'Qualys chain before rule 750', 'Covered'], [
  ['1 Hardware on the address', 'USEM IP Class Match and USEM IP Hardware Match', 'Yes'],
  ['2 vCenter on the address', 'Nothing by address; only by name through the platform FQDN and NetBIOS rules', 'No'],
  ['3 Cluster virtual IP on the address', 'Nothing; the load balancer rules handle load balancer virtual servers only', 'No'],
  ['4 Imaging hardware on the address', 'USEM Device Name Match, by name only (the address breaks a tie)', 'By name only'],
  ['5 IP phone on the address', 'USEM Device Name Match and USEM Cisco IP Phone MAC, by name only', 'By name only'],
  ['6 IP Address record, adapter, CI', 'USEM IP Layered Match (and USEM IP Adapter Match for adapters)', 'Yes'],
  ['7 DNS label as a hardware name', 'USEM Hostname Class Match and USEM Hostname Hardware Match', 'Yes'],
], [30, 55, 15]));

children.push(h1('5. The new rule: 750 USEM IP Outside Hardware Match'));
children.push(body('Built for steps 2 to 5, the lookups the chain did not make: the scanned address searched in the four classes the CMDB keeps outside the Hardware tree.'));
children.push(h2('Decisions (28 September)'));
children.push(bullet('A cluster virtual IP stands for its cluster, not for the node’s server: the node answering on a virtual address changes with every failover, the cluster does not.'));
children.push(bullet('The address alone is enough, as in Shazzam: no check of the CI name against the scanned DNS name.'));
children.push(bullet('All four classes: vCenter, cluster virtual IP, IP phone, imaging hardware.'));
children.push(bullet('Order 750, after the address rules and before USEM FQDN Name Broad Match: every earlier rule keeps its priority, and the new rule only sees hosts the chain leaves unmatched today.'));
children.push(h2('How it decides'));
[
  'Reads the scanned address; an empty, loopback or link-local address ends the rule.',
  'Reads the scanned OS. An OS that names a server or desktop system (Windows, ESXi, AIX, Solaris, HP-UX) on a phone or imaging address means the address now belongs to another machine, so those two classes are not counted; a Linux kernel fingerprint and anything mentioning a phone are accepted, as in USEM Device Name Match. For a vCenter or a cluster the OS rules nothing out.',
  'Searches vCenter, cluster virtual IP, IP phone and imaging hardware records carrying the address, ignored classes left out. A vCenter, phone or imaging device is the CI itself; a cluster virtual IP is replaced by the cluster it names.',
  'Returns the CI when exactly one is found, however many records led to it (two virtual IP records of one cluster give one cluster).',
].forEach((s) => children.push(numbered2([t(s)])));
children.push(h2('When it declines'));
children.push(bullet('Nothing outside the Hardware tree carries the address.'));
children.push(bullet('Two different CIs carry it (two phones, a phone and a vCenter, virtual IPs of two clusters).'));
children.push(bullet('A virtual IP on the address names no cluster.'));
children.push(bullet('A server or desktop OS is scanned on a phone or imaging address.'));
children.push(h2('What differs from Shazzam'));
children.push(bullet('Shazzam takes the first record it finds; the rule declines when two different CIs qualify, as every USEM rule does.'));
children.push(bullet('Shazzam returns the node’s server for a cluster virtual IP when the VIP names a node; the rule returns the cluster (decision above).'));
children.push(bullet('Shazzam checks hardware first; in the Qualys chain the hardware and adapter rules run before rule 750, so a hardware record on the same address still wins.'));

children.push(h1('6. Effect on the client instance'));
children.push(bullet('Hosts whose address is carried only by a vCenter, a cluster virtual IP, an IP phone or an imaging device move from unmatched to matched once they are re-evaluated (reapply or re-import); the rule record is created with reapply on.'));
children.push(bullet('A cluster virtual IP whose record carries the scanned name as its FQDN was matched by the platform FQDN rule to the virtual IP record; rule 750 runs first and now returns the cluster.'));
children.push(bullet('Nothing matched today by an earlier rule changes: rule 750 runs after them.'));

children.push(h1('7. Tests and delivery'));
children.push(body('Eighteen cases on marked records, run twice through the whole chain and through the rule alone, all as expected: the cluster (not the node’s server) for a virtual IP scanned as the Windows node, with and without DNS and OS; a virtual IP without a cluster declined; two records of one cluster giving that cluster; virtual IPs of two clusters declined; the vCenter under its own name, another name and a Windows fingerprint; the phone without DNS, under another name and as embedded Linux; a Windows desktop on the phone’s address declined; two phones declined; the imaging device; a phone and a vCenter on one address declined; a Linux server and a vCenter on one address, where the earlier address rule returns the server; nothing on the address; loopback. The earlier rule test suites run unchanged with the rule in the chain.'));
children.push(p([t('Update set: '), t('SNOWUSEMTP-895_MS_Qualys CI Lookup Rules IP Outside Hardware Match_V1.0', { bold: true }), t(' (Global, one rule). On the client instance the rule can also be created by hand: source Qualys Cloud Platform, order 750, source field IP, table sn_vul_qualys_host_attrb, method script, lookup target CI, active, reapply on, with the script from the file 750_USEM_IP_Outside_Hardware_Match.js.')]));

const doc = new Document({
  creator: 'Mihir Singh',
  styles: { default: { document: { run: { font: H.FONT, size: 20, color: H.INK } } } },
  numbering: { config: ['steps', 'steps2'].map((ref) => ({ reference: ref, levels: [{ level: 0, format: 'decimal', text: '%1.', alignment: 'left',
    style: { paragraph: { indent: { left: 540, hanging: 360 } } } }] })) },
  sections: [{ properties: { page: { margin: { top: 1000, bottom: 1000, left: 1100, right: 1100 } } }, children: children }],
});
const out = path.join(__dirname, 'Shazzam Logic and the Qualys CI Lookup Rules.docx');
Packer.toBuffer(doc).then((b) => { fs.writeFileSync(out, b); console.log('written:', out, b.length, 'bytes'); });
