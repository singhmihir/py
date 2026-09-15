// Word document: how load balancer addresses are handled by the USEM CI lookup rules, what is not in
// place (virtual to real address mapping) and how to run the check with the client's examples.
const fs = require('fs');
const { Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell, WidthType, BorderStyle, ShadingType,
        AlignmentType, LevelFormat, TableLayoutType, PageNumber, Footer } = require('docx');
const FONT = 'Arial', SZ = 18, MUTED = '555555', HEAD = 'E8EAED', ZEBRA = 'F6F7F8', NOTE = 'FFF6DC';
const HAIR = { style: BorderStyle.SINGLE, size: 4, color: 'C8CCD0' };
const t = (text, o) => { o = o || {}; return new TextRun({ text, font: o.mono ? 'Consolas' : FONT, size: o.size || SZ, bold: o.bold, italics: o.italics, color: o.color }); };
const p = (runs, o) => { o = o || {}; return new Paragraph({ children: Array.isArray(runs) ? runs : [runs], spacing: { before: o.before || 0, after: o.after == null ? 70 : o.after, line: o.line || 250 }, alignment: o.align, shading: o.fill ? { type: ShadingType.CLEAR, fill: o.fill } : undefined }); };
const h = (text) => new Paragraph({ children: [t(text, { bold: true, size: 24 })], spacing: { before: 200, after: 60, line: 250 },
  border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: 'C8CCD0', space: 2 } } });
const b = (runs) => new Paragraph({ children: Array.isArray(runs) ? runs : [runs], numbering: { reference: 'bullets', level: 0 }, spacing: { after: 40, line: 250 } });
const n = (runs, ref) => new Paragraph({ children: Array.isArray(runs) ? runs : [runs], numbering: { reference: ref || 'numbers', level: 0 }, spacing: { after: 40, line: 250 } });
const code = (lines) => lines.map((l, i) => new Paragraph({ children: [t(l, { mono: true, size: 16 })], spacing: { after: i == lines.length - 1 ? 80 : 0, line: 230 }, shading: { type: ShadingType.CLEAR, fill: 'F3F4F6' }, indent: { left: 200 } }));
const cell = (children, w, fill) => new TableCell({ children, width: { size: w, type: WidthType.DXA }, shading: fill ? { type: ShadingType.CLEAR, fill } : undefined, margins: { top: 34, bottom: 34, left: 80, right: 80 } });
function table(headers, rows, widths, monoCols) {
  monoCols = monoCols || [];
  const mk = (r, fill, bold) => new TableRow({ cantSplit: true, children: r.map((c, i) => cell([p(t(String(c), { bold, size: 17, mono: !bold && monoCols.indexOf(i) > -1 }), { after: 0, line: 225 })], widths[i], fill)) });
  return new Table({ rows: [mk(headers, HEAD, true)].concat(rows.map((r, i) => mk(r, i % 2 ? ZEBRA : undefined, false))),
    width: { size: widths.reduce((a, c) => a + c, 0), type: WidthType.DXA }, columnWidths: widths, layout: TableLayoutType.FIXED,
    borders: { top: HAIR, bottom: HAIR, left: HAIR, right: HAIR, insideHorizontal: HAIR, insideVertical: HAIR } });
}
const K = [];
K.push(p(t('Load Balancer Addresses in USEM CI Matching', { bold: true, size: 32 }), { after: 30 }));
K.push(p(t('How a scanned virtual address is resolved, how the real server behind a virtual server is reached, and what the check with the network team’s examples has to show', { color: MUTED }), { after: 120 }));

K.push(h('1. In short'));
K.push(p(t('Four things are in place for addresses that belong to a load balancer:')));
K.push(n(t('A load balancer device is never matched through an address it answers on. The three address rules decline as soon as the address search lands on a Load Balancer record.')));
K.push(n(t('A virtual server is matched to its Load Balancer Service record when the CMDB holds one. That record is the virtual IP itself, not the device and not the servers behind it.')));
K.push(n(t('A DNS name that discovery has tied to an address recorded on a device’s network adapter is matched to that device. This resolves aliases to the machine that owns the address.')));
K.push(n(t('A virtual server with exactly one real server behind it in the CMDB is matched to that server. The rule walks the platform’s own load balancer model, Load Balancer Service to Pool to Pool Member to server, and hands the finding to the real server only when it is the single one; with several servers, or without pool data, the virtual server record keeps the finding.')));
K.push(p(t('What this depends on: the pool and pool member records, or the equivalent relationships, must be in the CMDB. The CMDB extracts looked at so far hold no such records for the virtual servers in question, so for those the finding lands on the Load Balancer Service record when one exists and stays unmatched otherwise. Whether the network data collection feed puts the virtual-to-real mapping anywhere in the CMDB is exactly what the examples will show; section 6 describes the model the rule reads and section 7 how to check.'), { fill: NOTE }));
K.push(p(t('The mechanism described to the client, “DNS Name, then IP Address record, then adapter, then CI”, is mechanism 3 above. It reaches the device whose own adapter carries the address in the chain. A virtual address sits on the load balancer, not on a pool member’s adapter, so that chain does not lead to the real server behind a virtual IP; mechanism 4 is the one that does, and it needs the pool records.')));

K.push(h('2. What the rules read'));
K.push(p(t('Every rule receives one Qualys host record. For a virtual server it looks like this:')));
K.push(...code(['{', '  "ID": "1202267231",', '  "IP": "171.203.142.26",', '  "TRACKING_METHOD": "IP",', '  "OS": "F5 Big IP",', '  "DNS": "crisp-tx.bankofamerica.com"', '}']));
K.push(table(['Field', 'Meaning', 'Used by'], [
  ['IP', 'the address Qualys scanned; for a virtual server this is the virtual IP', 'the address rules and the service rule'],
  ['DNS', 'the name Qualys resolved for that address, when there is one', 'the name rules, the DNS chain and the service rule'],
  ['OS', 'the fingerprint of whatever answered; on a virtual IP it is usually the load balancer product', 'the class checks and the VIP signs'],
], [1300, 5200, 3500], [0]));
K.push(p(t('Nothing in the record says which real servers sit behind the address. Qualys sees the front door only, so any virtual-to-real translation has to come from the CMDB.'), { before: 60 }));

K.push(h('3. Mechanism 1: the load balancer device is never matched by address'));
K.push(p(t('Rules IP Hardware Match, IP Adapter Match and IP Layered Match search the scanned address on device records, on network adapters and on IP Address records. Each of them stops with no match as soon as the record found is a Load Balancer (class Load Balancer and its sub-classes such as BIG-IP). The reason is simple: an address a load balancer answers on is a virtual address, and the findings describe what sits behind it. Pinning them on the load balancer would send a web server’s weakness to the network team.')));
K.push(table(['Step', 'Data', 'Outcome'], [
  ['scanned address', '171.203.142.26 from the payload', ''],
  ['device search', 'BIG-IP device rvcpcz1atmlb01s carries ip_address 171.203.142.26', 'a Load Balancer: declined'],
  ['adapter search', 'no adapter of a non-balancer device carries the address', 'no match'],
  ['IP Address record search', 'no IP Address record of a non-balancer device carries the address', 'no match'],
], [2300, 5200, 2500]));
K.push(p(t('The device itself is still matched, by its own name, when Qualys scans its management interface (rule Hostname Hardware Match, or Network Interface Name Match for an interface label such as rvcpcz1atmlb01s-vs1).'), { before: 60 }));

K.push(h('4. Mechanism 2: a virtual server is matched to its Load Balancer Service record'));
K.push(p(t('Rule Load Balancer Service Match runs only for hosts that show a VIP sign: the OS text names a load balancer product (f5, big-ip, big ip, netscaler) or a segment of the DNS label is a VIP marker (vip, vs, a marker with digits such as vs1, or a segment ending in the marker such as multihostvip). Without such a sign the rule does nothing, so an ordinary server that happens to share an address with a virtual IP is never turned into a service.')));
K.push(p(t('With a sign, the rule looks for exactly one Load Balancer Service record, in this order: fqdn equal to the scanned DNS name, then name equal to the DNS name, then name equal to the label, then ip_address equal to the scanned address. A step that finds two records ends the rule with no match, because a weaker step could otherwise pick a different service. A step that finds nothing hands over to the next step.')));
K.push(table(['Payload', 'VIP sign', 'Service record found', 'Result'], [
  ['IP 171.203.142.26, OS "F5 Big IP", DNS crisp-tx.bankofamerica.com', 'OS names F5', 'crisp-tx, fqdn crisp-tx.bankofamerica.com, ip_address 171.203.142.26, port 443', 'matched by fqdn'],
  ['IP 171.145.73.51, OS "F5 Networks Big-IP", no DNS', 'OS names F5', 'vs_171.145.73.51_443, ip_address 171.145.73.51', 'matched by address'],
  ['IP 164.91.236.18, OS "Linux 2.6", DNS rbps-dev3-sve-vip.ecommnp.rpg', 'label segment vip', 'rbps-dev3-sve-vip', 'matched by name'],
  ['IP 164.91.176.197, OS "F5 Networks Big-IP", no DNS', 'OS names F5', 'two services on the address', 'declined'],
  ['IP 171.203.142.26, OS "Red Hat Enterprise Linux 9.8", DNS somehost.corp.bankofamerica.com', 'none', 'not searched', 'rule does not run'],
], [3600, 1500, 3400, 1500]));
K.push(p(t('What this gives the client: a finding on a virtual IP is attributed to the virtual server object. For findings on the front door itself (certificate, TLS settings, the ports the virtual server exposes) that is the right owner. It is not the real server behind the virtual IP.'), { before: 60 }));

K.push(h('5. Mechanism 3: DNS name, IP Address record, adapter, device'));
K.push(p(t('Discovery keeps names and addresses as their own records: a DNS Name record is tied to an IP Address record, the IP Address record belongs to a Network Adapter, and the adapter belongs to the device. Rule Layered DNS Match follows that chain. It is the only way to find a host whose name is not written on the device record at all, and it resolves an alias to the machine whose adapter carries the address.')));
K.push(table(['Link', 'Table', 'Sample'], [
  ['scanned DNS name', 'payload DNS', 'hklvteqoradbp3.hk.baml.com'],
  ['DNS Name record', 'cmdb_ci_dns_name (name)', 'hklvteqoradbp3.hk.baml.com'],
  ['tie to the address record', 'cmdb_ip_address_dns_name (dns_name, ip_address)', 'one row'],
  ['IP Address record', 'cmdb_ci_ip_address (ip_address, nic)', '167.202.60.26 on adapter eth0'],
  ['Network Adapter', 'cmdb_ci_network_adapter (cmdb_ci)', 'eth0 of the Linux Server'],
  ['device', 'the CI the adapter belongs to', 'Linux Server hklvteqoradbp3'],
], [2600, 4200, 3200], [1]));
K.push(p(t('The chain has a class check (a Cisco IOS host is not accepted on a Computer at the end of the chain) and a tie-break: when a name leads to two devices, the one reached through the scanned address is taken.'), { before: 60 }));
K.push(p(t('What this chain does not do: it only reaches a device whose own adapter carries the address in the chain. A virtual address is not on a pool member’s adapter; it sits on the load balancer. So this rule cannot translate a virtual IP into a real server. And if discovery has tied a virtual server’s DNS name to the address on the load balancer’s own interface, the chain ends on the load balancer device, which this rule does not refuse today; the address rules do. Section 8 proposes the one-line correction.'), { fill: NOTE }));

K.push(h('6. Mechanism 4: the one real server behind the virtual server'));
K.push(p(t('Rule Load Balancer Member Match runs just before the service rule, for the same hosts (a VIP sign is required) and finds the virtual server the same way. It then walks the platform’s own load balancer model:')));
K.push(table(['Record', 'Table', 'Fields that carry the mapping'], [
  ['Load Balancer Service (the virtual server)', 'cmdb_ci_lb_service', 'ip_address, port, fqdn, pool (reference to the pool), load_balancer (the device)'],
  ['Load Balancer Pool', 'cmdb_ci_lb_pool', 'service (reference to the virtual server), load_balancer'],
  ['Load Balancer Pool Member (one real server address)', 'cmdb_ci_lb_pool_member', 'pool (reference to the pool), ip_address, service_port, load_balancer'],
  ['the real server', 'a device class, usually Server or Linux / Windows Server', 'ip_address, or its adapters and IP Address records carrying the member address; a Depends on::Used by relationship from the pool member is the usual link'],
], [3000, 2900, 4100], [1]));
K.push(p(t('Each hop is read both through the reference fields and through relationships, because a bulk load may fill one and not the other: the pool field on the service, pools pointing at the service, pools related to it; members pointing at the pool or related to it; each member address looked up on device records, adapters and IP Address records, and each member followed through its relationships to hardware. Load balancer devices and ignored classes are never counted as real servers. The distinct servers are then counted: exactly one is the match; none, or two or more, and the rule declines so that the service rule attaches the virtual server record.'), { before: 60 }));
K.push(table(['Payload', 'What the CMDB holds', 'Result'], [
  ['IP 171.203.142.26, OS "F5 Big IP", DNS crisp-tx.bankofamerica.com', 'service crisp-tx, pool crisp-tx-pool, one member 10.10.20.31, Linux Server usvacrispweb01 on that address', 'the Linux Server'],
  ['the same virtual server scanned by address only', 'the same records', 'the Linux Server (service found by address)'],
  ['a virtual server whose pool holds three members on three servers', 'service, pool, three members, three servers', 'declined; the service rule attaches the virtual server'],
  ['a virtual server without a pool', 'service only', 'declined; the virtual server record'],
  ['a member address carried by two device records', 'two servers on one member address', 'declined; the virtual server record'],
  ['the only member is the load balancer itself', 'member address on the BIG-IP', 'declined; the virtual server record'],
  ['pool and member linked by relationships only, no reference fields', 'relationships Depends on::Used by, member address on an adapter', 'the server'],
  ['a Red Hat host on the virtual address without a VIP sign', 'not searched', 'rule does not run'],
], [3600, 3700, 2700]));
K.push(p(t('Why exactly one: the platform attaches one CI to one discovered item, and a virtual server that fronts several servers cannot be given to all of them by a lookup rule. One finding per member would need the Qualys feed to produce one item per member, which it does not. Keeping the virtual server record for those cases is the safe choice; if the client prefers another policy for shared pools (for example the pool members as related CIs for ownership), that is a separate piece of work outside the lookup rules.'), { before: 60 }));
K.push(p(t('What the extracts show so far: for the virtual servers pts-zelle-transfer-* and horizon-vip.* the CMDB holds DNS Name records and the placeholder records the import creates for unmatched hosts, and nothing in the three tables above. For those the new rule declines and nothing changes. If the network data collection feed carries a virtual-to-real mapping, it is either loaded elsewhere or not loaded at all; the integration agreement does not mention it.')));

K.push(h('7. How to run the check with the examples'));
K.push(p(t('For each example the network team gives (a virtual address and the real servers they expect behind it), the attached read-only script prints everything the CMDB holds. Paste the virtual addresses into the list at the top and run it as a background script. It writes nothing. For each address it lists:')));
K.push(n(t('the discovered items scanned on that address: number, DNS name, OS, state and the CI they hold today;'), 'steps'));
K.push(n(t('the Load Balancer Service records on the address or the name, with their pool and load balancer, and the pool members with their addresses and ports;'), 'steps'));
K.push(n(t('the load balancer devices carrying the address, and the DNS Name and IP Address records tied to it, with the device at the end of that chain;'), 'steps'));
K.push(n(t('the relationships that start or end at any of those records;'), 'steps'));
K.push(n(t('the servers carrying each pool member address, so the expected real servers can be recognised.'), 'steps'));
K.push(p(t('Reading the output: if the service, pool and members are there, the mapping exists and mechanism 4 applies as soon as the items are evaluated again. If only the service exists, the mapping is not in the CMDB and the finding stays on the virtual server record. If nothing exists, the virtual server is not modelled at all and matching it to anything would be a guess. When the mapping is kept elsewhere, the probe output shows where the hops break and the rule can be pointed at that place.'), { before: 60 }));

K.push(h('8. One correction to make in the rules'));
K.push(p(t('Layered DNS Match should refuse a Load Balancer device at the end of the chain, exactly as the address rules do. It is one condition in the last stage of that rule and changes nothing else. It closes the only way a virtual server’s DNS name could land on the load balancer device, and makes the statement “we never map the load balancer through a virtual address” hold for every rule. Not applied yet; to be applied on request.')));

const doc = new Document({
  styles: { default: { document: { run: { font: FONT, size: SZ } } } },
  numbering: { config: [
    { reference: 'bullets', levels: [{ level: 0, format: LevelFormat.BULLET, text: '•', alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 360, hanging: 240 } } } }] },
    { reference: 'numbers', levels: [{ level: 0, format: LevelFormat.DECIMAL, text: '%1.', alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 360, hanging: 260 } } } }] } ,
    { reference: 'steps', levels: [{ level: 0, format: LevelFormat.DECIMAL, text: '%1.', alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 360, hanging: 260 } } } }] } ] },
  sections: [{ properties: { page: { margin: { top: 1000, bottom: 900, left: 1000, right: 1000 } } },
    footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.RIGHT, children: [t('Load Balancer Addresses in USEM CI Matching   ', { size: 14, color: MUTED }), new TextRun({ children: [PageNumber.CURRENT], font: FONT, size: 14, color: MUTED })] })] }) },
    children: K }]
});
Packer.toBuffer(doc).then(buf => { fs.writeFileSync(__dirname + '/Load Balancer Addresses in CI Matching.docx', buf); console.log('written', buf.length, 'bytes'); });
