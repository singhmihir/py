// Demo preparation document: the Qualys CI lookup rules from order 400 upward, the shared building blocks, the code
// of each rule with a stage-by-stage walkthrough, load balancer handling end to end and a question bank.
// Code excerpts are read from rules/*.js so the document always quotes the delivered scripts.
const fs = require('fs');
const { Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell, WidthType, BorderStyle, ShadingType,
        AlignmentType, LevelFormat, TableLayoutType, PageNumber, Footer, PageBreak } = require('docx');
const FONT = 'Arial', SZ = 18, MUTED = '555555', HEAD = 'E8EAED', ZEBRA = 'F6F7F8', NOTE = 'FFF6DC', QA = 'EEF4FB';
const HAIR = { style: BorderStyle.SINGLE, size: 4, color: 'C8CCD0' };
const t = (text, o) => { o = o || {}; return new TextRun({ text, font: o.mono ? 'Consolas' : FONT, size: o.size || SZ, bold: o.bold, italics: o.italics, color: o.color }); };
const p = (runs, o) => { o = o || {}; return new Paragraph({ children: Array.isArray(runs) ? runs : [runs], spacing: { before: o.before || 0, after: o.after == null ? 70 : o.after, line: o.line || 250 }, alignment: o.align, shading: o.fill ? { type: ShadingType.CLEAR, fill: o.fill } : undefined, keepNext: o.keepNext }); };
const h1 = (text) => new Paragraph({ children: [t(text, { bold: true, size: 28 })], spacing: { before: 280, after: 80, line: 250 }, border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: '9AA0A6', space: 2 } }, keepNext: true });
const h2 = (text) => new Paragraph({ children: [t(text, { bold: true, size: 23 })], spacing: { before: 200, after: 60, line: 250 }, border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: 'C8CCD0', space: 2 } }, keepNext: true });
const h3 = (text) => new Paragraph({ children: [t(text, { bold: true, size: 19 })], spacing: { before: 140, after: 40, line: 250 }, keepNext: true });
const b = (runs) => new Paragraph({ children: Array.isArray(runs) ? runs : [runs], numbering: { reference: 'bullets', level: 0 }, spacing: { after: 40, line: 250 } });
let numRef = 0;
const numbered = (items) => { numRef++; return items.map(runs => new Paragraph({ children: Array.isArray(runs) ? runs : [runs], numbering: { reference: 'num' + numRef, level: 0 }, spacing: { after: 40, line: 250 } })); };
const code = (text) => { const lines = text.split('\n'); return lines.map((l, i) => new Paragraph({ children: [t(l || ' ', { mono: true, size: 15 })], spacing: { after: i == lines.length - 1 ? 90 : 0, line: 220 }, shading: { type: ShadingType.CLEAR, fill: 'F3F4F6' }, indent: { left: 160 } })); };
const qa = (q, a) => [p(t('Q. ' + q, { bold: true }), { fill: QA, after: 20, keepNext: true }), p(t('A. ' + a), { fill: QA, after: 90 })];
const cell = (children, w, fill) => new TableCell({ children, width: { size: w, type: WidthType.DXA }, shading: fill ? { type: ShadingType.CLEAR, fill } : undefined, margins: { top: 34, bottom: 34, left: 80, right: 80 } });
function table(headers, rows, widths, monoCols) {
  monoCols = monoCols || [];
  const mk = (r, fill, bold) => new TableRow({ cantSplit: true, children: r.map((c, i) => cell([p(t(String(c), { bold, size: 16, mono: !bold && monoCols.indexOf(i) > -1 }), { after: 0, line: 225 })], widths[i], fill)) });
  return new Table({ rows: [mk(headers, HEAD, true)].concat(rows.map((r, i) => mk(r, i % 2 ? ZEBRA : undefined, false))),
    width: { size: widths.reduce((a, c) => a + c, 0), type: WidthType.DXA }, columnWidths: widths, layout: TableLayoutType.FIXED,
    borders: { top: HAIR, bottom: HAIR, left: HAIR, right: HAIR, insideHorizontal: HAIR, insideVertical: HAIR } });
}
// ---- code extraction from the delivered scripts ------------------------------------------------------------------
const RULES = fs.readdirSync(__dirname + '/rules').filter(f => f.endsWith('.js'));
const file = (order) => fs.readFileSync(__dirname + '/rules/' + RULES.find(f => f.startsWith(order + '_')), 'utf8');
const SHARED = ['classFor', 'parentsOf', 'agrees', 'isLoadBalancer', 'nameAgrees', 'isMarker'];
function excerpt(order, opts) {
  opts = opts || {}; const keepFns = opts.keep || [];
  let s = file(order); s = s.slice(s.indexOf('(function process'));
  const out = []; let skip = false;
  for (const l of s.split('\n')) {
    const st = l.trim();
    const m = st.match(/^function (\w+)\(/);
    if (m && SHARED.indexOf(m[1]) > -1 && keepFns.indexOf(m[1]) < 0) { skip = true; out.push('    // ' + m[1] + '() as in Part 1'); continue; }
    if (skip) { if (l.startsWith('    }') && st == '}') skip = false; continue; }
    if (st.startsWith('//') && !st.startsWith('// --')) continue;
    if (st.startsWith('var ignore = (typeof') ) { out.push("    var ignore = ...;                            // the ignored classes, as in Part 1"); skip = 'ign'; continue; }
    if (skip === 'ign') { skip = false; continue; }
    if (!st) continue;
    out.push(l.replace(/\s+\/\/ .*$/, (mm) => mm));
  }
  return out.join('\n');
}
function fn(order, name) {   // one helper function with its comment paragraph, verbatim
  const s = file(order).split('\n'); let i = s.findIndex(l => l.trim().startsWith('function ' + name + '('));
  let start = i; while (start > 0 && s[start - 1].trim().startsWith('//') && !s[start - 1].trim().startsWith('// --')) start--;
  let end = i; while (!(s[end].startsWith('    }') && s[end].trim() == '}')) end++;
  return s.slice(start, end + 1).join('\n');
}
function header(order) { const s = file(order); return s.slice(0, s.indexOf('(function process')); }
function sample(order) { const s = header(order); const i = s.indexOf('{'); const j = s.indexOf('}', i); return s.slice(i, j + 1).split('\n').map(l => l.replace(/^   /, '')).join('\n'); }
const K = [];
// ================================================================ title and reading plan
K.push(p(t('Qualys CI Lookup Rules', { bold: true, size: 34 }), { after: 20 }));
K.push(p(t('Walkthrough preparation for rules 400 to 850: the code, how each rule reaches the CI, load balancers end to end, and the questions to expect', { color: MUTED, size: 20 }), { after: 140 }));
K.push(p(t('How to use the three hours', { bold: true })));
K.push(table(['Block', 'Minutes', 'What it gives you'], [
  ['Part 1  Foundations', '35', 'how the platform runs the chain, what the payload holds, the contract every script follows, and the six shared building blocks with their code. Everything in Part 2 refers back here.'],
  ['Part 2  The rules from 400 upward', '95', 'one section per rule: purpose, when it acts, the sample, the code, a stage-by-stage walk with the sample, why it declines, and the questions an architect asks about it.'],
  ['Part 3  Load balancers end to end', '30', 'the four mechanisms, who gets the finding in each case, the CMDB model behind the member rule, the open point, and the story for the network team’s examples.'],
  ['Part 4  Question bank and demo flow', '20', 'cross-cutting questions with short answers, and a suggested order for the walkthrough.'],
], [2400, 900, 6700]));
K.push(p(t('Read Part 1 slowly: the shared blocks are where most code questions land. In Part 2, read the code excerpt first, then the walk, then the questions. Skim Part 4 last and keep it open during the session.'), { before: 80 }));

// ================================================================ PART 1
K.push(h1('Part 1  Foundations'));
K.push(h2('1.1  How the platform runs the chain'));
K.push(p(t('Every Qualys host record that the integration imports becomes a Discovered Item. Before the item is saved, the platform’s CI identification (CIIdentify, in the Security Support Common scope) runs the CI lookup rules of the Qualys source in order of their Order field. A rule with method Script receives three variables: rule (the rule record), sourceValue (the value of the rule’s Source field taken from the payload, for example the DNS name or the IP) and sourcePayload (the whole record). The script returns the sys_id of a CI, or null. The first rule that returns a sys_id wins; every later rule is skipped. A rule that returns null simply hands the host to the next one.')));
K.push(p(t('Three platform behaviours around the chain matter for the questions:')));
K.push(b([t('Retired CIs. ', { bold: true }), t('After a rule returns a CI, the platform drops it when it is retired (install status Retired, operational status Retired, or life-cycle stage Retired) and the property sn_sec_cmn.filterOutDecommissionedCI is true, which is its default. Retired handling therefore belongs to that property, not to the rules; our rules treat retired records as candidates, which is the client’s expectation.')]));
K.push(b([t('Unmatched hosts. ', { bold: true }), t('When no rule returns a CI, the identification engine creates a placeholder CI of class Unclassed Hardware named with the FQDN, the item points at it and keeps the state unmatched (matching type created_by_ire). The class is in the platform’s ignore list, so no rule ever returns a placeholder.')]));
K.push(b([t('Re-evaluation. ', { bold: true }), t('An item runs through the rules when it is imported and when it is re-imported or reapplied. Changing a rule does not touch existing items until then.')]));
K.push(p(t('Every rule record carries: Source Qualys, Table sn_vul_qualys_host_attrb, Method Script, Lookup target CI, a Source field (DNS, IP, SERIAL_NUMBER), an Order, Active and Reapply.'), { before: 60 }));

K.push(h2('1.2  What the payload holds'));
K.push(p(t('The rules read a handful of fields of the Qualys host record. Everything else in the payload (tags, scan dates, asset groups) is ignored.')));
K.push(table(['Field', 'Meaning', 'Read by'], [
  ['DNS', 'the name Qualys resolved for the address, lower case, usually a full FQDN; empty on roughly one host in ten', 'every name rule, the interface and controller rules, the service and member rules, and the name check of the address rules'],
  ['IP', 'the scanned address', 'the address rules, the service and member rules, the tie-break of the layered DNS rule and of the device rule'],
  ['OS', 'the fingerprint of what answered; a product name from an authenticated scan, a guess or a list of guesses separated by " / " from an unauthenticated one, empty on about half of the unauthenticated hosts', 'classFor(), the class agreement, the VIP sign and the device rule'],
  ['SERIAL_NUMBER', 'the serial from an agent or authenticated scan', 'the two serial rules (175, 180)'],
  ['TRACKING_METHOD', 'IP, AGENT, NETBIOS or Cloud Agent; almost always IP in this feed', 'not read by the rules'],
  ['NETBIOS, QG_HOSTID', 'rarely present', 'the platform’s own late rules only'],
], [1900, 5000, 3100], [0]));
K.push(p(t('Two facts about the values that come up in questions: names are compared case-insensitively by the platform query engine (a label "wsaoi01zeapd1" finds the CI "WSAOI01ZEAPD1"), and the DNS field never carries an address-shaped value in this feed, so a first label is always a host label.'), { before: 60 }));

K.push(h2('1.3  The contract every script follows'));
K.push(p(t('All scripts have the same skeleton. Knowing it lets you read any rule in a minute.')));
K.push(...code(`(function process(rule, sourceValue, sourcePayload) {
    if (!sourceValue)                             // nothing to look up
        return null;
    ...prepare the value: trim, lower case, split the label...
    ...the ignored classes...
    ...the matching stages, each one able to return null...
    return match;                                 // a sys_id, or null
})(rule, sourceValue, sourcePayload);`));
K.push(b([t('Exactly one. ', { bold: true }), t('Whenever a search could return several CIs, the script takes the first row and checks hasNext(); a second row means the value is shared and the rule returns null. No rule ever guesses between two candidates. This is the single most important design rule and the answer to most "what if" questions.')]));
K.push(b([t('No custom properties. ', { bold: true }), t('Every suffix list, marker list and class list is an inline array at the top of the stage that uses it, so the rule record is self-contained and readable in one place. The only property read is the platform’s own ignore list.')]));
K.push(b([t('Decline early. ', { bold: true }), t('A rule that cannot apply (no DNS, no hyphen, no VIP sign, no class from the OS) returns null before any query.')]));
K.push(b([t('Comments as first-hand notes. ', { bold: true }), t('Each script opens with its purpose, the sample payload used in every note, what it reads and returns, and its place in the chain; each matching stage ends with a Sample line that walks that payload through the stage.')]));

K.push(h2('1.4  The shared building blocks'));
K.push(h3('a. The ignored classes'));
K.push(...code(`    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?
        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');
    ...
    if (ignore)
        gr.addQuery('sys_class_name', 'NOT IN', ignore);`));
K.push(p(t('The platform property sn_sec_cmn.ignoreCIClass lists classes that must never be matched: the unmatched-CI staging tables, Unclassed Hardware (the placeholders), incomplete IP records and DNS Name records. The identification engine may also pass the list in as _ignoreClass, which is why the script accepts both. Every search adds the NOT IN clause.')));

K.push(h3('b. classFor(): the class the scanned OS implies'));
K.push(...code(fn('400', 'classFor')));
K.push(table(['OS text contains', 'Class', 'Note'], [
  ['esx', 'cmdb_ci_esx_server', 'checked first so "VMware ESXi" never falls into the Linux branch'],
  ['windows + server', 'cmdb_ci_win_server', ''],
  ['windows (no "server")', 'cmdb_ci_computer', 'desktops and laptops (Windows 10, Windows 11)'],
  ['aix / solaris, sunos / hp-ux', 'AIX, Solaris, HP-UX server classes', ''],
  ['netapp, ontap', 'cmdb_ci_storage_server', ''],
  ['printer, laserjet, jetdirect', 'cmdb_ci_printer', ''],
  ['red hat, linux, centos, ubuntu, suse, debian, fedora, euleros, oracle enterprise, amazon', 'cmdb_ci_linux_server', 'a bare kernel fingerprint such as "Linux 2.6" lands here too'],
  ['nx-os, catos, cisco', 'cmdb_ci_netgear', 'checked last, so "Cisco IP Phone" also lands here; the phone rules do not rely on it'],
  ['three or more " / " guesses, or empty', '(no class)', 'an unauthenticated scan that could not identify the OS; the class rules decline and the hardware-wide rules take over without a class check'],
], [3300, 2300, 4400], [1]));
K.push(p(t('Why it exists: the class rules (250, 300, 400, 700) search only inside the class the OS points at, and the hardware-wide rules use the class as a check at the end. A wrong class would hide the right CI, so the mapping stays conservative and gives no class rather than a doubtful one.'), { before: 60 }));

K.push(h3('c. parentsOf() and agrees(): class agreement'));
K.push(p(t('Used by the hardware-wide rules (350, 410, 705, 730, 740). parentsOf() reads the table hierarchy (sys_db_object) upward from a class. agrees() answers whether a CI of class cls can be the scanned host once the OS gave a class.')));
K.push(...code(fn('410', 'parentsOf') + '\n' + fn('410', 'agrees')));
K.push(p(t('Reading it: with no class from the OS nothing is refused. The same class agrees. A sub-class agrees (an AIX Server for a host scanned as AIX). A parent agrees (a plain Server or Hardware record for an AIX host, because many CIs are kept in a generic class). And, in 350 and 410 only, an appliance class agrees with a Linux fingerprint: switches, balancers and storage nodes run Linux underneath and Qualys reports that kernel. Everything else is a different kind of machine: a Windows Server named like the scanned Linux host is a namesake, and a Computer on the address of a Cisco router is a reused address. The address rules (705, 730, 740) use the version without the appliance clause: an address alone on an appliance is not enough.')));

K.push(h3('d. isLoadBalancer(): the device that is never matched by address'));
K.push(...code(fn('705', 'isLoadBalancer')));
K.push(p(t('cmdb_ci_lb is the Load Balancer device class (BIG-IP is a sub-class); it extends Server, not Network Gear. get() on that table returns true for any record in the class or its sub-classes. The address rules refuse such a device because an address a balancer answers on is a virtual address and the findings describe what sits behind it; the controller rule refuses it for the same reason. The device is still matched by its own name when its management interface is scanned.')));

K.push(h3('e. nameAgrees(): the name check of the address rules'));
K.push(...code(fn('700', 'nameAgrees')));
K.push(p(t('Added on 15 September to the four address rules. An address alone is weak: leases move and decommissioned machines hand their address on. When the scan carries a DNS name, the CI reached through the address must be named with it: the same first label, or one side equal to the other plus a hyphenated tail ("<name>-mgmt" for an interface, "<name>-a" for a node). No DNS, or a CI without a name, checks nothing. It closed the one wrong match seen in the client run outputs, a Windows 11 host landing on the retired record of another machine that once held its address.')));

K.push(h3('f. isMarker(): recognising an interface or VIP segment'));
K.push(...code(fn('430', 'isMarker')));
K.push(p(t('Used by 430, 455 and 460 on the hyphen segments of a label. A segment matches a listed word when it is the word itself ("vlan"), the word followed by digits only ("vlan705", "v201"), or, for words of three letters or more, a segment ending in the word ("multihostvip"). The three-letter floor stops "vs" from matching every segment ending in "vs".')));

K.push(h2('1.5  Two roads to the CI'));
K.push(p(t('Every rule reaches the CI either through an identity or through an address, and the safety checks differ.')));
K.push(table(['Road', 'Rules', 'What identifies the CI', 'Safety'], [
  ['identity', '175, 180 serial; 200 phone MAC; 250 to 310 FQDN and host-plus-domain; 350 DNS chain; 400, 410 host name; 415 device name; 420 controller suffix; 430 interface label; 450, 850 full FQDN as name', 'a value written on the CI record (or, for 350, on its discovery records)', 'exactly one CI carries the value; the class agrees with the OS where a class is known'],
  ['address', '455 member; 460 service; 700, 705, 730, 740', 'the scanned address on the CI, its adapter or its IP Address record, or a virtual server model', 'exactly one owner; never a load balancer device; class agrees; the CI name agrees with the scanned name'],
], [1200, 3600, 2600, 2600]));
K.push(p(t('The order of the chain follows trust: serial first, then names with the most context (FQDN, host plus domain), then the plain host name, then special label shapes (controller, interface), then the virtual server rules, and only then the address rules, with a broad name fallback at the very end before the platform’s own rules.'), { before: 60 }));

K.push(h2('1.6  The chain'));
K.push(table(['Order', 'Rule', 'Field', 'One line'], [
  ['175', 'USEM Serial Number Class Match', 'SERIAL_NUMBER', 'serial inside the OS class, exactly one'],
  ['180', 'USEM Serial Number Hardware Match', 'SERIAL_NUMBER', 'serial across the Hardware tree, exactly one'],
  ['200', 'USEM Cisco IP Phone MAC', 'DNS', '"sep" plus twelve hex characters: the phone carrying that MAC'],
  ['250 / 260', 'USEM FQDN Class / Hardware Match', 'DNS', 'the scanned FQDN in the fqdn field'],
  ['300 / 310', 'USEM Hostname Domain Class / Hardware Match', 'DNS', 'host name plus dns_domain on the CI'],
  ['350', 'USEM Layered DNS Match', 'DNS', 'DNS Name record -> IP Address record -> adapter -> CI'],
  ['400', 'USEM Hostname Class Match', 'DNS', 'short host name inside the OS class (today’s first rule)'],
  ['410', 'USEM Hostname Hardware Match', 'DNS', 'short host name across the Hardware tree, class agreeing'],
  ['415', 'USEM Device Name Match', 'DNS', 'host name in the classes outside the Hardware tree: IP phones, scanners'],
  ['420', 'USEM Management Interface Match', 'DNS', 'controller label ("-ilo", "-idrac") -> the server'],
  ['430', 'USEM Network Interface Name Match', 'DNS', 'interface label ("-cz04-hsrp-vlan705") -> the device'],
  ['450', 'USEM FQDN Name Hardware Match', 'DNS', 'the full FQDN as the CI name, Hardware tree'],
  ['455', 'USEM Load Balancer Member Match', 'IP', 'the one real server behind a virtual server'],
  ['460', 'USEM Load Balancer Service Match', 'IP', 'the virtual server record (Load Balancer Service)'],
  ['700', 'USEM IP Class Match', 'IP', 'address inside the OS class, one CI, name agreeing'],
  ['705', 'USEM IP Hardware Match', 'IP', 'address across the Hardware tree, not a balancer, name and class agreeing'],
  ['730', 'USEM IP Adapter Match', 'IP', 'address on a network adapter -> its owner'],
  ['740', 'USEM IP Layered Match', 'IP', 'address on an IP Address record -> adapter -> owner'],
  ['850', 'USEM FQDN Name Broad Match', 'DNS', 'the full FQDN as the CI name, any class'],
  ['860 to 940', 'QUALYS HOST ID, Cloud Resource Id, FQDN, NetBIOS, DNS', 'various', 'the platform’s own rules, behaviour given by their type, kept as the last resort'],
], [900, 3300, 1300, 4500]));
K.push(p(t('The platform rules at the end carry template scripts; their behaviour comes from the rule type (field matching on the Qualys host id, cloud resource id, FQDN, NetBIOS, DNS). They still act: in testing, the DNS rule resolved a switch through its DNS Name record when our rules had refused it on class grounds.'), { before: 60 }));
// ================================================================ PART 2
K.push(new Paragraph({ children: [new PageBreak()] }));
K.push(h1('Part 2  The rules from 400 upward'));
K.push(p(t('Each section has the same shape: what the rule is for, when it acts, the sample payload from its header, the code with the shared blocks folded away (they are in Part 1), a walk through the stages with the sample, the ways it declines, and the questions to expect. The full scripts are on the rule records.')));

function ruleSection(order, name, intro, when, walk, declines, questions, opts) {
  opts = opts || {};
  K.push(h2(order + '  ' + name));
  K.push(p(t(intro)));
  K.push(p([t('When it acts. ', { bold: true }), t(when)]));
  K.push(p(t('Sample payload', { bold: true }), { after: 20, keepNext: true }));
  K.push(...code(sample(order)));
  K.push(p(t('Code', { bold: true }), { after: 20, keepNext: true }));
  K.push(...code(excerpt(order, { keep: opts.keep })));
  K.push(p(t('Walk through the stages', { bold: true }), { after: 20, keepNext: true }));
  walk.forEach(w => K.push(b([t(w[0] + ' ', { bold: true }), t(w[1])])));
  K.push(p(t('It declines when', { bold: true }), { after: 20, keepNext: true }));
  declines.forEach(d => K.push(b(t(d))));
  K.push(p(t('Questions to expect', { bold: true }), { after: 20, keepNext: true }));
  questions.forEach(q => K.push(...qa(q[0], q[1])));
}

ruleSection('400', 'USEM Hostname Class Match',
  'The plain short host name, searched inside the class the scanned OS points at. It is the workhorse of the chain: in the client run outputs it resolved the largest share of matched hosts. The class stands in for the domain information the CI record does not carry.',
  'Source field DNS. It needs a first label and a class from the OS; without a class it declines at once and leaves the host to 410.',
  [['Prepare.', 'The DNS value is trimmed and lower-cased, and the first label is cut at the first dot: "wsaoi01zeapd1.sdi.corp.bankofamerica.com" gives "wsaoi01zeapd1".'],
   ['Class from the OS.', 'classFor("Windows Server 2016 Standard 64 bit Edition Version 1607") gives cmdb_ci_win_server; pref holds it. An empty or multi-guess OS gives no class and the rule returns null here.'],
   ['Search inside that class.', 'new GlideRecord(pref) is the class table, which includes its sub-classes; the query is name = host with the ignored classes left out. isValid() guards against a class not installed on an instance.'],
   ['Exactly one.', 'The first row is the candidate; hasNext() true means a second Windows Server carries the name and the rule declines. The sample finds "WSAOI01ZEAPD1" and no second row, so its sys_id is returned.']],
  ['the DNS field is empty or the OS gives no class;', 'no CI of that class carries the name;', 'two CIs of that class carry the name (a duplicate, or an old and a new record).'],
  [['Why search only inside the class and not everywhere?', 'Because a short host name is not unique across classes: a router, a Windows server and a virtual machine can all be called the same. Inside the class the OS points at, a namesake of another kind is never seen. 410 widens the search to the Hardware tree afterwards, with a class check.'],
   ['A CI kept in the generic Server class scanned as Red Hat: does 400 find it?', 'No, cmdb_ci_server is a parent of Linux Server, not a sub-class, so the search on cmdb_ci_linux_server does not see it. 410 finds it and accepts it because a parent class agrees.'],
   ['Case: the CI name is upper case and the DNS label lower case.', 'The platform query is case-insensitive on string fields, so they match. The sample shows exactly that.'],
   ['What if the OS says Windows but the CI is a Windows Server in the Computer class?', 'classFor gives cmdb_ci_computer for a desktop OS and cmdb_ci_win_server for a server OS. Windows Server is a sub-class of Computer, so a desktop OS search on Computer includes Windows Servers, while a server OS search on Windows Server excludes desktops. That asymmetry is deliberate.']]);

ruleSection('410', 'USEM Hostname Hardware Match',
  'The same short host name across the whole Hardware tree, for CIs whose class differs from what the OS suggests or whose OS gave no class. The class agreement check is what keeps this wide search safe, and since 15 September it also accepts an appliance record (switch, balancer, storage node) for a Linux fingerprint.',
  'Source field DNS. It needs a first label; a class is optional and used only as the check at the end.',
  [['Prepare.', 'First label of the DNS name: "va2ausapabw0".'],
   ['Class as a preference.', 'classFor("AIX 7.3 TL3") gives cmdb_ci_aix_server; it is not a filter here, only the check in the last stage.'],
   ['Search the Hardware tree.', 'cmdb_ci_hardware is the parent of every device class (servers, computers, network gear, storage, printers, balancers); name = host with the ignored classes left out.'],
   ['Exactly one.', 'The first row is remembered with its class; a second row of any class means the name is shared and the rule declines.'],
   ['Class agreement.', 'agrees(cls): the sample CI is in the plain Server class, a parent of AIX Server, so it is accepted. A Windows Server or an IP Router named "va2ausapabw0" would be refused. An IP Switch named like a host scanned as "Ubuntu/Linux" is accepted since the appliance clause.']],
  ['no hardware CI carries the name, or two do (even in different classes);', 'the one CI’s class contradicts the OS: a Windows Server for a Linux scan, a Computer for a Cisco IOS scan.'],
  [['Why refuse a Windows Server named like a Linux host instead of trusting the name?', 'Because in the client CMDB the short name is reused across kinds of machines, and a wrong CI sends the finding to the wrong owner. The name says "a machine with this label exists"; the class says whether it is the same kind of machine. Both must hold.'],
   ['Why accept a switch for a Linux fingerprint, then?', 'Switches, balancers and storage nodes run Linux underneath and an unauthenticated scan reports that kernel. The client outputs showed twelve such cases, switches and BIG-IP devices named exactly with the scanned host, refused only because of the fingerprint. For any other class the fingerprint is still a contradiction.'],
   ['Two CIs, one live and one retired, carry the name. What happens?', 'The rule sees two rows and declines; it does not look at the status. That is on purpose: retired records stay candidates by the client’s design, and choosing between two records by status would be a guess.'],
   ['Does this rule see IP phones or scanners?', 'No. Those classes are outside the Hardware tree, which is why 415 exists.']]);

ruleSection('415', 'USEM Device Name Match',
  'The host name searched in the two device classes the CMDB keeps outside the Hardware tree: IP Phone, which extends the base CI class directly, and Imaging Hardware, where Scanner lives. Neither the hardware-wide rules nor the class rules could ever reach them, which left ten thousand contact-centre phones unmatched.',
  'Source field DNS. It needs a first label and an OS that does not name a server or desktop system; in the contact-centre domain the OS is empty on nearly every phone.',
  [['Prepare.', 'First label "avxdd008a"; the scanned address is kept for a tie-break only.'],
   ['The OS must not contradict.', 'classFor(os) gives no class for an empty OS, "Foundry Networks" or "Unknown OS", and cmdb_ci_linux_server for "Linux 2.x"; both are accepted, as is any text mentioning "phone". A class such as Windows or ESXi ends the rule: a desktop is not a phone.'],
   ['Search the two classes.', 'cmdb_ci_ip_phone and cmdb_ci_imaging_hardware are searched by name (sub-classes included, ignored classes left out). Every hit goes into found; the hits whose ip_address is the scanned address also go into onAddress.'],
   ['Decide.', 'One device named with the host is the match: the sample finds the phone "AVXDD008A" and returns it. When the name is shared, the one on the scanned address is taken, and only when exactly one carries it.']],
  ['the OS names a server or desktop system;', 'no phone or scanner carries the name;', 'several carry it and none, or two, sit on the scanned address.'],
  [['Why name only and not name plus address?', 'A phone name is built from its MAC address ("avx" plus the last six hex characters) and a scanner name from its asset label, so the name identifies the device; the address is a DHCP lease that moves. The scanner example in the incident had moved address and still belongs to its record. The address is used only to split a shared name.'],
   ['Why is the rule after 410 and not before?', 'So that a Hardware CI carrying the name always wins first. If a Linux server and a scanner shared a name, the server would be found by 400 or 410 before this rule looks at the scanner.'],
   ['Why list the two classes instead of searching cmdb_ci?', 'Because the base table also holds certificates, DNS Name records, business applications and other non-device classes named like hosts. The scanner example has five certificate records of the same name; a base-table search would see six candidates and decline.'],
   ['What about Cisco phones?', 'They are named "SEP" plus MAC and resolved by rule 200 through the MAC. 415 would find them by name too, but 200 runs first.']]);

ruleSection('420', 'USEM Management Interface Match',
  'Server management controllers (iLO, ILOM, iDRAC, IMM, CIMC, BMC, IPMI) are scanned under their own DNS label, the server name plus a suffix. Their findings belong to the server, so the rule strips the suffix and matches the server by name across the Hardware tree.',
  'Source field DNS. It needs a label with a hyphen, and either a listed suffix as the last segment or a controller product in the OS text.',
  [['Prepare.', '"tx6dd630001-ilo" is the label; dash is the position of the last hyphen; tail is "ilo".'],
   ['Recognise the controller.', 'Two inline lists: suffixes (the last segment itself: ilo, ilom, idrac, drac, ipmi, bmc, oob, mgmt, imm, cimc, rmm, con) and markers in the OS text (ilo, ilom, idrac, drac, remote access controller, imm, cimc, bmc, ipmi, lights out). A listed suffix gives the base name at once; otherwise a controller OS allows the last segment to be stripped whatever it is. Neither: null.'],
   ['The server by name.', 'cmdb_ci_hardware searched for name = base ("tx6dd630001"), ignored classes left out; exactly one row.'],
   ['Not a balancer.', 'A last check refuses a Load Balancer device, since a balancer’s management label must not hand the balancer’s findings to a server namesake.']],
  ['the label has no hyphen, or the tail is not a listed suffix and the OS is not a controller;', 'no hardware CI, or two, carry the base name;', 'the CI found is a load balancer.'],
  [['Why does a listed suffix suffice even when the OS is ordinary Linux?', 'Because the client names controllers that way consistently, and Qualys often fingerprints a controller as a generic embedded Linux. The suffix is the stronger sign. The reverse case, a controller OS with an unlisted tail, is also covered.'],
   ['Is a hyphenated server name such as "ah-1047132-001" at risk?', 'No. Its last segment "001" is not a listed suffix and its OS is not a controller, so the rule returns null and the name rules handle it.'],
   ['Why not search the class of the OS?', 'A controller reports its own firmware, not the server OS, so there is no class to derive. The Hardware tree with an exactly-one check is the right scope.'],
   ['How is a new suffix added?', 'One entry in the suffixes array at the top of the stage, on the rule record.']]);

ruleSection('430', 'USEM Network Interface Name Match',
  'Network devices are scanned through their interface and VLAN addresses, each with a DNS label made of the device name plus an interface tail, while the device CI is named with the leading part only. The rule walks the label from the longest prefix to the shortest and takes the first prefix that names exactly one network device or load balancer device.',
  'Source field DNS. It needs a hyphenated label and an interface sign: the name sits in the .network. domain, or one of the tail segments is a listed interface marker.',
  [['Prepare.', 'The label splits on hyphens: ["uspaltwrr01drm0119", "cz04", "hsrp", "vlan705"].'],
   ['Interface sign.', 'Domains list [".network."] and markers list [vlan, v, hsrp, vrrp, po, eth, gi, te, lo, mgmt, aom, vs, fab], checked with isMarker() on every segment after the first. The sample has both the domain and "hsrp" and "vlan705".'],
   ['Walk the prefixes.', 'k runs from segments.length - 1 down to 1, so the prefixes tried are "uspaltwrr01drm0119-cz04-hsrp", then "uspaltwrr01drm0119-cz04", then "uspaltwrr01drm0119". Each prefix is searched in cmdb_ci_netgear and cmdb_ci_lb; hits collects at most two sys_ids across both tables.'],
   ['Decide per prefix.', 'No hit: try the shorter prefix. Two hits: the name is shared, return null at once. One hit: return it. The sample reaches the shortest prefix and finds the IP Switch.']],
  ['there is no hyphen or no interface sign;', 'no prefix names a device;', 'the first prefix that names anything names two devices.'],
  [['Why longest prefix first?', 'Device names can themselves contain hyphens ("usa-oh-wvs-altair-02"), so the shorter prefixes are only tried when the longer ones name nothing. Trying short first would cut a hyphenated device name in half.'],
   ['Why only network gear and balancers?', 'Because interface labels belong to network devices. A server named like a prefix ("gtcmmrlpa05a" for "gtcmmrlpa05a-vlan10") is not returned; that case was tested and stays unmatched, which is right.'],
   ['Why stop on two hits rather than try a shorter prefix?', 'A shared name at one length means the label is ambiguous at that level; a shorter prefix would be a broader guess, not a better one.'],
   ['On the client instance this rule reads the IP field. What does that do?', 'It kills the rule: the script expects a DNS name in sourceValue, finds no hyphen and returns null for every host. The source field has to be set back to DNS. In the run outputs it matched none of two thousand items for that reason.']]);

ruleSection('450', 'USEM FQDN Name Hardware Match',
  'Some loads name the CI with the whole FQDN string instead of the short host name; the appliance domains ending in .rpg are the usual case. The rule compares the complete scanned name with the name field across the Hardware tree.',
  'Source field DNS. It needs a value with at least one dot; a bare label is left to the host name rules.',
  [['Prepare.', 'The whole value, lower-cased: "lva40bneehcs01.ecomm.devicenp.rpg".'],
   ['Search the Hardware tree.', 'name = fqdn on cmdb_ci_hardware, ignored classes left out.'],
   ['Exactly one.', 'First row, hasNext() check, return.']],
  ['the value has no dot;', 'no hardware CI, or two, are named with the full FQDN.'],
  [['Why is this after 410 when it reads the same field?', 'Because a CI named with a short host name is the common case and must win first; a CI named with the full FQDN is the exception, and searching it later costs nothing when the earlier rules matched.'],
   ['What is the difference from 250 FQDN Class Match?', '250 and 260 compare the scanned name with the fqdn field of the CI. 450 compares it with the name field, for records whose name is the FQDN and whose fqdn field is empty.'],
   ['The client instance runs a longer script under this name. Is that a problem?', 'It is a different version, about twice the delivered size. The delivered one is on the record here; the two have to be compared before the client copy is trusted.']]);
ruleSection('455', 'USEM Load Balancer Member Match',
  'The one real server behind a virtual server. For a host that shows a virtual IP sign the rule finds the Load Balancer Service record the way 460 does, then walks the platform’s load balancer model, Service to Pool to Pool Member to server, and returns the server only when exactly one sits behind the virtual server. With several servers, or without pool data, it declines and 460 attaches the virtual server record.',
  'Source field IP. It needs a VIP sign (a load balancer product in the OS text, or a VIP marker segment in the label), one service record, at least one pool and at least one member.',
  [['Prepare.', 'The address, the lower-cased DNS name and its label, the lower-cased OS text.'],
   ['VIP sign.', 'osMarkers [f5, big-ip, big ip, netscaler] against the OS text and labelMarkers [vip, vs] against the label segments through isMarker(). No sign, no walk.'],
   ['The one virtual server.', 'one(field, value) searches cmdb_ci_lb_service and returns the sys_id, undefined (nothing, try the next step) or null (two, stop). The steps are fqdn = DNS, name = DNS, name = label, ip_address = IP. The sample is found at the first step.'],
   ['The pool.', 'Three ways, because a bulk load may fill reference fields or relationships: the pool field on the service, pools whose service field points at the service, and pools related to the service through cmdb_rel_ci in either direction (related() checks that the other end is in the pool table). No pool: null.'],
   ['The members.', 'Members whose pool field is one of the pools, plus members related to a pool; each kept with its address, an empty address kept as an empty string so that no address search runs for it.'],
   ['The real servers.', 'For every member: its address searched on device records (cmdb_ci_hardware.ip_address), on network adapters and on IP Address records; and every hardware CI related to the member. isRealServer() keeps only Hardware-tree records that are neither a balancer nor of an ignored class. Distinct servers are counted: exactly one is returned; the sample finds "usvacrispweb01" alone.']],
  ['no VIP sign;', 'no service, or two services, for the scanned name or address;', 'no pool, no member, no server;', 'two or more distinct servers (a shared pool, or one member address on two device records).'],
  [['Why exactly one and not the whole pool?', 'A discovered item carries one CI. A pool of three servers cannot be given to all three by a lookup rule, and giving it to one would be wrong twice out of three. One finding per member would need the feed to produce one item per member, which it does not. So the single-server virtual server goes to its server and the shared pool stays on the virtual server record; any other policy for shared pools is separate work outside the rules.'],
   ['What happens on the client instance today, where no pool records were seen?', 'The rule declines at the pool stage and 460 attaches the virtual server record, exactly as before. Nothing changes until the pool model is loaded. The read-only probe script shows for any virtual address which of the hops exist.'],
   ['Why read relationships as well as reference fields?', 'The platform’s own discovery fills the reference fields; a bulk load from the network data collection feed may fill only relationships, or only the fields. Reading both means the rule works whichever way the mapping arrives.'],
   ['Could the rule return the load balancer itself?', 'No. isRealServer() refuses the Load Balancer class, so a member that points at the balancer’s own address is not counted; the tested case declined and the virtual server record was attached.'],
   ['Cost?', 'One rule run per host with a VIP sign only; on hosts without a sign it returns after two string checks. In the sweep of six thousand client items it added a millisecond per item.']],
  { keep: [] });

ruleSection('460', 'USEM Load Balancer Service Match',
  'A virtual IP answered by a load balancer is not the balancer, and the hardware rules refuse the balancer device on purpose. Such hosts belong to the Load Balancer Service CI that models the virtual server, and this rule finds it. It runs on the IP field so that virtual servers without a DNS name are covered too.',
  'Source field IP. It needs a VIP sign; without one it returns null before any query, so an ordinary server sharing an address with a virtual IP is never turned into a service.',
  [['Prepare.', 'The address, the DNS name and its label, the OS text.'],
   ['VIP sign.', 'The same two inline lists as 455. "f5 big ip" contains "f5"; "rbps-dev3-sve-vip.ecommnp.rpg" with a Linux fingerprint qualifies through the segment "vip"; "ah-1047132-001" with Red Hat has neither.'],
   ['The one service.', 'one() tries fqdn = DNS, then name = DNS, then name = label, then ip_address = IP on cmdb_ci_lb_service. Each step accepts exactly one service; a step that finds two ends the rule with null, because a weaker step could otherwise pick a different service; a step that finds nothing hands over to the next. The sample is found at the first step by fqdn.']],
  ['no VIP sign;', 'no service carries the name or the address;', 'two services carry the value at any step.'],
  [['Why match the service and not the real server?', 'Because the service record is the virtual IP and the findings scanned on it describe the front door: the certificate, the TLS settings, the ports the virtual server exposes. Where the CMDB shows exactly one real server behind it, 455 now hands the finding to that server first.'],
   ['Why does a step that finds two stop the rule instead of trying the next step?', 'A weaker step (the label, then the address) could pick one of the two services or a third one; that would be a guess dressed up as a match.'],
   ['A server with a Linux fingerprint named "something-vip": is it treated as a VIP?', 'Yes, the label segment "vip" is a sign, and the rule then looks for a service record named or addressed that way. If none exists it declines and the host goes on to the address rules, where the name check and the balancer refusal still apply.'],
   ['NetScaler, Avi, other products?', 'The OS markers list carries f5, big-ip, big ip and netscaler; another product is one entry in that array on the rule record, in both 455 and 460.']]);

ruleSection('700', 'USEM IP Class Match',
  'The first address rule. An address is the least trustworthy identifier the feed gives: addresses move between machines and are shared by load balancers. It is used only for hosts that no serial and no usable name resolved, inside the class the scanned OS points at, only when exactly one CI of that class carries it, and only when the CI name agrees with the scanned name.',
  'Source field IP. It needs an address that is not loopback or link-local and a class from the OS; the DNS name is read for the name check only.',
  [['Prepare.', 'The address "30.162.178.21"; 127.x and 169.254.x identify nothing and end the rule.'],
   ['Class from the OS.', 'classFor("VMware ESXi 7.0.3 build 24723872") gives cmdb_ci_esx_server; no class, no search.'],
   ['Search inside the class.', 'ip_address = ip on the class table, ignored classes left out; exactly one row, otherwise null.'],
   ['The CI must carry the scanned name.', 'nameAgrees(match): the sample carries no DNS, so nothing is checked and "vsdnesxm21" is returned. A host scanned as "vk1660790" whose address leads to a CI named "vk1448212" is declined: the address has been reused.']],
  ['loopback or link-local address, or no class from the OS;', 'no CI of the class carries the address, or two do;', 'the CI is named after another machine while the scan carries a name.'],
  [['Why is the class check enough here, without the balancer check?', 'A Load Balancer device is in the Server branch; a search on ESX Server, Windows Server, Linux Server or Computer never returns one. The only class search that could include balancers is Server itself, which classFor never returns.'],
   ['Why add the name check to an address rule?', 'The one wrong match in the client run outputs: a Windows 11 host on an address that a retired virtual machine of another name once held. The address rules now insist that, when the scan carries a name, the CI found carries it too (allowing an interface tail). Where the scan has no DNS, as for the sample, nothing changes.'],
   ['How many hosts reach the address rules?', 'In the client outputs, about one matched host in ten came through 700 or 730; those are hosts without a usable name. The name check only affects the ones that do carry a name.']]);

ruleSection('705', 'USEM IP Hardware Match',
  'The address across the whole Hardware tree, with the extra safety checks that the wide scope needs: the CI must not be a load balancer, it must carry the scanned name when the scan has one, and its class must not contradict the scanned OS.',
  'Source field IP. It needs an address; a class from the OS is optional and used only as the check at the end.',
  [['Prepare.', 'The address "30.162.178.24"; the multi-guess OS gives no class, so pref is empty.'],
   ['Search the Hardware tree.', 'ip_address = ip on cmdb_ci_hardware, ignored classes left out.'],
   ['Exactly one.', 'The first row is kept with its class; a second row is a shared virtual IP or a reused address and the rule declines.'],
   ['Reject a load balancer.', 'isLoadBalancer(id): the address is then a virtual IP and the findings describe a pool member behind it.'],
   ['The CI must carry the scanned name.', 'nameAgrees(id), as in 700.'],
   ['Reject a contradicting class.', 'agrees(cls) without the appliance clause: a Windows Server on the address of a Linux scan is a namesake; the sample has no class, so the plain Server is returned.']],
  ['the address is on no hardware CI or on two;', 'the one CI is a load balancer;', 'its name differs from the scanned name;', 'its class contradicts the OS.'],
  [['Why no appliance clause here when 410 has one?', 'In 410 the switch carries the scanned name, which is strong; here the only link is the address. An address alone on an appliance is not enough to attribute a Linux-fingerprinted scan to it, so the strict check stays.'],
   ['Order of the checks: why the balancer before the name and the class?', 'Cheapest and most decisive first. A balancer is refused whatever its name or class; the name check needs one extra read; the class check walks the table hierarchy.'],
   ['An address on a live server and on a retired one. What happens?', 'Two rows, decline. Retired records stay candidates, so the rule cannot break the tie by status; the client run outputs show several such addresses and they stay unmatched.']]);

ruleSection('730', 'USEM IP Adapter Match',
  'Discovery stores one Network Adapter record per network card, and a multi-homed server keeps its addresses there rather than on the CI record. This rule finds the adapter carrying the scanned address and takes its owning CI.',
  'Source field IP. It needs an address; the class from the OS and the DNS name are used as checks.',
  [['Prepare.', 'The address "30.162.178.22"; pref is empty for the multi-guess sample.'],
   ['Adapters carrying the address.', 'cmdb_ci_network_adapter with ip_address = ip and a non-empty cmdb_ci, the owner outside the ignored classes.'],
   ['One owner, class agreeing, not a balancer, named as scanned.', 'Owners whose class contradicts the OS are skipped as they are read; each remaining owner is counted once, so one server with two adapters on the address counts once and two servers count twice. One owner is accepted when it is not a load balancer and nameAgrees() holds. The sample has one adapter, one owner, no DNS: the Server is returned.']],
  ['no adapter carries the address, or adapters of two different CIs do;', 'the single owner is a load balancer, or is named after another machine, or (through the skip) contradicts the OS.'],
  [['Why skip contradicting owners instead of refusing at the end like 705?', 'Adapter records are discovery data and a stale one can point at the wrong kind of machine. Skipping it lets the rule still accept the remaining owner when exactly one agreeing owner is left, which the single-row logic of 705 cannot do.'],
   ['What is the difference between 730 and 740?', '730 reads the address written on the adapter record itself. 740 reads the IP Address records that newer discovery attaches to the adapter, where the adapter record may carry no address at all. Both end on the same owner field.'],
   ['On the client instance this rule matched about one host in twelve. Is that expected?', 'Yes. Those are hosts without a usable DNS name whose address discovery recorded on an adapter. With the name check the ones that do carry a name are only kept when the owner is named with it.']]);

ruleSection('740', 'USEM IP Layered Match',
  'Newer discovery writes each address as its own IP Address record linked to the adapter, and the adapter record itself may carry no address. This rule reads those records: IP Address record to Network Adapter to CI.',
  'Source field IP. It needs an address and the layered tables installed; the class and the DNS name are checks.',
  [['Prepare.', 'The address "30.162.178.23".'],
   ['IP Address records carrying the address.', 'cmdb_ci_ip_address with ip_address = ip and nic.cmdb_ci not empty; the dot-walk nic.cmdb_ci reaches the owning CI two links away; ignored classes left out.'],
   ['One owner, class agreeing, not a balancer, named as scanned.', 'The same counting as 730 on ipGr.nic.cmdb_ci: skip contradicting owners, count distinct owners, accept the single one when it is not a balancer and carries the scanned name.']],
  ['no IP Address record carries the address, or records of two different owners do;', 'the single owner is a load balancer, named after another machine, or contradicting the OS.'],
  [['isValid() at the top: why?', 'The layered IP Address table exists only where the newer discovery model is installed; on an instance without it the rule declines cleanly instead of failing.'],
   ['This rule produced the one wrong match in the client outputs. How was it fixed?', 'The host "vk1660790" was scanned on an address whose IP Address record belonged to the retired computer "vk1448212". Two things now stop it: the name check, because the owner’s name differs from the scanned name, and on the platform side the retired filter property. The case is part of the replay of the client outputs and declines.']]);

ruleSection('850', 'USEM FQDN Name Broad Match',
  'The one deliberately late, broad fallback: a CI named with the full FQDN anywhere in the CI table, classes outside the Hardware tree included, such as a virtual machine instance or another logical CI. It still insists on a single owner outside the ignored classes.',
  'Source field DNS. It needs a value with a dot. It runs after every address rule, so it only sees hosts that nothing else resolved.',
  [['Prepare.', 'The whole lower-cased value.'],
   ['Search the whole CI table.', 'name = fqdn on cmdb_ci, ignored classes left out.'],
   ['Exactly one.', 'The sample finds the Virtual Machine Instance "lva40bneehcs02.ecomm.devicenp.rpg", which lives outside the Hardware tree and escaped 450.']],
  ['the value has no dot;', 'no CI, or two, carry the full FQDN as their name.'],
  [['Why is such a broad search allowed at all?', 'Because it is last, it requires the complete FQDN as the exact name (not a short label), it needs a single owner, and the ignored classes are left out. A certificate named with an FQDN would be one more row and make the rule decline rather than mislead it.'],
   ['Why not put it before the address rules?', 'An exact FQDN match on a logical CI is weaker than an address on a hardware record with a class and a name check. The address rules run first for that reason; this is the safety net under them.']]);
// ================================================================ PART 3
K.push(new Paragraph({ children: [new PageBreak()] }));
K.push(h1('Part 3  Load balancers end to end'));
K.push(p(t('The architect’s question is really two: how do we keep the balancer device out of findings that are not its own, and how do we get from an address a balancer answers on to the machine the finding is about. The chain answers with four mechanisms that fire at different points; this part follows one virtual server through all of them and then names who gets the finding in every situation.')));

K.push(h2('3.1  The four mechanisms'));
K.push(...numbered([
  [t('The balancer device is never matched by address. ', { bold: true }), t('705 refuses the single CI when it is a Load Balancer; 730 and 740 refuse the single owner when it is one; 420 refuses a balancer found through a controller label. The device is matched only through its own identity: its name (400, 410) or an interface label of its own (430, which searches balancers on purpose), that is, when its management interface is what Qualys scanned.')],
  [t('A virtual server goes to its Load Balancer Service record. ', { bold: true }), t('460 attaches the virtual server object when the host shows a VIP sign and the CMDB holds the service, found by fqdn, name, label or address, exactly one at each step. That record is the virtual IP itself: the right owner for findings on the front door, such as the certificate, the TLS configuration or the exposed ports.')],
  [t('A DNS alias goes to the device whose adapter carries the address. ', { bold: true }), t('350 follows DNS Name record to IP Address record to Network Adapter to CI. It resolves an alias to the real machine that owns the address. It reaches a device only when the address in the chain is written on that device’s own adapter, which a virtual address never is: the virtual address sits on the balancer, not on a pool member. This is the chain described on the call; it is an alias mechanism, not a virtual-to-real translation.')],
  [t('A virtual server with exactly one real server behind it goes to that server. ', { bold: true }), t('455 walks Service to Pool to Pool Member to server through the platform’s load balancer model and returns the server only when it is the single one. With several, or without pool data, it declines and mechanism 2 applies. This is the virtual-to-real translation, and it depends on the pool records or the equivalent relationships being in the CMDB.')]]));

K.push(h2('3.2  One virtual server through the chain'));
K.push(p(t('Take the sample of 455 and 460: IP 171.203.142.26, OS "F5 Big IP", DNS crisp-tx.bankofamerica.com.')));
K.push(table(['Rule', 'What it does with this host', 'Outcome'], [
  ['175, 180', 'no serial in the payload', 'null'],
  ['200', 'the label is not "sep" plus twelve hex characters', 'null'],
  ['250, 260, 300, 310', 'no CI carries the FQDN in its fqdn field or "crisp-tx" with a dns_domain', 'null'],
  ['350', 'no DNS Name record for the name, or the chain ends on the balancer (see 3.5)', 'null (today)'],
  ['400', 'OS "F5 Big IP" gives no class', 'null'],
  ['410', 'no hardware CI named "crisp-tx"', 'null'],
  ['415', 'no phone or scanner named "crisp-tx"', 'null'],
  ['420, 430', 'no hyphen tail, not a controller, not an interface label', 'null'],
  ['450', 'no hardware CI named with the full FQDN', 'null'],
  ['455', 'VIP sign (f5); service "crisp-tx" by fqdn; pool "crisp-tx-pool"; one member 10.10.20.31; Linux Server "usvacrispweb01" on that address', 'the Linux Server, when the pool model exists'],
  ['460', 'VIP sign; service "crisp-tx" by fqdn', 'the Load Balancer Service, when 455 declined'],
  ['700 to 740', 'never reached for this host; had they been, 705 would find the BIG-IP device on the address and refuse it', ''],
], [1300, 6200, 2500]));

K.push(h2('3.3  Who gets the finding'));
K.push(table(['What the CMDB holds for the virtual address', 'Which rule answers', 'The CI on the discovered item'], [
  ['service, pool, one member, one server on the member address', '455', 'the real server'],
  ['service, pool, several members', '460', 'the virtual server record'],
  ['service, pool, one member whose address is on two device records', '460', 'the virtual server record (455 declines on two servers)'],
  ['service, pool whose only member is the balancer', '460', 'the virtual server record (the balancer is never a real server)'],
  ['service only, no pool data', '460', 'the virtual server record'],
  ['no service, only the balancer device on the address', 'none', 'unmatched (705 refuses the balancer); the import creates a placeholder'],
  ['no service, no device, only DNS Name records and placeholders (the pts-zelle-transfer and horizon-vip extracts)', 'none', 'unmatched'],
  ['the balancer’s own management address, scanned under its own name', '400 or 410', 'the balancer device, correctly, for its own findings'],
  ['the balancer’s interface label ("rvcpcz1atmlb01s-vs1")', '430', 'the balancer device'],
], [4600, 1700, 3700]));

K.push(h2('3.4  The model behind mechanism 4'));
K.push(table(['Record', 'Table', 'Fields the rule reads'], [
  ['Load Balancer Service (the virtual server)', 'cmdb_ci_lb_service', 'fqdn, name, ip_address (the four search steps), pool, and relationships to pools'],
  ['Load Balancer Pool', 'cmdb_ci_lb_pool', 'service (back-reference), relationships to the service and to members'],
  ['Load Balancer Pool Member (one real address)', 'cmdb_ci_lb_pool_member', 'pool, ip_address, relationships to hardware'],
  ['the real server', 'any Hardware-tree class except Load Balancer and the ignored classes', 'ip_address, or an adapter or IP Address record carrying the member address, or a relationship from the member'],
], [3300, 2500, 4200], [1]));
K.push(p(t('Every hop is read through the reference fields and through cmdb_rel_ci relationships in either direction, because the platform’s discovery fills the fields while a bulk load from the network data collection feed may fill relationships only. The read-only probe script prints, for a list of virtual addresses, which hops exist and where they break; that is the check to run with the network team’s examples.'), { before: 60 }));

K.push(h2('3.5  The open point'));
K.push(p(t('350 does not refuse a Load Balancer device at the end of its DNS chain, while 705, 730 and 740 do. If discovery ever ties a virtual server’s DNS name to an IP Address record on the balancer’s own interface, 350 would return the balancer device before 455 and 460 get their turn (an F5 fingerprint gives no class, so the class check does not stop it). It is one condition in the last stage of 350, not applied yet; say so if asked, and that it is scheduled once the examples confirm how the virtual servers are modelled.'), { fill: NOTE }));

K.push(h2('3.6  The story for the network team’s examples'));
K.push(p(t('Lori’s matching today attributes virtual-address findings to real servers through a virtual-to-real mapping she receives from the network data collection feed. Patrick has not found that mapping in the CMDB and it is not in the integration agreement. The position to hold: the rules refuse the balancer device by address, attach the virtual server record when it exists, and hand the finding to the real server when the CMDB shows exactly one behind the virtual server. What decides the outcome on their instance is whether the pool model, or the equivalent relationships, is loaded. The examples through the probe script will show it record by record; if the mapping is kept somewhere else, the member rule can be pointed at that place.')));

// ================================================================ PART 4
K.push(new Paragraph({ children: [new PageBreak()] }));
K.push(h1('Part 4  Question bank and demo flow'));
K.push(h2('4.1  Cross-cutting questions'));
[
 ['Why is the order the way it is?', 'Trust. Serial first (a physical identity), then names with the most context (FQDN, host plus domain, the DNS chain), then the plain host name with a class, then the special label shapes (phones and scanners outside the Hardware tree, controllers, interfaces), then the FQDN as a name, then the virtual server rules, then the address rules, and a broad name fallback last before the platform’s own rules. A weaker identifier never pre-empts a stronger one.'],
 ['What happens when two rules could both match?', 'The first one in order wins and the rest are skipped. Every rule is written so that a hit is safe on its own; the order only decides which safe hit is preferred.'],
 ['Why never choose between two candidates?', 'Because the cost of a wrong CI is a finding on the wrong owner, which is worse than an unmatched item that someone reviews. Every rule returns null on two candidates, whatever their status or class.'],
 ['How are retired CIs handled?', 'The rules treat them as candidates, by the client’s design. The platform then drops a retired CI when sn_sec_cmn.filterOutDecommissionedCI is true, which is the default. Whether retired records can be matched is decided by that property on the client instance, not by the rules.'],
 ['Why are there no properties for the suffix and marker lists?', 'By agreement with the client: each rule is self-contained and readable on its record. The lists sit at the top of the stage that uses them, one array each, with a comment saying what to add.'],
 ['Case sensitivity, trailing spaces, upper-case DNS?', 'Values are trimmed and lower-cased in the script; the platform compares string fields case-insensitively; the feed has no upper-case DNS values.'],
 ['IPv6?', 'The address rules compare the scanned string with the stored string; an IPv6 address stored in the same textual form matches, a differently abbreviated one does not. The feed sampled so far is IPv4.'],
 ['Performance?', 'The whole chain costs about thirty to forty milliseconds per host on the test instance, that is more than fifteen hundred hosts a minute; the heaviest rules (350, 415, 730, 740) are two to three milliseconds each. The chain stops at the first hit, so matched hosts are cheaper than unmatched ones.'],
 ['What does "unmatched" mean for the client?', 'No rule found a single safe CI. The import then creates an Unclassed Hardware placeholder named with the FQDN; the item points at it and the state stays unmatched. Most unmatched hosts in the client outputs (well over nine in ten) simply do not exist in the CMDB under any name, base name, FQDN or address.'],
 ['When does a changed rule take effect on existing items?', 'On the next import of the host, or on a reapply of the rules. Existing items are not re-evaluated by the change itself.'],
 ['How do we know the rules are right on the client instance?', 'A read-only assessment script runs on the client instance over recent matched and unmatched items, runs each through the active rules and compares with the CI the item holds, then explains every decline with what the CMDB holds. Over three runs, all but three of two thousand matched items reproduce, and the exceptions were understood and addressed.'],
 ['What was changed on 15 September and why?', 'Two refinements from those outputs: appliances reporting a Linux kernel are accepted by name (350, 410), and the address rules require the CI to carry the scanned name (700, 705, 730, 740). Then two new rules from the incident data: 415 for phones and scanners outside the Hardware tree, 455 for the one real server behind a virtual server.'],
 ['What is still open?', 'The balancer refusal in 350; the storage node labels (a base name on exactly one Storage Server with a node tail), which stay unmatched; the duplicate Cisco Meeting Server records, a CMDB matter; on the client instance, the source field of 430 back to DNS and the version of 450.'],
].forEach(q => K.push(...qa(q[0], q[1])));

K.push(h2('4.2  Suggested flow for the session'));
K.push(...numbered([
  t('Open with the contract and the chain table (Part 1.3 and 1.6): one slide worth of orientation, then everything else is "which stage of which rule".'),
  t('400 and 410 together: the plain host name with a class, then across the Hardware tree with the class agreement; show classFor() and agrees() once, on 410, and refer back to them for every later rule.'),
  t('415 with the phone example: the class hierarchy fact and why the Hardware tree never saw the phones.'),
  t('420 and 430: the two label-shape rules; show the suffix and marker lists on the records.'),
  t('450 and 850 briefly: the full FQDN as a name, Hardware tree first, whole CI table last.'),
  t('Load balancers as one block (Part 3): the four mechanisms, one virtual server through the chain, who gets the finding, the model behind 455, the open point.'),
  t('700 to 740: the address rules and their four checks; end with the name check and the case it fixed.'),
  t('Close with the question bank items on order, duplicates, retired CIs and re-evaluation.'),
]));
K.push(p(t('One habit for the questions: answer with the stage. "That is the exactly-one stage, it returns null on the second row" is better than a general statement, and every rule record shows the stage banner to point at.'), { before: 60 }));

// ================================================================ assemble
const numbering = [{ reference: 'bullets', levels: [{ level: 0, format: LevelFormat.BULLET, text: '•', alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 360, hanging: 240 } } } }] }];
for (let i = 1; i <= numRef; i++) numbering.push({ reference: 'num' + i, levels: [{ level: 0, format: LevelFormat.DECIMAL, text: '%1.', alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 360, hanging: 260 } } } }] });
const doc = new Document({
  styles: { default: { document: { run: { font: FONT, size: SZ } } } },
  numbering: { config: numbering },
  sections: [{ properties: { page: { margin: { top: 1000, bottom: 900, left: 1000, right: 1000 } } },
    footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.RIGHT, children: [t('Qualys CI Lookup Rules, walkthrough preparation   ', { size: 14, color: MUTED }), new TextRun({ children: [PageNumber.CURRENT], font: FONT, size: 14, color: MUTED })] })] }) },
    children: K }]
});
Packer.toBuffer(doc).then(buf => { fs.writeFileSync(__dirname + '/Qualys CI Lookup Rules - Walkthrough Preparation.docx', buf); console.log('written', buf.length, 'bytes'); });
