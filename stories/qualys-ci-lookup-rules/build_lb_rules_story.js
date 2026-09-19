// Rules 455 and 460 explained step by step, in everyday words, for a one-hour read. Code chunks are cut from
// the delivered scripts by line ranges (counted from the "(function process" line, comment-only lines dropped).
const fs = require('fs');
const { Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell, WidthType, BorderStyle, ShadingType,
        AlignmentType, LevelFormat, TableLayoutType, PageNumber, Footer, PageBreak } = require('docx');
const FONT = 'Arial', SZ = 19, MUTED = '555555', HEAD = 'E8EAED', ZEBRA = 'F6F7F8', NOTE = 'FFF6DC', CODE = 'EEF1F5', WORDS = 'EAF4EA', EX = 'EEF3FB';
const HAIR = { style: BorderStyle.SINGLE, size: 4, color: 'C8CCD0' };
const t = (text, o) => { o = o || {}; return new TextRun({ text, font: o.mono ? 'Consolas' : FONT, size: o.size || SZ, bold: o.bold, italics: o.italics, color: o.color }); };
const p = (runs, o) => { o = o || {}; return new Paragraph({ children: Array.isArray(runs) ? runs : [runs], spacing: { before: o.before || 0, after: o.after == null ? 80 : o.after, line: o.line || 260 }, alignment: o.align, shading: o.fill ? { type: ShadingType.CLEAR, fill: o.fill } : undefined, keepNext: o.keepNext, indent: o.indent ? { left: o.indent } : undefined }); };
const h1 = (text) => new Paragraph({ children: [t(text, { bold: true, size: 28 })], spacing: { before: 300, after: 90, line: 260 }, border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: '9AA0A6', space: 2 } }, keepNext: true });
const h2 = (text) => new Paragraph({ children: [t(text, { bold: true, size: 23 })], spacing: { before: 220, after: 70, line: 260 }, keepNext: true });
const b = (runs) => new Paragraph({ children: Array.isArray(runs) ? runs : [runs], numbering: { reference: 'bullets', level: 0 }, spacing: { after: 50, line: 260 } });
const codeBlock = (text) => { const ls = text.split('\n'); return ls.map((l, i) => new Paragraph({ children: [t(l || ' ', { mono: true, size: 15 })], spacing: { before: i == 0 ? 60 : 0, after: i == ls.length - 1 ? 60 : 0, line: 220 }, shading: { type: ShadingType.CLEAR, fill: CODE }, indent: { left: 160 }, keepNext: true })); };
const words = (text) => p([t('In everyday words. ', { bold: true }), t(text)], { fill: WORDS, indent: 160 });
const example = (text) => p([t('For our example host. ', { bold: true }), t(text)], { fill: EX, indent: 160 });
const stops = (text) => p([t('It stops here when: ', { bold: true, color: MUTED }), t(text, { color: MUTED })], { indent: 160, after: 120 });
const cell = (children, w, fill) => new TableCell({ children, width: { size: w, type: WidthType.DXA }, shading: fill ? { type: ShadingType.CLEAR, fill } : undefined, margins: { top: 40, bottom: 40, left: 90, right: 90 } });
function table(headers, rows, widths) {
  const mk = (r, fill, bold) => new TableRow({ cantSplit: true, children: r.map((c, i) => cell([p(t(String(c), { bold, size: 17 }), { after: 0, line: 230 })], widths[i], fill)) });
  return new Table({ rows: [mk(headers, HEAD, true)].concat(rows.map((r, i) => mk(r, i % 2 ? ZEBRA : undefined, false))),
    width: { size: widths.reduce((a, c) => a + c, 0), type: WidthType.DXA }, columnWidths: widths, layout: TableLayoutType.FIXED,
    borders: { top: HAIR, bottom: HAIR, left: HAIR, right: HAIR, insideHorizontal: HAIR, insideVertical: HAIR } });
}
const SRC = {};
for (const f of fs.readdirSync(__dirname + '/rules')) { const m = f.match(/^(\d+)_/); if (m) { let s = fs.readFileSync(__dirname + '/rules/' + f, 'utf8'); SRC[m[1]] = s.slice(s.indexOf('(function process')).split('\n'); } }
const chunk = (order, from, to) => SRC[order].slice(from - 1, to).filter(l => l.trim() && !l.trim().startsWith('//')).join('\n');
const step = (title, code, everyday, forExample, stopsWhen) => { K.push(h2(title)); K.push(...codeBlock(code)); K.push(words(everyday)); K.push(example(forExample)); if (stopsWhen) K.push(stops(stopsWhen)); };
const K = [];

K.push(p(t('Rules 455 and 460, Step by Step', { bold: true, size: 34 }), { after: 20 }));
K.push(p(t('The two load balancer rules explained as the questions they ask, in everyday words, with one example host followed all the way through', { color: MUTED, size: 20 }), { after: 140 }));
K.push(table(['Part', 'Minutes', 'What it covers'], [
  ['A  Before the code', '10', 'the situation, the example host, the CMDB records, what each rule answers, how a rule script works'],
  ['B  Rule 460 in seven steps', '15', 'the service rule: does this host look like a virtual IP, and which front-door record is it'],
  ['C  Rule 455 in twelve steps', '25', 'the member rule: the same start, then front door to pool to room list to the real server'],
  ['D  Two hosts end to end', '7', 'the example host, then a host with no pool data'],
  ['E  Questions in one line each', '3', 'the answers to keep ready'],
], [2600, 1000, 6400]));

// ================================================================ A
K.push(h1('A  Before the code'));
K.push(h2('A.1  The situation'));
K.push(p(t('Qualys scans an address and reports what answered there. Sometimes that address does not belong to a server at all: it is a virtual address on a load balancer. Think of a hotel reception desk. Visitors call one number, the desk; behind the desk there is a list of rooms, and in each room a real machine does the work. A finding scanned on the desk number is really about a room, or about the desk itself.')));
K.push(p(t('The CMDB can describe this arrangement with four kinds of records:')));
K.push(table(['Everyday name', 'CMDB record', 'What it holds'], [
  ['the desk (the virtual server)', 'Load Balancer Service', 'the desk’s address and name, and a link to its room list'],
  ['the room list (the pool)', 'Load Balancer Pool', 'a link back to the desk'],
  ['one room number (a pool member)', 'Load Balancer Pool Member', 'a link to the room list and the real address of one room'],
  ['the room (the real server)', 'a server record', 'the same real address, on the record, on a network card, or on an address record'],
  ['the desk hardware (the balancer device)', 'Load Balancer device, F5 BIG-IP', 'the desk’s address too; never the answer of these two rules'],
], [3000, 2900, 4100]));
K.push(p(t('Rule 460 answers the question "which desk is this?" and returns the desk record. Rule 455 answers "is there exactly one room behind this desk, and which server is it?" and returns the room. 455 runs first, because the room is the more precise answer; when it finds no single room it steps aside and 460 returns the desk.'), { before: 80 }));

K.push(h2('A.2  The example host and what the CMDB holds for it'));
K.push(p(t('One Qualys host record is used throughout. It says: the scanned address is 171.203.142.26, the name Qualys resolved for it is crisp-tx.bankofamerica.com, and the thing that answered identified itself as "F5 Big IP".')));
K.push(...codeBlock('{"ID": "1202267231", "IP": "171.203.142.26", "TRACKING_METHOD": "IP", "OS": "F5 Big IP", "DNS": "crisp-tx.bankofamerica.com"}'));
K.push(p(t('The CMDB holds, for this host:')));
K.push(b(t('a Load Balancer Service named crisp-tx, with fqdn crisp-tx.bankofamerica.com, address 171.203.142.26 and port 443, whose pool field points at the pool crisp-tx-pool;')));
K.push(b(t('the pool crisp-tx-pool, whose service field points back at crisp-tx;')));
K.push(b(t('one pool member, named crisp-tx-pool_10.10.20.31_443, whose pool field points at crisp-tx-pool and whose address is 10.10.20.31;')));
K.push(b(t('a Linux Server named usvacrispweb01 whose address field holds 10.10.20.31;')));
K.push(b(t('the balancer device rvcpcz1atmlb01s, an F5 BIG-IP, whose address field also holds 171.203.142.26;')));
K.push(b(t('no relationship records between any of these.')));
K.push(p(t('Expected outcome: 455 returns the Linux Server usvacrispweb01. If 455 had stepped aside, 460 would return the service crisp-tx.'), { fill: NOTE }));

K.push(h2('A.3  How a rule script works'));
K.push(p(t('The platform runs the script once per host, handing it the host record. The script asks a series of questions in order. Whenever a question settles the matter, the script answers and stops: "return null" means "this is not my case, let the next rule try", and "return" followed by a record identifier means "this is the CI". While it works, the script writes values down under short names (ip, dns, label, os, and so on) so that later questions can use them. That is all a variable is: a labelled note.')));
K.push(p(t('The scripts also define small helpers, named blocks of instructions that are written once and used several times, such as "is this word a marker?" or "look for one service record". A helper is like a recipe card: writing it down does nothing; using it later does the work.')));
K.push(p(t('The few symbols you will meet:'), { keepNext: true }));
K.push(table(['Symbol', 'Read it as'], [
  ['if (...)', 'only when the thing in brackets is true, do the next line'],
  ['!', 'not'],
  ['||  and  &&', 'or  and  and'],
  ['==  and  !=', 'is the same as  and  is different from'],
  ['x || \'\'', 'x, or an empty text when x is empty'],
  ['return null', 'stop: not my case'],
  ['return something', 'stop: this is the answer'],
  ['for (...) { ... }  and  while (...) { ... }', 'repeat the lines between the braces, once per item or once per row'],
  ['new GlideRecord(\'table\')', 'prepare a question for that table of the CMDB'],
  ['addQuery, query, next, hasNext', 'add a condition; ask; take the next row; is there another row'],
  ['getValue(\'field\')  and  getUniqueValue()', 'the value of a field on the current row; the identifier of the current row'],
], [3800, 6200]));

// ================================================================ B
K.push(new Paragraph({ children: [new PageBreak()] }));
K.push(h1('B  Rule 460, USEM Load Balancer Service Match, in seven steps'));
K.push(p(t('The rule runs on the scanned address. It first makes sure the host really looks like a virtual IP, then looks for the one service record that matches, trying four clues in turn.')));

step('Step 1  Take the scanned address, and give up on addresses that mean nothing', chunk('460', 1, 6),
  'The first line opens the script and names the three things the platform hands in: the rule record, the value of the rule’s Source field (the IP, because that is this rule’s Source field) and the whole host record. If the address is missing, the script stops with "not my case". Then it writes the address down as ip, trimmed of any spaces. An address starting with 127. is a machine talking to itself and one starting with 169.254. is an address a machine gives itself when no network gave it one; neither identifies a host, so the script stops for those too.',
  'sourceValue is "171.203.142.26". It is not empty, it does not start with 127. or 169.254., so ip = "171.203.142.26" and the script goes on.',
  'the IP field is empty, or the address is a loopback or a self-assigned one.');

step('Step 2  Take the name, its first part, and the OS text', chunk('460', 7, 9),
  'The script now writes down three more notes from the host record. dns is the DNS name, made lower case and trimmed, or an empty text when the host has no DNS name (that is what "|| \'\'" is for: without it an absent name would turn into the word "null"). label is the part of the name before the first dot, that is, the host label without the domain. os is the OS text in lower case, so that product words can be looked for without caring about capital letters.',
  'dns = "crisp-tx.bankofamerica.com", label = "crisp-tx", os = "f5 big ip".',
  'never; these lines only take notes.');

step('Step 3  Get the list of record classes that must never be returned', chunk('460', 12, 13),
  'The platform keeps a list of technical classes that no lookup rule may return: the placeholder records made for unmatched hosts, DNS Name records, incomplete address records and the staging tables. The script reads that list from the system property, or takes it from the platform when the platform hands it in directly. Every search later adds "and the class is not one of these".',
  'ignore = "sn_sec_cmn_unmatched_ci,sn_vul_qualys_ci,cmdb_ci_unclassed_hardware,cmdb_ci_incomplete_ip,cmdb_ci_dns_name".',
  'never.');

step('Step 4  A helper: is this piece of a name a marker word?', chunk('460', 17, 28),
  'This is a recipe card, not yet used. Given one piece of a hyphenated label and a list of marker words, it says yes in three cases: the piece is the word itself ("vip"); the piece is the word followed only by digits ("vs1", "vlan705"); or, for words of three letters or more, the piece ends with the word ("multihostvip"). Otherwise it says no. The "three letters or more" floor stops the two-letter word "vs" from matching every piece that happens to end in "vs".',
  'not used yet; step 5 uses it on the pieces of "crisp-tx".',
  'never; a helper only answers.');

step('Step 5  Does this host look like a virtual IP at all?', chunk('460', 39, 50),
  'Two short lists sit right here on the rule: product words that a load balancer reports as its OS (f5, big-ip, big ip, netscaler) and words that name a virtual IP inside a DNS label (vip, vs). A flag called evidence starts as false. The script looks for each product word inside the OS text; any hit sets the flag. Then it cuts the label at the hyphens and runs the helper from step 4 on each piece; any hit sets the flag. If the flag is still false the host is an ordinary machine, and the script stops with "not my case". This is what keeps the rule from ever turning a normal server into a desk record just because it shares an address with a desk.',
  'the OS text "f5 big ip" contains "f5", so the flag becomes true. The label "crisp-tx" splits into "crisp" and "tx"; neither is a marker, but the flag is already true. The script goes on.',
  'the OS names no load balancer product and no piece of the label is a VIP word.');

step('Step 6  A helper: look for exactly one service record by one clue', chunk('460', 59, 75),
  'Another recipe card. Given a field name and a value, it asks the Load Balancer Service table for records where that field holds that value, leaving the forbidden classes out. It can answer in three ways. "undefined" means "nothing to see here, try the next clue": either the value was empty (there was nothing to search) or no record has it. "null" means "stop the whole rule": two records carry the value, and the rule never guesses between two; the same answer is given when the service table does not exist on the instance. Otherwise it answers with the identifier of the one record found.',
  'not used yet; step 7 calls it up to four times.',
  'never by itself; step 7 acts on its answers.');

step('Step 7  Try four clues in order and answer', chunk('460', 76, 85),
  'The clues, strongest first: the whole DNS name in the fqdn field; the whole DNS name in the name field; the label in the name field; the scanned address in the address field. The script tries them one by one with the helper from step 6. A "null" from the helper (two records) ends the rule at once with "not my case", because a weaker clue could otherwise pick a different record. A found record is returned at once as the answer. An "undefined" moves on to the next clue. When all four clues are exhausted the rule answers "not my case". The last line simply runs the whole script with the three values the platform provides.',
  'the first clue, fqdn = "crisp-tx.bankofamerica.com", finds the service crisp-tx and no second record. The rule answers with the identifier of crisp-tx and stops. The other three clues are never tried.',
  'two services share the clue, or no clue finds anything.');

K.push(h2('Rule 460 in one paragraph'));
K.push(p(t('Take the address and the name. Make sure the host looks like a virtual IP, by its OS text or by a VIP word in its label. Then look for the one desk record that carries the DNS name, or the label, or the address, in that order, and return it. Never guess between two records. Never return a placeholder. If nothing fits, step aside.'), { fill: NOTE }));

// ================================================================ C
K.push(new Paragraph({ children: [new PageBreak()] }));
K.push(h1('C  Rule 455, USEM Load Balancer Member Match, in twelve steps'));
K.push(p(t('The first five steps are the same as in rule 460, word for word, apart from the name of the flag, which is called sign here. Steps 6 and 7 use the same helper but keep the service record instead of answering with it. Steps 8 to 12 are the walk from the desk to the room.')));

step('Steps 1 to 5  The same start: address, name, OS text, forbidden classes, VIP sign', chunk('455', 1, 16) + '\n' + chunk('455', 44, 55),
  'Exactly what rule 460 does in its steps 1 to 5: take the address (stop on empty, loopback or self-assigned), take the DNS name, the label and the OS text, read the forbidden classes, and check the VIP sign with the same two lists. The helper isMarker, not shown again, is identical. A host without a VIP sign leaves the rule here.',
  'ip = "171.203.142.26", dns = "crisp-tx.bankofamerica.com", label = "crisp-tx", os = "f5 big ip"; the OS text contains "f5", so sign is true and the script goes on.',
  'the address is empty or meaningless, or the host shows no VIP sign.');

step('Steps 6 and 7  Find the one desk record and keep it', chunk('455', 64, 91),
  'The helper one() is the same as in rule 460: for one clue it answers with a record, with "undefined" (nothing, next clue) or with "null" (two records, stop). The difference is in the loop. Rule 460 returned the record as soon as it was found; this rule writes it down under the name service and carries on, because the record is only the starting point of the walk. The loop also stops trying clues as soon as service is set ("&& !service"). A "null" from the helper still ends the whole rule, and so does reaching the end of the clues with nothing found.',
  'the first clue, fqdn, finds crisp-tx. service now holds the identifier of crisp-tx, the loop ends, and the script goes on to the walk.',
  'two services share a clue, or no clue finds a service.');

step('Step 8  Two helpers for the walk: "is this a real server?" and "what is tied to this record?"', chunk('455', 98, 121),
  'Two recipe cards. isRealServer takes a record identifier and says yes only when the record is in the Hardware tree (the family of device classes: servers, computers, network gear, storage), is not of a forbidden class, and is not a load balancer device. The balancer check matters: a desk’s room list could name the balancer itself, and the balancer is never a room. related takes a record identifier and a table name and returns the identifiers of every record tied to it by a relationship, in either direction (the record may be the parent or the child of the relationship), keeping only the ones that belong to the given table. It exists because a bulk load of the load balancer model may express the links as relationships instead of reference fields.',
  'not used yet. Later, isRealServer will say yes for the Linux Server usvacrispweb01 and would say no for the BIG-IP device; related will find nothing, because the example has no relationship records.',
  'never; helpers only answer.');

step('Step 9  From the desk to its room list: find the pool', chunk('455', 130, 147),
  'The script collects pools into a set called pools (a set keeps each identifier once, however many times it is added). Three sources are tried, so that the pool is found whichever way it was loaded: the pool field on the service record; pool records whose service field points back at the service; and pool records tied to the service by a relationship. The set is then turned into a plain list, poolIds. An empty list means the CMDB knows no room list for this desk, and the script stops with "not my case", which lets rule 460 attach the desk record.',
  'the service crisp-tx has crisp-tx-pool in its pool field, so the set gets that pool; the pool record’s service field also points at crisp-tx, which adds the same pool a second time (the set keeps it once); no relationship adds anything. poolIds holds one pool. The script goes on.',
  'the desk has no pool at all: no pool field, no pool pointing back, no relationship.');

step('Step 10  From the room list to the room numbers: find the members and their addresses', chunk('455', 156, 176),
  'Members are collected into members, a set that also remembers each member’s address. First the members whose pool field is one of the pools found; then, for each pool, the members tied to it by a relationship, skipping any already collected. The address is written as text, and an empty address is written as an empty text on purpose: turning an empty field into text would give the word "null", and a search for the address "null" would return every device that has no address at all. An empty member list stops the rule.',
  'the member crisp-tx-pool_10.10.20.31_443 has crisp-tx-pool in its pool field, so members holds that one member with the address "10.10.20.31". No relationship adds a member. The script goes on.',
  'the pool has no members.');

step('Step 11  From the room numbers to the rooms: find the real servers', chunk('455', 189, 220),
  'servers is a set of real servers, filled through the small helper keep, which only admits an identifier that passes isRealServer. For each member: when it has an address, that address is looked for in three places, on device records (the address field of anything in the Hardware tree), on network cards (adapter records that belong to a device), and on address records (IP Address records attached to a network card of a device); every owner found is offered to keep. Whether or not it has an address, the member’s relationships to hardware are followed as well, and those records are offered to keep. Balancer devices, placeholders and anything outside the Hardware tree are turned away at the door.',
  'the member address "10.10.20.31" is on the address field of the Linux Server usvacrispweb01, so that server is kept. No network card and no address record carries the address, and the member has no relationships. servers holds one server.',
  'never by itself; step 12 counts.');

step('Step 12  Count the rooms and answer', chunk('455', 221, 225),
  'The set of servers becomes a list. Exactly one server means the desk fronts one room, and the finding scanned on the desk belongs to it: the script answers with that server. Zero servers (the room numbers led nowhere) or two or more (a shared pool, or one address carried by two device records) mean the script cannot pick one, so it answers "not my case" and rule 460 attaches the desk record instead. The last line runs the script with the three values from the platform.',
  'one server: the rule answers with the Linux Server usvacrispweb01. That is the CI the discovered item receives.',
  'no server, or two or more servers, sit behind the desk.');

K.push(h2('Rule 455 in one paragraph'));
K.push(p(t('Start exactly like rule 460: address, name, OS text, VIP sign, and the one desk record, but keep it instead of answering. Then find the desk’s room list, the room numbers on it, and the rooms those numbers lead to, reading both the reference fields and the relationships, and turning balancer devices and placeholders away. If exactly one room is found, answer with it; otherwise step aside and let rule 460 answer with the desk.'), { fill: NOTE }));
K.push(h2('The two rules side by side'));
K.push(table(['Step', 'Rule 460', 'Rule 455'], [
  ['1  address', 'same', 'same'],
  ['2  name, label, OS text', 'same', 'same'],
  ['3  forbidden classes', 'same', 'same'],
  ['4  marker helper', 'same', 'same'],
  ['5  VIP sign', 'flag named evidence', 'flag named sign'],
  ['6  one-service helper', 'same', 'same'],
  ['7  four clues', 'returns the desk record as the answer', 'keeps the desk record and goes on'],
  ['8 to 12  the walk', 'not present', 'pool, members, real servers, count, answer'],
  ['answer for crisp-tx', 'the desk crisp-tx (only if 455 stepped aside)', 'the Linux Server usvacrispweb01'],
  ['answer with no pool data', 'the desk record', 'steps aside'],
], [2600, 3700, 3700]));
K.push(h2('Why exactly one'));
K.push(p(t('A discovered item carries one CI. A desk that fronts three rooms cannot be handed to all three by a lookup rule, and handing it to one of them would be wrong two times in three. So the rule is strict on purpose: one room, or the desk. Keeping the desk record for shared pools is the safe answer; any other policy for shared pools would be separate work, outside the lookup rules.')));

// ================================================================ D
K.push(new Paragraph({ children: [new PageBreak()] }));
K.push(h1('D  Two hosts end to end'));
K.push(h2('D.1  The example host: crisp-tx'));
K.push(p(t('The platform reaches rule 455 with the host record. The address is fine; the name, label and OS text are noted; the OS text "f5 big ip" says this is a virtual IP. The first clue, the fqdn, finds the desk record crisp-tx, and only that one. The desk’s pool field names the room list crisp-tx-pool. That list has one room number, 10.10.20.31. The address 10.10.20.31 is on the record of the Linux Server usvacrispweb01, which is a real server and not a balancer. One room: rule 455 answers with usvacrispweb01, the chain stops, and the discovered item is linked to that Linux Server. Rule 460 never runs for this host.')));
K.push(h2('D.2  A host whose desk has no room list: rbps-dev3-sve-vip'));
K.push(p(t('The host record says: address 164.91.236.18, OS text "Linux 2.6", DNS name rbps-dev3-sve-vip.ecommnp.rpg. The CMDB holds a Load Balancer Service named rbps-dev3-sve-vip with that address and an empty fqdn field, and nothing else: no pool, no members, no relationships.')));
K.push(p(t('Rule 455: the address is fine. The OS text names no product, but the label rbps-dev3-sve-vip splits into rbps, dev3, sve and vip, and vip is a VIP word, so the sign is true. The fqdn clue finds nothing (the field is empty on the record), the whole-name clue finds nothing (the record is named rbps-dev3-sve-vip, not the full DNS name), the label clue finds the desk record. Then the walk: no pool field, no pool points back, no relationship. The pool list is empty and rule 455 steps aside.')));
K.push(p(t('Rule 460: the same address, name and sign; the same three clues; the label clue finds the desk record and rule 460 answers with it. The discovered item is linked to the Load Balancer Service rbps-dev3-sve-vip. The day a pool with one member on a real server is loaded for this desk, rule 455 will answer with that server on the next import.')));

// ================================================================ E
K.push(h1('E  Questions in one line each'));
[
 ['Why does 455 run before 460?', 'The room is the more precise answer; the first rule to answer wins, so the precise one must go first.'],
 ['What if the CMDB has no pool records at all?', '455 steps aside at step 9 every time and 460 keeps attaching the desk record; nothing changes until the pool model is loaded.'],
 ['Why not return all the rooms?', 'One item, one CI; the rule refuses to guess among several, so shared pools stay on the desk record.'],
 ['Can either rule return the balancer device?', 'No: 460 searches only the service table, and 455 turns balancer devices away in isRealServer.'],
 ['Why four clues, in that order?', 'From the strongest (the whole DNS name in the fqdn field) to the weakest (the address); a weaker clue never overrides a stronger one that found two records.'],
 ['Why stop the whole rule when a clue finds two records?', 'Because trying a weaker clue afterwards could pick one of the two, or a third record, which is a guess.'],
 ['Why read relationships as well as reference fields?', 'The platform’s discovery fills the fields; a bulk load may fill only relationships; reading both works either way.'],
 ['Why the special care for a member with no address?', 'An empty field turned into text is the word "null", and a search for the address "null" returns every device without an address; the rule keeps it as an empty text instead.'],
 ['What does an ordinary server on a virtual address get?', 'No VIP sign, so neither rule runs; the address rules later refuse the balancer device and check the server’s name and class.'],
 ['How is another load balancer product added?', 'One word in the osMarkers list at step 5, on both rules.'],
].forEach(q => { K.push(p([t(q[0] + '  ', { bold: true }), t(q[1])], { after: 60 })); });

const doc = new Document({
  styles: { default: { document: { run: { font: FONT, size: SZ } } } },
  numbering: { config: [{ reference: 'bullets', levels: [{ level: 0, format: LevelFormat.BULLET, text: '•', alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 360, hanging: 240 } } } }] }] },
  sections: [{ properties: { page: { margin: { top: 1000, bottom: 900, left: 1000, right: 1000 } } },
    footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.RIGHT, children: [t('Rules 455 and 460, step by step   ', { size: 14, color: MUTED }), new TextRun({ children: [PageNumber.CURRENT], font: FONT, size: 14, color: MUTED })] })] }) },
    children: K }]
});
Packer.toBuffer(doc).then(buf => { fs.writeFileSync(__dirname + '/Rules 455 and 460 - Step by Step.docx', buf); console.log('written', buf.length, 'bytes'); });
