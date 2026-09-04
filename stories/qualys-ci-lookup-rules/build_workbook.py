"""Builds 'Qualys CI Lookup Rules - Code Line Explanations.xlsx' from rules/*.js:
an Overview sheet (one row per rule) and one sheet per rule listing every code
line with its explanation, grouped by stage."""
import glob, json, os, re
from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'Qualys CI Lookup Rules - Code Line Explanations.xlsx')
TEXT = Font(name='Arial', size=10)
BOLD = Font(name='Arial', size=10, bold=True)
CODE = Font(name='Courier New', size=9)
HEAD_FILL = PatternFill('solid', fgColor='1F3864'); HEAD_FONT = Font(name='Arial', size=10, bold=True, color='FFFFFF')
STAGE_FILL = PatternFill('solid', fgColor='DDEBF7')
THIN = Side(style='thin', color='BFBFBF'); BORDER = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)
WRAP = Alignment(wrap_text=True, vertical='top')


def parse(path):
    text = open(path).read()
    head, body = text.split('*/', 1)
    hl = [l[3:] if l.startswith('   ') else l for l in head.split('\n')]
    title = next(l for l in hl if l.startswith('RULE '))
    order, name = re.match(r'RULE (\d+) - (.*)', title).groups()
    # header paragraphs
    paras, cur = [], []
    for l in hl[3:]:
        if l.strip() == '':
            if cur: paras.append(' '.join(x.strip() for x in cur)); cur = []
        else:
            cur.append(l)
    if cur: paras.append(' '.join(x.strip() for x in cur))
    purpose = paras[0]
    payload = re.search(r'\{.*?\n   \}', head, re.S).group(0)
    payload = '\n'.join(l[3:] if l.startswith('   ') else l for l in payload.split('\n'))
    field = re.search(r'sourceValue\s+= the (\S+) field', head).group(1)
    expected = re.search(r'Expected for the sample: (.*?)\n\n', head, re.S).group(1)
    expected = ' '.join(x.strip() for x in expected.split('\n'))
    def bullet(lab):
        m = re.search(r'- %s\s*: (.*?)(?=\n   - |\n   =)' % lab, head, re.S)
        return ' '.join(x.strip() for x in m.group(1).split('\n'))
    before, reaches, after = bullet('Before it'), bullet('Reaches it'), bullet('After it')
    # body rows
    rows, pending, stage, i = [], [], '', 0
    lines = body.split('\n')
    while i < len(lines):
        l = lines[i]; s = l.strip()
        m = re.match(r'// ={6} STAGE (\d+): (.*?) =+$', s)
        if m:
            stage = 'Stage %s: %s' % m.groups()
            parts, i = [], i + 1
            while not re.match(r'// =+$', lines[i].strip()):
                t = lines[i].strip()[3:]
                lm = re.match(r'(What|Why|Sample)\s*: (.*)', t)
                if lm: parts.append([lm.group(1), lm.group(2)])
                else: parts[-1][1] += ' ' + t.strip()
                i += 1
            rows.append(('stage', stage, '\n'.join('%s: %s' % (a, b) for a, b in parts)))
            pending = []; i += 1; continue
        if s.startswith('// ->'):
            t = s[5:].strip(); i += 1
            while i < len(lines) and re.match(r'//\s{3,}\S', lines[i].strip()) and not lines[i].strip().startswith('// ->'):
                t += ' ' + lines[i].strip()[2:].strip(); i += 1
            if rows and rows[-1][0] == 'code':
                k, c, e = rows[-1]; rows[-1] = (k, c, (e + '\n' if e else '') + 'Result: ' + t)
            continue
        if s.startswith('//'):
            pending.append(s[2:].strip()); i += 1; continue
        if s == '':
            i += 1; continue
        code, trail = l, ''
        tm = re.search(r'\s*// (.*)$', l)
        if tm: code, trail = l[:tm.start()], tm.group(1)
        expl = ' '.join(pending)
        if trail: expl = (expl + '\n' if expl else '') + trail
        cs = code.strip()
        if rows and rows[-1][0] == 'code' and continues(rows[-1][1], cs):
            k, c, e = rows[-1]; rows[-1] = (k, c + '\n' + code.rstrip(), (e + '\n' + expl) if (e and expl) else (e or expl))
        else:
            rows.append(('code', code.rstrip(), expl))
        pending = []; i += 1
    out = []
    for k, c, e in rows:
        if k == 'code' and not e:
            e = default_expl(c)
        out.append((k, c, e))
    rows = out
    return dict(order=order, name=name, purpose=purpose, payload=payload, field=field, expected=expected,
                before=before, reaches=reaches, after=after, rows=rows)

CONTROL = re.compile(r'^(if|for|while)\s*\(.*\)$')


def continues(prev_code, cur):
    """True when the physical line cur belongs to the statement started in prev_code."""
    last = prev_code.split('\n')[-1].strip()
    if last.startswith('(function') or cur.startswith('})('):
        return False
    if CONTROL.match(last) and not cur.startswith('}'):
        return True                                   # single-line body of an if/for/while
    if not (last.endswith(';') or last.endswith('{') or last.endswith('}') or CONTROL.match(last)):
        return True                                   # statement not finished (operators, lists)
    return False


DEFAULTS = [
    (r'^\(function process', 'Entry point. The framework calls process(rule, sourceValue, sourcePayload) once per scanned host and uses what it returns: a CI sys_id links the host, null hands the host to the next rule.'),
    (r'^\}\)\(rule', 'Runs the function immediately with the values the framework supplied.'),
    (r'^function classFor', 'Helper: translates the OS text into the CMDB class the CI lives in (see the examples above).'),
    (r"if \(!os\) return ''", 'No OS text -> no class.'),
    (r"var s = \('' \+ os\)\.toLowerCase\(\)", 'Lower-case the OS text so that the key-word checks are case-insensitive.'),
    (r"return 'cmdb_ci_esx_server'", 'OS text contains "esx" (for example "VMware ESXi 7.0.3 build 24723872") -> ESX Server.'),
    (r"'cmdb_ci_win_server' : 'cmdb_ci_computer'", 'OS text contains "windows": with "server" -> Windows Server, otherwise -> Computer (a workstation).'),
    (r"return 'cmdb_ci_aix_server'", 'OS text contains "aix" (for example "AIX 7.3 TL3") -> AIX Server.'),
    (r"return 'cmdb_ci_solaris_server'", 'OS text contains "solaris" or "sunos" -> Solaris Server.'),
    (r"return 'cmdb_ci_hpux_server'", 'OS text contains "hp-ux" -> HPUX Server.'),
    (r"return 'cmdb_ci_storage_server'", 'OS text contains "netapp" or "ontap" -> Storage Server.'),
    (r"return 'cmdb_ci_printer'", 'OS text contains "printer", "laserjet" or "jetdirect" -> Printer.'),
    (r"return 'cmdb_ci_linux_server'", 'OS text contains one of the Linux family words ("red hat", "linux", "centos", "ubuntu", "suse", "debian", "fedora", "euleros", "oracle enterprise", "amazon") -> Linux Server.'),
    (r"return 'cmdb_ci_netgear'", 'OS text contains "nx-os", "catos" or "cisco" -> Network Gear.'),
    (r"^return '';$", 'Nothing matched -> no class preference.'),
    (r'^function isLoadBalancer', 'Helper: true when the CI with this sys_id is a Load Balancer.'),
    (r"var lb = new GlideRecord\('cmdb_ci_lb'\)", 'Search on the Load Balancer class.'),
    (r'return lb\.isValid\(\) && lb\.get\(id\)', 'True only when the class exists and a load balancer with this sys_id is found.'),
    (r'^function pick(Fqdn|Combo)\(table\)', 'Helper: the search-and-decide logic described in the stage banner, run on the table passed in.'),
    (r'^var gr = new GlideRecord\(table\)', 'Search on the table passed in (the class and every class beneath it).'),
    (r'^if \(!gr\.isValid\(\)\)', 'The class is not installed on this instance -> decline rather than fail.'),
    (r"^if \(ignore\)\n\s*\w+\.addQuery\('sys_class_name', 'NOT IN', ignore\)", 'When the ignore list is filled, exclude those classes from the search.'),
    (r"addQuery\('sys_class_name', 'NOT IN', ignore\)", 'When the ignore list is filled, exclude those classes from the search.'),
    (r"addQuery\('cmdb_ci\.sys_class_name', 'NOT IN', ignore\)", 'When the ignore list is filled, exclude adapters whose owning CI is in an ignored class.'),
    (r"addQuery\('nic\.cmdb_ci\.sys_class_name', 'NOT IN', ignore\)", 'When the ignore list is filled, exclude records whose owning CI is in an ignored class.'),
    (r"addQuery\('ip_address\.nic\.cmdb_ci\.sys_class_name', 'NOT IN', ignore\)", 'When the ignore list is filled, exclude chains that end on an ignored class.'),
    (r'^\w+\.query\(\);$', 'Runs the search.'),
    (r"^gr\.addQuery\('serial_number', serial\)", 'Condition: serial_number equals the cleaned serial (exact match).'),
    (r"^gr\.addQuery\('name', host\)", 'Condition: name equals the short hostname (CMDB names compare case-insensitively).'),
    (r"^gr\.addQuery\('name', fqdn\)", 'Condition: name equals the complete DNS name.'),
    (r"^gr\.addQuery\('ip_address', ip\)", 'Condition: ip_address equals the scanned address.'),
    (r"^gr\.addQuery\('fqdn', fqdn\)", 'Condition: fqdn equals the scanned DNS name.'),
    (r"^nic\.addQuery\('ip_address', ip\)", 'Condition: the adapter carries the scanned address.'),
    (r"^ipGr\.addQuery\('ip_address', ip\)", 'Condition: the IP Address record holds the scanned address.'),
    (r"^nic\.addQuery\('mac_address', 'IN'", 'Condition: the adapter MAC is one of the four spellings.'),
    (r"^ph\.addQuery\('mac_address', 'IN'", 'Condition: the phone record MAC is one of the four spellings.'),
    (r'^while \(\w+\.next\(\)\) \{', 'Loop over every row of the result.'),
    (r'^ids\.push\(gr\.getUniqueValue\(\)\)', 'Remember the sys_id of this CI.'),
    (r"^if \(ip && gr\.getValue\('ip_address'\) == ip\)", 'When this CI also carries the scanned IP, remember it as an IP-confirmed candidate.'),
    (r'^good\.push\(gr\.getUniqueValue\(\)\)', 'The domain evidence agrees -> remember the sys_id of this CI.'),
    (r'^if \(cifqdn == full', 'Keep the CI only when its own domain information confirms the scanned domain (one of the three tests).'),
    (r'^var phones = \{\}, count = 0, first = null', 'Bookkeeping: the phones already counted, how many, and the first one.'),
    (r'^var owners = \{\}', 'Bookkeeping: the owning CIs already counted.'),
    (r'^var count = 0, first = null', 'How many distinct owners were seen, and the first one.'),
    (r"^var owner = nic\.getValue\('cmdb_ci'\)", 'The CI that owns this adapter.'),
    (r"^var phone = new GlideRecord\('cmdb_ci_ip_phone'\)", 'Prepare a check that the owner is an IP Phone.'),
    (r'^phones\[owner\] = true;', 'Mark this phone as counted.'),
    (r'^owners\[owner\] = true;', 'Mark this CI as counted.'),
    (r'^count\+\+;', 'One more distinct owner.'),
    (r'^if \(count == 1\)\n\s*first = owner', 'Remember the first owner seen.'),
    (r'^if \(count == 1\)\n\s*return first', 'Exactly one owner -> that CI is the match.'),
    (r'^if \(count == 1 && !isLoadBalancer\(first\)\)', 'Exactly one owner and it is not a load balancer -> that CI is the match.'),
    (r'^if \(count > 1\) \{', 'Several owners: try the IP tie-break.'),
    (r'^var confirmed = Object\.keys\(ipOwners\)', 'The owners reached through the scanned IP.'),
    (r'^if \(confirmed\.length == 1\)', 'Exactly one owner confirmed by the address -> that CI is the match.'),
    (r'^ipOwners\[owner\] = true', 'Note that this owner is reached through the scanned IP.'),
    (r'^var byMac = ph\.getUniqueValue\(\)', 'The sys_id of the phone found by MAC.'),
    (r'^if \(ph\.next\(\)\) \{', 'At least one phone carries the MAC on its record.'),
    (r'^if \(!byName\.next\(\)\)', 'No phone with that device name -> decline.'),
    (r'^var named = byName\.getUniqueValue\(\)', 'The sys_id of the phone found by name.'),
    (r'^return named;', 'Exactly one phone -> its sys_id goes back to the framework.'),
    (r'^return null;$', 'Nothing usable -> decline; the next rule gets its turn.'),
    (r'^if \(!gr\.next\(\)\)', 'Empty result -> decline.'),
    (r'^var id = gr\.getUniqueValue\(\)', 'The sys_id of the CI found.'),
    (r'^if \(pref\) \{', 'Only when the OS gave a class preference:'),
    (r'^var chk = new GlideRecord\(pref\)', 'Search on the class the OS implies.'),
    (r'^if \(!\(chk\.isValid\(\) && chk\.get\(id\)\) && !generic\[cls\]\)', 'The CI is neither in the OS-implied class nor generically classed -> contradiction -> decline.'),
    (r'^return id;', 'The CI passed every check -> its sys_id goes back to the framework.'),
    (r'^if \(!m\)', 'The label is not a phone label -> decline.'),
    (r'^var candidates = \[', 'The four spellings of the MAC address.'),
    (r'^var pairs = \[\];', 'Will hold the six two-character pairs of the MAC.'),
    (r'^if \(!host\)', 'Empty hostname (a name starting with a dot) -> decline.'),
    (r'^\}$', ''),
]


EXTRA = [
    (r'^if \(!pref\)', 'The OS gave no class -> decline so that the hardware-wide rule gets its turn.'),
    (r'^if \(serial\.length < 4', 'Too short or a placeholder serial -> decline.'),
    (r"^var ph = new GlideRecord\('cmdb_ci_ip_phone'\)", 'Search on the IP Phone class.'),
    (r"^var byName = new GlideRecord\('cmdb_ci_ip_phone'\)", 'Search on the IP Phone class.'),
    (r"^var gr = new GlideRecord\('cmdb_ip_address_dns_name'\)", 'Search on the IP Address to DNS Name link table.'),
    (r"^var nic = new GlideRecord\('cmdb_ci_network_adapter'\)", 'Search on the Network Adapter table.'),
    (r"^var ipGr = new GlideRecord\('cmdb_ci_ip_address'\)", 'Search on the IP Address table.'),
    (r"^byName\.addQuery\('name', label\.toUpperCase\(\)\)", 'Condition: the phone is named with the SEP device name.'),
    (r'^var hex = m\[1\]', 'The twelve hexadecimal characters captured after "sep".'),
    (r'^for \(var i = 0; i < 12; i \+= 2\)', 'Cut the twelve characters into six pairs.'),
    (r"^var colon = pairs\.join\(':'\)", 'Join the pairs with colons.'),
    (r'^var generic = \{', 'The generically classed CI classes (see the comment above).'),
    (r'^if \(isLoadBalancer\(id\)\)', 'The single owner is a load balancer -> decline.'),
    (r'^var match = gr\.getUniqueValue\(\)', 'The sys_id of the CI found.'),
    (r'^return match;', 'Exactly one CI -> its sys_id goes back to the framework.'),
    (r'^return pick(Fqdn|Combo)\(', 'Run the helper on the chosen table and hand its answer back to the framework.'),
    (r'^var cifqdn = ', "The CI's own fqdn, lower-cased."),
    (r'^var cidom = ', "The CI's own dns_domain, lower-cased."),
    (r'^if \(ids\.length == 1\)', 'One CI carries the FQDN -> match.'),
    (r'^if \(good\.length == 1\)', 'One CI confirmed by name and domain -> match.'),
    (r'^if \(ids\.length > 1 && ipHits\.length == 1\)', 'Several CIs, exactly one confirmed by the scanned IP -> that one.'),
    (r'^if \(good\.length > 1 && ipHits\.length == 1\)', 'Several confirmed CIs, exactly one also carries the scanned IP -> that one.'),
    (r'^ipHits\.push\(gr\.getUniqueValue\(\)\)', 'Remember it as an IP-confirmed candidate.'),
    (r'^var ids = \[\];', 'Will hold every CI carrying the FQDN.'),
    (r'^var good = \[\];', 'Will hold the CIs whose domain evidence agrees.'),
    (r'^var ipHits = \[\];', 'Will hold those of them that also carry the scanned IP.'),
    (r'^var owners = \{\}, ipOwners = \{\};', 'Bookkeeping: the owning CIs already counted, and those reached through the scanned IP.'),
    (r"^var owner = '' \+ ", 'The CI at the end of this chain.'),
    (r'^if \(!owners\[owner\]\) \{', 'First time this CI is seen:'),
    (r"^nic\.addNotNullQuery\('cmdb_ci'\)", 'Condition: the adapter must belong to a CI.'),
    (r"^ipGr\.addNotNullQuery\('nic\.cmdb_ci'\)", 'Condition: the chain must end on a CI.'),
    (r"^gr\.addNotNullQuery\('ip_address\.nic\.cmdb_ci'\)", 'Condition: the chain must end on a CI.'),
    (r'^if \(phone\.get\(owner\) && !phones\[owner\]\) \{', 'Only IP phones count, and each phone only once.'),
    (r'^if \(count == 1\)$', 'Exactly one owner:'),
]
DEFAULTS[-1:-1] = EXTRA


def default_expl(code):
    cs = '\n'.join(l.strip() for l in code.split('\n'))
    for rx, e in DEFAULTS:
        if re.search(rx, cs):
            return e
    return ''


def header_row(ws, cols, widths):
    for j, (h, w) in enumerate(zip(cols, widths), 1):
        c = ws.cell(row=1, column=j, value=h); c.font = HEAD_FONT; c.fill = HEAD_FILL; c.alignment = WRAP; c.border = BORDER
        ws.column_dimensions[get_column_letter(j)].width = w
    ws.freeze_panes = 'A2'


rules = [parse(f) for f in sorted(glob.glob(os.path.join(HERE, 'rules', '*.js')))]
wb = Workbook(); ov = wb.active; ov.title = 'Overview'
header_row(ov, ['Order', 'Rule', 'Source field', 'Purpose', 'Runs before it', 'Which hosts reach it', 'Runs after it', 'Expected result for the sample', 'Sample payload'],
           [8, 30, 14, 55, 40, 40, 40, 50, 50])
for r, x in enumerate(rules, 2):
    vals = [int(x['order']), x['name'], x['field'], x['purpose'], x['before'], x['reaches'], x['after'], x['expected'], x['payload']]
    for j, v in enumerate(vals, 1):
        c = ov.cell(row=r, column=j, value=v); c.font = CODE if j == 9 else TEXT; c.alignment = WRAP; c.border = BORDER
ov.auto_filter.ref = 'A1:I%d' % (len(rules) + 1)
for x in rules:
    ws = wb.create_sheet(('%s %s' % (x['order'], x['name'].replace('USEM ', '')))[:31])
    header_row(ws, ['#', 'Stage', 'Code', 'Explanation'], [5, 34, 70, 90])
    r = 2; n = 0
    for kind, code, expl in x['rows']:
        if kind == 'stage':
            for j, v in enumerate(['', code, '', expl], 1):
                c = ws.cell(row=r, column=j, value=v); c.font = BOLD if j == 2 else TEXT; c.fill = STAGE_FILL; c.alignment = WRAP; c.border = BORDER
        else:
            n += 1
            for j, v in enumerate([n, '', code, expl], 1):
                c = ws.cell(row=r, column=j, value=v); c.font = CODE if j == 3 else TEXT; c.alignment = WRAP; c.border = BORDER
        r += 1
wb.save(OUT)
print('workbook written:', OUT, '| sheets', len(wb.sheetnames), '| code rows', sum(1 for x in rules for k, _, _ in x['rows'] if k == 'code'))
