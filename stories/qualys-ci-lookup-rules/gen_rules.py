"""Generates rules/<order>_<name>.js, the readable Qualys CI lookup rule scripts.

Header: purpose, sample payload, why the rule sits at its order. Stage banners
(what happens, why, sample data) only on the stages that do the matching; the
plumbing lines carry a single short comment.
"""
import json, os, textwrap

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'rules')
W = 100
IGN = 'sn_sec_cmn_unmatched_ci,sn_vul_qualys_ci,cmdb_ci_unclassed_hardware,cmdb_ci_incomplete_ip,cmdb_ci_dns_name'
ID_A = '3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c'
ID_B = '8c1d5e2f7a9b4c3d6e0f1a2b3c4d5e6f'
MULTI = 'Ubuntu / Tiny Core Linux / Linux 2.6.x / IBM ASM / HP StoreOnce / F5 Networks Big-IP / Cisco IOS Software'


def wrap(text, width, first='', rest=''):
    return textwrap.wrap(text, width=width, initial_indent=first, subsequent_indent=rest,
                         break_long_words=False, break_on_hyphens=False)


def c(text, indent='    '):
    """A plain comment, wrapped."""
    return '\n'.join(indent + '// ' + l for l in wrap(text, W - len(indent) - 3))


def r(text, indent='    '):
    """A '-> data after this line' comment."""
    return '\n'.join(indent + '// ' + l for l in wrap(text, W - len(indent) - 3, first='-> ', rest='   '))


def stage(n, title, what, why, sample, indent='    '):
    out = [indent + '// ' + '=' * 6 + ' STAGE %d: %s ' % (n, title) + '=' * max(3, W - len(indent) - 20 - len(title))]
    out[0] = out[0][:W]
    for label, text in (('What', what), ('Why', why), ('Sample', sample)):
        lab = '%-7s: ' % label
        out += [indent + '// ' + l for l in wrap(text, W - len(indent) - 3, first=lab, rest=' ' * len(lab))]
    out.append(indent + '// ' + '=' * (W - len(indent) - 3))
    return '\n'.join(out)


def header(order, name, purpose, payload, field, value, reads, expected, before, reaches, after):
    w = W - 3
    L = ['/* ' + '=' * (W - 3), '   RULE %s - %s' % (order, name), '   ' + '=' * (W - 3)]
    L += ['   ' + l for l in wrap(purpose, w)]
    L += ['', '   SAMPLE PAYLOAD (one Qualys Host Detection record, used in every example below)']
    L += ['   ' + l for l in json.dumps(payload, indent=2).split('\n')]
    L += ['', '   sourceValue   = the %s field -> "%s"' % (field, value),
          '   sourcePayload = the whole record' + ('; the rule also reads %s from it' % reads if reads else '')]
    L += ['   ' + l for l in wrap('Expected for the sample: ' + expected, w)]
    L += ['', '   WHY THIS RULE SITS AT ORDER %s' % order]
    L += ['   ' + l for l in wrap('Rules run from the lowest order to the highest; the first rule that returns a CI wins and the later rules are skipped. A rule that returns null passes the host on.', w)]
    for lab, text in (('Before it ', before), ('Reaches it', reaches), ('After it  ', after)):
        first = '- %s: ' % lab
        L += ['   ' + l for l in wrap(text, w, first=first, rest=' ' * len(first))]
    L.append('   ' + '=' * (W - 3) + ' */')
    return '\n'.join(L)


OPEN = '(function process(rule, sourceValue, sourcePayload) {'
CLOSE = '})(rule, sourceValue, sourcePayload);'
IGNORE_BLOCK = '\n'.join([
    c('CI classes that must never be matched (placeholder and technical classes). Administrators keep the list in the property sn_sec_cmn.ignoreCIClass; the framework may pass the same list in as _ignoreClass.'),
    "    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?",
    "        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');",
    r('ignore = "%s"' % IGN),
])
CLASSFOR = '\n'.join([
    c('classFor() turns the OS text Qualys reports into the CMDB class the CI lives in. Examples:'),
    '    //   "Red Hat Enterprise Linux 9.8"                              -> cmdb_ci_linux_server',
    '    //   "Windows Server 2016 Standard 64 bit Edition Version 1607"  -> cmdb_ci_win_server',
    '    //   "Windows 10 Enterprise 64 bit Edition Version 22H2"         -> cmdb_ci_computer',
    '    //   "VMware ESXi 7.0.3 build 24723872"                          -> cmdb_ci_esx_server',
    '    //   "AIX 7.3 TL3"                                               -> cmdb_ci_aix_server',
    '    //   "Cisco NX-OS 9.3(8)"                                        -> cmdb_ci_netgear',
    '    //   "%s"' % MULTI,
    '    //       -> "" : three or more guesses separated by "/" means the unauthenticated scan',
    '    //               could not identify the OS, so no class is chosen',
    '    function classFor(os) {',
    "        if (!os) return '';",
    "        var s = ('' + os).toLowerCase();",
    "        if (s.split('/').length > 2) return '';                  // multi-guess fingerprint",
    "        if (s.indexOf('esx') != -1) return 'cmdb_ci_esx_server';",
    "        if (s.indexOf('windows') != -1)",
    "            return s.indexOf('server') != -1 ? 'cmdb_ci_win_server' : 'cmdb_ci_computer';",
    "        if (s.indexOf('aix') != -1) return 'cmdb_ci_aix_server';",
    "        if (s.indexOf('solaris') != -1 || s.indexOf('sunos') != -1) return 'cmdb_ci_solaris_server';",
    "        if (s.indexOf('hp-ux') != -1) return 'cmdb_ci_hpux_server';",
    "        if (s.indexOf('netapp') != -1 || s.indexOf('ontap') != -1) return 'cmdb_ci_storage_server';",
    "        if (s.indexOf('printer') != -1 || s.indexOf('laserjet') != -1 || s.indexOf('jetdirect') != -1) return 'cmdb_ci_printer';",
    "        if (s.indexOf('red hat') != -1 || s.indexOf('linux') != -1 || s.indexOf('centos') != -1 ||",
    "            s.indexOf('ubuntu') != -1 || s.indexOf('suse') != -1 || s.indexOf('debian') != -1 ||",
    "            s.indexOf('fedora') != -1 || s.indexOf('euleros') != -1 ||",
    "            s.indexOf('oracle enterprise') != -1 || s.indexOf('amazon') != -1) return 'cmdb_ci_linux_server';",
    "        if (s.indexOf('nx-os') != -1 || s.indexOf('catos') != -1 || s.indexOf('cisco') != -1) return 'cmdb_ci_netgear';",
    "        return '';",
    '    }',
])
LB_HELPER = '\n'.join([
    c('isLoadBalancer(id) is true when the CI is a Load Balancer. A balancer answers on virtual addresses on behalf of its pool members, so it is never the host that was scanned.'),
    '    function isLoadBalancer(id) {',
    "        var lb = new GlideRecord('cmdb_ci_lb');",
    '        return lb.isValid() && lb.get(id);',
    '    }',
])
GENERIC = '\n'.join([
    c('Classes that say nothing about the OS (a CI loaded as a plain Server before discovery refined it); a CI in one of these never contradicts the scan.'),
    '    var generic = {cmdb_ci_hardware: 1, cmdb_ci_computer: 1, cmdb_ci_server: 1,',
    '        cmdb_ci_unix_server: 1};',
])


def check(value):
    return '\n'.join(['    if (!sourceValue)                             // nothing to look up -> null = "no match from this rule"', '        return null;'])


def serial_prep(value):
    return '\n'.join([
        "    var serial = ('' + sourceValue).trim();       // \"%s\"" % value,
        c('Placeholder serials that vendors ship on thousands of machines would match dozens of CIs at once, so they are refused, as is any serial shorter than four characters.'),
        "    var junk = ',0,none,n/a,na,unknown,empty,not specified,not available,no serial,' +",
        "        'default string,to be filled by o.e.m.,system serial number,chassis serial number,' +",
        "        '0123456789,1234567890,';",
        "    if (serial.length < 4 || junk.indexOf(',' + serial.toLowerCase() + ',') != -1)",
        '        return null;',
    ])


def fqdn_prep(value, ip=None):
    L = ["    var fqdn = ('' + sourceValue).trim().toLowerCase();   // \"%s\"" % value,
         "    if (fqdn.indexOf('.') == -1)                  // no domain part -> the hostname rules (400+) handle bare labels",
         '        return null;']
    if ip:
        L.append("    var ip = sourcePayload.IP ? '' + sourcePayload.IP : '';   // \"%s\", used only to break ties" % ip)
    return '\n'.join(L)


def split_prep(value, host, domain, ip):
    return '\n'.join([
        "    var full = ('' + sourceValue).trim().toLowerCase();   // \"%s\"" % value,
        "    var dot = full.indexOf('.');                  // %d, position of the first dot" % value.index('.'),
        '    if (dot < 1)                                  // no domain part -> the hostname rules (400+) handle bare labels',
        '        return null;',
        '    var host = full.substring(0, dot);            // "%s"' % host,
        '    var domain = full.substring(dot + 1);         // "%s"' % domain,
        "    var ip = sourcePayload.IP ? '' + sourcePayload.IP : '';   // \"%s\", used only to break ties" % ip,
    ])


def short_prep(value, host):
    return '\n'.join([
        "    var full = ('' + sourceValue).trim().toLowerCase();   // \"%s\"" % value,
        "    var host = full.split('.')[0];                // \"%s\"" % host,
        '    if (!host)',
        '        return null;',
    ])


def ip_prep(ip):
    return '\n'.join([
        "    var ip = ('' + sourceValue).trim();           // \"%s\"" % ip,
        "    if (!ip || ip.indexOf('127.') == 0 || ip.indexOf('169.254.') == 0)   // loopback and link-local identify nothing",
        '        return null;',
    ])


def class_stage(n, os_text, cls, label, next_rule):
    return '\n'.join([
        stage(n, 'Work out the CMDB class from the scanned OS',
              'classFor() maps the OS text to the class the CI should be in; the search that follows is limited to that class and its sub-classes.',
              'evidence is trusted only when it lands in a class that agrees with the scanned OS. A Red Hat host must resolve to a Linux Server CI, never to a Windows Server that happens to carry the same value.',
              'classFor("%s") -> "%s" (%s). An unknown or multi-guess OS gives "" and this rule declines so that %s takes over.' % (os_text, cls, label, next_rule)),
        CLASSFOR,
        '    var pref = classFor(sourcePayload.OS);',
        r('pref = "%s"' % cls),
        '    if (!pref)',
        '        return null;',
    ])


def class_pref(n, os_text, cls, label):
    return '\n'.join([
        stage(n, 'Work out the class the scanned OS implies (a preference, not a requirement)',
              'classFor() maps the OS text to a class; here it is only used at the end to reject a CI whose class contradicts the scan.',
              'this rule searches the whole hardware tree, so the class check is the safeguard against a namesake of a different type.',
              'classFor("%s") -> "%s" (%s); "" when the OS is unknown, and then no class check is made.' % (os_text, cls, label)),
        CLASSFOR,
        '    var pref = classFor(sourcePayload.OS);',
        r('pref = "%s"' % cls),
    ])


def search_lines(table_expr, table_desc, field, value, var='gr', valid=False):
    L = [('    var %s = new GlideRecord(%s);' % (var, table_expr)).ljust(46) + '// ' + table_desc]
    if valid:
        L += ['    if (!%s.isValid())                            // class not installed -> decline rather than fail' % var, '        return null;']
    L += ["    %s.addQuery('%s', %s);" % (var, field, value),
          '    if (ignore)',
          "        %s.addQuery('sys_class_name', 'NOT IN', ignore);" % var]
    return '\n'.join(L)


def decide(n, var, one, none, two, ci_desc):
    return '\n'.join([
        stage(n, 'Decide: exactly one CI, or decline',
              'runs the search, reads the first CI and accepts it only when no second CI is in the result.',
              'every finding of this host is linked to the CI returned; a wrong CI sends findings to the wrong owner. Two CIs sharing the value is an ambiguity, so the rule declines and a later rule with different evidence may still resolve the host.',
              'one CI (%s) -> return "%s". No CI -> %s. Two CIs -> %s -> return null.' % (one, ID_A, none, two)),
        '    %s.query();' % var,
        '    if (!%s.next())                               // empty result -> decline' % var,
        '        return null;',
        '    var match = %s.getUniqueValue();' % var,
        r('match = "%s", the sys_id of %s' % (ID_A, ci_desc)),
        '    if (%s.hasNext())                             // a second CI carries the same value -> never guess' % var,
        '        return null;',
        '    return match;',
        r('the framework links the vulnerable item to this CI and stops evaluating later rules'),
    ])


def pick_fqdn(n, fqdn, ip, ci_name, cls_label, run_expr, run_desc):
    return '\n'.join([
        stage(n, 'Exact FQDN search with the scanned IP as tie-break (pickFqdn)',
              'pickFqdn() searches one table for CIs whose fqdn field equals the scanned name, collects every hit and notes which of them also carry the scanned IP. One hit -> match. Several hits but exactly one with the scanned IP -> that one. Anything else -> null.',
              'an FQDN should be unique, but CMDBs carry duplicates (a retired server and its rebuilt replacement, a cluster alias on two nodes). The scanned IP is the second piece of evidence that breaks such a tie safely; without it the rule declines.',
              'the %s "%s" has fqdn "%s" and ip_address "%s" -> ids = ["%s"], ipHits = ["%s"] -> return "%s".' % (cls_label, ci_name, fqdn, ip, ID_A, ID_A, ID_A)),
        '    function pickFqdn(table) {',
        '        var gr = new GlideRecord(table);',
        '        if (!gr.isValid())',
        '            return null;',
        "        gr.addQuery('fqdn', fqdn);                // fqdn = \"%s\"" % fqdn,
        '        if (ignore)',
        "            gr.addQuery('sys_class_name', 'NOT IN', ignore);",
        '        gr.query();',
        '        var ids = [];                             // every CI carrying the FQDN',
        '        var ipHits = [];                          // those that also carry the scanned IP',
        '        while (gr.next()) {',
        '            ids.push(gr.getUniqueValue());',
        "            if (ip && gr.getValue('ip_address') == ip)",
        '                ipHits.push(gr.getUniqueValue());',
        '        }',
        r('ids = ["%s"], ipHits = ["%s"] for the sample; a duplicate would give ids = ["%s", "%s"]' % (ID_A, ID_A, ID_A, ID_B), indent='        '),
        '        if (ids.length == 1)                      // one CI -> match',
        '            return ids[0];',
        '        if (ids.length > 1 && ipHits.length == 1) // duplicates, one confirmed by the IP -> that one',
        '            return ipHits[0];',
        '        return null;                              // none, or an unresolved tie -> decline',
        '    }',
        ('    return pickFqdn(%s);' % run_expr).ljust(46) + '// ' + run_desc,
    ])


def pick_combo(n, full, host, domain, ip, ci_name, cls_label, run_expr, run_desc):
    return '\n'.join([
        stage(n, 'Hostname plus domain evidence, with the scanned IP as tie-break (pickCombo)',
              "pickCombo() searches one table for CIs named with the short hostname and keeps a CI only when its own domain information agrees with the scanned domain: its fqdn equals the scanned name, or its dns_domain equals the scanned domain, or its fqdn starts with the hostname and contains the domain. One confirmed CI -> match. Several but exactly one with the scanned IP -> that one. Anything else -> null.",
              'the same short hostname can exist in several domains (a test and a production machine both called app01). Domain evidence on the CI itself stops the findings from landing on the namesake in another domain.',
              'the %s "%s" has dns_domain "%s" -> confirmed -> good = ["%s"] -> return "%s". A CI "%s" with dns_domain "lab.example.net" is skipped.' % (cls_label, ci_name, domain, ID_A, ID_A, ci_name)),
        '    function pickCombo(table) {',
        '        var gr = new GlideRecord(table);',
        '        if (!gr.isValid())',
        '            return null;',
        "        gr.addQuery('name', host);                // name = \"%s\" (case-insensitive)" % host,
        '        if (ignore)',
        "            gr.addQuery('sys_class_name', 'NOT IN', ignore);",
        '        gr.query();',
        '        var good = [];                            // CIs whose domain evidence agrees',
        '        var ipHits = [];                          // those that also carry the scanned IP',
        '        while (gr.next()) {',
        "            var cifqdn = ('' + gr.getValue('fqdn')).toLowerCase();        // e.g. \"%s\"" % full,
        "            var cidom = ('' + gr.getValue('dns_domain')).toLowerCase();   // e.g. \"%s\"" % domain,
        '            if (cifqdn == full || cidom == domain ||',
        "                (cifqdn && cifqdn.indexOf(host + '.') == 0 && cifqdn.indexOf(domain) > 0)) {",
        '                good.push(gr.getUniqueValue());',
        "                if (ip && gr.getValue('ip_address') == ip)",
        '                    ipHits.push(gr.getUniqueValue());',
        '            }',
        '        }',
        r('good = ["%s"], ipHits = ["%s"] for the sample' % (ID_A, ID_A), indent='        '),
        '        if (good.length == 1)                     // one confirmed CI -> match',
        '            return good[0];',
        '        if (good.length > 1 && ipHits.length == 1) // several, one confirmed by the IP -> that one',
        '            return ipHits[0];',
        '        return null;                              // none, or an unresolved tie -> decline',
        '    }',
        ('    return pickCombo(%s);' % run_expr).ljust(46) + '// ' + run_desc,
    ])


def owners_stage(n, var, owner_expr, one_desc, next_rule):
    return '\n'.join([
        stage(n, 'Collect the owning CIs and decide',
              'walks the rows, counts each distinct owning CI once, and accepts the single owner when it is not a load balancer.',
              'one device with two adapters on the address must count once, two devices must count twice; two owners cannot be told apart by the address, and a load balancer on a virtual address is not the scanned host.',
              'one row -> owners = {"%s": true}, count = 1 -> return "%s" (%s). Two owners, or a load balancer -> return null and %s gets its turn.' % (ID_A, ID_A, one_desc, next_rule)),
        '    var owners = {};',
        '    var count = 0, first = null;',
        '    while (%s.next()) {' % var,
        '        var owner = %s;' % owner_expr,
        '        if (!owners[owner]) {                     // count each CI once',
        '            owners[owner] = true;',
        '            count++;',
        '            if (count == 1)',
        '                first = owner;',
        '        }',
        '    }',
        '    if (count == 1 && !isLoadBalancer(first))',
        '        return first;',
        '    return null;',
    ])


def write(order, name, text):
    fn = os.path.join(OUT, '%s_%s.js' % (order, name.replace(' ', '_')))
    open(fn, 'w').write(text.rstrip('\n') + '\n')
    return fn


RULES = []
IP_PAYLOAD = {"ID": "83047621", "IP": "30.162.178.21", "TRACKING_METHOD": "IP", "OS": "VMware ESXi 7.0.3 build 24723872"}


def rule_175():
    value = 'VMware-42 1a 9c 3f 7d 2e 61 b8-55 04 e2 91 6a 27 c3 08'
    payload = {"ID": "35832680", "IP": "171.128.225.96", "TRACKING_METHOD": "AGENT", "OS": "Red Hat Enterprise Linux 9.8",
               "DNS": "ah-1047132-001.sdi.corp.bankofamerica.com", "SERIAL_NUMBER": value}
    h = header('175', 'USEM Serial Number Class Match',
        'Match a scanned host to its CI by serial number, only inside the CMDB class the scanned OS implies. A serial number is the strongest identifier a machine has, so this is the first USEM rule in the chain.',
        payload, 'SERIAL_NUMBER', value, 'the OS',
        'the Linux Server CI "ah-1047132-001" whose serial_number holds the same serial; null when no Linux Server carries it, or two do.',
        'nothing custom. Serial numbers come first because a serial belongs to one machine for its whole life, while names and addresses are reused.',
        'every Qualys host that reports a SERIAL_NUMBER (today only hosts scanned by the authenticated Cloud Agent).',
        '180 repeats the serial search across every hardware class for hosts whose OS gives no class or whose CI is classed differently; 200 and above move on to names and, last, addresses.')
    body = [OPEN, check(value), serial_prep(value), IGNORE_BLOCK,
        class_stage(1, 'Red Hat Enterprise Linux 9.8', 'cmdb_ci_linux_server', 'Linux Server', 'rule 180 (all hardware, no class)'),
        stage(2, 'Search that class for the serial',
              'opens a search on the class chosen (its sub-classes included), keeps only CIs whose serial_number equals the serial, and leaves out the ignored classes.',
              'the serial must match exactly and inside the agreed class, so class evidence and serial evidence have to agree before the rule trusts the result.',
              'the search on cmdb_ci_linux_server for serial_number = "%s" finds the Linux Server "ah-1047132-001". A Windows Server with the same serial is outside the class and never appears.' % value),
        search_lines('pref', 'the Linux Server class and its sub-classes', 'serial_number', 'serial', valid=True),
        decide(3, 'gr', 'the Linux Server "ah-1047132-001"', 'return null and rule 180 gets its turn', '"ah-1047132-001" and a second Linux Server loaded with the same serial', 'the Linux Server "ah-1047132-001"'),
        CLOSE]
    return write('175', 'USEM Serial Number Class Match', h + '\n' + '\n'.join(body))
RULES.append(rule_175)


def rule_180():
    value = 'MXQ13005TC'
    payload = {"ID": "35920204", "IP": "171.135.28.125", "TRACKING_METHOD": "IP", "OS": MULTI,
               "DNS": "txr9gxcenah031.sdi.corp.bankofamerica.com", "SERIAL_NUMBER": value}
    h = header('180', 'USEM Serial Number Hardware Match',
        'Match a scanned host by serial number anywhere in the hardware tree (servers, computers, network gear, storage, printers). Second and last serial stage: it runs when rule 175 could not use the class the OS implies, and still insists on the serial belonging to exactly one CI.',
        payload, 'SERIAL_NUMBER', value, '',
        'the one hardware CI whose serial_number is "MXQ13005TC", for example the Server CI "txr9gxcenah031" (kept in the generic Server class because the scan could not identify its OS).',
        '175 already tried the serial inside the class the OS implies.',
        'hosts with a serial whose OS is unknown (the sample OS is an unauthenticated scan listing seven guesses) or whose CI sits in another class than the OS suggests.',
        '200 and above switch to names and addresses. A serial that is not unique in the whole hardware tree is never used.')
    body = [OPEN, check(value), serial_prep(value), IGNORE_BLOCK,
        stage(1, 'Search the whole hardware tree for the serial',
              'opens a search on cmdb_ci_hardware, the parent of every device class, keeps only CIs whose serial_number equals the serial, and leaves out the ignored classes. No class preference is used.',
              'the OS gave no usable class, so the serial itself carries the decision; that is safe because the next stage still requires it to belong to exactly one CI in the whole tree.',
              'the search on cmdb_ci_hardware for serial_number = "MXQ13005TC" finds the Server "txr9gxcenah031".'),
        search_lines("'cmdb_ci_hardware'", 'Hardware and every class beneath it', 'serial_number', 'serial'),
        decide(2, 'gr', 'the Server "txr9gxcenah031"', 'return null and rule 200 gets its turn', '"txr9gxcenah031" and a Storage Server loaded with the same serial', 'the Server "txr9gxcenah031"'),
        CLOSE]
    return write('180', 'USEM Serial Number Hardware Match', h + '\n' + '\n'.join(body))
RULES.append(rule_180)


def rule_200():
    value = 'sep64f69dd5c9b0.voip.bankofamerica.com'
    payload = {"ID": "41277345", "IP": "30.144.62.108", "TRACKING_METHOD": "IP", "OS": "Cisco IP Phone", "DNS": value}
    h = header('200', 'USEM Cisco IP Phone MAC',
        'Match Cisco IP phones. Cisco Unified Communications Manager names every phone "SEP" followed by its MAC address, and Qualys reports that name as the DNS host label. The rule turns the label back into a MAC address and looks for exactly one IP Phone CI that carries it.',
        payload, 'DNS', value, '',
        'the IP Phone CI whose network adapter, mac_address field or name carries the MAC 64:F6:9D:D5:C9:B0, for example the phone "SEP64F69DD5C9B0". Any DNS name that does not follow the SEP pattern makes the rule decline at once.',
        '175 and 180 handled serial numbers (phones report none).',
        'only hosts whose DNS label reads SEP plus twelve hexadecimal characters; every other host passes through untouched.',
        '250 and above are the name rules. Phones are resolved first so a phone label can never be mistaken for a server name, and a MAC clash can never pull in a server or a switch: this rule only searches IP Phone CIs.')
    body = [OPEN, check(value),
        stage(1, 'Recognise the SEP label and rebuild the MAC address',
              'takes the first label of the DNS name, checks it against the strict pattern "sep" plus exactly twelve hexadecimal characters, and rebuilds the MAC in the four spellings CMDBs use.',
              'a server named "sepulveda01" must not be treated as a phone, hence the strict pattern; different discovery tools write MACs differently, hence the four spellings.',
              '"%s" -> label "sep64f69dd5c9b0" -> hex "64f69dd5c9b0" -> candidates ["64:F6:9D:D5:C9:B0", "64:f6:9d:d5:c9:b0", "64F69DD5C9B0", "64f69dd5c9b0"].' % value),
        "    var label = ('' + sourceValue).split('.')[0].toLowerCase();   // \"sep64f69dd5c9b0\"",
        '    var m = label.match(/^sep([0-9a-f]{12})$/);  // null for anything that is not a phone label',
        '    if (!m)',
        '        return null;',
        '    var hex = m[1];                               // "64f69dd5c9b0"',
        '    var pairs = [];',
        '    for (var i = 0; i < 12; i += 2)',
        '        pairs.push(hex.substr(i, 2));             // ["64", "f6", "9d", "d5", "c9", "b0"]',
        "    var colon = pairs.join(':');                  // \"64:f6:9d:d5:c9:b0\"",
        '    var candidates = [colon.toUpperCase(), colon, hex.toUpperCase(), hex];',
        IGNORE_BLOCK,
        stage(2, 'Attempt 1: a network adapter with that MAC owned by an IP phone',
              'searches the Network Adapter table for adapters carrying one of the four spellings and belonging to a CI, keeps only owners that really are IP Phone CIs, each counted once, and accepts a single phone.',
              'discovery tools usually store the MAC on the adapter, not on the phone. Checking that the owner is an IP Phone guarantees a switch or server adapter with a colliding MAC is never returned.',
              'adapter "eth0" with mac_address "64:F6:9D:D5:C9:B0" belongs to the IP Phone "SEP64F69DD5C9B0" -> count = 1 -> return "%s".' % ID_A),
        "    var nic = new GlideRecord('cmdb_ci_network_adapter');",
        "    nic.addQuery('mac_address', 'IN', candidates.join(','));",
        "    nic.addNotNullQuery('cmdb_ci');",
        '    nic.query();',
        '    var phones = {}, count = 0, first = null;',
        '    while (nic.next()) {',
        "        var owner = nic.getValue('cmdb_ci');",
        "        var phone = new GlideRecord('cmdb_ci_ip_phone');",
        '        if (phone.get(owner) && !phones[owner]) { // only IP phones count, once each',
        '            phones[owner] = true;',
        '            count++;',
        '            if (count == 1)',
        '                first = owner;',
        '        }',
        '    }',
        '    if (count == 1)',
        '        return first;',
        stage(3, 'Attempt 2: the MAC stored on the IP phone record itself',
              'searches the IP Phone class for a phone whose own mac_address field is one of the four spellings and accepts it when it is the only one; otherwise attempt 3 runs.',
              'some loads write the MAC on the phone record instead of an adapter record.',
              'the IP Phone "SEP64F69DD5C9B0" with mac_address "64F69DD5C9B0" and no second row -> return "%s".' % ID_A),
        "    var ph = new GlideRecord('cmdb_ci_ip_phone');",
        "    ph.addQuery('mac_address', 'IN', candidates.join(','));",
        '    if (ignore)',
        "        ph.addQuery('sys_class_name', 'NOT IN', ignore);",
        '    ph.query();',
        '    if (ph.next()) {',
        '        var byMac = ph.getUniqueValue();',
        '        if (!ph.hasNext())                        // exactly one phone -> match',
        '            return byMac;',
        '    }',
        stage(4, 'Attempt 3: an IP phone named with its Unified CM device name',
              'searches the IP Phone class for a phone named "SEP64F69DD5C9B0" (the label in upper case) and accepts it when it is the only one.',
              'a phone loaded from the call manager export carries no MAC on either record but is named exactly like the DNS label.',
              'the IP Phone named "SEP64F69DD5C9B0" and no second row -> return "%s". No phone at all -> null.' % ID_A),
        "    var byName = new GlideRecord('cmdb_ci_ip_phone');",
        "    byName.addQuery('name', label.toUpperCase());  // \"SEP64F69DD5C9B0\"",
        '    if (ignore)',
        "        byName.addQuery('sys_class_name', 'NOT IN', ignore);",
        '    byName.query();',
        '    if (!byName.next())',
        '        return null;',
        '    var named = byName.getUniqueValue();',
        '    if (byName.hasNext())                         // two phones with one device name -> never guess',
        '        return null;',
        '    return named;',
        CLOSE]
    return write('200', 'USEM Cisco IP Phone MAC', h + '\n' + '\n'.join(body))
RULES.append(rule_200)


def rule_250():
    value = 'vsdnac22xsdi004.sdi.corp.bankofamerica.com'
    payload = {"ID": "83047612", "IP": "30.206.199.36", "TRACKING_METHOD": "IP", "OS": "VMware ESXi 7.0.3 build 24723872", "DNS": value}
    h = header('250', 'USEM FQDN Class Match',
        'Match a scanned host by its fully qualified domain name (FQDN) stored in the fqdn field of a CI, inside the class the scanned OS implies. An exact FQDN on the CI is the most precise name evidence there is, so this is the first name rule after the phone rule.',
        payload, 'DNS', value, 'the OS and the IP',
        'the ESX Server CI whose fqdn is "vsdnac22xsdi004.sdi.corp.bankofamerica.com". Two ESX Servers with that fqdn are accepted only when exactly one also carries the IP 30.206.199.36.',
        '175/180 (serial numbers) and 200 (phone labels) found nothing.',
        'every host with a dotted DNS name, which is the bulk of the Qualys feed.',
        '260 repeats the exact FQDN search across every hardware class; 300/310 fall back to hostname plus domain evidence; 400/410 to the short hostname alone.')
    body = [OPEN, check(value), fqdn_prep(value, '30.206.199.36'), IGNORE_BLOCK,
        class_stage(1, 'VMware ESXi 7.0.3 build 24723872', 'cmdb_ci_esx_server', 'ESX Server', 'rule 260 (all hardware, no class)'),
        pick_fqdn(2, value, '30.206.199.36', 'vsdnac22xsdi004', 'ESX Server', 'pref', 'exact FQDN inside the ESX Server class only'),
        CLOSE]
    return write('250', 'USEM FQDN Class Match', h + '\n' + '\n'.join(body))
RULES.append(rule_250)


def rule_260():
    value = 'txr9gxcenah031.sdi.corp.bankofamerica.com'
    payload = {"ID": "35920204", "IP": "171.135.28.125", "TRACKING_METHOD": "IP", "OS": MULTI, "DNS": value}
    h = header('260', 'USEM FQDN Hardware Match',
        'Match by exact FQDN anywhere in the hardware tree. Second FQDN stage, for hosts whose OS gives no class or whose CI is classed differently from the OS.',
        payload, 'DNS', value, 'the IP',
        'the one hardware CI whose fqdn is "txr9gxcenah031.sdi.corp.bankofamerica.com", for example the Server CI "txr9gxcenah031"; duplicates are resolved by the IP 171.135.28.125 or declined.',
        '250 tried the exact FQDN inside the class the OS implies.',
        'hosts whose OS gives no class (the sample is an unauthenticated scan with seven guesses) or whose CI is classed differently from the OS.',
        '300/310 use hostname plus domain evidence for CIs that carry no fqdn value at all.')
    body = [OPEN, check(value), fqdn_prep(value, '171.135.28.125'), IGNORE_BLOCK,
        pick_fqdn(1, value, '171.135.28.125', 'txr9gxcenah031', 'Server', "'cmdb_ci_hardware'", 'exact FQDN anywhere under Hardware'),
        CLOSE]
    return write('260', 'USEM FQDN Hardware Match', h + '\n' + '\n'.join(body))
RULES.append(rule_260)


def rule_300():
    value = 'ah-1047132-001.sdi.corp.bankofamerica.com'
    payload = {"ID": "35832680", "IP": "171.128.225.96", "TRACKING_METHOD": "AGENT", "OS": "Red Hat Enterprise Linux 9.8", "DNS": value,
               "QG_HOSTID": "633769a4-0139-0002-e352-005056bf41ea"}
    h = header('300', 'USEM Hostname Domain Class Match',
        'Match by the combination of short hostname and domain, inside the class the OS implies. Serves CIs named with the short hostname that carry the domain in another field (dns_domain or fqdn) instead of an exact fqdn value.',
        payload, 'DNS', value, 'the OS and the IP',
        'the Linux Server CI named "ah-1047132-001" whose dns_domain is "sdi.corp.bankofamerica.com" (or whose fqdn is the scanned name); a namesake in another domain is never picked.',
        '250/260 looked for the exact FQDN in the fqdn field.',
        'hosts whose CI has no exact fqdn value but is named with the short hostname and shows the domain elsewhere.',
        '310 repeats the search across all hardware; 350 uses the layered DNS records; 400/410 accept a unique short name without domain evidence.')
    body = [OPEN, check(value), split_prep(value, 'ah-1047132-001', 'sdi.corp.bankofamerica.com', '171.128.225.96'), IGNORE_BLOCK,
        class_stage(1, 'Red Hat Enterprise Linux 9.8', 'cmdb_ci_linux_server', 'Linux Server', 'rule 310 (all hardware, no class)'),
        pick_combo(2, value, 'ah-1047132-001', 'sdi.corp.bankofamerica.com', '171.128.225.96', 'ah-1047132-001', 'Linux Server', 'pref', 'hostname + domain inside the Linux Server class'),
        CLOSE]
    return write('300', 'USEM Hostname Domain Class Match', h + '\n' + '\n'.join(body))
RULES.append(rule_300)


def rule_310():
    value = 'lrche01xtrapd01.sdi.corp.bankofamerica.com'
    payload = {"ID": "35884392", "IP": "171.128.140.192", "TRACKING_METHOD": "IP", "OS": "Ubuntu/Linux", "DNS": value}
    h = header('310', 'USEM Hostname Domain Hardware Match',
        'Match by short hostname plus domain evidence anywhere in the hardware tree. Second combination stage, for hosts whose CI is classed generically (Server, Computer) or differently from the OS.',
        payload, 'DNS', value, 'the IP',
        'the hardware CI named "lrche01xtrapd01" whose fqdn is "lrche01xtrapd01.sdi.corp.bankofamerica.com" or whose dns_domain is "sdi.corp.bankofamerica.com", for example a CI in the generic Server class.',
        '300 tried hostname plus domain inside the class the OS implies (Linux Server for the sample OS "Ubuntu/Linux").',
        'hosts whose CI is classed generically (Server, Computer) or differently from the scanned OS, so the class-scoped search found nothing.',
        '350 (layered DNS records) and 400/410 (short hostname without domain evidence).')
    body = [OPEN, check(value), split_prep(value, 'lrche01xtrapd01', 'sdi.corp.bankofamerica.com', '171.128.140.192'), IGNORE_BLOCK,
        pick_combo(1, value, 'lrche01xtrapd01', 'sdi.corp.bankofamerica.com', '171.128.140.192', 'lrche01xtrapd01', 'Server', "'cmdb_ci_hardware'", 'hostname + domain anywhere under Hardware'),
        CLOSE]
    return write('310', 'USEM Hostname Domain Hardware Match', h + '\n' + '\n'.join(body))
RULES.append(rule_310)


def rule_350():
    value = 'hklvteqoradbp3.hk.baml.com'
    payload = {"ID": "42773078", "IP": "167.202.60.26", "TRACKING_METHOD": "IP", "OS": "Red Hat Enterprise Linux Server 7.9", "DNS": value,
               "QG_HOSTID": "6337dede-02e7-0002-ad2c-0050569765df"}
    h = header('350', 'USEM Layered DNS Match',
        'Match through the layered network model that CMDB discovery maintains: a DNS Name record is linked to an IP Address record, the IP Address record belongs to a Network Adapter, and the adapter belongs to the CI. Finds hosts whose name is not written on the CI record at all, and resolves aliases.',
        payload, 'DNS', value, 'the IP',
        'the CI at the end of the chain DNS Name "hklvteqoradbp3.hk.baml.com" -> IP Address "167.202.60.26" -> adapter "eth0" -> Linux Server "hklvteqoradbp3"; when several CIs answer to the name, the one whose chain runs through the scanned IP.',
        '250 to 310 looked at name fields stored on the CI record itself.',
        'hosts whose name lives only in the layered DNS records, and aliases that point at an address of the device.',
        '400/410 (short hostname alone) and 450 (CI named with the full FQDN).')
    body = [OPEN, check(value), fqdn_prep(value, '167.202.60.26'), IGNORE_BLOCK,
        stage(1, 'Search the chain DNS Name -> IP Address -> adapter -> CI',
              'searches the link table cmdb_ip_address_dns_name, whose rows tie one DNS Name record to one IP Address record. Dot-walking reaches the rest of the chain: dns_name.name is the name on the DNS Name record, ip_address.nic.cmdb_ci is the CI owning the adapter that holds the IP Address record.',
              'discovery writes names and addresses as separate records linked to the device; this is the only rule that can see them, and because the chain ends on whatever device holds the address, an alias resolves to the real machine.',
              'DNS Name "hklvteqoradbp3.hk.baml.com" <-> IP Address "167.202.60.26" -> adapter "eth0" -> Linux Server "hklvteqoradbp3" (sys_id %s).' % ID_A),
        "    var gr = new GlideRecord('cmdb_ip_address_dns_name');",
        '    if (!gr.isValid())                            // layered model not installed -> decline',
        '        return null;',
        "    gr.addQuery('dns_name.name', fqdn);           // the DNS Name record is named \"%s\"" % value,
        "    gr.addNotNullQuery('ip_address.nic.cmdb_ci'); // the chain must end on a CI",
        '    if (ignore)',
        "        gr.addQuery('ip_address.nic.cmdb_ci.sys_class_name', 'NOT IN', ignore);",
        '    gr.query();',
        stage(2, 'Collect the owning CIs and decide',
              'counts each distinct CI at the end of a chain once and notes which of them are reached through the scanned IP. One CI -> match. Several CIs but exactly one reached through the scanned IP -> that one. Otherwise null.',
              'a name that resolves to two devices (an alias moved between hosts, an old and a new record) must not be guessed; the scanned address is the extra evidence that makes the choice safe.',
              'one row -> count = 1 -> return "%s". Two CIs with ipOwners = {"%s": true} -> return "%s". Two CIs and no single IP confirmation -> null and rule 400 gets its turn.' % (ID_A, ID_A, ID_A)),
        '    var owners = {}, ipOwners = {};',
        '    var count = 0, first = null;',
        '    while (gr.next()) {',
        "        var owner = '' + gr.ip_address.nic.cmdb_ci;   // sys_id of the CI at the end of the chain",
        '        if (!owners[owner]) {                     // count each CI once',
        '            owners[owner] = true;',
        '            count++;',
        '            if (count == 1)',
        '                first = owner;',
        '        }',
        "        if (ip && ('' + gr.ip_address.ip_address) == ip)   // this chain runs through the scanned IP",
        '            ipOwners[owner] = true;',
        '    }',
        '    if (count == 1)',
        '        return first;',
        '    if (count > 1) {',
        '        var confirmed = Object.keys(ipOwners);',
        '        if (confirmed.length == 1)',
        '            return confirmed[0];',
        '    }',
        '    return null;',
        CLOSE]
    return write('350', 'USEM Layered DNS Match', h + '\n' + '\n'.join(body))
RULES.append(rule_350)


def rule_400():
    value = 'wsaoi01zeapd1.sdi.corp.bankofamerica.com'
    payload = {"ID": "35850078", "IP": "30.143.70.11", "TRACKING_METHOD": "IP", "OS": "Windows Server 2016 Standard 64 bit Edition Version 1607",
               "DNS": value, "NETBIOS": "WSAOI01ZEAPD1"}
    h = header('400', 'USEM Hostname Class Match',
        'Match by the short hostname alone, inside the class the OS implies. For CIs that carry only a short name and no domain information; the agreement between CI class and scanned OS replaces the missing domain evidence.',
        payload, 'DNS', value, 'the OS',
        'the Windows Server CI named "WSAOI01ZEAPD1" (names compare case-insensitively); a second Windows Server with the same name makes the rule decline.',
        '250 to 350 needed domain evidence on the CI (fqdn, dns_domain or the layered DNS records).',
        'hosts whose CI carries only a short name and no domain information at all.',
        '410 repeats the short name search across all hardware with a class sanity check; 450 handles CIs named with the full FQDN.')
    body = [OPEN, check(value), short_prep(value, 'wsaoi01zeapd1'), IGNORE_BLOCK,
        class_stage(1, 'Windows Server 2016 Standard 64 bit Edition Version 1607', 'cmdb_ci_win_server', 'Windows Server', 'rule 410 (all hardware, no class)'),
        stage(2, 'Search that class for the short name',
              'opens a search on the class chosen (its sub-classes included), keeps only CIs whose name equals the short hostname, and leaves out the ignored classes.',
              'with no domain to confirm, the class is the only safeguard against a namesake; inside the agreed class the name still has to be unique.',
              'the search on cmdb_ci_win_server for name = "wsaoi01zeapd1" finds the Windows Server "WSAOI01ZEAPD1".'),
        search_lines('pref', 'the Windows Server class and its sub-classes', 'name', 'host', valid=True),
        decide(3, 'gr', 'the Windows Server "WSAOI01ZEAPD1"', 'return null and rule 410 gets its turn', 'two Windows Servers named "WSAOI01ZEAPD1"', 'the Windows Server "WSAOI01ZEAPD1"'),
        CLOSE]
    return write('400', 'USEM Hostname Class Match', h + '\n' + '\n'.join(body))
RULES.append(rule_400)


def contradiction(n, cls, label, wrong):
    return '\n'.join([
        stage(n, 'Reject an owner whose class contradicts the scanned OS',
              'when the OS gave a class, the CI found must sit inside that class (sub-classes included) or be generically classed; any other class is a contradiction and the rule declines.',
              'a host that resolves to a %s CI by name or address is a namesake or a reused address, not the same machine; its findings would go to the wrong owner.' % wrong,
              'pref = "%s"; a plain Server passes through generic["cmdb_ci_server"]; a %s CI fails both checks -> null.' % (cls, wrong)),
        '    if (pref) {',
        '        var chk = new GlideRecord(pref);',
        '        if (!(chk.isValid() && chk.get(id)) && !generic[cls])',
        '            return null;',
        '    }',
        '    return id;',
        r('the framework links the vulnerable item to this CI and stops evaluating later rules'),
    ])


def one_owner(n, var, none_next, what_two):
    return '\n'.join([
        stage(n, 'Require exactly one owner',
              'reads the first CI, remembers its sys_id and class, and declines when a second CI carries the same value.',
              what_two,
              'one row -> id = "%s", cls = "cmdb_ci_server". No row -> null and %s gets its turn. Two rows -> null.' % (ID_A, none_next)),
        '    %s.query();' % var,
        '    if (!%s.next())' % var,
        '        return null;',
        '    var id = %s.getUniqueValue();' % var,
        "    var cls = '' + %s.getValue('sys_class_name');   // e.g. \"cmdb_ci_server\"" % var,
        '    if (%s.hasNext())                             // a second CI carries the same value -> never guess' % var,
        '        return null;',
    ])


def rule_410():
    value = 'va2ausapabw0.bankofamerica.com'
    payload = {"ID": "80217765", "IP": "171.150.219.123", "TRACKING_METHOD": "IP", "OS": "AIX 7.3 TL3", "DNS": value,
               "QG_HOSTID": "6337e0dc-007d-0002-c47d-005056a4fcd5"}
    h = header('410', 'USEM Hostname Hardware Match',
        'Match by the short hostname anywhere in the hardware tree, with a check that the CI found does not contradict the scanned OS. Second short-name stage, for CIs classed generically (Server, Computer, UNIX Server) or differently from the OS.',
        payload, 'DNS', value, 'the OS',
        'the one hardware CI named "va2ausapabw0"; accepted when it is an AIX Server or a generically classed Server, rejected when it is, say, a Windows Server.',
        '400 required the short name to be unique inside the class the OS implies.',
        'hosts whose CI is classed generically (Server, Computer, UNIX Server) or whose OS gave no class.',
        '450 (CI named with the full FQDN) and then the IP rules (700 and above) for hosts without a usable name.')
    body = [OPEN, check(value), short_prep(value, 'va2ausapabw0'), IGNORE_BLOCK,
        class_pref(1, 'AIX 7.3 TL3', 'cmdb_ci_aix_server', 'AIX Server'),
        GENERIC,
        stage(2, 'Search the whole hardware tree for the short name',
              'opens a search on cmdb_ci_hardware, keeps only CIs whose name equals the short hostname, and leaves out the ignored classes.',
              'the class-scoped search of rule 400 found nothing, so the name is searched everywhere; the safety comes from the two checks that follow.',
              'the search on cmdb_ci_hardware for name = "va2ausapabw0" finds the Server "va2ausapabw0" (class cmdb_ci_server).'),
        search_lines("'cmdb_ci_hardware'", 'Hardware and every class beneath it', 'name', 'host'),
        one_owner(3, 'gr', 'rule 450', 'two hardware CIs with one short name (a test and a production machine, a retired and a rebuilt one) can never be told apart by the name alone.'),
        contradiction(4, 'cmdb_ci_aix_server', 'AIX Server', 'Windows Server'),
        CLOSE]
    return write('410', 'USEM Hostname Hardware Match', h + '\n' + '\n'.join(body))
RULES.append(rule_410)


def rule_450():
    value = 'lva40bneehcs01.ecomm.devicenp.rpg'
    payload = {"ID": "71973166", "IP": "164.91.209.12", "TRACKING_METHOD": "AGENT", "OS": "Red Hat Enterprise Linux 8.10", "DNS": value,
               "QG_HOSTID": "633781ed-019b-0002-2f2f-0050569d20ff"}
    h = header('450', 'USEM FQDN Name Hardware Match',
        'Match CIs whose name field holds the complete FQDN string, in the hardware tree. Some CMDB loads (typically the appliance domains ending in .rpg) name the CI with the whole FQDN, so a short-name search can never find them.',
        payload, 'DNS', value, '',
        'the hardware CI whose name is exactly "lva40bneehcs01.ecomm.devicenp.rpg", when it is the only one.',
        'every rule so far compared the short hostname or the fqdn field.',
        'CIs named with the full FQDN, which none of the earlier rules can see.',
        '700 and above (IP address rules) and finally 850, the only rule allowed to search the broad cmdb_ci table by name.')
    body = [OPEN, check(value), fqdn_prep(value), IGNORE_BLOCK,
        stage(1, 'Search the whole hardware tree for a CI named with the full FQDN',
              'opens a search on cmdb_ci_hardware, keeps only CIs whose name equals the complete lower-cased DNS name, and leaves out the ignored classes.',
              'the name is compared with the whole string including the domain, which none of the earlier rules did.',
              'the search on cmdb_ci_hardware for name = "%s" finds the Server "%s".' % (value, value)),
        search_lines("'cmdb_ci_hardware'", 'Hardware and every class beneath it', 'name', 'fqdn'),
        decide(2, 'gr', 'the Server "%s"' % value, 'return null and the IP rules (700 and above) get their turn', 'two hardware CIs with that full name', 'the Server "%s"' % value),
        CLOSE]
    return write('450', 'USEM FQDN Name Hardware Match', h + '\n' + '\n'.join(body))
RULES.append(rule_450)


def rule_700():
    h = header('700', 'USEM IP Class Match',
        'Match by IP address, inside the class the OS implies. An address is the least trustworthy identifier (addresses move between machines and are shared by load balancers), so it is used only when the host has no serial and no usable name, and only when exactly one CI of the agreed class carries it.',
        IP_PAYLOAD, 'IP', '30.162.178.21', 'the OS',
        'the ESX Server CI whose ip_address is "30.162.178.21", for example "vsdnac22xsdi009"; a load balancer or a Windows CI with the same address is outside the class and cannot be picked.',
        'all serial and name rules (175 to 450). The sample has no DNS name, so every name rule declined.',
        'DNS-less hosts, typically ESXi management interfaces and appliances (89 of the 21,000 hosts in the reference extract).',
        '705 searches the address across all hardware with extra safety checks; 730 and 740 resolve it through adapters and the layered IP records.')
    body = [OPEN, check('30.162.178.21'), ip_prep('30.162.178.21'), IGNORE_BLOCK,
        class_stage(1, 'VMware ESXi 7.0.3 build 24723872', 'cmdb_ci_esx_server', 'ESX Server', 'rule 705 (all hardware, no class)'),
        stage(2, 'Search that class for the address',
              'opens a search on the class chosen (its sub-classes included), keeps only CIs whose ip_address equals the scanned address, and leaves out the ignored classes.',
              'inside the agreed class an address is reasonably safe: a virtual IP of a load balancer, or a Windows machine that inherited the address, sits outside the ESX Server class and never appears.',
              'the search on cmdb_ci_esx_server for ip_address = "30.162.178.21" finds the ESX Server "vsdnac22xsdi009".'),
        search_lines('pref', 'the ESX Server class and its sub-classes', 'ip_address', 'ip', valid=True),
        decide(3, 'gr', 'the ESX Server "vsdnac22xsdi009"', 'return null and rule 705 gets its turn', 'two ESX Servers carrying "30.162.178.21" (an address reused after a rebuild)', 'the ESX Server "vsdnac22xsdi009"'),
        CLOSE]
    return write('700', 'USEM IP Class Match', h + '\n' + '\n'.join(body))
RULES.append(rule_700)


def rule_705():
    h = header('705', 'USEM IP Hardware Match',
        'Match by IP address anywhere in the hardware tree, with two extra safety checks: the CI must not be a load balancer, and its class must not contradict the scanned OS.',
        IP_PAYLOAD, 'IP', '30.162.178.21', 'the OS',
        'the one hardware CI whose ip_address is "30.162.178.21", accepted when it is an ESX Server or generically classed; rejected when it is a Load Balancer or a CI of a contradicting class such as Windows Server.',
        '700 required the address to belong to one CI of the OS-implied class.',
        'DNS-less hosts whose CI is classed generically (Server) or whose OS gave no class.',
        '730 (address on a network adapter) and 740 (layered IP Address records).')
    body = [OPEN, check('30.162.178.21'), ip_prep('30.162.178.21'), IGNORE_BLOCK,
        class_pref(1, 'VMware ESXi 7.0.3 build 24723872', 'cmdb_ci_esx_server', 'ESX Server'),
        GENERIC, LB_HELPER,
        stage(2, 'Search the whole hardware tree for the address',
              'opens a search on cmdb_ci_hardware, keeps only CIs whose ip_address equals the scanned address, and leaves out the ignored classes.',
              'the class-scoped search of rule 700 found nothing, so the address is searched everywhere; the safety comes from the three checks that follow.',
              'the search on cmdb_ci_hardware for ip_address = "30.162.178.21" finds the Server "vsdnac22xsdi009" (class cmdb_ci_server).'),
        search_lines("'cmdb_ci_hardware'", 'Hardware and every class beneath it', 'ip_address', 'ip'),
        one_owner(3, 'gr', 'rule 730', 'an address answered by several CIs (a shared virtual IP, an address reused after a rebuild) is never a safe match.'),
        stage(4, 'Reject a load balancer',
              'declines when the single owner is a Load Balancer CI.',
              'a scanned address that belongs to a virtual IP describes a pool member behind the balancer, not the balancer.',
              'isLoadBalancer("%s") = false for the Server "vsdnac22xsdi009" -> carry on; true for the Load Balancer "lb-sdi-core-01" -> null.' % ID_A),
        '    if (isLoadBalancer(id))',
        '        return null;',
        contradiction(5, 'cmdb_ci_esx_server', 'ESX Server', 'Windows Server'),
        CLOSE]
    return write('705', 'USEM IP Hardware Match', h + '\n' + '\n'.join(body))
RULES.append(rule_705)


def rule_730():
    h = header('730', 'USEM IP Adapter Match',
        'Match by an IP address recorded on a Network Adapter record rather than on the CI itself (multi-homed servers, discovery-populated CIs). The adapter leads to its owning CI.',
        IP_PAYLOAD, 'IP', '30.162.178.21', '',
        'the CI that owns the adapter carrying "30.162.178.21", for example adapter "vmk0" of the ESX Server "vsdnac22xsdi009"; declined when adapters of two different CIs carry the address or the owner is a load balancer.',
        '700/705 looked for the address in the ip_address field of the CI record itself.',
        'hosts whose address is stored on an adapter record only.',
        '740 (layered IP Address records) and then the last-resort name rule 850.')
    body = [OPEN, check('30.162.178.21'), ip_prep('30.162.178.21'), IGNORE_BLOCK, LB_HELPER,
        stage(1, 'Search the Network Adapter records for the address',
              'searches the Network Adapter table for adapters whose ip_address equals the scanned address and that belong to a CI outside the ignored classes.',
              'discovery stores one adapter record per network card; a server with several cards keeps its addresses there instead of on the CI record.',
              'adapter "vmk0" with ip_address "30.162.178.21" belongs to the ESX Server "vsdnac22xsdi009" (sys_id %s).' % ID_A),
        "    var nic = new GlideRecord('cmdb_ci_network_adapter');",
        "    nic.addQuery('ip_address', ip);",
        "    nic.addNotNullQuery('cmdb_ci');               // the adapter must belong to a CI",
        '    if (ignore)',
        "        nic.addQuery('cmdb_ci.sys_class_name', 'NOT IN', ignore);",
        '    nic.query();',
        owners_stage(2, 'nic', "nic.getValue('cmdb_ci')", 'the ESX Server "vsdnac22xsdi009"', 'rule 740'),
        CLOSE]
    return write('730', 'USEM IP Adapter Match', h + '\n' + '\n'.join(body))
RULES.append(rule_730)


def rule_740():
    h = header('740', 'USEM IP Layered Match',
        'Match by IP address through the layered model that CMDB discovery maintains: an IP Address record belongs to a Network Adapter, and the adapter belongs to the CI.',
        IP_PAYLOAD, 'IP', '30.162.178.21', '',
        'the CI at the end of the chain IP Address "30.162.178.21" -> adapter "vmk0" -> ESX Server "vsdnac22xsdi009"; declined for several owners or a load balancer.',
        '730 looked for the address on Network Adapter records.',
        'hosts whose address exists only as an IP Address record in the layered model.',
        '850, the last-resort broad name search; if that also declines, the out-of-box Qualys rules (860 and above) get their turn.')
    body = [OPEN, check('30.162.178.21'), ip_prep('30.162.178.21'), IGNORE_BLOCK, LB_HELPER,
        stage(1, 'Search the IP Address records for the address',
              'searches the IP Address table for records whose ip_address equals the scanned address and whose adapter (nic) belongs to a CI outside the ignored classes; nic.cmdb_ci reaches the CI two links away.',
              'newer discovery writes each address as its own record linked to the adapter; rule 730 cannot see those when the adapter record itself carries no address.',
              'the IP Address record "30.162.178.21" belongs to adapter "vmk0", which belongs to the ESX Server "vsdnac22xsdi009" (sys_id %s).' % ID_A),
        "    var ipGr = new GlideRecord('cmdb_ci_ip_address');",
        '    if (!ipGr.isValid())                          // layered model not installed -> decline',
        '        return null;',
        "    ipGr.addQuery('ip_address', ip);",
        "    ipGr.addNotNullQuery('nic.cmdb_ci');          // the chain must end on a CI",
        '    if (ignore)',
        "        ipGr.addQuery('nic.cmdb_ci.sys_class_name', 'NOT IN', ignore);",
        '    ipGr.query();',
        owners_stage(2, 'ipGr', "'' + ipGr.nic.cmdb_ci", 'the ESX Server "vsdnac22xsdi009"', 'rule 850'),
        CLOSE]
    return write('740', 'USEM IP Layered Match', h + '\n' + '\n'.join(body))
RULES.append(rule_740)


def rule_850():
    value = 'lva40bneehcs01.ecomm.devicenp.rpg'
    payload = {"ID": "71973166", "IP": "164.91.209.12", "TRACKING_METHOD": "AGENT", "OS": "Red Hat Enterprise Linux 8.10", "DNS": value,
               "QG_HOSTID": "633781ed-019b-0002-2f2f-0050569d20ff"}
    h = header('850', 'USEM FQDN Name Broad Match',
        'The single, deliberately late, broad fallback: a CI named with the full FQDN anywhere in the CI table, classes outside the hardware tree included (a virtual machine instance, another logical CI). Still requires a unique owner outside the ignored classes.',
        payload, 'DNS', value, '',
        'the one CI in any class whose name is "lva40bneehcs01.ecomm.devicenp.rpg", for example a Virtual Machine Instance; declined when the name is shared.',
        'every hardware-scoped rule (175 to 740) has declined for this host.',
        'the rare CI named with the full FQDN that lives outside the hardware tree.',
        'the out-of-box Qualys rules: 860 QUALYS HOST ID, 880 Cloud Resource Id, 900 FQDN, 920 NetBIOS, 940 DNS, and 950/960 IP which are inactive by default.')
    body = [OPEN, check(value), fqdn_prep(value), IGNORE_BLOCK,
        stage(1, 'Search the whole CI table for a CI named with the full FQDN',
              'opens a search on cmdb_ci, the root of every CI class, keeps only CIs whose name equals the complete lower-cased DNS name, and leaves out the ignored classes.',
              'this is the only USEM rule that searches outside the hardware tree, which is why it runs last: every more precise rule has had its chance, and the ignore list still keeps placeholder classes out.',
              'the search on cmdb_ci for name = "%s" finds the Virtual Machine Instance "%s".' % (value, value)),
        search_lines("'cmdb_ci'", 'the root CI table, every class', 'name', 'fqdn'),
        decide(2, 'gr', 'the Virtual Machine Instance "%s"' % value, 'return null; the out-of-box Qualys rules (860 and above) get their turn', 'two CIs with that full name', 'the Virtual Machine Instance "%s"' % value),
        CLOSE]
    return write('850', 'USEM FQDN Name Broad Match', h + '\n' + '\n'.join(body))
RULES.append(rule_850)


# ================================================================== rules added for the unmatched population (V3.0)
PROP_LIST = '\n'.join([
    c('list() reads a comma separated system property into a lower-cased list, falling back to the default shipped with the rule. Administrators tune the rule by editing the property, not the script.'),
    '    function list(name, fallback) {',
    "        var parts = ('' + gs.getProperty(name, fallback)).split(',');",
    '        var out = [];',
    '        for (var i = 0; i < parts.length; i++) {',
    '            var item = parts[i].trim().toLowerCase();',
    '            if (item)',
    '                out.push(item);',
    '        }',
    '        return out;',
    '    }',
])
SEG_MATCH = '\n'.join([
    c('isMarker() reports whether one hyphen segment of the label is a listed marker: the word itself ("vlan"), the word followed by digits only ("vlan705", "v201"), or, for words of three letters or more, a segment ending in the word ("multihostvip").'),
    '    function isMarker(segment, words) {',
    '        for (var i = 0; i < words.length; i++) {',
    '            var w = words[i];',
    '            if (segment == w)',
    '                return true;',
    '            if (segment.indexOf(w) == 0 && /^[0-9]+$/.test(segment.substring(w.length)))',
    '                return true;',
    '            if (w.length >= 3 && segment.length > w.length && segment.substring(segment.length - w.length) == w)',
    '                return true;',
    '        }',
    '        return false;',
    '    }',
])


def rule_420():
    value = 'tx6dd630001-ilo.bankofamerica.com'
    payload = {"ID": "1201534877", "IP": "159.185.200.11", "TRACKING_METHOD": "IP", "OS": "HP iLO", "DNS": value}
    h = header('420', 'USEM Management Interface Match',
        'Match the management controller of a server (HP iLO, Oracle ILOM, Dell iDRAC, IBM IMM, Cisco CIMC, generic BMC or IPMI) to the server itself. Controllers are scanned under their own DNS label, which is the server name plus a suffix ("-ilo", "-ilom", "-idrac"), so the name rules never find them. The findings belong to the server owner.',
        payload, 'DNS', value, 'the OS',
        'the hardware CI named "tx6dd630001" (the label without "-ilo"), for example a Linux Server; null when no CI or two CIs carry that name, or when the CI is a load balancer.',
        '400/410 tried the full label "tx6dd630001-ilo" as a hostname and found nothing, because no CI is named after the controller.',
        'hosts whose label ends with a listed controller suffix, or whose OS text names a controller (property lists usem.ci_lookup.mgmt_suffixes and usem.ci_lookup.mgmt_os_markers).',
        '430 (network interface names) and 450 (CI named with the full FQDN).')
    body = [OPEN, check(value),
        "    var full = ('' + sourceValue).trim().toLowerCase();   // \"tx6dd630001-ilo.bankofamerica.com\"",
        "    var label = full.split('.')[0];               // \"tx6dd630001-ilo\"",
        "    var dash = label.lastIndexOf('-');             // 11, position of the last hyphen",
        '    if (dash < 1)                                 // no hyphen -> nothing to strip -> decline',
        '        return null;',
        "    var os = ('' + (sourcePayload.OS || '')).toLowerCase();   // \"hp ilo\"",
        IGNORE_BLOCK, PROP_LIST,
        stage(1, 'Recognise a management controller and derive the server name',
              'the segment after the last hyphen is compared with the suffix list; when it is listed, the server name is the label without it. Otherwise the OS text is compared with the controller markers; when one is found, the last segment is stripped whatever it is, because controllers are named after their server with a site-specific tail such as "-r".',
              'the two pieces of evidence cover both naming habits seen in the scans: an explicit suffix with any OS, and a controller OS with an arbitrary tail. Without either the host is not a controller and the rule must not touch it.',
              '"tx6dd630001-ilo" -> tail "ilo" is listed -> base = "tx6dd630001". "crpchictx103-r" with OS "HP iLO" -> tail "r" is not listed, but the OS names a controller -> base = "crpchictx103". "usposwks0042-x" with OS "Windows 10" -> neither -> decline.'),
        "    var suffixes = list('usem.ci_lookup.mgmt_suffixes', 'ilo,ilom,idrac,drac,ipmi,bmc,oob,mgmt,imm,cimc,rmm,con');",
        "    var markers = list('usem.ci_lookup.mgmt_os_markers', 'ilo,ilom,idrac,drac,remote access controller,imm,cimc,bmc,ipmi,lights out');",
        '    var tail = label.substring(dash + 1);         // "ilo"',
        "    var base = '';",
        '    if (suffixes.indexOf(tail) != -1)',
        '        base = label.substring(0, dash);          // listed suffix -> "tx6dd630001"',
        '    else',
        '        for (var i = 0; i < markers.length; i++)',
        '            if (os.indexOf(markers[i]) != -1) {',
        '                base = label.substring(0, dash);  // controller OS -> strip the last segment',
        '                break;',
        '            }',
        r('base = "tx6dd630001" for the sample; "" when the host shows no controller evidence'),
        '    if (!base)',
        '        return null;',
        stage(2, 'Search the hardware tree for the server name',
              'opens a search on cmdb_ci_hardware, keeps only CIs whose name equals the derived server name, and leaves out the ignored classes.',
              'the controller can sit in front of a server, a storage node or a network device, so the whole hardware tree is searched; safety comes from the uniqueness check that follows.',
              'the search on cmdb_ci_hardware for name = "tx6dd630001" finds the Linux Server "tx6dd630001".'),
        search_lines("'cmdb_ci_hardware'", 'Hardware and every class beneath it', 'name', 'base'),
        stage(3, 'Decide: exactly one CI that is not a load balancer, or decline',
              'runs the search, accepts the CI only when it is the single one, and refuses a load balancer.',
              'two CIs with the server name cannot be told apart from the controller label alone, and a load balancer answering on a management address is still not the scanned host.',
              'one CI -> return "%s". No CI -> null and rule 430 gets its turn. Two CIs named "crpchictx103" -> null.' % ID_A),
        '    gr.query();',
        '    if (!gr.next())                               // no CI carries the server name -> decline',
        '        return null;',
        '    var match = gr.getUniqueValue();',
        '    if (gr.hasNext())                             // two CIs carry it -> never guess',
        '        return null;',
        "    var lb = new GlideRecord('cmdb_ci_lb');",
        '    if (lb.isValid() && lb.get(match))            // a load balancer is never the host',
        '        return null;',
        '    return match;',
        r('the framework links the vulnerable item to the server and stops evaluating later rules'),
        CLOSE]
    return write('420', 'USEM Management Interface Match', h + '\n' + '\n'.join(body))
RULES.append(rule_420)


def rule_430():
    value = 'uspaltwrr01drm0119-cz04-hsrp-vlan705.network.bankofamerica.com'
    payload = {"ID": "1187423005", "IP": "171.149.3.49", "TRACKING_METHOD": "IP", "OS": "Linux 2.6", "DNS": value}
    h = header('430', 'USEM Network Interface Name Match',
        'Match a network device scanned through one of its interface or VLAN addresses. Such addresses carry a DNS label made of the device name plus an interface tail ("-cz04-hsrp-vlan705", "-atm1-v201", "-aom"), and the device CI is named by the leading part only. The rule walks the label from the longest prefix to the shortest and accepts the first prefix that names exactly one Network Gear CI.',
        payload, 'DNS', value, 'the OS',
        'the network device named "uspaltwrr01drm0119" (an IP Switch, router, firewall or load balancer device); null when no prefix names a device or when a prefix names two.',
        '400/410 tried the whole label as a hostname; 420 looked for a management controller suffix.',
        'hosts whose DNS domain is an interface domain (".network." by default, property usem.ci_lookup.interface_domains) or whose label contains an interface marker segment such as "vlan705", "v201", "hsrp", "aom" (property usem.ci_lookup.interface_markers).',
        '450 (CI named with the full FQDN) and 460 (load balancer services).')
    body = [OPEN, check(value),
        "    var full = ('' + sourceValue).trim().toLowerCase();   // \"uspaltwrr01drm0119-cz04-hsrp-vlan705.network.bankofamerica.com\"",
        "    var label = full.split('.')[0];               // \"uspaltwrr01drm0119-cz04-hsrp-vlan705\"",
        "    var segments = label.split('-');              // [\"uspaltwrr01drm0119\", \"cz04\", \"hsrp\", \"vlan705\"]",
        '    if (segments.length < 2)                      // no hyphen -> no interface tail -> decline',
        '        return null;',
        IGNORE_BLOCK, PROP_LIST, SEG_MATCH,
        stage(1, 'Require interface evidence',
              'the rule goes on only when the DNS domain contains a listed interface domain, or one of the segments after the first is a listed interface marker.',
              'plenty of ordinary server names contain hyphens ("ah-1047132-001"); without the interface evidence the prefix walk would strip real hostnames and could land on an unrelated device.',
              '".network." is found in the sample name -> evidence. "gtcmmrlpa05a-vlan10.corp.bankofamerica.com" -> segment "vlan10" is a marker -> evidence. "ah-1047132-001.corp.bankofamerica.com" -> neither -> decline.'),
        "    var domains = list('usem.ci_lookup.interface_domains', '.network.');",
        "    var markers = list('usem.ci_lookup.interface_markers', 'vlan,v,hsrp,vrrp,po,eth,gi,te,lo,mgmt,aom,vs,fab');",
        '    var evidence = false;',
        '    for (var d = 0; d < domains.length; d++)',
        '        if (full.indexOf(domains[d]) != -1)',
        '            evidence = true;',
        '    for (var s = 1; s < segments.length; s++)',
        '        if (isMarker(segments[s], markers))',
        '            evidence = true;',
        r('evidence = true for the sample (the domain contains ".network." and "vlan705" is a marker)'),
        '    if (!evidence)',
        '        return null;',
        stage(2, 'Walk the prefixes from the longest to the shortest against Network Gear',
              'drops one segment at a time from the right and searches Network Gear (switches, routers, firewalls) and Load Balancer devices for a CI with exactly that name. The first prefix that finds anything decides: one CI is the match, two CIs mean the rule declines.',
              'the device name is the leading part of the label but its length varies by site; trying the longest prefix first keeps "site-device-01" from being cut down to "site" when a CI named with the longer form exists.',
              'prefixes tried: "uspaltwrr01drm0119-cz04-hsrp" (none), "uspaltwrr01drm0119-cz04" (none), "uspaltwrr01drm0119" (the IP Switch "uspaltwrr01drm0119") -> return "%s". Two switches named "ustxrdnwl01rsm004z" -> null.' % ID_A),
        c('Network devices live in two branches of the CMDB: Network Gear (switches, routers, firewalls) and Load Balancer, which the platform files under Server. Both are searched; the hits are counted together.'),
        "    var tables = ['cmdb_ci_netgear', 'cmdb_ci_lb'];",
        '    for (var k = segments.length - 1; k >= 1; k--) {',
        "        var base = segments.slice(0, k).join('-');   // \"uspaltwrr01drm0119-cz04-hsrp\", then \"uspaltwrr01drm0119-cz04\", then \"uspaltwrr01drm0119\"",
        '        var hits = [];                            // sys_ids of the devices named exactly like this prefix',
        '        for (var t = 0; t < tables.length; t++) {',
        '            var gr = new GlideRecord(tables[t]);',
        '            if (!gr.isValid())',
        '                continue;',
        "            gr.addQuery('name', base);",
        '            if (ignore)',
        "                gr.addQuery('sys_class_name', 'NOT IN', ignore);",
        '            gr.query();',
        '            while (gr.next() && hits.length < 2)',
        '                hits.push(gr.getUniqueValue());',
        '        }',
        '        if (hits.length == 0)                     // nothing named like this -> try a shorter prefix',
        '            continue;',
        '        if (hits.length > 1)                      // two devices carry this name -> never guess',
        '            return null;',
        '        return hits[0];',
        '    }',
        '    return null;',
        r('no prefix names a device -> decline; the host continues to rule 450'),
        CLOSE]
    return write('430', 'USEM Network Interface Name Match', h + '\n' + '\n'.join(body))
RULES.append(rule_430)


def rule_460():
    value = '171.203.142.26'
    payload = {"ID": "1202267231", "IP": value, "TRACKING_METHOD": "IP", "OS": "F5 Big IP", "DNS": "crisp-tx.bankofamerica.com"}
    h = header('460', 'USEM Load Balancer Service Match',
        'Match a virtual IP answered by a load balancer to the Load Balancer Service CI that models it. The hardware rules deliberately refuse the balancer device, because a VIP is not the balancer; this rule gives such hosts their proper CI instead of leaving them unmatched. It runs on the IP field so that VIPs without a DNS name are covered too.',
        payload, 'IP', value, 'the OS and the DNS name',
        'the Load Balancer Service CI whose fqdn is "crisp-tx.bankofamerica.com" (or, failing that, whose name is the DNS name or its label, or whose ip_address is "171.203.142.26"); null without VIP evidence, without a service, or when two services carry the value.',
        '175 to 450 searched the hardware tree and declined: a VIP has no serial, its name is not a server name, and the address belongs to a load balancer device, which those rules refuse.',
        'hosts with VIP evidence: an OS text naming a load balancer product (property usem.ci_lookup.vip_os_markers) or a DNS label with a VIP marker segment such as "-vip", "vs1" (property usem.ci_lookup.vip_markers).',
        '700 and above (IP address rules) for hosts that are not VIPs.')
    body = [OPEN, check(value), ip_prep(value),
        "    var dns = ('' + (sourcePayload.DNS || '')).trim().toLowerCase();   // \"crisp-tx.bankofamerica.com\" or \"\"",
        "    var label = dns.split('.')[0];                // \"crisp-tx\"",
        "    var os = ('' + (sourcePayload.OS || '')).toLowerCase();   // \"f5 big ip\"",
        IGNORE_BLOCK, PROP_LIST, SEG_MATCH,
        stage(1, 'Require VIP evidence',
              'the rule goes on only when the OS text contains a listed load balancer product word, or one of the label segments is a listed VIP marker.',
              'a Load Balancer Service must never be returned for an ordinary server that happens to share an address with a VIP; the evidence keeps this rule to the hosts that really are VIPs.',
              '"f5 big ip" contains "f5" -> evidence. "rbps-dev3-sve-vip.ecommnp.rpg" with OS "Linux 2.6" -> segment "vip" -> evidence. "ah-1047132-001" with OS "Red Hat Enterprise Linux 9.8" -> neither -> decline.'),
        "    var osMarkers = list('usem.ci_lookup.vip_os_markers', 'f5,big-ip,big ip,netscaler');",
        "    var labelMarkers = list('usem.ci_lookup.vip_markers', 'vip,vs');",
        '    var evidence = false;',
        '    for (var m = 0; m < osMarkers.length; m++)',
        '        if (os.indexOf(osMarkers[m]) != -1)',
        '            evidence = true;',
        "    var segments = label ? label.split('-') : [];",
        '    for (var s = 0; s < segments.length; s++)',
        '        if (isMarker(segments[s], labelMarkers))',
        '            evidence = true;',
        r('evidence = true for the sample'),
        '    if (!evidence)',
        '        return null;',
        stage(2, 'Find the one Load Balancer Service by fqdn, then by name, then by address',
              'searches cmdb_ci_lb_service (and its sub-classes) for the scanned DNS name in the fqdn field, then in the name field, then for the label in the name field, then for the scanned address in ip_address. Each step accepts exactly one service; a step that finds two services ends the rule with null, a step that finds nothing hands over to the next step.',
              'the most specific evidence is tried first, and an ambiguous answer is never skipped over to a weaker one, because the weaker evidence could pick a different service.',
              'fqdn = "crisp-tx.bankofamerica.com" finds the Load Balancer Service "crisp-tx" -> return "%s". A VIP with two services on the same address and no DNS -> null.' % ID_A),
        '    function one(field, value) {',
        '        if (!value)',
        '            return undefined;                     // no value to search -> next step',
        "        var gr = new GlideRecord('cmdb_ci_lb_service');",
        '        if (!gr.isValid())',
        '            return null;                          // class not installed -> decline',
        '        gr.addQuery(field, value);',
        '        if (ignore)',
        "            gr.addQuery('sys_class_name', 'NOT IN', ignore);",
        '        gr.query();',
        '        if (!gr.next())',
        '            return undefined;                     // nothing found -> next step',
        '        var id = gr.getUniqueValue();',
        '        if (gr.hasNext())',
        '            return null;                          // two services -> never guess',
        '        return id;',
        '    }',
        "    var steps = [['fqdn', dns], ['name', dns], ['name', label], ['ip_address', ip]];",
        '    for (var t = 0; t < steps.length; t++) {',
        '        var found = one(steps[t][0], steps[t][1]);',
        '        if (found === null)                       // ambiguous at this step -> decline',
        '            return null;',
        '        if (found)                                // exactly one service -> match',
        '            return found;',
        '    }',
        '    return null;',
        r('no service for any of the evidence -> decline; the host continues to rule 700'),
        CLOSE]
    return write('460', 'USEM Load Balancer Service Match', h + '\n' + '\n'.join(body))
RULES.append(rule_460)


if __name__ == '__main__':
    os.makedirs(OUT, exist_ok=True)
    files = [f() for f in RULES]
    bad = [fn for fn in files if '...' in open(fn).read() or '…' in open(fn).read()]
    print('written', len(files), 'rule scripts;', 'ellipsis found in: %s' % bad if bad else 'no ellipsis anywhere')
