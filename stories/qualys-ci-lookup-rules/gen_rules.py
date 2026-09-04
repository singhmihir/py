"""Generates rules/<order>_<name>.js, the readable Qualys CI lookup rule scripts.

Every script carries a header (purpose, sample payload, why the rule sits at its
order, the list of stages) and the code split into numbered stages. Each stage
states what happens, why the stage exists and what the sample data looks like;
each code line is followed by a "->" comment with the data after that line.
"""
import json, os, re, textwrap

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'rules')
W = 100
IGN = 'sn_sec_cmn_unmatched_ci,sn_vul_qualys_ci,cmdb_ci_unclassed_hardware,cmdb_ci_incomplete_ip,cmdb_ci_dns_name'
ID_A = '3f2a9c7e1b8d4a5f9e6c0d2b7a4f8e1c'
ID_B = '8c1d5e2f7a9b4c3d6e0f1a2b3c4d5e6f'
ID_C = 'a7b3c9d1e5f2a8b4c6d0e2f4a1b3c5d7'
MULTI = 'Ubuntu / Tiny Core Linux / Linux 2.6.x / IBM ASM / HP StoreOnce / F5 Networks Big-IP / Cisco IOS Software'


def wrap(text, width, first='', rest=''):
    return textwrap.wrap(text, width=width, initial_indent=first, subsequent_indent=rest,
                         break_long_words=False, break_on_hyphens=False)


def note(*texts, indent='    '):
    """Comment lines (one paragraph per text)."""
    out = []
    for t in texts:
        out += [indent + '// ' + l for l in wrap(t, W - len(indent) - 3)]
    return '\n'.join(out)


def res(text, indent='    '):
    """The '-> data after this line' comment."""
    lines = wrap(text, W - len(indent) - 3, first='-> ', rest='   ')
    return '\n'.join(indent + '// ' + l for l in lines)


def stage(n, title, what, why, sample=None, indent='    '):
    bar = indent + '// ' + '-' * (W - len(indent) - 3)
    out = [bar, indent + '// STAGE %d - %s' % (n, title)]
    for label, text in (('What happens', what), ('Why', why), ('Sample', sample)):
        if text is None:
            continue
        lab = '%-13s: ' % label
        out += [indent + '// ' + l for l in wrap(text, W - len(indent) - 3, first=lab, rest=' ' * len(lab))]
    out.append(bar)
    return '\n'.join(out)


def header(order, name, purpose, payload, field, value, reads, expected, before, reaches, after, stages):
    w = W - 3
    L = ['/* ' + '=' * (W - 3), '   RULE %s - %s' % (order, name), '   ' + '=' * (W - 3), '   PURPOSE']
    L += ['   ' + l for l in wrap(purpose, w)]
    L += ['', '   SAMPLE PAYLOAD', '   One Qualys Host Detection record, used for every example in this script:']
    L += ['   ' + l for l in json.dumps(payload, indent=2).split('\n')]
    L += ['', '   sourceValue   = the %s field of that record -> "%s"' % (field, value),
          '   sourcePayload = the whole record above' + ('; the rule also reads %s from it' % reads if reads else ''),
          '   rule          = this lookup rule record (name, order, source); the logic does not need it']
    L += ['   ' + l for l in wrap('Expected outcome for the sample: ' + expected, w)]
    L += ['', '   WHY THIS RULE SITS AT ORDER %s' % order]
    L += ['   ' + l for l in wrap('Rules run from the lowest order to the highest. The first rule that returns a CI wins and every later rule is skipped; a rule that returns null simply passes the host on to the next rule.', w)]
    for lab, text in (('Before it ', before), ('Reaches it', reaches), ('After it  ', after)):
        first = '- %s: ' % lab
        L += ['   ' + l for l in wrap(text, w, first=first, rest=' ' * len(first))]
    L += ['', '   THE STAGES OF THIS SCRIPT']
    for i, s in enumerate(stages, 1):
        L += ['   ' + l for l in wrap(s, w, first='%2d. ' % i, rest='    ')]
    L.append('   ' + '=' * (W - 3) + ' */')
    return '\n'.join(L)


OPEN = '(function process(rule, sourceValue, sourcePayload) {'
CLOSE = '})(rule, sourceValue, sourcePayload);'


# ---------------------------------------------------------------- shared stages
def st_check(n, field_label, value):
    return '\n'.join([
        stage(n, 'Check that Qualys sent %s' % field_label,
              'the rule stops with null when the field is empty. null is the signal "no match from this rule"; the framework then tries the next rule in order.',
              'a search for an empty value can never identify one machine and would only cost time on every host that lacks the field.',
              'sourceValue = "%s" -> not empty -> the rule carries on.' % value),
        '    if (!sourceValue)',
        '        return null;',
        res('for the sample the condition is false and nothing happens; for an empty value the rule ends here with null.'),
    ])


def st_ignore(n):
    return '\n'.join([
        stage(n, 'Read the list of CI classes that must never be matched',
              'reads the list of CI classes that must never be matched. Administrators keep it in the system property sn_sec_cmn.ignoreCIClass as comma separated class names. The framework may also hand the same list to the script as a variable called _ignoreClass; when that variable exists and is filled the script uses it, otherwise it reads the property directly.',
              'placeholder and technical classes must never receive vulnerability findings: the unmatched CI placeholders that Security Operations creates, the Qualys staging CI class, Unclassed Hardware, incomplete IP records and DNS Name records. Keeping the list in one property means it can be changed without editing sixteen scripts.',
              'with the platform default the property holds "%s"; an empty property gives ignore = "" and then no class filter is added to the searches below.' % IGN),
        "    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?",
        "        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');",
        res('ignore = "%s", one text, comma separated, ready for a NOT IN condition.' % IGN),
    ])


def classfor_code():
    I = '        '
    L = ['    function classFor(os) {',
         "        if (!os) return '';",
         res('no OS text at all -> "" (no class).', indent=I),
         "        var s = ('' + os).toLowerCase();",
         res('s = the OS text in lower case, so that "Windows", "WINDOWS" and "windows" all compare the same.', indent=I),
         "        if (s.split('/').length > 2) return '';",
         res('"%s" splits into 7 parts at the "/" characters -> more than 2 -> an unauthenticated guess list -> "" (no class).' % MULTI.lower(), indent=I),
         "        if (s.indexOf('esx') != -1) return 'cmdb_ci_esx_server';",
         res('"vmware esxi 7.0.3 build 24723872" contains "esx" -> "cmdb_ci_esx_server" (ESX Server).', indent=I),
         "        if (s.indexOf('windows') != -1)",
         "            return s.indexOf('server') != -1 ? 'cmdb_ci_win_server' : 'cmdb_ci_computer';",
         res('"windows server 2016 standard 64 bit edition version 1607" -> "cmdb_ci_win_server" (Windows Server); "windows 10 enterprise 64 bit edition version 22h2" has no "server" -> "cmdb_ci_computer" (Computer, a workstation).', indent=I),
         "        if (s.indexOf('aix') != -1) return 'cmdb_ci_aix_server';",
         res('"aix 7.3 tl3" -> "cmdb_ci_aix_server" (AIX Server).', indent=I),
         "        if (s.indexOf('solaris') != -1 || s.indexOf('sunos') != -1) return 'cmdb_ci_solaris_server';",
         res('"oracle solaris 11.4" -> "cmdb_ci_solaris_server" (Solaris Server).', indent=I),
         "        if (s.indexOf('hp-ux') != -1) return 'cmdb_ci_hpux_server';",
         res('"hp-ux b.11.31" -> "cmdb_ci_hpux_server" (HPUX Server).', indent=I),
         "        if (s.indexOf('netapp') != -1 || s.indexOf('ontap') != -1) return 'cmdb_ci_storage_server';",
         res('"netapp ontap 9.12.1" -> "cmdb_ci_storage_server" (Storage Server).', indent=I),
         "        if (s.indexOf('printer') != -1 || s.indexOf('laserjet') != -1 || s.indexOf('jetdirect') != -1) return 'cmdb_ci_printer';",
         res('"hp laserjet m507" -> "cmdb_ci_printer" (Printer).', indent=I),
         "        if (s.indexOf('red hat') != -1 || s.indexOf('linux') != -1 || s.indexOf('centos') != -1 ||",
         "            s.indexOf('ubuntu') != -1 || s.indexOf('suse') != -1 || s.indexOf('debian') != -1 ||",
         "            s.indexOf('fedora') != -1 || s.indexOf('euleros') != -1 ||",
         "            s.indexOf('oracle enterprise') != -1 || s.indexOf('amazon') != -1) return 'cmdb_ci_linux_server';",
         res('"red hat enterprise linux 9.8", "suse linux enterprise server 15 sp5" and "amazon linux 2023" -> "cmdb_ci_linux_server" (Linux Server).', indent=I),
         "        if (s.indexOf('nx-os') != -1 || s.indexOf('catos') != -1 || s.indexOf('cisco') != -1) return 'cmdb_ci_netgear';",
         res('"cisco nx-os 9.3(8)" -> "cmdb_ci_netgear" (Network Gear).', indent=I),
         "        return '';",
         res('anything else, for example "unknown" -> "" (no class).', indent=I),
         '    }']
    return '\n'.join(L)


def st_classfor(n, os_text, walk, cls, label, mandatory, next_rule):
    body = [
        stage(n, 'Work out the CMDB class from the scanned operating system',
              'the helper classFor() reads the operating system text Qualys reports and returns the CMDB class such a machine is stored in. It lowers the text, gives up when the text is an unauthenticated multi-guess fingerprint (three or more guesses separated by "/"), then looks for key words in a fixed order and returns an empty string when nothing fits. Searching a class also searches every class beneath it, so cmdb_ci_linux_server covers all Linux flavour classes.',
              'evidence is only trusted when it lands in a class that agrees with the scanned OS: a Red Hat host must resolve to a Linux Server CI, never to a Windows Server that happens to carry the same value.',
              'classFor("%s"): %s -> returns "%s" (%s).' % (os_text, walk, cls, label)),
        classfor_code(),
        '',
        '    var pref = classFor(sourcePayload.OS);',
        res('pref = "%s" for the sample OS "%s".' % (cls, os_text)),
    ]
    if mandatory:
        body += [
            '    if (!pref)',
            '        return null;',
            res('pref = "" happens for an unknown OS or a multi-guess fingerprint; this rule then declines so that %s gets its turn.' % next_rule),
        ]
    return '\n'.join(body)


def st_decide(n, var, one, none, two):
    return '\n'.join([
        stage(n, 'Decide: exactly one CI, or decline',
              'runs the search, reads the first CI and accepts it only when there is no second CI in the result.',
              'every finding of this host will be linked to the CI the rule returns. A wrong CI sends the findings to the wrong owner, so when two CIs share the value the rule refuses to guess and answers null; a later rule with different evidence may still resolve the host, and if none does the host stays unmatched for the CMDB team to review.',
              'one CI -> %s. No CI -> %s. Two CIs -> %s.' % (one, none, two)),
        '    %s.query();' % var,
        res('the search has run; %s now sits just before the first row of the result (0, 1 or more CIs).' % var),
        '    if (!%s.next())' % var,
        '        return null;',
        res('next() moves to the first CI and returns true. When the result is empty it returns false and the rule declines with null.'),
        '    var match = %s.getUniqueValue();' % var,
        res('match = the 32-character sys_id of that CI, for example "%s"; this is the value the framework expects back.' % ID_A),
        '    if (%s.hasNext())' % var,
        '        return null;',
        res('hasNext() is true when a second CI is waiting in the result: two owners of one value is an ambiguity, so the rule declines.'),
        '    return match;',
        res('exactly one CI: its sys_id goes back to the framework, which links the vulnerable item to it and stops evaluating later rules.'),
    ])


def st_serial_clean(n, value):
    return '\n'.join([
        stage(n, 'Clean the serial number',
              "'' + sourceValue turns the platform value into a plain text string and trim() removes blanks at both ends. Blanks inside the value stay, because they are part of the serial.",
              'some feeds pad values with blanks; a search for " MXQ13005TC " would not find "MXQ13005TC".',
              'serial = "%s".' % value),
        "    var serial = ('' + sourceValue).trim();",
        res('serial = "%s" (%d characters).' % (value, len(value))),
    ])


def st_serial_junk(n, value):
    low = value.lower()
    return '\n'.join([
        stage(n, 'Reject placeholder serial numbers',
              'the rule keeps a list of placeholder serials that vendors ship on thousands of machines ("To Be Filled By O.E.M.", "System Serial Number", "0123456789", "None" and so on) and refuses to search for any of them, or for a serial shorter than four characters.',
              'a placeholder would match dozens of CIs at once and the tie could never be broken; declining at once lets the name and address rules do the work instead.',
              '"%s" is %d characters long and is not in the list -> carry on. "N/A" would be found as ",n/a," in the list -> decline. "12" is shorter than four characters -> decline.' % (low, len(value))),
        "    var junk = ',0,none,n/a,na,unknown,empty,not specified,not available,no serial,' +",
        "        'default string,to be filled by o.e.m.,system serial number,chassis serial number,' +",
        "        '0123456789,1234567890,';",
        res('junk = one long text with a comma before and after every placeholder, so that "," + serial + "," can only be found when the whole serial equals a placeholder (",na," is never found inside ",not available,").'),
        "    if (serial.length < 4 || junk.indexOf(',' + serial.toLowerCase() + ',') != -1)",
        '        return null;',
        res('serial.toLowerCase() = "%s"; junk.indexOf(",%s,") = -1 (not found) and the length is %d -> the condition is false -> carry on.' % (low, low, len(value))),
    ])


def st_ip_clean(n, ip):
    return '\n'.join([
        stage(n, 'Clean the address and reject addresses that identify nothing',
              "'' + sourceValue turns the value into plain text and trim() removes blanks at both ends. Then the rule refuses loopback addresses (127.x.x.x) and link-local addresses (169.254.x.x).",
              'every machine answers on 127.0.0.1, and 169.254.x.x addresses are self-assigned when no network is available, so neither can ever point at one CI.',
              'ip = "%s" -> neither prefix matches -> carry on.' % ip),
        "    var ip = ('' + sourceValue).trim();",
        res('ip = "%s".' % ip),
        "    if (!ip || ip.indexOf('127.') == 0 || ip.indexOf('169.254.') == 0)",
        '        return null;',
        res('indexOf("127.") == 0 would mean the text starts with "127."; for "%s" both indexOf calls return -1 -> the condition is false -> carry on.' % ip),
    ])


def st_fqdn_clean(n, fqdn, bare, next_rules):
    return '\n'.join([
        stage(n, 'Clean the DNS name and require a domain part',
              "'' + sourceValue turns the value into plain text, trim() removes blanks at both ends and toLowerCase() lowers it. Then the rule requires at least one dot in the name.",
              'DNS names are case-insensitive and CMDB values are stored in mixed case, so both sides are compared in lower case. A name without a dot is a bare hostname, which %s look after.' % next_rules,
              'fqdn = "%s"; indexOf(".") finds a dot -> carry on. A bare label "%s" has no dot -> indexOf(".") = -1 -> decline.' % (fqdn, bare)),
        "    var fqdn = ('' + sourceValue).trim().toLowerCase();",
        res('fqdn = "%s".' % fqdn),
        "    if (fqdn.indexOf('.') == -1)",
        '        return null;',
        res('indexOf(".") = %d for the sample (the position of the first dot) -> not -1 -> carry on.' % fqdn.index('.')),
    ])


def st_ip_note(n, ip):
    return '\n'.join([
        stage(n, 'Note the scanned IP address for tie-breaks',
              'copies the IP field of the payload into plain text, or an empty text when the payload has none.',
              'the IP is not used to search; it is only used later to choose between two CIs that both carry the scanned name.',
              'ip = "%s".' % ip),
        "    var ip = sourcePayload.IP ? '' + sourcePayload.IP : '';",
        res('ip = "%s" (or "" when the payload has no IP field).' % ip),
    ])


def st_lb_helper(n):
    return '\n'.join([
        stage(n, 'The helper isLoadBalancer(id)',
              'defines a small helper used later: it reports true when the CI with the given sys_id is stored in the Load Balancer class (cmdb_ci_lb) or one of its sub-classes.',
              'a load balancer answers on virtual addresses on behalf of the pool members behind it; a scanned address that belongs to such a virtual IP describes a pool member, not the balancer, so the balancer must never be returned.',
              'isLoadBalancer("%s") = true when that sys_id is the Load Balancer "lb-sdi-core-01"; false for the ESX Server "vsdnac22xsdi009".' % ID_B),
        '    function isLoadBalancer(id) {',
        "        var lb = new GlideRecord('cmdb_ci_lb');",
        res('lb = a search on the Load Balancer class; isValid() is false when that class is not installed', indent='        '),
        '        return lb.isValid() && lb.get(id);',
        res('get(id) returns true only when a load balancer with that sys_id exists', indent='        '),
        '    }',
    ])


def pick_fqdn_block(n, fqdn, ip, ci_name, cls_label, run_table_desc):
    return '\n'.join([
        stage(n, 'The helper pickFqdn(table)',
              'defines the helper used in the next stage. It searches one table for CIs whose fqdn field equals the scanned name (ignored classes left out), collects the sys_id of every CI found, notes which of them also carry the scanned IP address, and decides: one CI -> that CI; several CIs but exactly one with the scanned IP -> that one; anything else -> null.',
              'an FQDN is meant to be unique, but CMDBs do carry duplicates: a retired server and its rebuilt replacement, or a cluster alias loaded on two nodes. The scanned IP is the second piece of evidence that can safely break such a tie; without it the rule declines rather than guess.',
              'the %s "%s" (sys_id %s) has fqdn = "%s" -> ids = ["%s"], ipHits = ["%s"] because its ip_address is also "%s" -> ids.length == 1 -> return "%s".' % (cls_label, ci_name, ID_A, fqdn, ID_A, ID_A, ip, ID_A)),
        '    function pickFqdn(table) {',
        '        var gr = new GlideRecord(table);',
        res('gr = a search on the table given (the class and every class beneath it); nothing has run yet', indent='        '),
        '        if (!gr.isValid())',
        '            return null;',
        res('isValid() is false only when the class does not exist on this instance; then the helper declines rather than fail', indent='        '),
        "        gr.addQuery('fqdn', fqdn);",
        res('condition added: fqdn = "%s" (exact match, case-insensitive)' % fqdn, indent='        '),
        '        if (ignore)',
        "            gr.addQuery('sys_class_name', 'NOT IN', ignore);",
        res('condition added: sys_class_name NOT IN (%s)' % IGN.replace(',', ', '), indent='        '),
        '        gr.query();',
        res('the search has run; gr sits before the first row of the result', indent='        '),
        '        var ids = [];',
        '        var ipHits = [];',
        res('two empty lists: ids will hold every CI found, ipHits the ones that also carry the scanned IP', indent='        '),
        '        while (gr.next()) {',
        res('each pass of the loop looks at one CI of the result', indent='            '),
        '            ids.push(gr.getUniqueValue());',
        res('ids = ["%s"] after the first CI, ["%s", "%s"] when a second one exists' % (ID_A, ID_A, ID_B), indent='            '),
        "            if (ip && gr.getValue('ip_address') == ip)",
        '                ipHits.push(gr.getUniqueValue());',
        res('ipHits = ["%s"] when this CI\'s ip_address field is "%s"; unchanged otherwise' % (ID_A, ip), indent='            '),
        '        }',
        '        if (ids.length == 1)',
        '            return ids[0];',
        res('exactly one CI carries the FQDN -> its sys_id is the answer', indent='        '),
        '        if (ids.length > 1 && ipHits.length == 1)',
        '            return ipHits[0];',
        res('two or more CIs carry the FQDN and exactly one of them also has the scanned IP -> that one is the answer', indent='        '),
        '        return null;',
        res('no CI, or several CIs without a single IP confirmation -> decline', indent='        '),
        '    }',
        '',
        stage(n + 1, 'Run the helper %s' % run_table_desc, None, None),
    ])


def pick_combo_block(n, full, host, domain, ip, ci_name, cls_label):
    return '\n'.join([
        stage(n, 'The helper pickCombo(table)',
              "defines the helper used in the next stage. It searches one table for CIs whose name is the short hostname, and keeps a CI only when the CI's own domain information agrees with the scanned domain: its fqdn equals the scanned name, or its dns_domain equals the scanned domain, or its fqdn starts with the hostname and contains the scanned domain. Then it decides: one confirmed CI -> that CI; several but exactly one with the scanned IP -> that one; anything else -> null.",
              'the same short hostname can exist in several domains (a test and a production machine both called app01). Requiring domain evidence on the CI itself stops the findings from landing on the namesake in another domain.',
              'the %s "%s" (sys_id %s) has dns_domain = "%s" -> confirmed -> good = ["%s"]; a CI "%s" with dns_domain = "lab.example.net" is skipped -> good.length == 1 -> return "%s".' % (cls_label, ci_name, ID_A, domain, ID_A, ci_name, ID_A)),
        '    function pickCombo(table) {',
        '        var gr = new GlideRecord(table);',
        res('gr = a search on the table given (the class and every class beneath it)', indent='        '),
        '        if (!gr.isValid())',
        '            return null;',
        res('the class does not exist on this instance -> decline rather than fail', indent='        '),
        "        gr.addQuery('name', host);",
        res('condition added: name = "%s" (CMDB names compare case-insensitively, so "%s" is found too)' % (host, host.upper()), indent='        '),
        '        if (ignore)',
        "            gr.addQuery('sys_class_name', 'NOT IN', ignore);",
        res('condition added: sys_class_name NOT IN (%s)' % IGN.replace(',', ', '), indent='        '),
        '        gr.query();',
        res('the search has run; every CI named "%s" in the table is in the result' % host, indent='        '),
        '        var good = [];',
        '        var ipHits = [];',
        res('two empty lists: good will hold the CIs whose domain evidence agrees, ipHits those of them that also carry the scanned IP', indent='        '),
        '        while (gr.next()) {',
        res('each pass of the loop looks at one CI named "%s"' % host, indent='            '),
        "            var cifqdn = ('' + gr.getValue('fqdn')).toLowerCase();",
        res('cifqdn = the CI\'s own fqdn in lower case, for example "%s", or "" when the field is empty' % full, indent='            '),
        "            var cidom = ('' + gr.getValue('dns_domain')).toLowerCase();",
        res('cidom = the CI\'s own dns_domain in lower case, for example "%s", or "" when empty' % domain, indent='            '),
        '            if (cifqdn == full || cidom == domain ||',
        "                (cifqdn && cifqdn.indexOf(host + '.') == 0 && cifqdn.indexOf(domain) > 0)) {",
        res('the CI confirms the domain in one of three ways: its fqdn is the scanned name; its dns_domain is the scanned domain; or its fqdn starts with "%s." and contains "%s" somewhere after it.' % (host, domain), indent='                '),
        '                good.push(gr.getUniqueValue());',
        res('good = ["%s"] after the first confirmed CI' % ID_A, indent='                '),
        "                if (ip && gr.getValue('ip_address') == ip)",
        '                    ipHits.push(gr.getUniqueValue());',
        res('ipHits = ["%s"] when this CI\'s ip_address is also "%s"' % (ID_A, ip), indent='                '),
        '            }',
        res('a CI named "%s" whose domain evidence disagrees (another domain, or no domain at all) is simply skipped' % host, indent='            '),
        '        }',
        '        if (good.length == 1)',
        '            return good[0];',
        res('exactly one CI has the name and the domain -> its sys_id is the answer', indent='        '),
        '        if (good.length > 1 && ipHits.length == 1)',
        '            return ipHits[0];',
        res('several confirmed CIs, and exactly one of them also carries the scanned IP -> that one is the answer', indent='        '),
        '        return null;',
        res('no confirmed CI, or several without a single IP confirmation -> decline', indent='        '),
        '    }',
    ])


def write(order, name, text):
    fn = os.path.join(OUT, '%s_%s.js' % (order, name.replace(' ', '_')))
    open(fn, 'w').write(text.rstrip('\n') + '\n')
    return fn


RULES = []

# ================================================================== 175
def rule_175():
    order, name = '175', 'USEM Serial Number Class Match'
    value = 'VMware-42 1a 9c 3f 7d 2e 61 b8-55 04 e2 91 6a 27 c3 08'
    payload = {"ID": "35832680", "IP": "171.128.225.96", "TRACKING_METHOD": "AGENT", "OS": "Red Hat Enterprise Linux 9.8",
               "DNS": "ah-1047132-001.sdi.corp.bankofamerica.com", "SERIAL_NUMBER": value}
    h = header(order, name,
        'Match a scanned host to its CI by serial number, but only inside the CMDB class that the scanned operating system implies. A serial number is the strongest identifier a physical or virtual machine has, so this is the first USEM rule in the chain.',
        payload, 'SERIAL_NUMBER', value, 'the OS',
        'the Linux Server CI "ah-1047132-001" whose serial_number field holds the same serial; its sys_id is returned. If no Linux Server carries the serial, or two do, the rule returns null.',
        'nothing custom runs before it. Serial numbers come first because a serial belongs to one machine for its whole life, while names and addresses are reused.',
        'every Qualys host that reports a SERIAL_NUMBER. Today only hosts scanned by the authenticated Cloud Agent report one; unauthenticated network scans leave the field empty and those hosts skip straight to the name rules.',
        '180 repeats the serial search across every hardware class for hosts whose OS gives no class or whose CI is classed differently; 200 and above move on to names and, last of all, addresses.',
        ['Check that Qualys sent a serial number', 'Clean the serial number', 'Reject placeholder serial numbers',
         'Read the list of CI classes that must never be matched', 'Work out the CMDB class from the scanned operating system',
         'Search that class for the serial', 'Decide: exactly one CI, or decline'])
    body = [OPEN,
        st_check(1, 'a serial number', value),
        st_serial_clean(2, value),
        st_serial_junk(3, value),
        st_ignore(4),
        st_classfor(5, 'Red Hat Enterprise Linux 9.8',
            's = "red hat enterprise linux 9.8"; s.split("/") has 1 part (not a multi-guess); "esx", "windows", "aix", "solaris", "sunos", "hp-ux", "netapp", "ontap", "printer", "laserjet" and "jetdirect" are not found; "red hat" is found',
            'cmdb_ci_linux_server', 'Linux Server', True, 'rule 180 (which searches all hardware without a class)'),
        stage(6, 'Search that class for the serial',
              'opens a search on the class chosen above (which automatically includes its sub-classes), keeps only CIs whose serial_number equals the cleaned serial, and leaves out every class on the ignore list.',
              'the serial must match exactly (no wildcard) and inside the agreed class only, so class evidence and serial evidence have to agree before the rule trusts the result.',
              'the search on cmdb_ci_linux_server for serial_number = "%s" finds the Linux Server "ah-1047132-001" (sys_id %s). A Windows Server with the same serial is outside the class and never appears in the result.' % (value, ID_A)),
        '    var gr = new GlideRecord(pref);',
        res('gr = a search on the Linux Server class and every class beneath it; nothing has run yet.'),
        '    if (!gr.isValid())',
        '        return null;',
        res('isValid() is false only when the class does not exist on this instance (a plugin not installed); then the rule declines rather than fail.'),
        "    gr.addQuery('serial_number', serial);",
        res('condition added: serial_number = "%s" (exact match, case-insensitive).' % value),
        '    if (ignore)',
        "        gr.addQuery('sys_class_name', 'NOT IN', ignore);",
        res('condition added: sys_class_name NOT IN (%s), so an ignored class can never appear in the result.' % IGN.replace(',', ', ')),
        st_decide(7, 'gr', 'the Linux Server "ah-1047132-001" -> return "%s"' % ID_A, 'return null and rule 180 gets its turn',
                  '"ah-1047132-001" and a second Linux Server loaded twice with the same serial -> return null'),
        CLOSE]
    return write(order, name, h + '\n' + '\n'.join(body))
RULES.append(rule_175)

# ================================================================== 180
def rule_180():
    order, name = '180', 'USEM Serial Number Hardware Match'
    value = 'MXQ13005TC'
    payload = {"ID": "35920204", "IP": "171.135.28.125", "TRACKING_METHOD": "IP", "OS": MULTI,
               "DNS": "txr9gxcenah031.sdi.corp.bankofamerica.com", "SERIAL_NUMBER": value}
    h = header(order, name,
        'Match a scanned host to its CI by serial number anywhere in the hardware tree (servers, computers, network gear, storage, printers). It is the second and last serial stage: it runs when rule 175 could not use the class the OS implies, and it still insists on the serial belonging to exactly one CI.',
        payload, 'SERIAL_NUMBER', value, '',
        'the one hardware CI whose serial_number is "MXQ13005TC", for example the Server CI "txr9gxcenah031" (stored in the generic Server class because the scan could not identify its OS); its sys_id is returned.',
        '175 already tried the serial inside the class the OS implies.',
        'hosts with a serial whose OS is unknown (the sample OS is an unauthenticated scan listing seven guesses, so no class can be chosen) or whose CI sits in a different class than the OS suggests, so that 175 found nothing.',
        '200 and above switch to names and addresses. A serial that is not unique in the whole hardware tree is never used.',
        ['Check that Qualys sent a serial number', 'Clean the serial number', 'Reject placeholder serial numbers',
         'Read the list of CI classes that must never be matched', 'Search the whole hardware tree for the serial',
         'Decide: exactly one CI, or decline'])
    body = [OPEN,
        st_check(1, 'a serial number', value),
        st_serial_clean(2, value),
        st_serial_junk(3, value),
        st_ignore(4),
        stage(5, 'Search the whole hardware tree for the serial',
              'opens a search on cmdb_ci_hardware, the parent class of every physical and virtual device class (Server, Linux Server, Windows Server, Computer, Network Gear, Storage Server, Printer and so on), keeps only CIs whose serial_number equals the cleaned serial, and leaves out every class on the ignore list. No class preference is used at this stage.',
              'the OS gave no usable class, so the serial itself has to carry the decision; that is safe because the next stage still requires the serial to belong to exactly one CI in the whole tree.',
              'the search on cmdb_ci_hardware for serial_number = "MXQ13005TC" finds the Server "txr9gxcenah031" (sys_id %s).' % ID_A),
        "    var gr = new GlideRecord('cmdb_ci_hardware');",
        res('gr = a search on Hardware and every class beneath it; nothing has run yet.'),
        "    gr.addQuery('serial_number', serial);",
        res('condition added: serial_number = "MXQ13005TC" (exact match, case-insensitive).'),
        '    if (ignore)',
        "        gr.addQuery('sys_class_name', 'NOT IN', ignore);",
        res('condition added: sys_class_name NOT IN (%s).' % IGN.replace(',', ', ')),
        st_decide(6, 'gr', 'the Server "txr9gxcenah031" -> return "%s"' % ID_A, 'return null and rule 200 gets its turn',
                  '"txr9gxcenah031" and a Storage Server that was loaded with the same serial -> return null'),
        CLOSE]
    return write(order, name, h + '\n' + '\n'.join(body))
RULES.append(rule_180)

# ================================================================== 200
def rule_200():
    order, name = '200', 'USEM Cisco IP Phone MAC'
    value = 'sep64f69dd5c9b0.voip.bankofamerica.com'
    payload = {"ID": "41277345", "IP": "30.144.62.108", "TRACKING_METHOD": "IP", "OS": "Cisco IP Phone", "DNS": value}
    h = header(order, name,
        'Match Cisco IP phones. Cisco Unified Communications Manager names every phone "SEP" followed by the phone\'s MAC address, and Qualys reports that name as the DNS host label. The rule turns the label back into a MAC address and looks for exactly one IP Phone CI that carries it.',
        payload, 'DNS', value, '',
        'the IP Phone CI whose network adapter, mac_address field or name carries the MAC 64:F6:9D:D5:C9:B0, for example the phone named "SEP64F69DD5C9B0"; its sys_id is returned. Any DNS name that does not follow the SEP pattern makes the rule decline at once.',
        '175 and 180 handled serial numbers (phones report none).',
        'only hosts whose DNS label reads SEP plus twelve hexadecimal characters; every other host passes through untouched.',
        '250 and above are the name rules. Phones are resolved here first so a phone label can never be mistaken for a server name, and so a MAC address clash can never pull in a server or a switch: this rule only ever searches IP Phone CIs.',
        ['Check that Qualys sent a DNS name', 'Take the first label of the DNS name', 'Recognise the SEP pattern and extract the MAC address',
         'Spell the MAC address the four ways CMDBs store it', 'Read the list of CI classes that must never be matched',
         'Attempt 1: a network adapter with that MAC that belongs to an IP phone', 'Attempt 2: the MAC stored on the IP phone record itself',
         'Attempt 3: an IP phone named with its Unified CM device name'])
    body = [OPEN,
        st_check(1, 'a DNS name', value),
        stage(2, 'Take the first label of the DNS name',
              'splits the DNS name at the dots, keeps the first part and lowers it.',
              'the phone identity is in the first label only; the rest ("voip.bankofamerica.com") is the telephony domain shared by every phone.',
              '"%s" -> split(".") = ["sep64f69dd5c9b0", "voip", "bankofamerica", "com"] -> [0] = "sep64f69dd5c9b0".' % value),
        "    var label = ('' + sourceValue).split('.')[0].toLowerCase();",
        res('label = "sep64f69dd5c9b0".'),
        stage(3, 'Recognise the SEP pattern and extract the MAC address',
              'checks the label against the pattern "sep" followed by exactly twelve hexadecimal characters (0 to 9, a to f) and nothing else. When it fits, the twelve characters are kept as the MAC address.',
              'a server named "sepulveda01" must not be treated as a phone, so the pattern is strict: exactly "sep", exactly twelve hex characters, from the start to the end of the label.',
              '"sep64f69dd5c9b0" fits -> hex = "64f69dd5c9b0". "wsaoi01zeapd1" does not fit -> the rule declines and the host goes on to the name rules.'),
        '    var m = label.match(/^sep([0-9a-f]{12})$/);',
        res('m = ["sep64f69dd5c9b0", "64f69dd5c9b0"] (the whole match and the captured twelve characters), or null when the label does not fit.'),
        '    if (!m)',
        '        return null;',
        res('m is null for every host that is not a phone -> decline; for the sample m is filled -> carry on.'),
        '    var hex = m[1];',
        res('hex = "64f69dd5c9b0".'),
        stage(4, 'Spell the MAC address the four ways CMDBs store it',
              'cuts the twelve characters into six pairs, joins them with colons, and prepares four spellings: colon-separated upper case, colon-separated lower case, plain upper case and plain lower case.',
              'different discovery tools write MAC addresses differently; searching all four spellings at once means the phone is found whichever tool created its record.',
              'pairs = ["64", "f6", "9d", "d5", "c9", "b0"]; colon = "64:f6:9d:d5:c9:b0"; candidates = ["64:F6:9D:D5:C9:B0", "64:f6:9d:d5:c9:b0", "64F69DD5C9B0", "64f69dd5c9b0"].'),
        '    var pairs = [];',
        res('pairs = [] (empty list to start with).'),
        '    for (var i = 0; i < 12; i += 2)',
        '        pairs.push(hex.substr(i, 2));',
        res('i takes the values 0, 2, 4, 6, 8, 10; substr(i, 2) cuts two characters at each position -> pairs = ["64", "f6", "9d", "d5", "c9", "b0"].'),
        "    var colon = pairs.join(':');",
        res('colon = "64:f6:9d:d5:c9:b0".'),
        '    var candidates = [colon.toUpperCase(), colon, hex.toUpperCase(), hex];',
        res('candidates = ["64:F6:9D:D5:C9:B0", "64:f6:9d:d5:c9:b0", "64F69DD5C9B0", "64f69dd5c9b0"].'),
        st_ignore(5),
        stage(6, 'Attempt 1: a network adapter with that MAC that belongs to an IP phone',
              'searches the Network Adapter table for adapters whose mac_address is one of the four spellings and that belong to a CI, then keeps only the owners that really are IP Phone CIs, each counted once.',
              'discovery tools usually store the MAC on the adapter record, not on the phone itself. Checking that the owner is an IP Phone guarantees that a switch or server adapter with a colliding MAC is never returned.',
              'adapter "eth0" with mac_address "64:F6:9D:D5:C9:B0" belongs to the IP Phone "SEP64F69DD5C9B0" (sys_id %s) -> phones = {"%s": true}, count = 1, first = "%s" -> return "%s".' % (ID_A, ID_A, ID_A, ID_A)),
        "    var nic = new GlideRecord('cmdb_ci_network_adapter');",
        res('nic = a search on the Network Adapter table.'),
        "    nic.addQuery('mac_address', 'IN', candidates.join(','));",
        res('condition added: mac_address IN ("64:F6:9D:D5:C9:B0", "64:f6:9d:d5:c9:b0", "64F69DD5C9B0", "64f69dd5c9b0").'),
        "    nic.addNotNullQuery('cmdb_ci');",
        res('condition added: cmdb_ci is not empty, so only adapters that belong to a CI are considered.'),
        '    nic.query();',
        res('the search has run; nic sits before the first adapter of the result.'),
        '    var phones = {};',
        '    var count = 0, first = null;',
        res('phones = {} (phone CIs already counted, keyed by sys_id), count = 0, first = null.'),
        '    while (nic.next()) {',
        res('each pass of the loop looks at one adapter carrying the MAC.', indent='        '),
        "        var owner = nic.getValue('cmdb_ci');",
        res('owner = the sys_id of the CI that owns the adapter, for example "%s".' % ID_A, indent='        '),
        "        var phone = new GlideRecord('cmdb_ci_ip_phone');",
        '        if (phone.get(owner) && !phones[owner]) {',
        res('phone.get(owner) is true only when that CI is an IP Phone; !phones[owner] is true the first time this phone is seen.', indent='            '),
        '            phones[owner] = true;',
        '            count++;',
        '            if (count == 1)',
        '                first = owner;',
        res('phones = {"%s": true}, count = 1, first = "%s" after the first phone; a second, different phone would make count = 2.' % (ID_A, ID_A), indent='            '),
        '        }',
        res('an adapter owned by a server or a switch is skipped here, so it can never be counted.', indent='        '),
        '    }',
        '    if (count == 1)',
        '        return first;',
        res('exactly one phone owns an adapter with this MAC -> return its sys_id "%s". Zero phones -> attempt 2. Two phones -> attempt 2 as well, the record itself may settle it.' % ID_A),
        stage(7, 'Attempt 2: the MAC stored on the IP phone record itself',
              'searches the IP Phone table for phones whose own mac_address field is one of the four spellings (ignored classes left out) and accepts the phone only when it is the single one.',
              'some loads write the MAC on the phone record instead of an adapter record; this attempt covers them without ever leaving the IP Phone class.',
              'the IP Phone "SEP64F69DD5C9B0" with mac_address = "64F69DD5C9B0" -> byMac = "%s" and no second row -> return "%s".' % (ID_A, ID_A)),
        "    var ph = new GlideRecord('cmdb_ci_ip_phone');",
        res('ph = a search on the IP Phone class.'),
        "    ph.addQuery('mac_address', 'IN', candidates.join(','));",
        res('condition added: mac_address IN (the four spellings).'),
        '    if (ignore)',
        "        ph.addQuery('sys_class_name', 'NOT IN', ignore);",
        res('condition added: sys_class_name NOT IN (%s).' % IGN.replace(',', ', ')),
        '    ph.query();',
        res('the search has run.'),
        '    if (ph.next()) {',
        res('at least one phone carries the MAC on its record.', indent='        '),
        '        var byMac = ph.getUniqueValue();',
        res('byMac = the sys_id of that phone, for example "%s".' % ID_A, indent='        '),
        '        if (!ph.hasNext())',
        '            return byMac;',
        res('no second phone -> return "%s". A second phone with the same MAC -> fall through to attempt 3.' % ID_A, indent='        '),
        '    }',
        stage(8, 'Attempt 3: an IP phone named with its Unified CM device name',
              'searches the IP Phone table for a phone whose name is the label in upper case ("SEP64F69DD5C9B0"), the device name Unified CM assigns, and accepts it only when it is the single one.',
              'a phone loaded from the call manager export has no MAC on either record, but it is named exactly like the DNS label; this attempt catches those without loosening any check.',
              'the IP Phone named "SEP64F69DD5C9B0" -> named = "%s" and no second row -> return "%s". No phone at all -> return null and the host continues to rule 250.' % (ID_A, ID_A)),
        "    var byName = new GlideRecord('cmdb_ci_ip_phone');",
        res('byName = a search on the IP Phone class.'),
        "    byName.addQuery('name', label.toUpperCase());",
        res('condition added: name = "SEP64F69DD5C9B0".'),
        '    if (ignore)',
        "        byName.addQuery('sys_class_name', 'NOT IN', ignore);",
        res('condition added: sys_class_name NOT IN (%s).' % IGN.replace(',', ', ')),
        '    byName.query();',
        res('the search has run.'),
        '    if (!byName.next())',
        '        return null;',
        res('no phone with that name -> decline; the host goes on to the name rules, which will not recognise a SEP label either, so it ends up unmatched for review.'),
        '    var named = byName.getUniqueValue();',
        res('named = "%s".' % ID_A),
        '    if (byName.hasNext())',
        '        return null;',
        res('two phones with the same device name -> ambiguous -> decline.'),
        '    return named;',
        res('exactly one phone -> its sys_id goes back to the framework.'),
        CLOSE]
    return write(order, name, h + '\n' + '\n'.join(body))
RULES.append(rule_200)

# ================================================================== 250
def rule_250():
    order, name = '250', 'USEM FQDN Class Match'
    value = 'vsdnac22xsdi004.sdi.corp.bankofamerica.com'
    payload = {"ID": "83047612", "IP": "30.206.199.36", "TRACKING_METHOD": "IP", "OS": "VMware ESXi 7.0.3 build 24723872", "DNS": value}
    h = header(order, name,
        'Match a scanned host by its fully qualified domain name (FQDN) stored in the fqdn field of a CI, inside the CMDB class the scanned OS implies. An exact FQDN on the CI is the most precise name evidence there is, so this is the first name rule after the phone rule.',
        payload, 'DNS', value, 'the OS and the IP',
        'the ESX Server CI whose fqdn field is "vsdnac22xsdi004.sdi.corp.bankofamerica.com"; its sys_id is returned. Two ESX Servers with that fqdn are accepted only when exactly one of them also carries the IP 30.206.199.36.',
        '175/180 (serial numbers) and 200 (phone labels) found nothing.',
        'every host with a dotted DNS name, which is the bulk of the Qualys feed.',
        '260 repeats the exact FQDN search across every hardware class; 300 and 310 fall back to hostname plus domain evidence; 400 and 410 to the short hostname alone.',
        ['Check that Qualys sent a DNS name', 'Clean the DNS name and require a domain part', 'Note the scanned IP address for tie-breaks',
         'Read the list of CI classes that must never be matched', 'Work out the CMDB class from the scanned operating system',
         'The helper pickFqdn(table)', 'Run the helper inside the class the OS implies'])
    body = [OPEN,
        st_check(1, 'a DNS name', value),
        st_fqdn_clean(2, value, 'vsdnac22xsdi004', 'the hostname rules (400 and above)'),
        st_ip_note(3, '30.206.199.36'),
        st_ignore(4),
        st_classfor(5, 'VMware ESXi 7.0.3 build 24723872', 's = "vmware esxi 7.0.3 build 24723872"; s.split("/") has 1 part; "esx" is found straight away',
                    'cmdb_ci_esx_server', 'ESX Server', True, 'rule 260 (which searches all hardware without a class)'),
        pick_fqdn_block(6, value, '30.206.199.36', 'vsdnac22xsdi004', 'ESX Server', 'inside the class the OS implies'),
        '    return pickFqdn(pref);',
        res('pickFqdn("cmdb_ci_esx_server") -> "%s" for the sample; that sys_id goes back to the framework, which links the vulnerable item to the ESX Server "vsdnac22xsdi004" and stops evaluating later rules. null makes the host continue to rule 260.' % ID_A),
        CLOSE]
    return write(order, name, h + '\n' + '\n'.join(body))
RULES.append(rule_250)

# ================================================================== 260
def rule_260():
    order, name = '260', 'USEM FQDN Hardware Match'
    value = 'txr9gxcenah031.sdi.corp.bankofamerica.com'
    payload = {"ID": "35920204", "IP": "171.135.28.125", "TRACKING_METHOD": "IP", "OS": MULTI, "DNS": value}
    h = header(order, name,
        'Match by exact FQDN anywhere in the hardware tree. This is the second FQDN stage, for hosts whose OS gives no class or whose CI is classed differently from the OS.',
        payload, 'DNS', value, 'the IP',
        'the one hardware CI whose fqdn is "txr9gxcenah031.sdi.corp.bankofamerica.com", for example the Server CI "txr9gxcenah031"; duplicates are resolved by the IP 171.135.28.125 or declined.',
        '250 tried the exact FQDN inside the class the OS implies.',
        'hosts whose OS gives no class (the sample is an unauthenticated scan with seven guesses) or whose CI is classed differently from the OS, so 250 found nothing.',
        '300 and 310 use hostname plus domain evidence for CIs that carry no fqdn value at all.',
        ['Check that Qualys sent a DNS name', 'Clean the DNS name and require a domain part', 'Note the scanned IP address for tie-breaks',
         'Read the list of CI classes that must never be matched', 'The helper pickFqdn(table)', 'Run the helper on the whole hardware tree'])
    body = [OPEN,
        st_check(1, 'a DNS name', value),
        st_fqdn_clean(2, value, 'txr9gxcenah031', 'the hostname rules (400 and above)'),
        st_ip_note(3, '171.135.28.125'),
        st_ignore(4),
        pick_fqdn_block(5, value, '171.135.28.125', 'txr9gxcenah031', 'Server', 'on the whole hardware tree'),
        "    return pickFqdn('cmdb_ci_hardware');",
        res('pickFqdn("cmdb_ci_hardware") searches Hardware and every class beneath it -> "%s" for the sample; null makes the host continue to rule 300.' % ID_A),
        CLOSE]
    return write(order, name, h + '\n' + '\n'.join(body))
RULES.append(rule_260)


def st_split(n, full, host, domain, ip_after):
    return '\n'.join([
        stage(n, 'Clean the DNS name and split it into hostname and domain',
              "'' + sourceValue turns the value into plain text, trim() removes blanks at both ends, toLowerCase() lowers it. indexOf(\".\") finds the first dot; the text before it is the short hostname and the text after it is the domain.",
              'the rule needs both halves: the hostname to find candidate CIs by name, and the domain to confirm that a candidate really belongs to the scanned domain. A name without a dot has no domain to confirm, so the rule declines and leaves it to the hostname rules (400 and above).',
              'full = "%s"; dot = %d; host = "%s"; domain = "%s".' % (full, full.index('.'), host, domain)),
        "    var full = ('' + sourceValue).trim().toLowerCase();",
        res('full = "%s".' % full),
        "    var dot = full.indexOf('.');",
        res('dot = %d, the position of the first dot (positions count from 0).' % full.index('.')),
        '    if (dot < 1)',
        '        return null;',
        res('dot = -1 (no dot) or 0 (the name starts with a dot) -> decline; %d -> carry on.' % full.index('.')),
        '    var host = full.substring(0, dot);',
        res('host = "%s" (everything before the first dot).' % host),
        '    var domain = full.substring(dot + 1);',
        res('domain = "%s" (everything after the first dot).' % domain),
    ])


# ================================================================== 300
def rule_300():
    order, name = '300', 'USEM Hostname Domain Class Match'
    value = 'ah-1047132-001.sdi.corp.bankofamerica.com'
    payload = {"ID": "35832680", "IP": "171.128.225.96", "TRACKING_METHOD": "AGENT", "OS": "Red Hat Enterprise Linux 9.8", "DNS": value,
               "QG_HOSTID": "633769a4-0139-0002-e352-005056bf41ea"}
    h = header(order, name,
        'Match by the combination of short hostname and domain, inside the class the OS implies. It serves CIs that are named with the short hostname and carry the domain in another field (dns_domain or fqdn) instead of an exact fqdn value.',
        payload, 'DNS', value, 'the OS and the IP',
        'the Linux Server CI named "ah-1047132-001" whose dns_domain is "sdi.corp.bankofamerica.com" (or whose fqdn is the scanned name); a namesake in another domain is never picked.',
        '250/260 looked for the exact FQDN in the fqdn field.',
        'hosts whose CI has no exact fqdn value but is named with the short hostname and shows the domain elsewhere.',
        '310 repeats the search across all hardware; 350 uses the layered DNS records; 400/410 accept a unique short name without any domain evidence.',
        ['Check that Qualys sent a DNS name', 'Clean the DNS name and split it into hostname and domain', 'Note the scanned IP address for tie-breaks',
         'Read the list of CI classes that must never be matched', 'Work out the CMDB class from the scanned operating system',
         'The helper pickCombo(table)', 'Run the helper inside the class the OS implies'])
    body = [OPEN,
        st_check(1, 'a DNS name', value),
        st_split(2, value, 'ah-1047132-001', 'sdi.corp.bankofamerica.com', '171.128.225.96'),
        st_ip_note(3, '171.128.225.96'),
        st_ignore(4),
        st_classfor(5, 'Red Hat Enterprise Linux 9.8',
            's = "red hat enterprise linux 9.8"; s.split("/") has 1 part; "esx", "windows", "aix", "solaris", "sunos", "hp-ux", "netapp", "ontap", "printer", "laserjet" and "jetdirect" are not found; "red hat" is found',
            'cmdb_ci_linux_server', 'Linux Server', True, 'rule 310 (which searches all hardware without a class)'),
        pick_combo_block(6, value, 'ah-1047132-001', 'sdi.corp.bankofamerica.com', '171.128.225.96', 'ah-1047132-001', 'Linux Server'),
        stage(7, 'Run the helper inside the class the OS implies', None, None),
        '    return pickCombo(pref);',
        res('pickCombo("cmdb_ci_linux_server") -> "%s" for the sample; that sys_id goes back to the framework, which links the vulnerable item to the Linux Server "ah-1047132-001" and stops evaluating later rules. null makes the host continue to rule 310.' % ID_A),
        CLOSE]
    return write(order, name, h + '\n' + '\n'.join(body))
RULES.append(rule_300)

# ================================================================== 310
def rule_310():
    order, name = '310', 'USEM Hostname Domain Hardware Match'
    value = 'lrche01xtrapd01.sdi.corp.bankofamerica.com'
    payload = {"ID": "35884392", "IP": "171.128.140.192", "TRACKING_METHOD": "IP", "OS": "Ubuntu/Linux", "DNS": value}
    h = header(order, name,
        'Match by short hostname plus domain evidence anywhere in the hardware tree. This is the second combination stage, for hosts whose CI is classed generically (Server, Computer) or differently from the OS.',
        payload, 'DNS', value, 'the IP',
        'the hardware CI named "lrche01xtrapd01" whose fqdn is "lrche01xtrapd01.sdi.corp.bankofamerica.com" or whose dns_domain is "sdi.corp.bankofamerica.com", for example a CI in the generic Server class.',
        '300 tried hostname plus domain inside the class the OS implies (Linux Server for the sample OS "Ubuntu/Linux").',
        'hosts whose CI is classed generically (Server, Computer) or differently from the scanned OS, so the class-scoped search found nothing.',
        '350 (layered DNS records) and 400/410 (short hostname without domain evidence).',
        ['Check that Qualys sent a DNS name', 'Clean the DNS name and split it into hostname and domain', 'Note the scanned IP address for tie-breaks',
         'Read the list of CI classes that must never be matched', 'The helper pickCombo(table)', 'Run the helper on the whole hardware tree'])
    body = [OPEN,
        st_check(1, 'a DNS name', value),
        st_split(2, value, 'lrche01xtrapd01', 'sdi.corp.bankofamerica.com', '171.128.140.192'),
        st_ip_note(3, '171.128.140.192'),
        st_ignore(4),
        pick_combo_block(5, value, 'lrche01xtrapd01', 'sdi.corp.bankofamerica.com', '171.128.140.192', 'lrche01xtrapd01', 'Server'),
        stage(6, 'Run the helper on the whole hardware tree', None, None),
        "    return pickCombo('cmdb_ci_hardware');",
        res('pickCombo("cmdb_ci_hardware") searches Hardware and every class beneath it -> "%s" for the sample; null makes the host continue to rule 350.' % ID_A),
        CLOSE]
    return write(order, name, h + '\n' + '\n'.join(body))
RULES.append(rule_310)

# ================================================================== 350
def rule_350():
    order, name = '350', 'USEM Layered DNS Match'
    value = 'hklvteqoradbp3.hk.baml.com'
    payload = {"ID": "42773078", "IP": "167.202.60.26", "TRACKING_METHOD": "IP", "OS": "Red Hat Enterprise Linux Server 7.9", "DNS": value,
               "QG_HOSTID": "6337dede-02e7-0002-ad2c-0050569765df"}
    h = header(order, name,
        'Match through the layered network model that CMDB discovery maintains: a DNS Name record is linked to an IP Address record, the IP Address record belongs to a Network Adapter, and the adapter belongs to the CI. This finds hosts whose name is not written on the CI record at all, and it also resolves aliases.',
        payload, 'DNS', value, 'the IP',
        'the CI at the end of the chain DNS Name "hklvteqoradbp3.hk.baml.com" -> IP Address "167.202.60.26" -> adapter "eth0" -> Linux Server "hklvteqoradbp3"; when several CIs answer to the name, the one whose chain runs through the scanned IP is taken.',
        '250 to 310 looked at name fields stored on the CI record itself.',
        'hosts whose name lives only in the layered DNS records, and aliases that point at an address of the device.',
        '400/410 (short hostname alone) and 450 (CI named with the full FQDN).',
        ['Check that Qualys sent a DNS name', 'Clean the DNS name and require a domain part', 'Note the scanned IP address for tie-breaks',
         'Read the list of CI classes that must never be matched', 'Search the chain DNS Name -> IP Address -> adapter -> CI',
         'Collect the owning CIs', 'Decide: one owner, or the owner confirmed by the scanned IP'])
    body = [OPEN,
        st_check(1, 'a DNS name', value),
        st_fqdn_clean(2, value, 'hklvteqoradbp3', 'the hostname rules (400 and above)'),
        st_ip_note(3, '167.202.60.26'),
        st_ignore(4),
        stage(5, 'Search the chain DNS Name -> IP Address -> adapter -> CI',
              'searches the link table cmdb_ip_address_dns_name, whose rows tie one DNS Name record to one IP Address record. Through dot-walking (field.field.field) the conditions reach the other records of the chain: dns_name.name is the name on the DNS Name record, ip_address.nic.cmdb_ci is the CI that owns the adapter that holds the IP Address record. Rows whose chain ends nowhere, or on an ignored class, are left out.',
              'discovery writes names and addresses as separate records linked to the device instead of on the device record; this is the only rule that can see those, and because the chain ends on whatever device actually holds the address, an alias resolves to the real machine.',
              'the link row DNS Name "hklvteqoradbp3.hk.baml.com" <-> IP Address "167.202.60.26"; the IP Address record belongs to adapter "eth0"; adapter "eth0" belongs to the Linux Server "hklvteqoradbp3" (sys_id %s).' % ID_A),
        "    var gr = new GlideRecord('cmdb_ip_address_dns_name');",
        res('gr = a search on the IP Address to DNS Name link table.'),
        '    if (!gr.isValid())',
        '        return null;',
        res('the layered model is not installed on this instance -> decline rather than fail.'),
        "    gr.addQuery('dns_name.name', fqdn);",
        res('condition added: the linked DNS Name record is named "%s".' % value),
        "    gr.addNotNullQuery('ip_address.nic.cmdb_ci');",
        res('condition added: the linked IP Address record belongs to an adapter (nic) that belongs to a CI (cmdb_ci); chains that stop early are left out.'),
        '    if (ignore)',
        "        gr.addQuery('ip_address.nic.cmdb_ci.sys_class_name', 'NOT IN', ignore);",
        res('condition added: the class of the CI at the end of the chain is NOT IN (%s).' % IGN.replace(',', ', ')),
        '    gr.query();',
        res('the search has run; each row of the result is one name-to-address link whose chain ends on a CI.'),
        stage(6, 'Collect the owning CIs',
              'walks the result rows and records each distinct CI at the end of a chain; separately, records which of those CIs are reached through the scanned IP address.',
              'one device with several addresses appears once per address, so each CI must be counted once; the IP bookkeeping prepares the tie-break of the next stage.',
              'one row -> owners = {"%s": true}, count = 1, first = "%s"; because the row\'s IP Address record is "167.202.60.26", ipOwners = {"%s": true}.' % (ID_A, ID_A, ID_A)),
        '    var owners = {};',
        '    var ipOwners = {};',
        '    var count = 0, first = null;',
        res('owners = {} (every CI seen, keyed by sys_id), ipOwners = {} (the CIs reached through the scanned IP), count = 0, first = null.'),
        '    while (gr.next()) {',
        res('each pass of the loop looks at one link row.', indent='        '),
        "        var owner = '' + gr.ip_address.nic.cmdb_ci;",
        res('owner = the sys_id of the CI at the end of this row\'s chain, for example "%s".' % ID_A, indent='        '),
        '        if (!owners[owner]) {',
        '            owners[owner] = true;',
        '            count++;',
        '            if (count == 1)',
        '                first = owner;',
        '        }',
        res('the first time a CI is seen: owners gains it, count grows by one, and first remembers the very first CI. A second row for the same CI changes nothing.', indent='        '),
        "        if (ip && ('' + gr.ip_address.ip_address) == ip)",
        '            ipOwners[owner] = true;',
        res('when this row\'s IP Address record equals the scanned IP "167.202.60.26", the CI is noted in ipOwners.', indent='        '),
        '    }',
        stage(7, 'Decide: one owner, or the owner confirmed by the scanned IP',
              'accepts the single CI when exactly one was collected. When several CIs answer to the name, accepts the one CI that was reached through the scanned IP, provided there is exactly one such CI. Otherwise declines.',
              'a name that resolves to two devices (an alias moved between hosts, an old and a new record) must not be guessed; the scanned address is the additional evidence that makes the choice safe.',
              'count = 1 -> return "%s". count = 2 with ipOwners = {"%s": true} -> return "%s". count = 2 with ipOwners empty or holding both -> return null.' % (ID_A, ID_A, ID_A)),
        '    if (count == 1)',
        '        return first;',
        res('one CI at the end of every chain -> its sys_id goes back to the framework.'),
        '    if (count > 1) {',
        '        var confirmed = Object.keys(ipOwners);',
        res('confirmed = the list of CIs reached through the scanned IP, for example ["%s"].' % ID_A, indent='        '),
        '        if (confirmed.length == 1)',
        '            return confirmed[0];',
        res('exactly one CI confirmed by the address -> return it.', indent='        '),
        '    }',
        '    return null;',
        res('no CI, or several without a single IP confirmation -> decline; the host continues to rule 400.'),
        CLOSE]
    return write(order, name, h + '\n' + '\n'.join(body))
RULES.append(rule_350)


def st_short(n, full, host):
    return '\n'.join([
        stage(n, 'Clean the DNS name and take the short hostname',
              "'' + sourceValue turns the value into plain text, trim() removes blanks at both ends, toLowerCase() lowers it, and split(\".\")[0] keeps the text before the first dot.",
              'CIs without domain information carry only the short name, so the short name is what has to be compared. A bare label with no dot works as well: split gives the whole text back.',
              'full = "%s"; split(".") = %s; host = "%s".' % (full, json.dumps(full.split('.')), host)),
        "    var full = ('' + sourceValue).trim().toLowerCase();",
        res('full = "%s".' % full),
        "    var host = full.split('.')[0];",
        res('host = "%s".' % host),
        '    if (!host)',
        '        return null;',
        res('host is empty only for a name that starts with a dot -> decline; "%s" -> carry on.' % host),
    ])


# ================================================================== 400
def rule_400():
    order, name = '400', 'USEM Hostname Class Match'
    value = 'wsaoi01zeapd1.sdi.corp.bankofamerica.com'
    payload = {"ID": "35850078", "IP": "30.143.70.11", "TRACKING_METHOD": "IP", "OS": "Windows Server 2016 Standard 64 bit Edition Version 1607",
               "DNS": value, "NETBIOS": "WSAOI01ZEAPD1"}
    h = header(order, name,
        'Match by the short hostname alone, inside the class the OS implies. This is for CIs that carry only a short name and no domain information; the agreement between the CI class and the scanned OS replaces the missing domain evidence.',
        payload, 'DNS', value, 'the OS',
        'the Windows Server CI named "WSAOI01ZEAPD1" (names compare case-insensitively, so "wsaoi01zeapd1" finds it); a second Windows Server with the same name makes the rule decline.',
        '250 to 350 needed domain evidence on the CI (fqdn, dns_domain or the layered DNS records).',
        'hosts whose CI carries only a short name and no domain information at all.',
        '410 repeats the short name search across all hardware with a class sanity check; 450 handles CIs named with the full FQDN.',
        ['Check that Qualys sent a DNS name', 'Clean the DNS name and take the short hostname', 'Read the list of CI classes that must never be matched',
         'Work out the CMDB class from the scanned operating system', 'Search that class for the short name', 'Decide: exactly one CI, or decline'])
    body = [OPEN,
        st_check(1, 'a DNS name', value),
        st_short(2, value, 'wsaoi01zeapd1'),
        st_ignore(3),
        st_classfor(4, 'Windows Server 2016 Standard 64 bit Edition Version 1607',
            's = "windows server 2016 standard 64 bit edition version 1607"; s.split("/") has 1 part; "esx" is not found; "windows" is found and "server" is found too',
            'cmdb_ci_win_server', 'Windows Server', True, 'rule 410 (which searches all hardware without a class)'),
        stage(5, 'Search that class for the short name',
              'opens a search on the class chosen above (and its sub-classes), keeps only CIs whose name equals the short hostname, and leaves out every class on the ignore list.',
              'with no domain to confirm, the class is the only safeguard against a namesake; inside the agreed class the short name still has to be unique (next stage).',
              'the search on cmdb_ci_win_server for name = "wsaoi01zeapd1" finds the Windows Server "WSAOI01ZEAPD1" (sys_id %s).' % ID_A),
        '    var gr = new GlideRecord(pref);',
        res('gr = a search on the Windows Server class and every class beneath it.'),
        '    if (!gr.isValid())',
        '        return null;',
        res('the class does not exist on this instance -> decline rather than fail.'),
        "    gr.addQuery('name', host);",
        res('condition added: name = "wsaoi01zeapd1"; CMDB names compare case-insensitively, so "WSAOI01ZEAPD1" is found.'),
        '    if (ignore)',
        "        gr.addQuery('sys_class_name', 'NOT IN', ignore);",
        res('condition added: sys_class_name NOT IN (%s).' % IGN.replace(',', ', ')),
        st_decide(6, 'gr', 'the Windows Server "WSAOI01ZEAPD1" -> return "%s"' % ID_A, 'return null and rule 410 gets its turn',
                  'two Windows Servers named "WSAOI01ZEAPD1" (for example one retired and one rebuilt) -> return null'),
        CLOSE]
    return write(order, name, h + '\n' + '\n'.join(body))
RULES.append(rule_400)


GENERIC_STAGE = ('lists the classes that say nothing about the operating system: Hardware, Computer, Server and UNIX Server. A CI stored in one of these never contradicts the scan.',
                 'many CIs are loaded into the generic Server class before discovery refines them; rejecting those would leave a large part of the estate unmatched for no good reason.')


# ================================================================== 410
def rule_410():
    order, name = '410', 'USEM Hostname Hardware Match'
    value = 'va2ausapabw0.bankofamerica.com'
    payload = {"ID": "80217765", "IP": "171.150.219.123", "TRACKING_METHOD": "IP", "OS": "AIX 7.3 TL3", "DNS": value,
               "QG_HOSTID": "6337e0dc-007d-0002-c47d-005056a4fcd5"}
    h = header(order, name,
        'Match by the short hostname anywhere in the hardware tree, with a sanity check that the CI found does not contradict the scanned OS. This is the second short-name stage, for CIs classed generically (Server, Computer, UNIX Server) or differently from the OS.',
        payload, 'DNS', value, 'the OS',
        'the one hardware CI named "va2ausapabw0"; accepted when it is an AIX Server or a generically classed Server, rejected when it is, say, a Windows Server (an AIX scan cannot belong to a Windows machine).',
        '400 required the short name to be unique inside the class the OS implies.',
        'hosts whose CI is classed generically (Server, Computer, UNIX Server) or whose OS gave no class, so 400 found nothing.',
        '450 (CI named with the full FQDN) and then the IP rules (700 and above) for hosts without a usable name.',
        ['Check that Qualys sent a DNS name', 'Clean the DNS name and take the short hostname', 'Read the list of CI classes that must never be matched',
         'Work out the CMDB class from the scanned operating system (a preference, not a requirement)', 'List the classes that never contradict the scan',
         'Search the whole hardware tree for the short name', 'Require exactly one owner', 'Reject an owner whose class contradicts the scanned OS', 'Return the owner'])
    body = [OPEN,
        st_check(1, 'a DNS name', value),
        st_short(2, value, 'va2ausapabw0'),
        st_ignore(3),
        st_classfor(4, 'AIX 7.3 TL3', 's = "aix 7.3 tl3"; s.split("/") has 1 part; "esx" and "windows" are not found; "aix" is found',
                    'cmdb_ci_aix_server', 'AIX Server', False, ''),
        res('unlike rule 400, an empty pref does not stop this rule: the search below runs without a class, and stage 8 simply has nothing to check.'),
        stage(5, 'List the classes that never contradict the scan', GENERIC_STAGE[0], GENERIC_STAGE[1],
              'generic["cmdb_ci_server"] = 1 (true), generic["cmdb_ci_win_server"] = undefined (false).'),
        '    var generic = {cmdb_ci_hardware: 1, cmdb_ci_computer: 1, cmdb_ci_server: 1,',
        '        cmdb_ci_unix_server: 1};',
        res('generic = a lookup table with the four class names; generic[cls] answers "is this class generic?".'),
        stage(6, 'Search the whole hardware tree for the short name',
              'opens a search on cmdb_ci_hardware, the parent class of every device class, keeps only CIs whose name equals the short hostname, and leaves out every class on the ignore list.',
              'the class-scoped search of rule 400 found nothing, so the name is now searched everywhere; the safety comes from the two checks that follow.',
              'the search on cmdb_ci_hardware for name = "va2ausapabw0" finds the Server "va2ausapabw0" (sys_id %s, class cmdb_ci_server).' % ID_A),
        "    var gr = new GlideRecord('cmdb_ci_hardware');",
        res('gr = a search on Hardware and every class beneath it.'),
        "    gr.addQuery('name', host);",
        res('condition added: name = "va2ausapabw0" (case-insensitive).'),
        '    if (ignore)',
        "        gr.addQuery('sys_class_name', 'NOT IN', ignore);",
        res('condition added: sys_class_name NOT IN (%s).' % IGN.replace(',', ', ')),
        '    gr.query();',
        res('the search has run.'),
        stage(7, 'Require exactly one owner',
              'reads the first CI, remembers its sys_id and its class, and declines when a second CI carries the same name.',
              'two hardware CIs with one short name (a test and a production machine, a retired and a rebuilt one) can never be told apart by the name alone.',
              'one row -> id = "%s", cls = "cmdb_ci_server". Two rows -> return null.' % ID_A),
        '    if (!gr.next())',
        '        return null;',
        res('no CI has this name -> decline; the host continues to rule 450.'),
        '    var id = gr.getUniqueValue();',
        res('id = "%s".' % ID_A),
        "    var cls = '' + gr.getValue('sys_class_name');",
        res('cls = "cmdb_ci_server" (the exact class of the CI found).'),
        '    if (gr.hasNext())',
        '        return null;',
        res('a second CI with the same name is waiting in the result -> ambiguous -> decline.'),
        stage(8, 'Reject an owner whose class contradicts the scanned OS',
              'when the OS gave a class preference, checks that the CI found sits inside that class (or one of its sub-classes) or is generically classed; any other class is a contradiction and the rule declines.',
              'a host scanned as AIX that resolves by name to a Windows Server CI is a namesake, not the same machine; linking the findings there would send AIX vulnerabilities to a Windows owner.',
              'pref = "cmdb_ci_aix_server"; chk.get("%s") on the AIX Server class is false because the CI is a plain Server, but generic["cmdb_ci_server"] is true -> accepted. For a Windows Server CI both checks fail -> return null.' % ID_A),
        '    if (pref) {',
        '        var chk = new GlideRecord(pref);',
        res('chk = a search on the AIX Server class and its sub-classes.', indent='        '),
        '        if (!(chk.isValid() && chk.get(id)) && !generic[cls])',
        '            return null;',
        res('chk.get(id) is true when the CI is an AIX Server; generic[cls] is true when it is generically classed; when neither holds the CI contradicts the scan -> decline.', indent='        '),
        '    }',
        stage(9, 'Return the owner', None, None),
        '    return id;',
        res('the sys_id "%s" goes back to the framework, which links the vulnerable item to the CI and stops evaluating later rules.' % ID_A),
        CLOSE]
    return write(order, name, h + '\n' + '\n'.join(body))
RULES.append(rule_410)

# ================================================================== 450
def rule_450():
    order, name = '450', 'USEM FQDN Name Hardware Match'
    value = 'lva40bneehcs01.ecomm.devicenp.rpg'
    payload = {"ID": "71973166", "IP": "164.91.209.12", "TRACKING_METHOD": "AGENT", "OS": "Red Hat Enterprise Linux 8.10", "DNS": value,
               "QG_HOSTID": "633781ed-019b-0002-2f2f-0050569d20ff"}
    h = header(order, name,
        'Match CIs whose name field holds the complete FQDN string, in the hardware tree. Some CMDB loads (typically the appliance domains ending in .rpg) name the CI with the whole FQDN, so a short-name search can never find them.',
        payload, 'DNS', value, '',
        'the hardware CI whose name is exactly "lva40bneehcs01.ecomm.devicenp.rpg"; its sys_id is returned when it is the only one.',
        'every rule so far compared the short hostname or the fqdn field.',
        'CIs named with the full FQDN, which none of the earlier rules can see.',
        '700 and above (IP address rules) and finally 850, the only rule allowed to search the broad cmdb_ci table by name.',
        ['Check that Qualys sent a DNS name', 'Clean the DNS name and require a domain part', 'Read the list of CI classes that must never be matched',
         'Search the whole hardware tree for a CI named with the full FQDN', 'Decide: exactly one CI, or decline'])
    body = [OPEN,
        st_check(1, 'a DNS name', value),
        st_fqdn_clean(2, value, 'lva40bneehcs01', 'the hostname rules (400 and 410)'),
        st_ignore(3),
        stage(4, 'Search the whole hardware tree for a CI named with the full FQDN',
              'opens a search on cmdb_ci_hardware, keeps only CIs whose name equals the complete lower-cased DNS name, and leaves out every class on the ignore list.',
              'the name field is compared with the whole string including the domain, which is exactly what the earlier rules never did.',
              'the search on cmdb_ci_hardware for name = "%s" finds the Server "%s" (sys_id %s).' % (value, value, ID_A)),
        "    var gr = new GlideRecord('cmdb_ci_hardware');",
        res('gr = a search on Hardware and every class beneath it.'),
        "    gr.addQuery('name', fqdn);",
        res('condition added: name = "%s" (the full string, case-insensitive).' % value),
        '    if (ignore)',
        "        gr.addQuery('sys_class_name', 'NOT IN', ignore);",
        res('condition added: sys_class_name NOT IN (%s).' % IGN.replace(',', ', ')),
        st_decide(5, 'gr', 'the Server "%s" -> return "%s"' % (value, ID_A), 'return null and the host continues to the IP rules (700 and above)',
                  'two hardware CIs with that full name -> return null'),
        CLOSE]
    return write(order, name, h + '\n' + '\n'.join(body))
RULES.append(rule_450)

# ================================================================== 700
IP_PAYLOAD = {"ID": "83047621", "IP": "30.162.178.21", "TRACKING_METHOD": "IP", "OS": "VMware ESXi 7.0.3 build 24723872"}

def rule_700():
    order, name = '700', 'USEM IP Class Match'
    value = '30.162.178.21'
    h = header(order, name,
        'Match by IP address, inside the class the OS implies. An address is the least trustworthy identifier (addresses move between machines and are shared by load balancers), so it is used only when the host has no serial and no usable name, and only when exactly one CI of the agreed class carries it.',
        IP_PAYLOAD, 'IP', value, 'the OS',
        'the ESX Server CI whose ip_address is "30.162.178.21", for example "vsdnac22xsdi009"; a load balancer or a Windows CI with the same address is outside the class and cannot be picked.',
        'all serial and name rules (175 to 450). The sample has no DNS name at all, so every name rule declined.',
        'DNS-less hosts, typically ESXi management interfaces and appliances (89 of the 21,000 hosts in the reference extract).',
        '705 searches the address across all hardware with extra safety checks; 730 and 740 resolve it through adapters and the layered IP records.',
        ['Check that Qualys sent an IP address', 'Clean the address and reject addresses that identify nothing', 'Read the list of CI classes that must never be matched',
         'Work out the CMDB class from the scanned operating system', 'Search that class for the address', 'Decide: exactly one CI, or decline'])
    body = [OPEN,
        st_check(1, 'an IP address', value),
        st_ip_clean(2, value),
        st_ignore(3),
        st_classfor(4, 'VMware ESXi 7.0.3 build 24723872', 's = "vmware esxi 7.0.3 build 24723872"; s.split("/") has 1 part; "esx" is found straight away',
                    'cmdb_ci_esx_server', 'ESX Server', True, 'rule 705 (which searches all hardware without a class)'),
        stage(5, 'Search that class for the address',
              'opens a search on the class chosen above (and its sub-classes), keeps only CIs whose ip_address field equals the scanned address, and leaves out every class on the ignore list.',
              'inside the agreed class an address is reasonably safe: a virtual IP of a load balancer, or a Windows machine that inherited the address, sits outside the ESX Server class and never appears.',
              'the search on cmdb_ci_esx_server for ip_address = "30.162.178.21" finds the ESX Server "vsdnac22xsdi009" (sys_id %s).' % ID_A),
        '    var gr = new GlideRecord(pref);',
        res('gr = a search on the ESX Server class and every class beneath it.'),
        '    if (!gr.isValid())',
        '        return null;',
        res('the class does not exist on this instance -> decline rather than fail.'),
        "    gr.addQuery('ip_address', ip);",
        res('condition added: ip_address = "30.162.178.21" (exact match).'),
        '    if (ignore)',
        "        gr.addQuery('sys_class_name', 'NOT IN', ignore);",
        res('condition added: sys_class_name NOT IN (%s).' % IGN.replace(',', ', ')),
        st_decide(6, 'gr', 'the ESX Server "vsdnac22xsdi009" -> return "%s"' % ID_A, 'return null and rule 705 gets its turn',
                  'two ESX Servers carrying "30.162.178.21" (an address reused after a rebuild) -> return null'),
        CLOSE]
    return write(order, name, h + '\n' + '\n'.join(body))
RULES.append(rule_700)

# ================================================================== 705
def rule_705():
    order, name = '705', 'USEM IP Hardware Match'
    value = '30.162.178.21'
    h = header(order, name,
        'Match by IP address anywhere in the hardware tree, with two extra safety checks: the CI must not be a load balancer, and its class must not contradict the scanned OS.',
        IP_PAYLOAD, 'IP', value, 'the OS',
        'the one hardware CI whose ip_address is "30.162.178.21", accepted when it is an ESX Server or generically classed; rejected when it is a Load Balancer (a virtual address answered on behalf of pool members) or a CI of a contradicting class such as Windows Server.',
        '700 required the address to belong to one CI of the OS-implied class.',
        'DNS-less hosts whose CI is classed generically (Server) or whose OS gave no class.',
        '730 (address on a network adapter) and 740 (layered IP Address records).',
        ['Check that Qualys sent an IP address', 'Clean the address and reject addresses that identify nothing', 'Read the list of CI classes that must never be matched',
         'Work out the CMDB class from the scanned operating system (a preference, not a requirement)', 'List the classes that never contradict the scan',
         'The helper isLoadBalancer(id)', 'Search the whole hardware tree for the address', 'Require exactly one owner', 'Reject a load balancer',
         'Reject an owner whose class contradicts the scanned OS', 'Return the owner'])
    body = [OPEN,
        st_check(1, 'an IP address', value),
        st_ip_clean(2, value),
        st_ignore(3),
        st_classfor(4, 'VMware ESXi 7.0.3 build 24723872', 's = "vmware esxi 7.0.3 build 24723872"; s.split("/") has 1 part; "esx" is found straight away',
                    'cmdb_ci_esx_server', 'ESX Server', False, ''),
        res('an empty pref does not stop this rule: the search below runs without a class, and stage 10 simply has nothing to check.'),
        stage(5, 'List the classes that never contradict the scan', GENERIC_STAGE[0], GENERIC_STAGE[1],
              'generic["cmdb_ci_server"] = 1 (true), generic["cmdb_ci_win_server"] = undefined (false).'),
        '    var generic = {cmdb_ci_hardware: 1, cmdb_ci_computer: 1, cmdb_ci_server: 1,',
        '        cmdb_ci_unix_server: 1};',
        res('generic = a lookup table with the four class names; generic[cls] answers "is this class generic?".'),
        st_lb_helper(6),
        stage(7, 'Search the whole hardware tree for the address',
              'opens a search on cmdb_ci_hardware, keeps only CIs whose ip_address field equals the scanned address, and leaves out every class on the ignore list.',
              'the class-scoped search of rule 700 found nothing, so the address is now searched everywhere; the safety comes from the three checks that follow.',
              'the search on cmdb_ci_hardware for ip_address = "30.162.178.21" finds the Server "vsdnac22xsdi009" (sys_id %s, class cmdb_ci_server).' % ID_A),
        "    var gr = new GlideRecord('cmdb_ci_hardware');",
        res('gr = a search on Hardware and every class beneath it.'),
        "    gr.addQuery('ip_address', ip);",
        res('condition added: ip_address = "30.162.178.21".'),
        '    if (ignore)',
        "        gr.addQuery('sys_class_name', 'NOT IN', ignore);",
        res('condition added: sys_class_name NOT IN (%s).' % IGN.replace(',', ', ')),
        '    gr.query();',
        res('the search has run.'),
        stage(8, 'Require exactly one owner',
              'reads the first CI, remembers its sys_id and its class, and declines when a second CI carries the same address.',
              'an address answered by several CIs (a shared virtual IP, an address reused after a rebuild) is never a safe match.',
              'one row -> id = "%s", cls = "cmdb_ci_server". Two rows -> return null.' % ID_A),
        '    if (!gr.next())',
        '        return null;',
        res('no CI carries the address -> decline; the host continues to rule 730.'),
        '    var id = gr.getUniqueValue();',
        res('id = "%s".' % ID_A),
        "    var cls = '' + gr.getValue('sys_class_name');",
        res('cls = "cmdb_ci_server" (the exact class of the CI found).'),
        '    if (gr.hasNext())',
        '        return null;',
        res('a second CI with the same address is waiting in the result -> ambiguous -> decline.'),
        stage(9, 'Reject a load balancer',
              'asks the helper whether the single owner is a Load Balancer CI and declines when it is.',
              'a scanned address that belongs to a virtual IP describes a pool member behind the balancer, not the balancer; the findings must not land on the balancer.',
              'isLoadBalancer("%s") = false for the Server "vsdnac22xsdi009" -> carry on; true for the Load Balancer "lb-sdi-core-01" -> return null.' % ID_A),
        '    if (isLoadBalancer(id))',
        '        return null;',
        res('for the sample the helper answers false and nothing happens.'),
        stage(10, 'Reject an owner whose class contradicts the scanned OS',
              'when the OS gave a class preference, checks that the CI found sits inside that class (or one of its sub-classes) or is generically classed; any other class is a contradiction and the rule declines.',
              'an ESXi scan that lands by address on a Windows Server CI is a reused address, not the same machine.',
              'pref = "cmdb_ci_esx_server"; chk.get("%s") on the ESX Server class is false because the CI is a plain Server, but generic["cmdb_ci_server"] is true -> accepted. For a Windows Server CI both checks fail -> return null.' % ID_A),
        '    if (pref) {',
        '        var chk = new GlideRecord(pref);',
        res('chk = a search on the ESX Server class and its sub-classes.', indent='        '),
        '        if (!(chk.isValid() && chk.get(id)) && !generic[cls])',
        '            return null;',
        res('chk.get(id) is true when the CI is an ESX Server; generic[cls] is true when it is generically classed; when neither holds the CI contradicts the scan -> decline.', indent='        '),
        '    }',
        stage(11, 'Return the owner', None, None),
        '    return id;',
        res('the sys_id "%s" goes back to the framework, which links the vulnerable item to the CI and stops evaluating later rules.' % ID_A),
        CLOSE]
    return write(order, name, h + '\n' + '\n'.join(body))
RULES.append(rule_705)

# ================================================================== 730
def rule_730():
    order, name = '730', 'USEM IP Adapter Match'
    value = '30.162.178.21'
    h = header(order, name,
        'Match by an IP address recorded on a Network Adapter record rather than on the CI itself (multi-homed servers, discovery-populated CIs). The adapter leads to its owning CI.',
        IP_PAYLOAD, 'IP', value, '',
        'the CI that owns the adapter carrying "30.162.178.21", for example adapter "vmk0" of the ESX Server "vsdnac22xsdi009"; declined when adapters of two different CIs carry the address or when the owner is a load balancer.',
        '700/705 looked for the address in the ip_address field of the CI record itself.',
        'hosts whose address is stored on an adapter record only.',
        '740 (layered IP Address records) and then the last-resort name rule 850.',
        ['Check that Qualys sent an IP address', 'Clean the address and reject addresses that identify nothing', 'Read the list of CI classes that must never be matched',
         'The helper isLoadBalancer(id)', 'Search the Network Adapter records for the address', 'Collect the owning CIs', 'Decide: one owner that is not a load balancer, or decline'])
    body = [OPEN,
        st_check(1, 'an IP address', value),
        st_ip_clean(2, value),
        st_ignore(3),
        st_lb_helper(4),
        stage(5, 'Search the Network Adapter records for the address',
              'searches the Network Adapter table for adapters whose ip_address equals the scanned address and that belong to a CI whose class is not on the ignore list.',
              'discovery stores one adapter record per network card of a device; a server with several cards keeps its addresses there instead of on the CI record.',
              'adapter "vmk0" with ip_address "30.162.178.21" belongs to the ESX Server "vsdnac22xsdi009" (sys_id %s).' % ID_A),
        "    var nic = new GlideRecord('cmdb_ci_network_adapter');",
        res('nic = a search on the Network Adapter table.'),
        "    nic.addQuery('ip_address', ip);",
        res('condition added: ip_address = "30.162.178.21".'),
        "    nic.addNotNullQuery('cmdb_ci');",
        res('condition added: cmdb_ci is not empty, so only adapters that belong to a CI are considered.'),
        '    if (ignore)',
        "        nic.addQuery('cmdb_ci.sys_class_name', 'NOT IN', ignore);",
        res('condition added: the class of the owning CI is NOT IN (%s).' % IGN.replace(',', ', ')),
        '    nic.query();',
        res('the search has run; each row is one adapter carrying the address.'),
        stage(6, 'Collect the owning CIs',
              'walks the adapters and records each distinct owning CI once.',
              'one device can have two adapters on the same address (a bonded pair); it must count as one owner, while two different devices must count as two.',
              'one adapter -> owners = {"%s": true}, count = 1, first = "%s".' % (ID_A, ID_A)),
        '    var owners = {};',
        '    var count = 0, first = null;',
        res('owners = {} (every CI seen, keyed by sys_id), count = 0, first = null.'),
        '    while (nic.next()) {',
        res('each pass of the loop looks at one adapter.', indent='        '),
        "        var owner = nic.getValue('cmdb_ci');",
        res('owner = the sys_id of the CI that owns this adapter, for example "%s".' % ID_A, indent='        '),
        '        if (!owners[owner]) {',
        '            owners[owner] = true;',
        '            count++;',
        '            if (count == 1)',
        '                first = owner;',
        '        }',
        res('the first time a CI is seen: owners gains it, count grows by one, and first remembers the very first CI. A second adapter of the same CI changes nothing.', indent='        '),
        '    }',
        stage(7, 'Decide: one owner that is not a load balancer, or decline',
              'accepts the single owner when exactly one CI was collected and it is not a Load Balancer; declines otherwise.',
              'two owners cannot be told apart by the address, and a load balancer answering on a virtual address is not the host that was scanned.',
              'count = 1 and isLoadBalancer("%s") = false -> return "%s". count = 2, or the owner is the Load Balancer "lb-sdi-core-01" -> return null.' % (ID_A, ID_A)),
        '    if (count == 1 && !isLoadBalancer(first))',
        '        return first;',
        res('exactly one owner and not a load balancer -> its sys_id goes back to the framework.'),
        '    return null;',
        res('no owner, several owners, or a load balancer -> decline; the host continues to rule 740.'),
        CLOSE]
    return write(order, name, h + '\n' + '\n'.join(body))
RULES.append(rule_730)

# ================================================================== 740
def rule_740():
    order, name = '740', 'USEM IP Layered Match'
    value = '30.162.178.21'
    h = header(order, name,
        'Match by IP address through the layered model that CMDB discovery maintains: an IP Address record belongs to a Network Adapter, and the adapter belongs to the CI.',
        IP_PAYLOAD, 'IP', value, '',
        'the CI at the end of the chain IP Address "30.162.178.21" -> adapter "vmk0" -> ESX Server "vsdnac22xsdi009"; declined for several owners or a load balancer.',
        '730 looked for the address on Network Adapter records.',
        'hosts whose address exists only as an IP Address record in the layered model.',
        '850, the last-resort broad name search; if that also declines, the out-of-box Qualys rules (860 and above) get their turn.',
        ['Check that Qualys sent an IP address', 'Clean the address and reject addresses that identify nothing', 'Read the list of CI classes that must never be matched',
         'The helper isLoadBalancer(id)', 'Search the IP Address records for the address', 'Collect the owning CIs', 'Decide: one owner that is not a load balancer, or decline'])
    body = [OPEN,
        st_check(1, 'an IP address', value),
        st_ip_clean(2, value),
        st_ignore(3),
        st_lb_helper(4),
        stage(5, 'Search the IP Address records for the address',
              'searches the IP Address table (cmdb_ci_ip_address) for records whose ip_address equals the scanned address and whose adapter (nic) belongs to a CI whose class is not on the ignore list. Through dot-walking, nic.cmdb_ci reaches the CI two links away.',
              'newer discovery writes each address as its own record linked to the adapter; rule 730 cannot see those because the adapter record itself may carry no address.',
              'the IP Address record "30.162.178.21" belongs to adapter "vmk0", which belongs to the ESX Server "vsdnac22xsdi009" (sys_id %s).' % ID_A),
        "    var ipGr = new GlideRecord('cmdb_ci_ip_address');",
        res('ipGr = a search on the IP Address table.'),
        '    if (!ipGr.isValid())',
        '        return null;',
        res('the layered model is not installed on this instance -> decline rather than fail.'),
        "    ipGr.addQuery('ip_address', ip);",
        res('condition added: ip_address = "30.162.178.21".'),
        "    ipGr.addNotNullQuery('nic.cmdb_ci');",
        res('condition added: the record belongs to an adapter (nic) that belongs to a CI (cmdb_ci).'),
        '    if (ignore)',
        "        ipGr.addQuery('nic.cmdb_ci.sys_class_name', 'NOT IN', ignore);",
        res('condition added: the class of the CI at the end of the chain is NOT IN (%s).' % IGN.replace(',', ', ')),
        '    ipGr.query();',
        res('the search has run; each row is one IP Address record carrying the address.'),
        stage(6, 'Collect the owning CIs',
              'walks the records and notes each distinct CI at the end of a chain once.',
              'a device may hold the same address on two adapters; it must count as one owner, while two different devices must count as two.',
              'one record -> owners = {"%s": true}, count = 1, first = "%s".' % (ID_A, ID_A)),
        '    var owners = {};',
        '    var count = 0, first = null;',
        res('owners = {} (every CI seen, keyed by sys_id), count = 0, first = null.'),
        '    while (ipGr.next()) {',
        res('each pass of the loop looks at one IP Address record.', indent='        '),
        "        var owner = '' + ipGr.nic.cmdb_ci;",
        res('owner = the sys_id of the CI at the end of this record\'s chain, for example "%s".' % ID_A, indent='        '),
        '        if (!owners[owner]) {',
        '            owners[owner] = true;',
        '            count++;',
        '            if (count == 1)',
        '                first = owner;',
        '        }',
        res('the first time a CI is seen: owners gains it, count grows by one, and first remembers the very first CI.', indent='        '),
        '    }',
        stage(7, 'Decide: one owner that is not a load balancer, or decline',
              'accepts the single owner when exactly one CI was collected and it is not a Load Balancer; declines otherwise.',
              'two owners cannot be told apart by the address, and a load balancer answering on a virtual address is not the host that was scanned.',
              'count = 1 and isLoadBalancer("%s") = false -> return "%s". count = 2, or the owner is a load balancer -> return null.' % (ID_A, ID_A)),
        '    if (count == 1 && !isLoadBalancer(first))',
        '        return first;',
        res('exactly one owner and not a load balancer -> its sys_id goes back to the framework.'),
        '    return null;',
        res('no owner, several owners, or a load balancer -> decline; the host continues to rule 850.'),
        CLOSE]
    return write(order, name, h + '\n' + '\n'.join(body))
RULES.append(rule_740)

# ================================================================== 850
def rule_850():
    order, name = '850', 'USEM FQDN Name Broad Match'
    value = 'lva40bneehcs01.ecomm.devicenp.rpg'
    payload = {"ID": "71973166", "IP": "164.91.209.12", "TRACKING_METHOD": "AGENT", "OS": "Red Hat Enterprise Linux 8.10", "DNS": value,
               "QG_HOSTID": "633781ed-019b-0002-2f2f-0050569d20ff"}
    h = header(order, name,
        'The single, deliberately late, broad fallback: a CI named with the full FQDN anywhere in the CI table, including classes outside the hardware tree (for example a virtual machine instance or another logical CI). It still requires a unique owner outside the ignored classes.',
        payload, 'DNS', value, '',
        'the one CI in any class whose name is "lva40bneehcs01.ecomm.devicenp.rpg", for example a Virtual Machine Instance; declined when the name is shared.',
        'every hardware-scoped rule (175 to 740) has declined for this host.',
        'the rare CI named with the full FQDN that lives outside the hardware tree.',
        'the out-of-box Qualys rules: 860 QUALYS HOST ID, 880 Cloud Resource Id, 900 FQDN, 920 NetBIOS, 940 DNS, and 950/960 IP which are inactive by default. Those are the vendor\'s best-effort matching.',
        ['Check that Qualys sent a DNS name', 'Clean the DNS name and require a domain part', 'Read the list of CI classes that must never be matched',
         'Search the whole CI table for a CI named with the full FQDN', 'Decide: exactly one CI, or decline'])
    body = [OPEN,
        st_check(1, 'a DNS name', value),
        st_fqdn_clean(2, value, 'lva40bneehcs01', 'the hostname rules (400 and 410)'),
        st_ignore(3),
        stage(4, 'Search the whole CI table for a CI named with the full FQDN',
              'opens a search on cmdb_ci, the root of every CI class, keeps only CIs whose name equals the complete lower-cased DNS name, and leaves out every class on the ignore list.',
              'this is the only USEM rule that searches outside the hardware tree, which is why it runs last: every more precise rule has had its chance, and the ignore list still keeps placeholder classes out.',
              'the search on cmdb_ci for name = "%s" finds the Virtual Machine Instance "%s" (sys_id %s).' % (value, value, ID_A)),
        "    var gr = new GlideRecord('cmdb_ci');",
        res('gr = a search on the root CI table, which covers every class.'),
        "    gr.addQuery('name', fqdn);",
        res('condition added: name = "%s" (the full string, case-insensitive).' % value),
        '    if (ignore)',
        "        gr.addQuery('sys_class_name', 'NOT IN', ignore);",
        res('condition added: sys_class_name NOT IN (%s).' % IGN.replace(',', ', ')),
        st_decide(5, 'gr', 'the Virtual Machine Instance "%s" -> return "%s"' % (value, ID_A),
                  'return null; the out-of-box Qualys rules (860 and above) get their turn and, if they also decline, the host stays unmatched for review',
                  'two CIs with that full name -> return null'),
        CLOSE]
    return write(order, name, h + '\n' + '\n'.join(body))
RULES.append(rule_850)


if __name__ == '__main__':
    os.makedirs(OUT, exist_ok=True)
    files = [f() for f in RULES]
    bad = []
    for fn in files:
        t = open(fn).read()
        if '...' in t or '…' in t:
            bad.append(fn)
    print('written', len(files), 'rule scripts;', 'ellipsis found in: %s' % bad if bad else 'no ellipsis anywhere')
