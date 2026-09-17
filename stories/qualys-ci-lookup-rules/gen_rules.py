"""Generates rules/<order>_<name>.js, the Qualys CI lookup rule scripts.

Each script opens with a short header (what the rule matches, the sample payload every note
refers to, what the rule reads and returns, where it sits in the chain) and carries a note on
each stage that does the matching, ending with what happens to the sample. Plumbing lines get
a single short comment or none.
"""
import json, os, re, textwrap

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'rules')
W = 100
MULTI = 'Ubuntu / Tiny Core Linux / Linux 2.6.x / IBM ASM / HP StoreOnce / F5 Networks Big-IP / Cisco IOS Software'


def wrap(text, width, first='', rest=''):
    return textwrap.wrap(text, width=width, initial_indent=first, subsequent_indent=rest,
                         break_long_words=False, break_on_hyphens=False)


def c(text, indent='    '):
    """A plain comment, wrapped."""
    return '\n'.join(indent + '// ' + l for l in wrap(text, W - len(indent) - 3))


def stage(title, text, sample, indent='    '):
    """A stage note: a short ruled title line, the explanation, then what happens to the sample."""
    head = indent + '// -- ' + title + ' '
    out = [head + '-' * max(3, W - len(head))]
    out += [indent + '// ' + l for l in wrap(text, W - len(indent) - 3)]
    out += [indent + '// ' + l for l in wrap(sample, W - len(indent) - 3, first='Sample: ', rest='        ')]
    return '\n'.join(out)


def header(name, purpose, payload, source, value, reads, result, outcome, before, reaches, after):
    w = W - 3
    L = ['/* ' + name, '   ' + '-' * w]
    L += ['   ' + l for l in wrap(purpose, w)]
    L += ['', '   Sample payload (one Qualys host record, used in every note below)']
    L += ['   ' + l for l in json.dumps(payload, indent=2).split('\n')]
    L += ['   ' + l for l in wrap('sourceValue is the %s field, "%s"%s.' % (source, value, ('; the rule also reads %s from sourcePayload' % reads) if reads else ''), w, first='Input  : ', rest='         ')]
    L += ['   ' + l for l in wrap(result, w, first='Returns: ', rest='         ')]
    L += ['   ' + l for l in wrap(outcome, w, first='Sample : ', rest='         ')]
    L.append('')
    L.append('   Place in the chain (the first rule to return a CI wins; a null hands the host to the next rule)')
    for lab, text in (('Before ', before), ('Reaches', reaches), ('After  ', after)):
        L += ['   ' + l for l in wrap(text, w, first='%s: ' % lab, rest='         ')]
    L.append('   ' + '-' * w + ' */')
    return '\n'.join(L)


OPEN = '(function process(rule, sourceValue, sourcePayload) {'
CLOSE = '})(rule, sourceValue, sourcePayload);'
IGNORE_BLOCK = '\n'.join([
    c('Classes that must never be matched (placeholder and technical CIs); the list lives in the property sn_sec_cmn.ignoreCIClass and the framework may pass it in as _ignoreClass.'),
    "    var ignore = (typeof _ignoreClass != 'undefined' && _ignoreClass) ?",
    "        ('' + _ignoreClass) : gs.getProperty('sn_sec_cmn.ignoreCIClass', '');",
])
CLASSFOR = '\n'.join([
    c('classFor() maps the OS text Qualys reports to the CMDB class the CI should be in, e.g. "Red Hat Enterprise Linux 9.8" is a Linux Server, "Windows Server 2016 Standard" a Windows Server and "VMware ESXi 7.0.3" an ESX Server. A string of guesses separated by "/" comes from an unauthenticated scan that could not identify the OS; three or more guesses give no class at all.'),
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
    c('A load balancer answers on virtual addresses for the servers behind it, so it is never the host that was scanned.'),
    '    function isLoadBalancer(id) {',
    "        var lb = new GlideRecord('cmdb_ci_lb');",
    '        return lb.isValid() && lb.get(id);',
    '    }',
])
AGREES = '\n'.join([
    c('agrees() decides whether a CI of class cls can be the scanned host once the OS gave a class: the same class, one of its sub-classes, or one of its parents (a Cisco IOS host may be kept as a plain Network Gear or Hardware record). Any other class is a different kind of machine: a Computer named or addressed like a router is a namesake or a reused address, never the router. With no class from the OS nothing is refused.'),
    '    function parentsOf(table) {                   // the class and every class above it',
    '        var out = [table];',
    "        var db = new GlideRecord('sys_db_object');",
    "        db.addQuery('name', table);",
    '        db.query();',
    "        while (db.next() && db.getValue('super_class')) {",
    "            var parent = '' + db.super_class.name;",
    '            out.push(parent);',
    "            db = new GlideRecord('sys_db_object');",
    "            db.addQuery('name', parent);",
    '            db.query();',
    '        }',
    '        return out;',
    '    }',
    '    function agrees(cls) {',
    '        if (!pref || cls == pref)',
    '            return true;',
    '        if (parentsOf(cls).indexOf(pref) != -1)     // cls is a sub-class of pref',
    '            return true;',
    '        return parentsOf(pref).indexOf(cls) != -1;   // cls is a parent of pref',
    '    }',
])
AGREES_APPLIANCE = '\n'.join([
    c('agrees() decides whether a CI of class cls can be the scanned host once the OS gave a class: the same class, one of its sub-classes, or one of its parents (a Cisco IOS host may be kept as a plain Network Gear or Hardware record). Any other class is a different kind of machine: a Windows Server named like the scanned Linux host is a namesake, never the host. With no class from the OS nothing is refused.'),
    '    //',
    c('A Linux fingerprint is also accepted against Network Gear, Load Balancer and Storage Server records: switches, balancers and storage nodes run Linux underneath and Qualys reports that kernel, so the fingerprint says nothing against those classes.'),
    '    function parentsOf(table) {                   // the class and every class above it',
    '        var out = [table];',
    "        var db = new GlideRecord('sys_db_object');",
    "        db.addQuery('name', table);",
    '        db.query();',
    "        while (db.next() && db.getValue('super_class')) {",
    "            var parent = '' + db.super_class.name;",
    '            out.push(parent);',
    "            db = new GlideRecord('sys_db_object');",
    "            db.addQuery('name', parent);",
    '            db.query();',
    '        }',
    '        return out;',
    '    }',
    '    function agrees(cls) {',
    '        if (!pref || cls == pref)',
    '            return true;',
    '        var above = parentsOf(cls);',
    "        var appliance = above.indexOf('cmdb_ci_netgear') != -1 ||",
    "            above.indexOf('cmdb_ci_lb') != -1 || above.indexOf('cmdb_ci_storage_server') != -1;",
    "        if (pref == 'cmdb_ci_linux_server' && appliance)   // an appliance reporting its Linux",
    '            return true;',
    '        if (above.indexOf(pref) != -1)               // cls is a sub-class of pref',
    '            return true;',
    '        return parentsOf(pref).indexOf(cls) != -1;   // cls is a parent of pref',
    '    }',
])
NAME_AGREES = '\n'.join([
    c('nameAgrees() checks the CI found against the host name the scan carries. Nothing is checked when the payload has no DNS or the CI has no name. Otherwise the first label of the CI name must equal the scanned label, or one must be the other plus a hyphenated tail ("<name>-mgmt" for a management interface, "<name>-a" for a node). A CI named after another machine sits on a reused address (a lease that moved, a decommissioned host whose address was handed on) and is not the scanned host, whatever its class.'),
    '    function nameAgrees(ciId) {',
    "        var label = ('' + (sourcePayload.DNS || '')).trim().toLowerCase().split('.')[0];",
    '        if (!label)',
    '            return true;',
    "        var ci = new GlideRecord('cmdb_ci');",
    '        ci.get(ciId);',
    "        var name = ('' + ci.getValue('name')).trim().toLowerCase().split('.')[0];",
    '        if (!name)',
    '            return true;',
    "        return name == label || label.indexOf(name + '-') == 0 || name.indexOf(label + '-') == 0;",
    '    }',
])
RETIRED = '\n'.join([
    c("retired() is the platform's own test for a decommissioned CI: install status Retired, operational status Retired, or a Retired life cycle stage."),
    '    function retired(ci) {',
    "        return ci.getValue('install_status') == '7' || ci.getValue('operational_status') == '6' ||",
    "            ci.life_cycle_stage_status.getDisplayValue() == 'Retired';",
    '    }',
])
PARENTS_OF = '\n'.join([
    '    function parentsOf(table) {                   // the class and every class above it',
    '        var out = [table];',
    "        var db = new GlideRecord('sys_db_object');",
    "        db.addQuery('name', table);",
    '        db.query();',
    "        while (db.next() && db.getValue('super_class')) {",
    "            var parent = '' + db.super_class.name;",
    '            out.push(parent);',
    "            db = new GlideRecord('sys_db_object');",
    "            db.addQuery('name', parent);",
    '            db.query();',
    '        }',
    '        return out;',
    '    }',
])


NARROW = '\n'.join([
    c('narrow() keeps the records carrying a flag when any does, so a record answering on the scanned address, or a live record, is preferred to the others without dropping the only records there are.'),
    '    function narrow(list, flag) {',
    '        var out = [];',
    '        for (var i = 0; i < list.length; i++)',
    '            if (list[i][flag])',
    '                out.push(list[i]);',
    '        return out.length ? out : list;',
    '    }',
])


def service_one(with_twins):
    """one(field, value): the virtual server carrying the value. Several records of one name are the
    same virtual server recorded more than once (an HA pair, a test copy): the records on the scanned
    address are kept, then the live ones. The service rule needs one record left; the member rule walks
    the pools of all of them. Two names decline."""
    L = ['    function one(field, value) {',
         '        if (!value)',
         '            return undefined;                     // nothing to search, next step',
         "        var gr = new GlideRecord('cmdb_ci_lb_service');",
         '        if (!gr.isValid())',
         '            return null;                          // class not installed here, decline',
         '        gr.addQuery(field, value);',
         '        if (ignore)',
         "            gr.addQuery('sys_class_name', 'NOT IN', ignore);",
         '        gr.query();',
         '        var rows = [], names = {};',
         '        while (gr.next()) {',
         "            names[('' + (gr.getValue('name') || '')).trim().toLowerCase()] = true;",
         "            rows.push({id: gr.getUniqueValue(), here: gr.getValue('ip_address') == ip,",
         '                live: !retired(gr)});',
         '        }',
         '        if (!rows.length)',
         '            return undefined;                     // nothing found, next step',
         '        if (Object.keys(names).length > 1)',
         '            return null;                          // two different services, never guess',
         "        rows = narrow(rows, 'here');              // the records answering on the scanned address",
         '        if (rows.length > 1)',
         "            rows = narrow(rows, 'live');          // the live records, a retired copy set aside"]
    if with_twins:
        L += ['        twins = [];',
              '        for (var w = 0; w < rows.length; w++)',
              '            twins.push(rows[w].id);',
              '        return twins[0];']
    else:
        L += ['        if (rows.length > 1)',
              '            return null;                          // two records still compete, never guess',
              '        return rows[0].id;']
    L.append('    }')
    return '\n'.join(L)


CHECK = '\n'.join(['    if (!sourceValue)                             // nothing to look up', '        return null;'])


def serial_prep(value):
    return '\n'.join([
        "    var serial = ('' + sourceValue).trim();       // \"%s\"" % value,
        c('Placeholder serials that vendors ship on thousands of machines ("To be filled by O.E.M.", "0123456789") would match dozens of CIs, so they are refused, as is anything shorter than four characters. The sample serial is neither, so it goes through.'),
        "    var junk = ',0,none,n/a,na,unknown,empty,not specified,not available,no serial,' +",
        "        'default string,to be filled by o.e.m.,system serial number,chassis serial number,' +",
        "        '0123456789,1234567890,';",
        "    if (serial.length < 4 || junk.indexOf(',' + serial.toLowerCase() + ',') != -1)",
        '        return null;',
    ])


def fqdn_prep(value, ip=None):
    L = ["    var fqdn = ('' + sourceValue).trim().toLowerCase();   // \"%s\"" % value,
         "    if (fqdn.indexOf('.') == -1)                  // a bare label is left to the hostname rules",
         '        return null;']
    if ip:
        L.append("    var ip = sourcePayload.IP ? '' + sourcePayload.IP : '';   // \"%s\", only used to break a tie" % ip)
    return '\n'.join(L)


def split_prep(value, host, domain, ip):
    return '\n'.join([
        "    var full = ('' + sourceValue).trim().toLowerCase();   // \"%s\"" % value,
        '    var dot = full.indexOf(\'.\');',
        '    if (dot < 1)                                  // a bare label is left to the hostname rules',
        '        return null;',
        '    var host = full.substring(0, dot);            // "%s"' % host,
        '    var domain = full.substring(dot + 1);         // "%s"' % domain,
        "    var ip = sourcePayload.IP ? '' + sourcePayload.IP : '';   // \"%s\", only used to break a tie" % ip,
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


def class_stage(os_text, cls, label, fallback):
    return '\n'.join([
        stage('Class from the scanned OS',
              'The search below stays inside the class the OS points at (sub-classes included), so a Red Hat host can only land on a Linux Server and a Windows Server carrying the same value is never seen. An unknown or multi-guess OS gives no class and the rule declines; %s takes over.' % fallback,
              'classFor("%s") gives %s, so pref is %s and the search below runs on that class.' % (os_text, label, cls)),
        CLASSFOR,
        '    var pref = classFor(sourcePayload.OS);',
        '    if (!pref)',
        '        return null;',
    ])


def class_pref(os_text, cls, label):
    return '\n'.join([
        stage('Class the scanned OS implies, kept as a preference',
              'This rule searches the whole hardware tree, so the class is not a filter here; it is checked at the end to reject a CI whose class contradicts the scan. An unknown OS gives no class and then no check is made.',
              'classFor("%s") gives %s, so pref is %s; it is only used in the last stage.' % (os_text, label, cls)),
        CLASSFOR,
        '    var pref = classFor(sourcePayload.OS);',
    ])


def search_lines(table_expr, table_desc, field, value, var='gr', valid=False):
    L = [('    var %s = new GlideRecord(%s);' % (var, table_expr)).ljust(46) + '// ' + table_desc]
    if valid:
        L += ['    if (!%s.isValid())                            // class not installed here, decline' % var, '        return null;']
    L += ["    %s.addQuery('%s', %s);" % (var, field, value),
          '    if (ignore)',
          "        %s.addQuery('sys_class_name', 'NOT IN', ignore);" % var]
    return '\n'.join(L)


def decide_named(var, sample):
    return '\n'.join([
        '    %s.query();' % var,
        '    if (!%s.next())' % var,
        '        return null;',
        '    var match = %s.getUniqueValue();' % var,
        '    if (%s.hasNext())                             // a second CI carries the same value, never guess' % var,
        '        return null;',
        stage('The CI must carry the scanned name',
              'An address alone is not enough when the scan also carries a host name: the CI found must be named with it, allowing a hyphenated tail on either side. This keeps a finding scanned as one host off a record named after another, which is what a reused address produces.',
              sample),
        '    if (!nameAgrees(match))',
        '        return null;',
        '    return match;',
    ])


def decide(var='gr'):
    return '\n'.join([
        '    %s.query();' % var,
        '    if (!%s.next())' % var,
        '        return null;',
        '    var match = %s.getUniqueValue();' % var,
        '    if (%s.hasNext())                             // a second CI carries the same value, never guess' % var,
        '        return null;',
        '    return match;',
    ])


def pick_fqdn(scope_text, run_expr, run_desc, fqdn, ip, ci):
    return '\n'.join([
        stage('Exact FQDN, scanned IP as the tie-break',
              'pickFqdn() collects every CI %s whose fqdn equals the scanned name and notes which of them also carry the scanned IP. One hit is the match. Duplicates do exist in the CMDB (a retired server and its rebuilt replacement, a cluster alias on two nodes); when exactly one of them carries the scanned IP that one is taken, otherwise the rule declines rather than guess.' % scope_text,
              'the %s has fqdn "%s", so ids holds that one CI and its sys_id is returned. Were a second CI to carry the same fqdn, the one with ip_address "%s" would be taken; if neither or both carried it, the rule would decline.' % (ci, fqdn, ip)),
        '    function pickFqdn(table) {',
        '        var gr = new GlideRecord(table);',
        '        if (!gr.isValid())',
        '            return null;',
        "        gr.addQuery('fqdn', fqdn);",
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
        '        if (ids.length == 1)',
        '            return ids[0];',
        '        if (ids.length > 1 && ipHits.length == 1) // duplicates, one confirmed by the IP',
        '            return ipHits[0];',
        '        return null;                              // none, or a tie nothing can break',
        '    }',
        ('    return pickFqdn(%s);' % run_expr).ljust(46) + '// ' + run_desc,
    ])


def pick_combo(scope_text, run_expr, run_desc, host, domain, ip, ci):
    return '\n'.join([
        stage('Short hostname plus domain evidence, scanned IP as the tie-break',
              'pickCombo() looks for CIs %s named with the short hostname and keeps one only when its own record agrees with the scanned domain: fqdn equal to the scanned name, dns_domain equal to the scanned domain, or an fqdn that starts with the hostname and contains the domain. The same short name lives in several domains (a test and a production box both called app01), and this check is what keeps the findings off the namesake. One confirmed CI is the match; several with exactly one carrying the scanned IP gives that one; anything else declines.' % scope_text,
              'the %s is named "%s" and its dns_domain is "%s", so it lands in good as the only entry and its sys_id is returned. A CI "%s" with dns_domain "lab.example.net" would be skipped; two confirmed CIs would be resolved by ip_address "%s" or declined.' % (ci, host, domain, host, ip)),
        '    function pickCombo(table) {',
        '        var gr = new GlideRecord(table);',
        '        if (!gr.isValid())',
        '            return null;',
        "        gr.addQuery('name', host);                // name compares case-insensitively",
        '        if (ignore)',
        "            gr.addQuery('sys_class_name', 'NOT IN', ignore);",
        '        gr.query();',
        '        var good = [];                            // CIs whose domain evidence agrees',
        '        var ipHits = [];                          // those that also carry the scanned IP',
        '        while (gr.next()) {',
        "            var cifqdn = ('' + gr.getValue('fqdn')).toLowerCase();",
        "            var cidom = ('' + gr.getValue('dns_domain')).toLowerCase();",
        '            if (cifqdn == full || cidom == domain ||',
        "                (cifqdn && cifqdn.indexOf(host + '.') == 0 && cifqdn.indexOf(domain) > 0)) {",
        '                good.push(gr.getUniqueValue());',
        "                if (ip && gr.getValue('ip_address') == ip)",
        '                    ipHits.push(gr.getUniqueValue());',
        '            }',
        '        }',
        '        if (good.length == 1)',
        '            return good[0];',
        '        if (good.length > 1 && ipHits.length == 1) // several, one confirmed by the IP',
        '            return ipHits[0];',
        '        return null;                              // none, or a tie nothing can break',
        '    }',
        ('    return pickCombo(%s);' % run_expr).ljust(46) + '// ' + run_desc,
    ])


def owners_stage(var, owner_expr, class_expr, what, sample):
    return '\n'.join([
        stage('One owning CI: class agreeing, not a load balancer, named as scanned',
              'An owner whose class contradicts the scanned OS is skipped: its address record then belongs to a different kind of machine, most often a stale or misattributed discovery record. Each remaining owner is counted once, so %s. Two different owners cannot be told apart by the address, so the rule declines. One owner that is a load balancer is refused, because the address is then a virtual IP and the scanned host sits behind it. One owner named after another machine is refused, because the address has been reused.' % what,
              sample),
        '    var owners = {};',
        '    var count = 0, first = null;',
        '    while (%s.next()) {' % var,
        '        var owner = %s;' % owner_expr,
        "        if (!agrees('' + %s))              // a class the OS rules out is not counted" % class_expr,
        '            continue;',
        '        if (!owners[owner]) {',
        '            owners[owner] = true;',
        '            count++;',
        '            if (count == 1)',
        '                first = owner;',
        '        }',
        '    }',
        '    if (count == 1 && !isLoadBalancer(first) && nameAgrees(first))',
        '        return first;',
        '    return null;',
    ])


def one_owner(var, why_two, sample):
    return '\n'.join([
        stage('Exactly one CI carries the value',
              'The first row is remembered with its class; a second row means %s and the rule declines.' % why_two,
              sample),
        '    %s.query();' % var,
        '    if (!%s.next())' % var,
        '        return null;',
        '    var id = %s.getUniqueValue();' % var,
        "    var cls = '' + %s.getValue('sys_class_name');" % var,
        '    if (%s.hasNext())' % var,
        '        return null;',
    ])


def contradiction(wrong, sample):
    return '\n'.join([
        stage('Reject a CI whose class contradicts the scanned OS',
              'When the OS gave a class, the CI found must be of that class, of a sub-class of it, or of a parent of it. A host that lands on a %s by name or address is a namesake or a reused address, not the same machine, and its findings would go to the wrong owner.' % wrong,
              sample),
        '    if (!agrees(cls))',
        '        return null;',
        '    return id;',
    ])


def class_pref_chain(os_text, cls, label):
    return '\n'.join([
        stage('Class the scanned OS implies, kept as a preference',
              'This rule follows discovery records rather than searching a class, so the class is not a filter; it is used to leave out a CI at the end of the chain whose class contradicts the scan. An unknown or multi-guess OS gives no class and then nothing is left out.',
              'classFor("%s") gives %s, so pref is %s.' % (os_text, label, cls)),
        CLASSFOR,
        '    var pref = classFor(sourcePayload.OS);',
    ])


POLISHED = {'350', '410', '415', '455', '460', '700', '705', '730', '740'}   # re-issued 15 Sep with the aligned layout; the rest keep their delivered text
TRAIL = re.compile(r'^(\s*)(\S.*?\S)\s*// (.*)$')


def polish(text):
    """Layout pass: a blank line before every stage note and helper note that follows code, trailing
    comments aligned on one column, and a trailing comment that would push a line past the width
    moved onto its own line above the code."""
    out = []
    in_sample = False
    for line in text.split('\n'):
        s = line.strip()
        if s.startswith('//') and out:
            prev = out[-1].strip()
            if prev and not prev.startswith('//') and not prev.endswith('{') and not prev.endswith('*/'):
                out.append('')
            if in_sample and s.startswith('// ') and not s.startswith('//         ') and not s.startswith('// -- '):
                out.append(line[:len(line) - len(line.lstrip())] + '//')   # a new note after a Sample paragraph
        in_sample = s.startswith('// Sample:') or (in_sample and s.startswith('//         '))
        m = TRAIL.match(line)
        if m and not s.startswith('//') and m.group(2).count("'") % 2 == 0 and m.group(2).count('"') % 2 == 0:
            indent, code, note = m.groups()
            aligned = indent + code + ' ' * max(50 - len(indent + code), 2) + '// ' + note
            if len(aligned) <= W:
                line = aligned
            else:
                out.append(indent + '// ' + note)
                line = indent + code
        out.append(line)
    return '\n'.join(out)


def write(order, name, text):
    fn = os.path.join(OUT, '%s_%s.js' % (order, name.replace(' ', '_')))
    if order in POLISHED:
        text = polish(text)
    open(fn, 'w').write(text.rstrip('\n') + '\n')
    return fn


RULES = []
IP_PAYLOAD = {"ID": "83047621", "IP": "30.162.178.21", "TRACKING_METHOD": "IP", "OS": "VMware ESXi 7.0.3 build 24723872"}


def rule_175():
    value = 'VMware-42 1a 9c 3f 7d 2e 61 b8-55 04 e2 91 6a 27 c3 08'
    payload = {"ID": "35832680", "IP": "171.128.225.96", "TRACKING_METHOD": "AGENT", "OS": "Red Hat Enterprise Linux 9.8",
               "DNS": "ah-1047132-001.sdi.corp.bankofamerica.com", "SERIAL_NUMBER": value}
    h = header('USEM Serial Number Class Match',
        'Serial number first. A serial stays with a machine for its whole life while names and addresses get reused, so it is the strongest identifier Qualys gives us. This rule trusts it only inside the CMDB class the scanned OS points at.',
        payload, 'SERIAL_NUMBER', value, 'the OS',
        'the sys_id of the one CI of that class whose serial_number equals the scanned serial; null when none or more than one carries it.',
        'the Linux Server CI "ah-1047132-001", whose serial_number holds the same serial; null when no Linux Server carries it, or two do.',
        'nothing custom runs before this rule.',
        'every host that reports a serial. In our feed that is the Cloud Agent hosts; the unauthenticated network scans rarely carry one.',
        'USEM Serial Number Hardware Match repeats the search across the whole hardware tree for hosts whose OS gives no class or whose CI is classed differently.')
    body = [OPEN, CHECK, serial_prep(value), IGNORE_BLOCK,
        class_stage('Red Hat Enterprise Linux 9.8', 'cmdb_ci_linux_server', 'Linux Server', 'the hardware-wide serial match'),
        stage('Serial search inside that class, one CI only',
              'Exact match on serial_number with the ignored classes left out. The CI is accepted only when it is the single row: two CIs sharing a serial do happen (a cloned virtual machine, a serial typed on the wrong record) and nothing here can tell them apart, so the rule declines and a later rule with different evidence gets its chance.',
              'the search on cmdb_ci_linux_server for serial_number "%s" finds the Linux Server "ah-1047132-001" and no second row, so its sys_id is returned. A Windows Server with the same serial is outside the class and never appears.' % value),
        search_lines('pref', 'the class chosen and its sub-classes', 'serial_number', 'serial', valid=True),
        decide(), CLOSE]
    return write('175', 'USEM Serial Number Class Match', h + '\n' + '\n'.join(body))
RULES.append(rule_175)


def rule_180():
    value = 'MXQ13005TC'
    payload = {"ID": "35920204", "IP": "171.135.28.125", "TRACKING_METHOD": "IP", "OS": MULTI,
               "DNS": "txr9gxcenah031.sdi.corp.bankofamerica.com", "SERIAL_NUMBER": value}
    h = header('USEM Serial Number Hardware Match',
        'Second and last serial rule: the same serial search, but across the whole hardware tree (servers, computers, network gear, storage, printers). It exists for hosts whose OS gives no usable class and for CIs that sit in a different class than the OS suggests.',
        payload, 'SERIAL_NUMBER', value, '',
        'the sys_id of the one hardware CI whose serial_number equals the scanned serial; null when none or more than one carries it.',
        'the Server CI "txr9gxcenah031", kept in the generic Server class because the scan could not identify its OS; its serial_number is "%s".' % value,
        'USEM Serial Number Class Match already tried the serial inside the class the OS implies; the sample OS is a list of seven guesses, so that rule declined without searching.',
        'hosts with a serial whose OS is unknown (an unauthenticated scan listing several guesses, as in the sample) or whose CI is classed differently.',
        'the phone rule and the name rules. A serial that is not unique in the whole hardware tree is never used.')
    body = [OPEN, CHECK, serial_prep(value), IGNORE_BLOCK,
        stage('Serial search across the hardware tree, one CI only',
              'cmdb_ci_hardware is the parent of every device class, so nothing is filtered by class here; the safety is that the serial still has to belong to exactly one CI in the whole tree.',
              'the search on cmdb_ci_hardware for serial_number "%s" finds the Server "txr9gxcenah031" and no second row, so its sys_id is returned. A Storage Server loaded with the same serial would make the rule decline.' % value),
        search_lines("'cmdb_ci_hardware'", 'Hardware and every class beneath it', 'serial_number', 'serial'),
        decide(), CLOSE]
    return write('180', 'USEM Serial Number Hardware Match', h + '\n' + '\n'.join(body))
RULES.append(rule_180)


def rule_200():
    value = 'sep64f69dd5c9b0.voip.bankofamerica.com'
    payload = {"ID": "41277345", "IP": "30.144.62.108", "TRACKING_METHOD": "IP", "OS": "Cisco IP Phone", "DNS": value}
    h = header('USEM Cisco IP Phone MAC',
        'Cisco Unified Communications Manager names every phone "SEP" followed by its MAC address, and Qualys reports that name as the DNS label (under voip.bankofamerica.com in our feed). The rule turns the label back into a MAC address and looks for exactly one IP Phone CI that carries it.',
        payload, 'DNS', value, '',
        'the sys_id of the IP Phone CI whose network adapter, mac_address field or name carries that MAC; null for any label that is not a phone label, and when no phone or two phones carry the MAC.',
        'the IP Phone CI "SEP64F69DD5C9B0", found through the adapter that carries the MAC 64:F6:9D:D5:C9:B0.',
        'the serial number rules (phones report none).',
        'only hosts whose DNS label is "sep" plus twelve hexadecimal characters; every other host passes through untouched.',
        'the FQDN and hostname rules. Phones are resolved before them so a phone label is never tried as a server name, and because only IP Phone CIs are searched a MAC clash can never pull in a switch or a server.')
    body = [OPEN, CHECK,
        stage('Recognise the phone label and rebuild the MAC address',
              'The first label of the DNS name must be exactly "sep" plus twelve hex characters; a server called "sepulveda01" must not be treated as a phone. The MAC is rebuilt in the four spellings the CMDB holds, because discovery tools and the call manager export write it differently.',
              '"%s" gives the label "sep64f69dd5c9b0", the hex "64f69dd5c9b0" and candidates ["64:F6:9D:D5:C9:B0", "64:f6:9d:d5:c9:b0", "64F69DD5C9B0", "64f69dd5c9b0"].' % value),
        "    var label = ('' + sourceValue).split('.')[0].toLowerCase();   // \"sep64f69dd5c9b0\"",
        '    var m = label.match(/^sep([0-9a-f]{12})$/);',
        '    if (!m)',
        '        return null;',
        '    var hex = m[1];                               // "64f69dd5c9b0"',
        '    var pairs = [];',
        '    for (var i = 0; i < 12; i += 2)',
        '        pairs.push(hex.substr(i, 2));             // ["64", "f6", "9d", "d5", "c9", "b0"]',
        "    var colon = pairs.join(':');                  // \"64:f6:9d:d5:c9:b0\"",
        '    var candidates = [colon.toUpperCase(), colon, hex.toUpperCase(), hex];',
        IGNORE_BLOCK,
        stage('Find the one phone that carries the MAC',
              'Three places are tried in turn: a network adapter with that MAC whose owner is an IP Phone CI (discovery usually stores the MAC on the adapter), the mac_address field on the phone record itself, and finally a phone named with the Unified CM device name. Each place must yield exactly one phone; two phones on one MAC or one device name is never guessed. Checking that the adapter owner really is an IP Phone is what keeps a switch or server adapter with a colliding MAC out.',
              'the adapter "eth0" with mac_address "64:F6:9D:D5:C9:B0" belongs to the IP Phone "SEP64F69DD5C9B0"; count is 1, so that phone is returned from the first attempt. A phone with the MAC on its own record, or one simply named "SEP64F69DD5C9B0", would be found by the second or third attempt.'),
        "    var nic = new GlideRecord('cmdb_ci_network_adapter');   // 1. adapter with that MAC, owned by an IP phone",
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
        "    var ph = new GlideRecord('cmdb_ci_ip_phone');           // 2. the MAC stored on the phone record",
        "    ph.addQuery('mac_address', 'IN', candidates.join(','));",
        '    if (ignore)',
        "        ph.addQuery('sys_class_name', 'NOT IN', ignore);",
        '    ph.query();',
        '    if (ph.next()) {',
        '        var byMac = ph.getUniqueValue();',
        '        if (!ph.hasNext())',
        '            return byMac;',
        '    }',
        "    var byName = new GlideRecord('cmdb_ci_ip_phone');       // 3. the phone named with its device name",
        "    byName.addQuery('name', label.toUpperCase());  // \"SEP64F69DD5C9B0\"",
        '    if (ignore)',
        "        byName.addQuery('sys_class_name', 'NOT IN', ignore);",
        '    byName.query();',
        '    if (!byName.next())',
        '        return null;',
        '    var named = byName.getUniqueValue();',
        '    if (byName.hasNext())',
        '        return null;',
        '    return named;',
        CLOSE]
    return write('200', 'USEM Cisco IP Phone MAC', h + '\n' + '\n'.join(body))
RULES.append(rule_200)


def rule_250():
    value = 'vsdnac22xsdi004.sdi.corp.bankofamerica.com'
    payload = {"ID": "83047612", "IP": "30.206.199.36", "TRACKING_METHOD": "IP", "OS": "VMware ESXi 7.0.3 build 24723872", "DNS": value}
    h = header('USEM FQDN Class Match',
        'The first name rule: the scanned DNS name against the fqdn field of a CI, inside the class the scanned OS points at. An exact FQDN on the CI is the most precise name evidence we have, so it comes before any hostname matching.',
        payload, 'DNS', value, 'the OS and the IP',
        'the sys_id of the one CI of that class whose fqdn equals the scanned name; with duplicate fqdn values, the one that also carries the scanned IP; null otherwise.',
        'the ESX Server CI "vsdnac22xsdi004", whose fqdn is the scanned name; two ESX Servers with that fqdn are accepted only when exactly one also carries the IP 30.206.199.36.',
        'the serial number rules and the IP phone rule found nothing.',
        'every host with a dotted DNS name, which is the bulk of the Qualys feed.',
        'USEM FQDN Hardware Match repeats the exact FQDN search across every hardware class; the hostname-plus-domain rules and then the plain hostname rules follow.')
    body = [OPEN, CHECK, fqdn_prep(value, '30.206.199.36'), IGNORE_BLOCK,
        class_stage('VMware ESXi 7.0.3 build 24723872', 'cmdb_ci_esx_server', 'ESX Server', 'the hardware-wide FQDN match'),
        pick_fqdn('of that class', 'pref', 'exact FQDN inside the class chosen', value, '30.206.199.36', 'ESX Server "vsdnac22xsdi004"'),
        CLOSE]
    return write('250', 'USEM FQDN Class Match', h + '\n' + '\n'.join(body))
RULES.append(rule_250)


def rule_260():
    value = 'txr9gxcenah031.sdi.corp.bankofamerica.com'
    payload = {"ID": "35920204", "IP": "171.135.28.125", "TRACKING_METHOD": "IP", "OS": MULTI, "DNS": value}
    h = header('USEM FQDN Hardware Match',
        'The exact FQDN search again, across the whole hardware tree. It picks up the hosts whose OS gives no class and the CIs kept in a generic or different class than the OS suggests.',
        payload, 'DNS', value, 'the IP',
        'the sys_id of the one hardware CI whose fqdn equals the scanned name; with duplicates, the one that also carries the scanned IP; null otherwise.',
        'the Server CI "txr9gxcenah031" whose fqdn is the scanned name; duplicates are resolved by the IP 171.135.28.125 or declined.',
        'USEM FQDN Class Match tried the exact FQDN inside the class the OS implies; the sample OS is a list of seven guesses, so that rule declined without searching.',
        'hosts whose OS gives no class (unauthenticated scans with a multi-guess OS, as in the sample) or whose CI is classed differently from the OS.',
        'the hostname-plus-domain rules, for CIs that carry no fqdn value at all.')
    body = [OPEN, CHECK, fqdn_prep(value, '171.135.28.125'), IGNORE_BLOCK,
        pick_fqdn('under Hardware', "'cmdb_ci_hardware'", 'exact FQDN anywhere under Hardware', value, '171.135.28.125', 'Server "txr9gxcenah031"'),
        CLOSE]
    return write('260', 'USEM FQDN Hardware Match', h + '\n' + '\n'.join(body))
RULES.append(rule_260)


def rule_300():
    value = 'ah-1047132-001.sdi.corp.bankofamerica.com'
    payload = {"ID": "35832680", "IP": "171.128.225.96", "TRACKING_METHOD": "AGENT", "OS": "Red Hat Enterprise Linux 9.8", "DNS": value,
               "QG_HOSTID": "633769a4-0139-0002-e352-005056bf41ea"}
    h = header('USEM Hostname Domain Class Match',
        'For CIs that are named with the short hostname and carry the domain in another field (dns_domain, or an fqdn that was never copied into the name). The short name and the domain are matched together, inside the class the scanned OS points at.',
        payload, 'DNS', value, 'the OS and the IP',
        'the sys_id of the one CI of that class named with the short hostname whose own domain information agrees with the scanned domain; a namesake in another domain is never picked.',
        'the Linux Server CI named "ah-1047132-001" whose dns_domain is "sdi.corp.bankofamerica.com".',
        'the FQDN rules looked for the exact name in the fqdn field and found nothing.',
        'hosts whose CI has no exact fqdn value but is named with the short hostname and shows the domain elsewhere.',
        'USEM Hostname Domain Hardware Match repeats the search across all hardware, USEM Layered DNS Match reads the discovery DNS records, and the plain hostname rules accept a unique short name without domain evidence.')
    body = [OPEN, CHECK, split_prep(value, 'ah-1047132-001', 'sdi.corp.bankofamerica.com', '171.128.225.96'), IGNORE_BLOCK,
        class_stage('Red Hat Enterprise Linux 9.8', 'cmdb_ci_linux_server', 'Linux Server', 'the hardware-wide hostname-plus-domain match'),
        pick_combo('of that class', 'pref', 'hostname plus domain inside the class chosen', 'ah-1047132-001', 'sdi.corp.bankofamerica.com', '171.128.225.96', 'Linux Server'),
        CLOSE]
    return write('300', 'USEM Hostname Domain Class Match', h + '\n' + '\n'.join(body))
RULES.append(rule_300)


def rule_310():
    value = 'lrche01xtrapd01.sdi.corp.bankofamerica.com'
    payload = {"ID": "35884392", "IP": "171.128.140.192", "TRACKING_METHOD": "IP", "OS": "Ubuntu/Linux", "DNS": value}
    h = header('USEM Hostname Domain Hardware Match',
        'Short hostname plus domain evidence again, across the whole hardware tree, for CIs classed generically (Server, Computer) or differently from the scanned OS.',
        payload, 'DNS', value, 'the IP',
        'the sys_id of the one hardware CI named with the short hostname whose fqdn or dns_domain agrees with the scanned domain; null otherwise.',
        'the CI named "lrche01xtrapd01" in the generic Server class, whose fqdn is the scanned name.',
        'USEM Hostname Domain Class Match tried the same evidence inside the class the OS implies (Linux Server for "Ubuntu/Linux") and found nothing, because the CI sits in the generic Server class.',
        'hosts whose CI is classed generically or differently from the scanned OS, so the class-scoped search found nothing.',
        'USEM Layered DNS Match and then the plain hostname rules.')
    body = [OPEN, CHECK, split_prep(value, 'lrche01xtrapd01', 'sdi.corp.bankofamerica.com', '171.128.140.192'), IGNORE_BLOCK,
        pick_combo('under Hardware', "'cmdb_ci_hardware'", 'hostname plus domain anywhere under Hardware', 'lrche01xtrapd01', 'sdi.corp.bankofamerica.com', '171.128.140.192', 'Server'),
        CLOSE]
    return write('310', 'USEM Hostname Domain Hardware Match', h + '\n' + '\n'.join(body))
RULES.append(rule_310)


def rule_350():
    value = 'hklvteqoradbp3.hk.baml.com'
    payload = {"ID": "42773078", "IP": "167.202.60.26", "TRACKING_METHOD": "IP", "OS": "Red Hat Enterprise Linux Server 7.9", "DNS": value,
               "QG_HOSTID": "6337dede-02e7-0002-ad2c-0050569765df"}
    h = header('USEM Layered DNS Match',
        'Discovery keeps names and addresses as their own records linked to the device: a DNS Name record is tied to an IP Address record, the IP Address record belongs to a Network Adapter, and the adapter belongs to the CI. This rule follows that chain, which is the only way to find a host whose name is not written on the CI record at all, and it resolves aliases to the real machine. A CI at the end of the chain whose class contradicts the scanned OS is left out, because the discovery records then describe a different kind of machine, and a load balancer device at the end of the chain is refused, because the name then belongs to a virtual address the balancer answers on.',
        payload, 'DNS', value, 'the OS and the IP',
        'the sys_id of the CI at the end of the chain DNS Name -> IP Address -> adapter -> CI, its class agreeing with the scanned OS when one is known (a Linux fingerprint agrees with Network Gear, Load Balancer and Storage Server records too); when several CIs answer to the name, the one whose chain runs through the scanned IP; null otherwise, and null when the CI reached is a load balancer device.',
        'the Linux Server "hklvteqoradbp3", reached through DNS Name "hklvteqoradbp3.hk.baml.com" -> IP Address "167.202.60.26" -> adapter "eth0".',
        'the FQDN and hostname-plus-domain rules looked at name fields stored on the CI record itself.',
        'hosts whose name lives only in the discovery DNS records, and aliases that point at an address of the device.',
        'the plain hostname rules and USEM FQDN Name Hardware Match.')
    body = [OPEN, CHECK, fqdn_prep(value, '167.202.60.26'), IGNORE_BLOCK,
        class_pref_chain('Red Hat Enterprise Linux Server 7.9', 'cmdb_ci_linux_server', 'Linux Server'),
        AGREES_APPLIANCE, LB_HELPER,
        stage('Follow the chain DNS Name -> IP Address -> adapter -> CI',
              'cmdb_ip_address_dns_name ties one DNS Name record to one IP Address record; dot-walking reaches the rest: dns_name.name is the name on the DNS Name record and ip_address.nic.cmdb_ci is the CI owning the adapter that holds the address. Because the chain ends on whatever device holds the address, an alias resolves to the real machine.',
              'the DNS Name record "hklvteqoradbp3.hk.baml.com" is linked to the IP Address record "167.202.60.26", which belongs to the adapter "eth0" of the Linux Server "hklvteqoradbp3"; that is the one row the query returns.'),
        "    var gr = new GlideRecord('cmdb_ip_address_dns_name');",
        '    if (!gr.isValid())                            // layered model not installed here, decline',
        '        return null;',
        "    gr.addQuery('dns_name.name', fqdn);           // \"%s\"" % value,
        "    gr.addNotNullQuery('ip_address.nic.cmdb_ci'); // the chain must end on a CI",
        '    if (ignore)',
        "        gr.addQuery('ip_address.nic.cmdb_ci.sys_class_name', 'NOT IN', ignore);",
        '    gr.query();',
        stage('One CI at the end of the chain: class agreeing, not a load balancer, IP as the tie-break',
              'A CI whose class contradicts the scanned OS is skipped: a Computer at the end of the chain for a Cisco IOS host is a stale or misattributed discovery record, not the router. Each remaining CI is counted once, and the CIs reached through the scanned address are noted. One CI is the match. A name that resolves to two devices (an alias moved between hosts, an old and a new record) is taken only when exactly one of them is reached through the scanned IP; otherwise the rule declines. The CI chosen is refused when it is a load balancer device: the name then belongs to a virtual address the balancer answers on, the scanned host sits behind it, and the load balancer rules take over.',
              'the chain ends on a Linux Server, the class pref holds, so it is counted: count is 1 and the sys_id of "hklvteqoradbp3" is returned. A Computer at the end of the chain would also count (a parent of Linux Server), and so would an IP Switch, an appliance that reports the Linux it runs on; a Windows Server would be skipped. Were the name also linked to an address of a second Linux Server, ipOwners would hold only the CI reached through "167.202.60.26" and that one would be returned. Were the chain to end on the Load Balancer "hklvf5lb01", the rule would decline and the host would go on to the load balancer rules.'),
        '    var owners = {}, ipOwners = {};',
        '    var count = 0, first = null;',
        '    while (gr.next()) {',
        "        var owner = '' + gr.ip_address.nic.cmdb_ci;",
        "        if (!agrees('' + gr.ip_address.nic.cmdb_ci.sys_class_name))   // a class the OS rules out is not counted",
        '            continue;',
        '        if (!owners[owner]) {',
        '            owners[owner] = true;',
        '            count++;',
        '            if (count == 1)',
        '                first = owner;',
        '        }',
        "        if (ip && ('' + gr.ip_address.ip_address) == ip)   // this chain runs through the scanned IP",
        '            ipOwners[owner] = true;',
        '    }',
        '    if (count == 1)',
        '        return isLoadBalancer(first) ? null : first;',
        '    if (count > 1) {',
        '        var confirmed = Object.keys(ipOwners);',
        '        if (confirmed.length == 1 && !isLoadBalancer(confirmed[0]))',
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
    h = header('USEM Hostname Class Match',
        'The short hostname alone, inside the class the scanned OS points at. For CIs that carry only a short name and no domain information; the agreement between CI class and scanned OS stands in for the missing domain evidence.',
        payload, 'DNS', value, 'the OS',
        'the sys_id of the one CI of that class named with the short hostname (names compare case-insensitively); null when none or two carry it.',
        'the Windows Server CI named "WSAOI01ZEAPD1"; a second Windows Server with the same name would make the rule decline.',
        'every rule so far needed domain evidence on the CI (fqdn, dns_domain or the discovery DNS records).',
        'hosts whose CI carries only a short name and no domain information at all.',
        'USEM Hostname Hardware Match repeats the short name search across all hardware with a class sanity check; USEM FQDN Name Hardware Match handles CIs named with the full FQDN.')
    body = [OPEN, CHECK, short_prep(value, 'wsaoi01zeapd1'), IGNORE_BLOCK,
        class_stage('Windows Server 2016 Standard 64 bit Edition Version 1607', 'cmdb_ci_win_server', 'Windows Server', 'the hardware-wide hostname match'),
        stage('Short name search inside that class, one CI only',
              'With no domain to confirm, the class is the only safeguard against a namesake, and inside the class the name still has to be unique: two CIs with the same short name cannot be told apart here and the rule declines.',
              'the search on cmdb_ci_win_server for name "wsaoi01zeapd1" finds the Windows Server "WSAOI01ZEAPD1" and no second row, so its sys_id is returned.'),
        search_lines('pref', 'the class chosen and its sub-classes', 'name', 'host', valid=True),
        decide(), CLOSE]
    return write('400', 'USEM Hostname Class Match', h + '\n' + '\n'.join(body))
RULES.append(rule_400)


def rule_410():
    value = 'va2ausapabw0.bankofamerica.com'
    payload = {"ID": "80217765", "IP": "171.150.219.123", "TRACKING_METHOD": "IP", "OS": "AIX 7.3 TL3", "DNS": value,
               "QG_HOSTID": "6337e0dc-007d-0002-c47d-005056a4fcd5"}
    h = header('USEM Hostname Hardware Match',
        'The short hostname across the whole hardware tree, with a check that the CI found does not contradict the scanned OS. For CIs kept in a parent class (Server, Computer, Hardware) or in a different class than the OS suggests.',
        payload, 'DNS', value, 'the OS',
        'the sys_id of the one hardware CI named with the short hostname, accepted when its class is the one the OS implies, a sub-class of it or a parent of it, or an appliance class (Network Gear, Load Balancer, Storage Server) for a Linux fingerprint; null when the name is shared or the class contradicts the scan.',
        'the CI named "va2ausapabw0" in the plain Server class, a parent of AIX Server; it would also be accepted as an AIX Server, and rejected as, say, a Windows Server or an IP Router.',
        'USEM Hostname Class Match required the short name to be unique inside the class the OS implies (AIX Server) and found nothing there.',
        'hosts whose CI is kept in a parent class or whose OS gave no class.',
        'USEM FQDN Name Hardware Match, then the IP address rules for hosts without a usable name.')
    body = [OPEN, CHECK, short_prep(value, 'va2ausapabw0'), IGNORE_BLOCK,
        class_pref('AIX 7.3 TL3', 'cmdb_ci_aix_server', 'AIX Server'),
        AGREES_APPLIANCE,
        stage('Short name search across the hardware tree',
              'Nothing is filtered by class here; the two checks that follow provide the safety.',
              'the search on cmdb_ci_hardware for name "va2ausapabw0" finds the Server "va2ausapabw0", class cmdb_ci_server.'),
        search_lines("'cmdb_ci_hardware'", 'Hardware and every class beneath it', 'name', 'host'),
        one_owner('gr', 'two hardware CIs with one short name (a test and a production box, a retired and a rebuilt one), which the name alone cannot tell apart',
                  'one row, so id is the sys_id of "va2ausapabw0" and cls is "cmdb_ci_server". A second CI with that name would end the rule here.'),
        contradiction('Windows Server',
                      'pref is cmdb_ci_aix_server and cls is cmdb_ci_server, a parent of AIX Server, so agrees() is true and the sys_id is returned. A Windows Server or an IP Router named "va2ausapabw0" is neither a sub-class nor a parent of AIX Server and the rule would decline. An IP Switch named "cncnshasd03sae0002" scanned as "Ubuntu/Linux" is accepted: the switch reports the Linux it runs on.'),
        CLOSE]
    return write('410', 'USEM Hostname Hardware Match', h + '\n' + '\n'.join(body))
RULES.append(rule_410)


def rule_415():
    value = 'avxdd008a.cc.bofa.com'
    payload = {"ID": "753026617", "IP": "10.190.29.132", "TRACKING_METHOD": "IP", "DNS": value}
    h = header('USEM Device Name Match',
        'Two device classes sit outside the Hardware tree of the CMDB: IP Phone extends the base CI class directly and Scanner sits under Imaging Hardware. The hardware-wide name rules never see those records, and the class rules need an OS that a phone or a scanner does not report to an unauthenticated scan. This rule looks for the scanned host name in exactly those classes: one device carrying the name is the match, and when the name is shared the scanned address breaks the tie.',
        payload, 'DNS', value, 'the OS and the IP',
        'the sys_id of the one IP Phone or Imaging Hardware CI named with the host name; when several carry it, the one whose ip_address is the scanned address; null otherwise, and null when the scanned OS names a server or desktop system.',
        'the IP Phone CI "AVXDD008A" (an Avaya station named "avx" plus the tail of its MAC address), whose ip_address is also "10.190.29.132".',
        'USEM Hostname Hardware Match searched the Hardware tree for the plain host name; the phone and scanner classes are not in that tree, so it declined, and every earlier rule needed an OS class, a serial or a Cisco phone label.',
        'phones and scanners named in DNS, which in our feed scan without an OS; in the contact-centre domain cc.bofa.com nearly every host is such a phone.',
        'USEM Management Interface Match, then the interface, service and address rules.')
    body = [OPEN, CHECK, short_prep(value, 'avxdd008a'),
        "    var ip = sourcePayload.IP ? '' + sourcePayload.IP : '';   // \"10.190.29.132\", only used to break a tie",
        IGNORE_BLOCK,
        stage('The scanned OS must not name a different kind of machine',
              'A phone or a scanner reports no OS to an unauthenticated scan, or a guess such as an embedded Linux kernel, "Unknown OS" or a vendor name. Only an OS that clearly names a server or desktop system (Windows, ESXi, AIX, Solaris, HP-UX) rules the device out; a Linux kernel fingerprint is what an appliance shows and is accepted, and so is anything that mentions a phone.',
              'the sample carries no OS, so nothing rules the device out; "Foundry Networks", "Unknown OS" or "Linux 2.x" on a phone would pass too, "Windows 10 Enterprise" would end the rule here.'),
        CLASSFOR,
        "    var os = ('' + (sourcePayload.OS || '')).toLowerCase();",
        '    var pref = classFor(os);',
        "    if (pref && pref != 'cmdb_ci_linux_server' && os.indexOf('phone') == -1)",
        '        return null;',
        stage('Search the device classes outside the Hardware tree',
              'Each class is searched by name, sub-classes included, with the ignored classes left out. The classes are listed here rather than derived because they are exactly the device classes the CMDB keeps outside the Hardware tree; a scanner or phone record loaded elsewhere is not the concern of this rule.',
              'cmdb_ci_ip_phone holds one record named "AVXDD008A" (the query is not case-sensitive) with ip_address "10.190.29.132"; cmdb_ci_imaging_hardware holds none, so found has one entry and onAddress the same one.'),
        "    var classes = ['cmdb_ci_ip_phone', 'cmdb_ci_imaging_hardware'];   // IP phones; scanners and other imaging devices",
        '    var found = [], onAddress = [];',
        '    for (var i = 0; i < classes.length; i++) {',
        '        var gr = new GlideRecord(classes[i]);',
        '        if (!gr.isValid())                        // class not installed here, try the next one',
        '            continue;',
        "        gr.addQuery('name', host);",
        '        if (ignore)',
        "            gr.addQuery('sys_class_name', 'NOT IN', ignore);",
        '        gr.query();',
        '        while (gr.next()) {',
        '            found.push(gr.getUniqueValue());',
        "            if (ip && ('' + gr.getValue('ip_address')) == ip)",
        '                onAddress.push(gr.getUniqueValue());',
        '        }',
        '    }',
        stage('One device carrying the name, the scanned address as the tie-break',
              'One device named with the host is the match: a phone name is built from its MAC address and a scanner name from its asset label, so the name alone identifies the device even after its DHCP address has changed. When the name is shared (a phone re-registered under a new record, a scanner loaded twice) the one whose ip_address is the scanned address is taken, and only when exactly one carries it; otherwise the rule declines.',
              'found holds the one IP Phone "AVXDD008A", so its sys_id is returned. Were a second phone named "avxdd008a", only the one on "10.190.29.132" would be taken; two phones on that address would make the rule decline.'),
        '    if (found.length == 1)',
        '        return found[0];',
        '    if (found.length > 1 && onAddress.length == 1)',
        '        return onAddress[0];',
        '    return null;',
        CLOSE]
    return write('415', 'USEM Device Name Match', h + '\n' + '\n'.join(body))
RULES.append(rule_415)


def rule_450():
    value = 'lva40bneehcs01.ecomm.devicenp.rpg'
    payload = {"ID": "71973166", "IP": "164.91.209.12", "TRACKING_METHOD": "AGENT", "OS": "Red Hat Enterprise Linux 8.10", "DNS": value,
               "QG_HOSTID": "633781ed-019b-0002-2f2f-0050569d20ff"}
    h = header('USEM FQDN Name Hardware Match',
        'Some loads name the CI with the whole FQDN string instead of the short hostname (the appliance domains ending in .rpg are the usual case), so a short name search never finds them. This rule compares the complete scanned name with the name field, across the hardware tree.',
        payload, 'DNS', value, '',
        'the sys_id of the one hardware CI whose name is exactly the scanned FQDN; null when none or two carry it.',
        'the hardware CI named exactly "%s", when it is the only one.' % value,
        'every rule so far compared the short hostname "lva40bneehcs01" or the fqdn field.',
        'CIs named with the full FQDN, which none of the earlier rules can see.',
        'the IP address rules, and finally USEM FQDN Name Broad Match, the only rule allowed to search the whole CI table.')
    body = [OPEN, CHECK, fqdn_prep(value), IGNORE_BLOCK,
        stage('Full FQDN as the CI name, across the hardware tree, one CI only',
              'The name is compared with the whole string including the domain; the CI is accepted only when it is the single row.',
              'the search on cmdb_ci_hardware for name "%s" finds the Server named exactly that and no second row, so its sys_id is returned.' % value),
        search_lines("'cmdb_ci_hardware'", 'Hardware and every class beneath it', 'name', 'fqdn'),
        decide(), CLOSE]
    return write('450', 'USEM FQDN Name Hardware Match', h + '\n' + '\n'.join(body))
RULES.append(rule_450)


def rule_700():
    h = header('USEM IP Class Match',
        'The first address rule. An address is the least trustworthy identifier we get: addresses move between machines and are shared by load balancers. It is used only for hosts without a serial and without a usable name, inside the class the scanned OS points at, and only when exactly one CI of that class carries it.',
        IP_PAYLOAD, 'IP', '30.162.178.21', 'the OS',
        'the sys_id of the one CI of that class whose ip_address equals the scanned address, when its name agrees with the scanned host name; null when none or two carry it or the name differs.',
        'the ESX Server CI "vsdnesxm21", whose ip_address is "30.162.178.21"; a load balancer or a Windows CI on the same address is outside the class and cannot be picked.',
        'all serial and name rules. The sample has no DNS name, so every name rule declined.',
        'DNS-less hosts, a small group in the feed, mostly ESXi management interfaces and appliances.',
        'USEM IP Hardware Match searches the address across all hardware with extra safety checks; the adapter and layered address rules follow.')
    body = [OPEN, CHECK, ip_prep('30.162.178.21'), IGNORE_BLOCK,
        class_stage('VMware ESXi 7.0.3 build 24723872', 'cmdb_ci_esx_server', 'ESX Server', 'the hardware-wide address match'),
        NAME_AGREES,
        stage('Address search inside that class, one CI only',
              'Inside the agreed class an address is reasonably safe: a virtual IP of a load balancer or a Windows machine that inherited the address sits outside the class and never appears. Two CIs of the class on one address (an address reused after a rebuild) still make the rule decline.',
              'the search on cmdb_ci_esx_server for ip_address "30.162.178.21" finds the ESX Server "vsdnesxm21" and no second row, so its sys_id is returned.'),
        search_lines('pref', 'the class chosen and its sub-classes', 'ip_address', 'ip', valid=True),
        decide_named('gr', 'the sample carries no DNS, so nothing is checked and the sys_id of "vsdnesxm21" is returned. A host scanned as "vk1660790" whose address leads to a CI named "vk1448212" would be declined here: the address has been reused.'),
        CLOSE]
    return write('700', 'USEM IP Class Match', h + '\n' + '\n'.join(body))
RULES.append(rule_700)


def rule_705():
    payload = {"ID": "83047624", "IP": "30.162.178.24", "TRACKING_METHOD": "IP", "OS": MULTI}
    h = header('USEM IP Hardware Match',
        'The address across the whole hardware tree, with two extra safety checks: the CI must not be a load balancer, and its class must not contradict the scanned OS.',
        payload, 'IP', '30.162.178.24', 'the OS',
        'the sys_id of the one hardware CI whose ip_address equals the scanned address, when it is not a load balancer, its name agrees with the scanned host name and its class is the one the OS implies, a sub-class of it or a parent of it; null otherwise.',
        'the CI in the generic Server class whose ip_address is "30.162.178.24"; a Load Balancer on that address would be refused, and with a known OS a CI of a contradicting class would be too.',
        'USEM IP Class Match required the address to belong to one CI of the class the OS implies; the sample OS is a list of guesses, so that rule declined without searching.',
        'DNS-less hosts whose CI is kept in a parent class or whose OS gave no class.',
        'USEM IP Adapter Match and USEM IP Layered Match.')
    body = [OPEN, CHECK, ip_prep('30.162.178.24'), IGNORE_BLOCK,
        class_pref(MULTI, '""', 'no class'),
        AGREES, LB_HELPER, NAME_AGREES,
        stage('Address search across the hardware tree',
              'Nothing is filtered by class here; the four checks that follow provide the safety.',
              'the search on cmdb_ci_hardware for ip_address "30.162.178.24" finds one CI in the generic Server class.'),
        search_lines("'cmdb_ci_hardware'", 'Hardware and every class beneath it', 'ip_address', 'ip'),
        one_owner('gr', 'an address answered by several CIs (a shared virtual IP, an address reused after a rebuild), which is never a safe match',
                  'one row, so id is the sys_id of that Server and cls is "cmdb_ci_server".'),
        stage('Reject a load balancer',
              'A scanned address that belongs to a load balancer is a virtual IP; the findings describe a pool member behind it, not the balancer.',
              'the Server is not a Load Balancer, so the rule carries on. A Load Balancer on "30.162.178.24" would end it here.'),
        '    if (isLoadBalancer(id))',
        '        return null;',
        stage('The CI must carry the scanned name',
              'An address alone is not enough when the scan also carries a host name: the CI found must be named with it, allowing a hyphenated tail on either side. This keeps a finding scanned as one host off a record named after another, which is what a reused address produces.',
              'the sample carries no DNS, so nothing is checked. A host scanned as "vk1660790" whose address sits on a Server named "vk1448212" would be declined here.'),
        '    if (!nameAgrees(id))',
        '        return null;',
        contradiction('Windows Server',
                      'pref is empty for the sample, so agrees() is true and the sys_id is returned. With OS "VMware ESXi 7.0.3", pref would be cmdb_ci_esx_server; the plain Server, a parent of ESX Server, would still pass, a Windows Server or a Computer named like a router would be rejected.'),
        CLOSE]
    return write('705', 'USEM IP Hardware Match', h + '\n' + '\n'.join(body))
RULES.append(rule_705)


def rule_730():
    payload = {"ID": "83047622", "IP": "30.162.178.22", "TRACKING_METHOD": "IP", "OS": MULTI}
    h = header('USEM IP Adapter Match',
        'Discovery stores one Network Adapter record per network card, and a multi-homed server keeps its addresses there rather than on the CI record. This rule finds the adapter carrying the scanned address and takes its owning CI.',
        payload, 'IP', '30.162.178.22', '',
        'the sys_id of the CI that owns the adapter carrying the scanned address, when its class agrees with the scanned OS and its name with the scanned host name; null when adapters of two different CIs carry it, the owner is a load balancer or the name differs.',
        'the Server that owns the adapter "eth0" carrying "30.162.178.22"; the address is not written on the Server record itself.',
        'the address rules so far read the ip_address field of the CI record, which holds nothing for the sample.',
        'hosts whose address is recorded on an adapter only.',
        'USEM IP Layered Match and then the broad name rule.')
    body = [OPEN, CHECK, ip_prep('30.162.178.22'), IGNORE_BLOCK,
        class_pref_chain(MULTI, '""', 'no class'),
        AGREES, LB_HELPER, NAME_AGREES,
        stage('Adapters carrying the address',
              'Adapters with the scanned address that belong to a CI outside the ignored classes.',
              'the adapter "eth0" with ip_address "30.162.178.22" belongs to a Server; that is the one row the query returns.'),
        "    var nic = new GlideRecord('cmdb_ci_network_adapter');",
        "    nic.addQuery('ip_address', ip);               // \"30.162.178.22\"",
        "    nic.addNotNullQuery('cmdb_ci');               // the adapter must belong to a CI",
        '    if (ignore)',
        "        nic.addQuery('cmdb_ci.sys_class_name', 'NOT IN', ignore);",
        '    nic.query();',
        owners_stage('nic', "nic.getValue('cmdb_ci')", 'nic.cmdb_ci.sys_class_name', 'one server with two adapters on the address counts once and two servers count twice',
                     'pref is empty and the sample carries no DNS, so every owner counts and no name is checked; one adapter, one owner, not a Load Balancer: the sys_id of the Server is returned. A second server with an adapter on "30.162.178.22" would make the rule decline, and so would a scan named "vk1660790" whose adapter belongs to a Server named "vk1448212"; with OS "Cisco IOS 15.9" an adapter owned by a Computer would be skipped.'),
        CLOSE]
    return write('730', 'USEM IP Adapter Match', h + '\n' + '\n'.join(body))
RULES.append(rule_730)


def rule_740():
    payload = {"ID": "83047623", "IP": "30.162.178.23", "TRACKING_METHOD": "IP", "OS": MULTI}
    h = header('USEM IP Layered Match',
        'Newer discovery writes each address as its own IP Address record linked to the adapter, and the adapter record itself may carry no address. This rule reads those records: IP Address -> Network Adapter -> CI.',
        payload, 'IP', '30.162.178.23', '',
        'the sys_id of the CI at the end of the chain IP Address -> adapter -> CI, when its class agrees with the scanned OS and its name with the scanned host name; null for several owners, a load balancer or a differing name.',
        'the Server at the end of the chain IP Address "30.162.178.23" -> adapter "eth0" -> CI; neither the Server record nor the adapter record carries the address itself.',
        'USEM IP Adapter Match looked for the address on the adapter records, which hold nothing for the sample.',
        'hosts whose address exists only as an IP Address record.',
        'USEM FQDN Name Broad Match, and after that the out-of-box Qualys rules.')
    body = [OPEN, CHECK, ip_prep('30.162.178.23'), IGNORE_BLOCK,
        class_pref_chain(MULTI, '""', 'no class'),
        AGREES, LB_HELPER, NAME_AGREES,
        stage('IP Address records carrying the address',
              'nic.cmdb_ci reaches the CI two links away; the record must belong to an adapter that belongs to a CI outside the ignored classes.',
              'the IP Address record "30.162.178.23" belongs to the adapter "eth0", which belongs to a Server; that is the one row the query returns.'),
        "    var ipGr = new GlideRecord('cmdb_ci_ip_address');",
        '    if (!ipGr.isValid())                          // layered model not installed here, decline',
        '        return null;',
        "    ipGr.addQuery('ip_address', ip);              // \"30.162.178.23\"",
        "    ipGr.addNotNullQuery('nic.cmdb_ci');          // the chain must end on a CI",
        '    if (ignore)',
        "        ipGr.addQuery('nic.cmdb_ci.sys_class_name', 'NOT IN', ignore);",
        '    ipGr.query();',
        owners_stage('ipGr', "'' + ipGr.nic.cmdb_ci", 'ipGr.nic.cmdb_ci.sys_class_name', 'one device with two address records counts once and two devices count twice',
                     'pref is empty and the sample carries no DNS, so every owner counts and no name is checked; one record, one owner, not a Load Balancer: the sys_id of the Server is returned. A scan named "vk1660790" whose address record belongs to a Server named "vk1448212" would be declined; with OS "Cisco IOS 15.9" a record owned by a Computer would be skipped.'),
        CLOSE]
    return write('740', 'USEM IP Layered Match', h + '\n' + '\n'.join(body))
RULES.append(rule_740)


def rule_850():
    value = 'lva40bneehcs02.ecomm.devicenp.rpg'
    payload = {"ID": "71973167", "IP": "164.91.209.13", "TRACKING_METHOD": "AGENT", "OS": "Red Hat Enterprise Linux 8.10", "DNS": value}
    h = header('USEM FQDN Name Broad Match',
        'The one deliberately late, broad fallback: a CI named with the full FQDN anywhere in the CI table, classes outside the hardware tree included (a virtual machine instance, another logical CI). It still insists on a single owner outside the ignored classes.',
        payload, 'DNS', value, '',
        'the sys_id of the one CI in any class whose name is exactly the scanned FQDN; null when the name is shared.',
        'the Virtual Machine Instance named "%s", which lives outside the hardware tree and so escaped every earlier rule.' % value,
        'every hardware-scoped rule has declined for this host; USEM FQDN Name Hardware Match searched for the same name but only under Hardware.',
        'the rare CI named with the full FQDN that lives outside the hardware tree.',
        'the out-of-box Qualys rules (Qualys Host ID, Cloud Resource Id, FQDN, NetBIOS, DNS; the IP ones are inactive by default).')
    body = [OPEN, CHECK, fqdn_prep(value), IGNORE_BLOCK,
        stage('Full FQDN as the CI name, across the whole CI table, one CI only',
              'This is the only USEM rule that searches outside the hardware tree, which is why it runs last: every more precise rule has had its chance, and the ignore list still keeps the placeholder classes out.',
              'the search on cmdb_ci for name "%s" finds the Virtual Machine Instance named exactly that and no second row, so its sys_id is returned.' % value),
        search_lines("'cmdb_ci'", 'the root CI table, every class', 'name', 'fqdn'),
        decide(), CLOSE]
    return write('850', 'USEM FQDN Name Broad Match', h + '\n' + '\n'.join(body))
RULES.append(rule_850)


# ================================================================== rules for the unmatched backlog
SEG_MATCH = '\n'.join([
    c('isMarker() says whether one hyphen segment of the label is a listed marker: the word itself ("vlan"), the word followed by digits only ("vlan705", "v201"), or, for words of three letters or more, a segment ending in the word ("multihostvip").'),
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
    h = header('USEM Management Interface Match',
        'Server management controllers (HP iLO, Oracle ILOM, Dell iDRAC, IBM IMM, Cisco CIMC, generic BMC or IPMI) are scanned under their own DNS label, which is the server name plus a suffix such as "-ilo", "-ilom" or "-idrac", so the name rules never find them. The findings belong to the server, and this rule strips the suffix and matches the server.',
        payload, 'DNS', value, 'the OS',
        'the sys_id of the one hardware CI named like the label without its controller suffix; null when the host shows no controller evidence, when no CI or two CIs carry that name, or when the CI is a load balancer.',
        'the Linux Server CI "tx6dd630001", the label without "-ilo".',
        'the hostname rules tried the whole label "tx6dd630001-ilo" and found nothing, because no CI is named after the controller.',
        'hosts whose label ends with one of the controller suffixes, or whose OS text names a controller; both lists are declared in the script, at the top of the matching stage.',
        'USEM Network Interface Name Match and USEM FQDN Name Hardware Match.')
    body = [OPEN, CHECK,
        "    var full = ('' + sourceValue).trim().toLowerCase();   // \"tx6dd630001-ilo.bankofamerica.com\"",
        "    var label = full.split('.')[0];               // \"tx6dd630001-ilo\"",
        "    var dash = label.lastIndexOf('-');             // 11",
        '    if (dash < 1)                                 // no hyphen, nothing to strip',
        '        return null;',
        "    var os = ('' + (sourcePayload.OS || '')).toLowerCase();   // \"hp ilo\"",
        IGNORE_BLOCK,
        stage('Recognise a controller and derive the server name',
              'The segment after the last hyphen is checked against the suffix list; when it is listed the server name is the label without it. Otherwise the OS text is checked for a controller word, and then the last segment is stripped whatever it is, because some controllers carry a site-specific tail instead. Both habits are in the feed. Without either piece of evidence the host is not a controller and the rule must not touch it.',
              'the tail "ilo" is in suffixes, so base is "tx6dd630001". "crpchictx103-r" with OS "HP iLO" has an unlisted tail but a controller OS, so base would be "crpchictx103". "usposwks0042-x" with a Windows OS has neither, so the rule would decline.'),
        c('The label suffixes that mark a controller, and the words that name one in the OS text. Extend these two lists when a site uses another naming habit.'),
        "    var suffixes = ['ilo', 'ilom', 'idrac', 'drac', 'ipmi', 'bmc', 'oob', 'mgmt', 'imm', 'cimc', 'rmm', 'con'];",
        "    var markers = ['ilo', 'ilom', 'idrac', 'drac', 'remote access controller', 'imm', 'cimc', 'bmc', 'ipmi', 'lights out'];",
        '    var tail = label.substring(dash + 1);         // "ilo"',
        "    var base = '';",
        '    if (suffixes.indexOf(tail) != -1)',
        '        base = label.substring(0, dash);          // listed suffix: "tx6dd630001"',
        '    else',
        '        for (var i = 0; i < markers.length; i++)',
        '            if (os.indexOf(markers[i]) != -1) {',
        '                base = label.substring(0, dash);  // controller OS: strip the last segment',
        '                break;',
        '            }',
        '    if (!base)',
        '        return null;',
        stage('The server by name, across the hardware tree, one CI only',
              'The controller can sit in front of a server, a storage node or a network device, so the whole hardware tree is searched. Two CIs with the server name cannot be told apart from the controller label alone and the rule declines; a load balancer is refused because a balancer answering on a management address is still not the scanned host.',
              'the search on cmdb_ci_hardware for name "tx6dd630001" finds the Linux Server "tx6dd630001" and no second row; it is not a Load Balancer, so its sys_id is returned. Two servers named "crpchictx103" would make the rule decline.'),
        search_lines("'cmdb_ci_hardware'", 'Hardware and every class beneath it', 'name', 'base'),
        '    gr.query();',
        '    if (!gr.next())',
        '        return null;',
        '    var match = gr.getUniqueValue();',
        '    if (gr.hasNext())',
        '        return null;',
        "    var lb = new GlideRecord('cmdb_ci_lb');",
        '    if (lb.isValid() && lb.get(match))',
        '        return null;',
        '    return match;',
        CLOSE]
    return write('420', 'USEM Management Interface Match', h + '\n' + '\n'.join(body))
RULES.append(rule_420)


def rule_430():
    value = 'uspaltwrr01drm0119-cz04-hsrp-vlan705.network.bankofamerica.com'
    payload = {"ID": "1187423005", "IP": "171.149.3.49", "TRACKING_METHOD": "IP", "OS": "Linux 2.6", "DNS": value}
    h = header('USEM Network Interface Name Match',
        'Network devices are scanned through their interface and VLAN addresses, and each of those carries a DNS label made of the device name plus an interface tail ("-cz04-hsrp-vlan705", "-atm1-v201", "-aom"), while the device CI is named with the leading part only. The rule walks the label from the longest prefix to the shortest and takes the first prefix that names exactly one network device.',
        payload, 'DNS', value, 'the OS',
        'the sys_id of the one Network Gear or Load Balancer device CI named with a prefix of the label; null when the host shows no interface evidence, when no prefix names a device, or when a prefix names two.',
        'the IP Switch CI "uspaltwrr01drm0119", the longest prefix of the label that names a device.',
        'the hostname rules tried the whole label and USEM Management Interface Match looked for a controller suffix; "vlan705" is not one.',
        'hosts whose DNS domain is an interface domain (".network." in our feed) or whose label contains an interface marker segment such as "vlan705", "v201", "hsrp", "aom"; both lists are declared in the script, at the top of the matching stage.',
        'USEM FQDN Name Hardware Match and USEM Load Balancer Service Match.')
    body = [OPEN, CHECK,
        "    var full = ('' + sourceValue).trim().toLowerCase();   // \"uspaltwrr01drm0119-cz04-hsrp-vlan705.network.bankofamerica.com\"",
        "    var label = full.split('.')[0];               // \"uspaltwrr01drm0119-cz04-hsrp-vlan705\"",
        "    var segments = label.split('-');              // [\"uspaltwrr01drm0119\", \"cz04\", \"hsrp\", \"vlan705\"]",
        '    if (segments.length < 2)                      // no hyphen, no interface tail',
        '        return null;',
        IGNORE_BLOCK, SEG_MATCH,
        stage('Interface evidence first',
              'The rule goes on only when the DNS domain contains a listed interface domain or one of the segments after the first is a listed marker. Plenty of ordinary server names contain hyphens ("ah-1047132-001"); without this check the prefix walk would strip real hostnames and could land on an unrelated device.',
              'the name contains ".network." and the segment "vlan705" is the marker "vlan" followed by digits, so evidence is true on both counts. "ah-1047132-001.corp.bankofamerica.com" has neither and the rule would decline.'),
        c('The domains under which devices are scanned per interface, and the label segments that mark an interface or VLAN address. Extend these two lists when a site uses another naming habit.'),
        "    var domains = ['.network.'];",
        "    var markers = ['vlan', 'v', 'hsrp', 'vrrp', 'po', 'eth', 'gi', 'te', 'lo', 'mgmt', 'aom', 'vs', 'fab'];",
        '    var evidence = false;',
        '    for (var d = 0; d < domains.length; d++)',
        '        if (full.indexOf(domains[d]) != -1)',
        '            evidence = true;',
        '    for (var s = 1; s < segments.length; s++)',
        '        if (isMarker(segments[s], markers))',
        '            evidence = true;',
        '    if (!evidence)',
        '        return null;',
        stage('Walk the prefixes from the longest to the shortest',
              'One segment is dropped from the right at a time and the prefix is searched as a device name. The device name is the leading part of the label but its length varies by site, and trying the longest prefix first keeps "site-device-01" from being cut down to "site" when a CI with the longer name exists. The first prefix that finds anything decides: one CI is the match, two CIs mean the rule declines. Network devices live in two branches of the CMDB, Network Gear (switches, routers, firewalls) and Load Balancer, which the platform files under Server; both are searched and the hits are counted together.',
              'the prefixes tried are "uspaltwrr01drm0119-cz04-hsrp" (nothing), "uspaltwrr01drm0119-cz04" (nothing) and "uspaltwrr01drm0119", which names the IP Switch "uspaltwrr01drm0119" and nothing else, so its sys_id is returned. Two switches named "ustxrdnwl01rsm004z" would make the rule decline at that prefix.'),
        "    var tables = ['cmdb_ci_netgear', 'cmdb_ci_lb'];",
        '    for (var k = segments.length - 1; k >= 1; k--) {',
        "        var base = segments.slice(0, k).join('-');   // longest prefix first, e.g. \"uspaltwrr01drm0119-cz04-hsrp\"",
        '        var hits = [];',
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
        '        if (hits.length == 0)                     // nothing named like this, try a shorter prefix',
        '            continue;',
        '        if (hits.length > 1)                      // two devices carry this name, never guess',
        '            return null;',
        '        return hits[0];',
        '    }',
        '    return null;',
        CLOSE]
    return write('430', 'USEM Network Interface Name Match', h + '\n' + '\n'.join(body))
RULES.append(rule_430)


LB_WALK = '\n'.join([
    c('isRealServer() says whether a CI can be the machine behind the virtual server: a record in the Hardware tree that is neither a load balancer nor of an ignored class. related() collects the CIs tied to a record by a relationship in either direction, kept to one class and its sub-classes; a mapping loaded as relationships instead of reference fields is read the same way.'),
    '    function isRealServer(id) {',
    "        var hw = new GlideRecord('cmdb_ci_hardware');",
    '        if (!hw.get(id))',
    '            return false;',
    "        var cls = ',' + hw.getValue('sys_class_name') + ',';",
    "        if (ignore && (',' + ignore + ',').indexOf(cls) != -1)",
    '            return false;',
    "        var lb = new GlideRecord('cmdb_ci_lb');",
    '        return !(lb.isValid() && lb.get(id));',
    '    }',
    '    function related(id, table) {',
    '        var out = [];',
    "        var rel = new GlideRecord('cmdb_rel_ci');",
    "        rel.addQuery('parent', id).addOrCondition('child', id);",
    '        rel.query();',
    '        while (rel.next()) {',
    "            var other = rel.getValue('parent') == id ?",
    "                rel.getValue('child') : rel.getValue('parent');",
    '            var g = new GlideRecord(table);',
    '            if (g.isValid() && g.get(other))',
    '                out.push(other);',
    '        }',
    '        return out;',
    '    }',
])


def lb_sign_stage(flag, sample):
    return '\n'.join([
        stage('VIP sign first',
              'The rule goes on only when the OS text contains a listed load balancer word or one of the label segments is a listed VIP marker. An ordinary server that shares an address with a virtual IP is never treated as a VIP.',
              sample),
        c('The load balancer products looked for in the OS text, and the label segments that mark a virtual IP. Keep both lists the same in the member rule and the service rule.'),
        "    var osMarkers = ['f5', 'big-ip', 'big ip', 'netscaler'];",
        "    var labelMarkers = ['vip', 'vs'];",
        '    var %s = false;' % flag,
        '    for (var m = 0; m < osMarkers.length; m++)',
        '        if (os.indexOf(osMarkers[m]) != -1)',
        '            %s = true;' % flag,
        "    var segments = label ? label.split('-') : [];",
        '    for (var s = 0; s < segments.length; s++)',
        '        if (isMarker(segments[s], labelMarkers))',
        '            %s = true;' % flag,
        '    if (!%s)' % flag,
        '        return null;',
    ])


def lb_service_stage(sample):
    return '\n'.join([
        RETIRED, NARROW,
        stage('The one virtual server, by fqdn, then name, then address',
              'The scanned DNS name in the fqdn field, then in the name field, then the label in the name field, then the scanned address in ip_address. Each step accepts one virtual server. Several records carrying one name are the same virtual server recorded more than once (an HA pair keeps the same object on both devices; a test leaves a copy): the records answering on the scanned address are kept, then the live ones. Two different names on the same value end the rule; a step that finds nothing hands over to the next.',
              sample),
        '    var twins = [];                               // every record kept of the virtual server found',
        service_one(True),
        "    var steps = [['fqdn', dns], ['name', dns], ['name', label], ['ip_address', ip]];",
        '    var service = null;',
        '    for (var t = 0; t < steps.length && !service; t++) {',
        '        var found = one(steps[t][0], steps[t][1]);',
        '        if (found === null)',
        '            return null;',
        '        if (found)',
        '            service = found;',
        '    }',
        '    if (!service)',
        '        return null;',
    ])


def lb_pools_stage(text, sample, on_none):
    return '\n'.join([
        stage('The pool behind the virtual server', text, sample),
        '    var pools = {};',
        '    for (var w = 0; w < twins.length; w++) {',
        "        var svc = new GlideRecord('cmdb_ci_lb_service');",
        '        svc.get(twins[w]);',
        "        if (svc.getValue('pool'))",
        "            pools[svc.getValue('pool')] = true;",
        "        var byService = new GlideRecord('cmdb_ci_lb_pool');",
        '        if (byService.isValid()) {',
        "            byService.addQuery('service', twins[w]);",
        '            byService.query();',
        '            while (byService.next())',
        '                pools[byService.getUniqueValue()] = true;',
        '        }',
        "        var relPools = related(twins[w], 'cmdb_ci_lb_pool');",
        '        for (var r1 = 0; r1 < relPools.length; r1++)',
        '            pools[relPools[r1]] = true;',
        '    }',
        '    var poolIds = Object.keys(pools);',
        '    if (!poolIds.length)',
        '        ' + on_none,
    ])


def lb_members_stage(sample, on_none):
    return '\n'.join([
        stage('The pool members and their addresses',
              'Members are the records whose pool field points at one of the pools, plus the members related to a pool. Each member is kept with its address, an empty one as an empty string so that no address search runs for it; a member without an address can still lead to a server through a relationship.',
              sample),
        '    var members = {};',
        "    var mem = new GlideRecord('cmdb_ci_lb_pool_member');",
        '    if (mem.isValid()) {',
        "        mem.addQuery('pool', 'IN', poolIds.join(','));",
        '        mem.query();',
        '        while (mem.next())',
        "            members[mem.getUniqueValue()] = '' + (mem.getValue('ip_address') || '');",
        '    }',
        '    for (var p1 = 0; p1 < poolIds.length; p1++) {',
        "        var relMembers = related(poolIds[p1], 'cmdb_ci_lb_pool_member');",
        '        for (var r2 = 0; r2 < relMembers.length; r2++) {',
        '            if (members[relMembers[r2]] !== undefined)',
        '                continue;',
        "            var mg = new GlideRecord('cmdb_ci_lb_pool_member');",
        '            mg.get(relMembers[r2]);',
        "            members[relMembers[r2]] = '' + (mg.getValue('ip_address') || '');",
        '        }',
        '    }',
        '    var memberIds = Object.keys(members);',
        '    if (!memberIds.length)',
        '        ' + on_none,
    ])


def lb_servers_stage(title, text, sample):
    return '\n'.join([
        stage(title, text, sample),
        '    var servers = {};                             // sys_id -> first label of the name',
        '    var identities = {};                          // distinct member addresses; an address-less member by record',
        '    var unresolved = 0;                           // members that lead to no server in the CMDB',
        '    function keep(id) {',
        '        if (!id)',
        '            return false;',
        '        if (servers[id] !== undefined)',
        '            return true;',
        '        if (!isRealServer(id))',
        '            return false;',
        "        var ci = new GlideRecord('cmdb_ci_hardware');",
        '        ci.get(id);',
        "        servers[id] = ('' + (ci.getValue('name') || '')).trim().toLowerCase().split('.')[0] || id;",
        '        return true;',
        '    }',
        '    for (var k = 0; k < memberIds.length; k++) {',
        '        var addr = members[memberIds[k]];',
        '        var led = false;                          // whether this member led to a server',
        '        identities[addr || memberIds[k]] = true;',
        '        if (addr) {',
        "            var hw = new GlideRecord('cmdb_ci_hardware');",
        "            hw.addQuery('ip_address', addr);",
        '            hw.query();',
        '            while (hw.next())',
        '                led = keep(hw.getUniqueValue()) || led;',
        "            var nic = new GlideRecord('cmdb_ci_network_adapter');",
        "            nic.addQuery('ip_address', addr);",
        "            nic.addNotNullQuery('cmdb_ci');",
        '            nic.query();',
        '            while (nic.next())',
        "                led = keep(nic.getValue('cmdb_ci')) || led;",
        "            var ipr = new GlideRecord('cmdb_ci_ip_address');",
        '            if (ipr.isValid()) {',
        "                ipr.addQuery('ip_address', addr);",
        "                ipr.addNotNullQuery('nic.cmdb_ci');",
        '                ipr.query();',
        '                while (ipr.next())',
        "                    led = keep('' + ipr.nic.cmdb_ci) || led;",
        '            }',
        '        }',
        "        var relServers = related(memberIds[k], 'cmdb_ci_hardware');",
        '        for (var r3 = 0; r3 < relServers.length; r3++)',
        '            led = keep(relServers[r3]) || led;',
        '        if (!led)',
        '            unresolved++;',
        '    }',
        '    var ids = Object.keys(servers);',
        '    var machines = {};                            // name label -> its records',
        '    for (var n = 0; n < ids.length; n++)',
        '        machines[servers[ids[n]]] = (machines[servers[ids[n]]] || []).concat(ids[n]);',
        '    var labels = Object.keys(machines);',
    ])


def rule_455():
    value = '171.203.142.26'
    payload = {"ID": "1202267231", "IP": value, "TRACKING_METHOD": "IP", "OS": "F5 Big IP", "DNS": "crisp-tx.bankofamerica.com"}
    h = header('USEM Load Balancer Member Match',
        'A virtual server usually fronts several real servers, but many front exactly one. When the CMDB holds the pool behind the virtual server and every member of it leads to one and the same machine, the findings scanned on the virtual address belong to that machine. This rule finds the virtual server the way the service rule does, walks Load Balancer Service to Pool to Pool Member to server, and returns the machine only when the whole pool points at it. With several machines, a member the CMDB cannot place, or no pool data, it declines; the service rule then decides whether the virtual server record can stand for the host.',
        payload, 'IP', value, 'the OS and the DNS name',
        'the sys_id of the one real server behind the virtual server (a machine recorded more than once counts once, its live record standing for it); null when the host shows no VIP sign, no virtual server matches or two differently named ones carry the value, the virtual server has no pool or no members, a member leads to no server in the CMDB, two or more machines sit behind it, or two live records of the one machine compete.',
        'the Linux Server "usvacrispweb01", the only member of the pool "crisp-tx-pool" behind the Load Balancer Service "crisp-tx", reached through the member address "10.10.20.31".',
        'the hardware rules declined: a VIP has no serial, "crisp-tx" is not a server name, and the address belongs to a load balancer device.',
        'virtual servers whose pool, fully known to the CMDB, holds exactly one real server.',
        'USEM Load Balancer Service Match, which attaches the virtual server record when the CMDB does not show several servers behind it.')
    body = [OPEN, CHECK, ip_prep(value),
        "    var dns = ('' + (sourcePayload.DNS || '')).trim().toLowerCase();   // \"crisp-tx.bankofamerica.com\", may be empty",
        "    var label = dns.split('.')[0];                // \"crisp-tx\"",
        "    var os = ('' + (sourcePayload.OS || '')).toLowerCase();   // \"f5 big ip\"",
        IGNORE_BLOCK, SEG_MATCH,
        lb_sign_stage('sign', '"f5 big ip" contains "f5", so sign is true. "rbps-dev3-sve-vip.ecommnp.rpg" with OS "Linux 2.6" would qualify through the segment "vip"; "ah-1047132-001" with OS "Red Hat Enterprise Linux 9.8" has neither and the rule would decline.'),
        lb_service_stage('the first step, fqdn "crisp-tx.bankofamerica.com", finds the Load Balancer Service "crisp-tx" and no second row, so twins holds that one record. Two live records named "crisp-tx" on "171.203.142.26", one per balancer of the pair, would both be kept and the pool of each walked below; a retired copy beside a live one would be set aside.'),
        LB_WALK,
        lb_pools_stage('A pool is reached three ways for each record kept, because the load balancer model can be loaded either through reference fields or through relationships: the pool field on the service, pools whose service field points at the service, and pools related to the service. Without a pool the rule declines and the service rule takes over.',
                       'the service "crisp-tx" carries the pool "crisp-tx-pool" in its pool field; poolIds holds that one sys_id.', 'return null;'),
        lb_members_stage('the pool "crisp-tx-pool" has one member, "crisp-tx-pool_10.10.20.31_443", with ip_address "10.10.20.31"; members holds that one entry.', 'return null;'),
        lb_servers_stage('The real servers: every member placed, one machine, one live record',
              'Each member address is looked for on device records, on network adapters and on IP Address records, and each member is followed through its relationships to hardware; load balancer devices and ignored classes are left out. Every server found is kept with the first label of its name, and a member that leads to no server is counted as unplaced. Several records of one name are one machine recorded more than once (a rebuilt server whose old record was retired, a copy left by a test): its live record stands for it when it is the only live one. The machine is the match only when every member leads to it. An unplaced member leaves the pool partly unknown and the rule declines: the one server found may not be the one that was scanned. No server, two differently named machines, or two live records of the one machine decline as well, leaving the host to the service rule.',
              'the Linux Server "usvacrispweb01" carries "10.10.20.31" in its ip_address field, so the one member is placed, servers holds one entry and its sys_id is returned. A retired Server record also named "usvacrispweb01" would be set aside for the live Linux Server; two live records of that name, a second member on "10.10.20.32" that no CI carries, or one owned by "usvacrispweb02", would make the rule decline.'),
        '    if (unresolved || labels.length != 1)',
        '        return null;                              // an unplaced member, no server, or two machines',
        '    var records = machines[labels[0]];',
        '    if (records.length == 1)',
        '        return records[0];',
        '    var live = [];                                // one machine recorded more than once',
        '    for (var f = 0; f < records.length; f++) {',
        "        var ci = new GlideRecord('cmdb_ci_hardware');",
        '        ci.get(records[f]);',
        '        if (!retired(ci))',
        '            live.push(records[f]);',
        '    }',
        '    return live.length == 1 ? live[0] : null;     // two live records compete, never guess',
        CLOSE]
    return write('455', 'USEM Load Balancer Member Match', h + '\n' + '\n'.join(body))
RULES.append(rule_455)


def rule_460():
    value = '171.203.142.26'
    payload = {"ID": "1202267231", "IP": value, "TRACKING_METHOD": "IP", "OS": "F5 Big IP", "DNS": "crisp-tx.bankofamerica.com"}
    h = header('USEM Load Balancer Service Match',
        'A virtual IP answered by a load balancer is not the balancer, and the hardware rules refuse the balancer device on purpose. Such hosts belong to the Load Balancer Service CI that models the VIP, and this rule finds it. It runs on the IP field so that VIPs without a DNS name are covered too.',
        payload, 'IP', value, 'the OS and the DNS name',
        'the sys_id of the one Load Balancer Service CI found by fqdn, then by name, then by address (a retired copy of the record found is set aside); null when the host shows no VIP evidence, when no service matches, when two differently named services carry the value, or when two live records of one virtual server compete.',
        'the Load Balancer Service CI "crisp-tx", whose fqdn is "crisp-tx.bankofamerica.com".',
        'the hardware rules declined: a VIP has no serial, "crisp-tx" is not a server name, and the address belongs to a load balancer device.',
        'hosts with VIP evidence (an OS text naming a load balancer product, or a DNS label with a VIP marker segment such as "-vip" or "vs1"; both lists are declared in the script, at the top of the matching stage) that the member rule left: no pool known, several servers behind the virtual server, or a member the CMDB cannot place.',
        'the IP address rules, for hosts that are not VIPs.')
    body = [OPEN, CHECK, ip_prep(value),
        "    var dns = ('' + (sourcePayload.DNS || '')).trim().toLowerCase();   // \"crisp-tx.bankofamerica.com\", may be empty",
        "    var label = dns.split('.')[0];                // \"crisp-tx\"",
        "    var os = ('' + (sourcePayload.OS || '')).toLowerCase();   // \"f5 big ip\"",
        IGNORE_BLOCK, SEG_MATCH,
        stage('VIP evidence first',
              'The rule goes on only when the OS text contains a listed load balancer word or one of the label segments is a listed VIP marker. A Load Balancer Service must never be returned for an ordinary server that happens to share an address with a VIP; this check keeps the rule to the hosts that really are VIPs.',
              '"f5 big ip" contains "f5", so evidence is true. "rbps-dev3-sve-vip.ecommnp.rpg" with OS "Linux 2.6" would qualify through the segment "vip"; "ah-1047132-001" with OS "Red Hat Enterprise Linux 9.8" has neither and the rule would decline.'),
        c('The load balancer products looked for in the OS text, and the label segments that mark a virtual IP. Extend these two lists when a site uses another naming habit.'),
        "    var osMarkers = ['f5', 'big-ip', 'big ip', 'netscaler'];",
        "    var labelMarkers = ['vip', 'vs'];",
        '    var evidence = false;',
        '    for (var m = 0; m < osMarkers.length; m++)',
        '        if (os.indexOf(osMarkers[m]) != -1)',
        '            evidence = true;',
        "    var segments = label ? label.split('-') : [];",
        '    for (var s = 0; s < segments.length; s++)',
        '        if (isMarker(segments[s], labelMarkers))',
        '            evidence = true;',
        '    if (!evidence)',
        '        return null;',
        RETIRED, NARROW,
        stage('The one service, by fqdn, then name, then address',
              'The scanned DNS name is tried in the fqdn field, then in the name field, then the label in the name field, then the scanned address in ip_address. Each step accepts one virtual server. Several records carrying one name are the same virtual server recorded more than once (an HA pair keeps the same object on both devices; a test leaves a copy): the records answering on the scanned address are kept, then the live ones, and the one record left is returned. Two records still standing, both devices of a pair live, are an ambiguity nothing here can settle, so the rule declines; two different names on the same value decline as well, because a weaker piece of evidence could otherwise pick a different service. A step that finds nothing hands over to the next.',
              'the first step, fqdn "crisp-tx.bankofamerica.com", finds the Load Balancer Service "crisp-tx" and no second row, so its sys_id is returned. Two live records named "crisp-tx" on "171.203.142.26", one per balancer of the pair, would make the rule decline; were one of them retired, the live one would be returned. A VIP without a DNS name and two differently named services on "171.203.142.26" would reach the last step and decline there.'),
        service_one(False),
        "    var steps = [['fqdn', dns], ['name', dns], ['name', label], ['ip_address', ip]];",
        '    for (var t = 0; t < steps.length; t++) {',
        '        var found = one(steps[t][0], steps[t][1]);',
        '        if (found === null)',
        '            return null;',
        '        if (found)',
        '            return found;',
        '    }',
        '    return null;',
        CLOSE]
    return write('460', 'USEM Load Balancer Service Match', h + '\n' + '\n'.join(body))
RULES.append(rule_460)


if __name__ == '__main__':
    os.makedirs(OUT, exist_ok=True)
    files = [f() for f in RULES]
    bad = [fn for fn in files if '...' in open(fn).read() or '…' in open(fn).read()]
    print('written', len(files), 'rule scripts;', 'ellipsis found in: %s' % bad if bad else 'no ellipsis anywhere')
