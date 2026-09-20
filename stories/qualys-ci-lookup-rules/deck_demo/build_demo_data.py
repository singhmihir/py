"""Content for 'Qualys CI Lookup Rules - CMDB Team Demo.pptx' (demo_data.json).

Concept slides, one explanation slide per rule (purpose, what it reads and returns, the matching
stages, its place in the chain) and three example slides per rule. Examples come from the output of
'Lookup Rules - Demo Examples Script.js' run on the client instance, pasted into
demo_examples_output.txt next to this file (the EX lines); until that file exists the two load
balancer rules take their examples from the client exports of 17 Sep and every other rule shows a
placeholder slide. Rebuild with `python3 build_demo_data.py && node build_demo_deck.js`.
"""
import json, os, re, pickle, sys

HERE = os.path.dirname(os.path.abspath(__file__))
STORY = os.path.dirname(HERE)
BASE_URL = 'https://bofasecopsdev.service-now.com'
LB_EXPORTS = '/tmp/claude-0/-home-user-py/92674a7d-a733-5fc3-a7aa-42bdf76f593b/scratchpad/inc3/data.pkl'
OUTPUT = os.path.join(HERE, 'demo_examples_output.txt')
CONTROLLER_SUFFIXES = ['ilo', 'ilom', 'idrac', 'drac', 'ipmi', 'bmc', 'oob', 'mgmt', 'imm', 'cimc', 'rmm', 'con']

CONCEPTS = [
    dict(title='What a CI lookup rule does', kicker='Key concepts', bullets=[
        'Qualys sends one record per scanned host: DNS name, IP address, operating system, serial number, NetBIOS name. Each record lands as a Discovered Item.',
        'The platform runs the CI lookup rules in order. Each rule reads one source field (serial, DNS or IP) plus the rest of the record, searches the CMDB and returns one CI or nothing.',
        'The first rule that returns a CI wins: the item is matched to it and every vulnerable item of that host attaches to that CI.',
        'When no rule answers, the item stays unmatched and receives a placeholder record (Unclassed Hardware) until it is evaluated again.',
        'Items are evaluated again on the next import, when a rule changes, or on demand with the list action "Reapply CI lookup rules".',
    ]),
    dict(title='Principles the USEM rules share', kicker='Key concepts', bullets=[
        'Exactly one record or decline. A rule never picks between two candidates; ambiguity stays unmatched for the CMDB to resolve.',
        'The scanned OS sets the class: Red Hat means Linux Server, Windows Server means Windows Server, NetApp means Storage Server. The search stays inside that class first, then goes hardware-wide.',
        'Class agreement: a CI reached through DNS or IP records must be of a class the OS implies (same, parent or child), so a Cisco IOS router never lands on a Computer.',
        'Ignored classes never answer: adapters, IP address records, storage volumes, certificates and the other classes on sn_sec_cmn.ignoreCIClass.',
        'Strongest identifier first: serial, then FQDN, host name with domain, DNS layers, host name, controllers and interfaces, virtual servers, IP address, and a broad name search last.',
        'No fitness heuristics: no "best" record by class depth or last update. A retired duplicate is set aside for the live record; two live records decline.',
    ]),
]

# ------------------------------------------------------------------ per-rule explanation
DECK = json.load(open(os.path.join(STORY, 'deck', 'deck_data.json')))['rules']
BY_ORDER = {r['order']: r for r in DECK}
GROUP = {'Serial': 'Serial number', 'Phone': 'Phone', 'Name': 'Name', 'Backlog': 'Controllers, interfaces, virtual servers', 'Address': 'IP address', 'Fallback': 'Broad name'}
EXTRA = {
    '415': dict(name='USEM Device Name Match', group='Name',
                purpose='IP Phones and Scanners sit outside the Hardware tree, so the hardware-wide name rules never see them, and they report no OS. This rule looks for the scanned host name in exactly those two classes.',
                reads='DNS, plus the OS and the IP', returns='the one IP Phone or Imaging Hardware CI named with the host name; the scanned address breaks a tie',
                before='USEM Hostname Hardware Match, which searches the Hardware tree only.', after='USEM Management Interface Match.',
                rows=[['Refuse when the OS names a server or desktop'], ['Host name searched in IP Phone and Imaging Hardware'], ['One device, else the scanned address breaks the tie']]),
    '455': dict(name='USEM Load Balancer Member Match', group='Backlog',
                purpose='Many virtual servers front exactly one real server. When the CMDB holds the pool behind the virtual server and every member leads to one and the same machine, the findings belong to that machine.',
                reads='IP, plus the OS and the DNS name', returns='the one real server behind the virtual server; null with several machines, a member the CMDB cannot place, or no pool data',
                before='the hardware rules, which decline a virtual address.', after='USEM Load Balancer Service Match, which attaches the virtual server record when the CMDB does not show several servers behind it.',
                rows=[['VIP sign: load balancer OS or a VIP marker in the name'], ['Virtual server found on fqdn, then name, then address'], ['Service to Pool to Pool Member to server'], ['One machine behind the whole pool, else decline']]),
}
ORDERS = ['175', '180', '200', '250', '260', '300', '310', '350', '400', '410', '415', '420', '430', '450', '455', '460', '700', '705', '730', '740', '850']


MECHANICS_FILE = os.path.join(HERE, 'mechanics.json')   # verified scripting-level content per rule, written from the readers' output
MECH = {}
if os.path.exists(MECHANICS_FILE):
    for family in json.load(open(MECHANICS_FILE)).values():
        for r in family.get('rules', []):
            MECH[r['order']] = r


def rule_entry(order):
    r = BY_ORDER.get(order) or EXTRA[order]
    m = MECH.get(order)
    entry = dict(order=order, name=r['name'], group=GROUP[r['group']], purpose=r['purpose'], reads=r['reads'], returns=r['returns'],
                 before=r['before'], after=r['after'], mechanics=[row[0] for row in r['rows']], declines=[])
    if m:
        entry.update(purpose=m['purpose'], reads=m['reads'], returns=m['returns'], before=m['before'], after=m['after'],
                     mechanics=[dict(title=s['title'], detail=s['detail']) for s in m['mechanics']], declines=m['declines'], literals=m['literals'],
                     sibling_difference=m.get('sibling_difference', ''))
    return entry


RULES = [rule_entry(o) for o in ORDERS]

# ------------------------------------------------------------------ examples
def first_label(dns):
    return (dns or '').split('.')[0]


def domain_of(dns):
    parts = (dns or '').split('.')
    return '.'.join(parts[1:]) if len(parts) > 1 else ''


def class_from_os(os_text):
    s = (os_text or '').lower()
    if len(s.split('/')) > 2: return ''
    if 'esx' in s: return 'ESX Server'
    if 'windows' in s: return 'Windows Server' if 'server' in s else 'Computer'
    if 'aix' in s: return 'AIX Server'
    if 'solaris' in s or 'sunos' in s: return 'Solaris Server'
    if 'hp-ux' in s: return 'HP-UX Server'
    if 'netapp' in s or 'ontap' in s: return 'Storage Server'
    if any(w in s for w in ['printer', 'laserjet', 'jetdirect']): return 'Printer'
    if any(w in s for w in ['red hat', 'linux', 'centos', 'ubuntu', 'suse', 'debian', 'fedora', 'euleros', 'oracle enterprise', 'amazon']): return 'Linux Server'
    if any(w in s for w in ['nx-os', 'catos', 'cisco']): return 'Network Gear'
    return ''


def walk(order, item, ci, extra):
    dns, ip, os_text = item.get('dns', ''), item.get('ip', ''), item.get('os', '')
    name, domain, cls = first_label(dns), domain_of(dns), class_from_os(os_text)
    ci_name, ci_cls = ci.get('name', ''), ci.get('cls_label') or ci.get('cls', '')
    q = lambda v: '"%s"' % v
    cls_line = 'OS %s sets the class %s' % (q(os_text), cls) if cls else 'OS %s gives no class, so the search is hardware-wide' % q(os_text or 'not reported')
    one = 'Exactly one record answers, ignored classes left out: %s [%s]' % (ci_name, ci_cls)
    if order == '175':
        return ['Serial read from the record: %s' % q(item.get('serial', '')), cls_line, 'One %s carries that serial: %s' % (cls, ci_name)]
    if order == '180':
        return ['Serial read from the record: %s' % q(item.get('serial', '')), 'Class search gave nothing or the OS gives no class, so the whole hardware tree is searched', one]
    if order == '200':
        return ['DNS name %s starts with sep and twelve hex characters: the phone\'s MAC address' % q(dns), 'Network adapter carrying that MAC found, then the phone it belongs to', 'Phone CI: %s [%s]' % (ci_name, ci_cls)]
    if order in ('250', '260'):
        return ['Whole FQDN %s searched on the fqdn field' % q(dns), cls_line if order == '250' else 'Class search gave nothing, so the whole hardware tree is searched',
                'One record carries it; with several, the scanned address %s breaks the tie' % ip, 'Match: %s [%s]' % (ci_name, ci_cls)]
    if order in ('300', '310'):
        return ['Host name %s and domain %s searched together (name and dns_domain)' % (q(name), q(domain)), cls_line if order == '300' else 'Hardware-wide search', one]
    if order == '350':
        return ['DNS Name record %s followed to its IP Address records, then to the adapter, then to the CI' % q(dns), 'The CI\'s class agrees with the scanned OS %s' % q(os_text), 'Match: %s [%s]' % (ci_name, ci_cls)]
    if order == '400':
        return ['Host name %s searched on the name field' % q(name), cls_line, one]
    if order == '410':
        return ['Host name %s searched on the name field across the whole hardware tree' % q(name), 'Class agreement with the scanned OS %s' % q(os_text or 'not reported'), one]
    if order == '415':
        return ['No server or desktop OS reported', 'Host name %s searched in IP Phone and Imaging Hardware, outside the hardware tree' % q(name), 'One device (or the one on the scanned address %s): %s [%s]' % (ip, ci_name, ci_cls)]
    if order == '420':
        low = name.lower(); base = name
        for s in CONTROLLER_SUFFIXES:
            if low.endswith('-' + s) or low.endswith(s) and len(low) > len(s):
                base = name[:len(name) - len(s)].rstrip('-_.'); break
        return ['Management controller sign: suffix on %s or a controller word in the OS %s' % (q(name), q(os_text)), 'Controller suffix stripped, server name %s searched' % q(base), 'One server of that name: %s [%s]' % (ci_name, ci_cls)]
    if order == '430':
        return ['Interface sign: domain or marker in %s' % q(dns), 'The device name before the interface marker searched on Network Gear and Load Balancer devices', 'One device of that name: %s [%s]' % (ci_name, ci_cls)]
    if order == '450':
        return ['Whole FQDN %s searched on the name field, hardware-wide' % q(dns), 'Class agreement with the scanned OS %s' % q(os_text or 'not reported'), one]
    if order == '455':
        svc = (extra.get('services_on_address') or [None])[0]
        lines = ['VIP sign: OS %s or a VIP marker in %s' % (q(os_text), q(dns))]
        if svc:
            pools = svc.get('pools') or []
            members = [m for p in pools for m in p.get('members', [])]
            lines.append('Virtual server %s on %s, pool %s, %d member%s' % (svc.get('name'), ip, pools[0]['name'] if pools else 'none', len(members), '' if len(members) == 1 else 's'))
            lines.append('Every member (%s) leads to the same machine' % ', '.join(sorted(set(m.get('ip') or m.get('name') for m in members))[:4]))
        else:
            lines.append('Virtual server on %s found, its pool walked to the pool members' % ip)
            lines.append('Every member leads to the same machine')
        lines.append('Server returned: %s [%s]' % (ci_name, ci_cls))
        return lines
    if order == '460':
        return ['VIP sign: OS %s or a VIP marker in %s' % (q(os_text), q(dns)), 'Load Balancer Service record looked up on fqdn, then name, then the address %s; the pool is not read' % ip,
                'One live record for that virtual server: %s' % ci_name, 'The virtual server record stands for the host']
    if order in ('700', '705'):
        return ['Address %s searched on ip_address' % q(ip), cls_line if order == '700' else 'Hardware-wide search with class agreement against the scanned OS', one]
    if order == '730':
        return ['IP Address record %s followed to its network adapter, then to the CI' % q(ip), 'The CI\'s class agrees with the scanned OS %s' % q(os_text or 'not reported'), 'Match: %s [%s]' % (ci_name, ci_cls)]
    if order == '740':
        return ['IP Address record %s followed through the adapter and DNS layers to the CI' % q(ip), 'The CI\'s class agrees with the scanned OS %s' % q(os_text or 'not reported'), 'Match: %s [%s]' % (ci_name, ci_cls)]
    if order == '850':
        return ['Every earlier rule declined', 'Host name %s searched on the name field across all CI classes' % q(name), one]
    return [one]


def ci_facts(ci):
    facts = []
    for key, label in [('fqdn', 'FQDN'), ('dns_domain', 'DNS domain'), ('ip_address', 'IP address'), ('serial_number', 'Serial number'), ('mac_address', 'MAC address'),
                       ('load_balancer', 'Load balancer'), ('model', 'Model'), ('install_status', 'Install status'), ('operational_status', 'Operational status')]:
        v = ci.get(key, '')
        if v and v not in ('Unknown', 'null'):
            facts.append([label, v])
    return facts


def item_facts(item):
    facts = [['DNS name', item.get('dns') or '(none)'], ['IP address', item.get('ip', '')], ['Operating system', item.get('os') or '(not reported)']]
    for key, label in [('serial', 'Serial number'), ('netbios', 'NetBIOS name'), ('tracking', 'Tracking'), ('updated', 'Last evaluated')]:
        if item.get(key):
            facts.append([label, item[key]])
    return facts


def example(order, item, ci, extra):
    return dict(number=item['number'], host=item.get('dns') or item.get('ip', ''),
                item_link='%s/sn_sec_cmn_src_ci_list.do?sysparm_query=number=%s' % (BASE_URL, item['number']),
                item_facts=item_facts(item), walk=walk(order, item, ci, extra),
                ci_name=ci.get('name', ''), ci_class=ci.get('cls_label') or ci.get('cls', ''),
                ci_link='%s/%s.do?sys_id=%s' % (BASE_URL, ci.get('cls') or 'cmdb_ci', ci.get('sys_id', '')), ci_facts=ci_facts(ci))


def from_script_output(path):
    """EX lines of the demo examples script, grouped by rule order; plus the matched counts."""
    examples, counts = {}, {}
    for line in open(path, encoding='utf-8', errors='ignore'):
        line = line.rstrip('\n')
        m = re.match(r'\s*== (\d+) .*?: (\d+) matched items', line)
        if m:
            counts[m.group(1)] = int(m.group(2))
        s = line.strip()
        if s.startswith('EX '):
            ex = json.loads(s[3:])
            examples.setdefault(ex['rule'], []).append(example(ex['rule'], ex['item'], ex['ci'], ex))
    return examples, counts


def from_lb_exports():
    """The two load balancer rules from the 17 Sep client exports: 455 servers with their service and pool, 460 service records."""
    if not os.path.exists(LB_EXPORTS):
        return {}
    p = pickle.load(open(LB_EXPORTS, 'rb'))
    items, services, cis, members = p['items'], p['services'], p['cis'], p['members']
    by_ip = {}
    for s in services.values():
        by_ip.setdefault(s['ip'], []).append(s)
    out = {}
    preferred = {'455': ['SDI000002418623', 'SDI000002411394', 'SDI000002375027', 'SDI000002993687', 'SDI000003028419'],
                 '460': ['SDI000003028240', 'SDI000003069763', 'SDI000003069406', 'SDI000003727785', 'SDI000003069445', 'SDI000003069510']}
    label = {'Load Balancer Service': 'cmdb_ci_lb_service', 'Linux Server': 'cmdb_ci_linux_server', 'Windows Server': 'cmdb_ci_win_server', 'Server': 'cmdb_ci_server'}
    for order, rule_name in [('455', 'BOFA Load Balancer Member Match'), ('460', 'BOFA Load Balancer Service Match')]:
        rows = [i for i in items if i['rule'] == rule_name]
        rows.sort(key=lambda i: (i['number'] not in preferred[order], preferred[order].index(i['number']) if i['number'] in preferred[order] else 0))
        picks = []
        for i in rows[:3]:
            item = dict(number=i['number'], dns=i['dns'], ip=i['ip'], os=i['os'], updated=i['updated'])
            ci = dict(sys_id=i['ci'], name=i['ci_name'], cls=label.get(i['ci_class'], 'cmdb_ci'), cls_label=i['ci_class'])
            extra = {}
            svcs = by_ip.get(i['ip'], [])
            if order == '455' and svcs:
                s = svcs[0]
                pool_members = [dict(name=m['name'], ip=m['ip'], port=m['port']) for m in members if m.get('pool_name') == s['pool_name']]
                extra['services_on_address'] = [dict(name=s['name'], pools=[dict(name=s['pool_name'], members=pool_members)])]
            if order == '460':
                ci['fqdn'] = cis.get(i['ci'], {}).get('fqdn', '')
                ci['ip_address'] = cis.get(i['ci'], {}).get('ip', '')
                ci['load_balancer'] = cis.get(i['ci'], {}).get('lb', '')
            picks.append(example(order, item, ci, extra))
        out[order] = picks
    return out


examples, counts = ({}, {})
if os.path.exists(OUTPUT):
    examples, counts = from_script_output(OUTPUT)
    source = 'demo_examples_output.txt'
else:
    examples = from_lb_exports()
    source = 'client exports of 17 Sep (load balancer rules only)'
for r in RULES:
    r['examples'] = examples.get(r['order'], [])[:3]
    r['matched'] = counts.get(r['order'])

CHAIN = [[r['order'], r['name'].replace('USEM ', ''), r['reads'], r['returns']] for r in RULES]
data = dict(title='Qualys CI Lookup Rules', subtitle='How a scanned host finds its CI', concepts=CONCEPTS, chain=CHAIN, rules=RULES, example_source=source)
json.dump(data, open(os.path.join(HERE, 'demo_data.json'), 'w'), indent=1)
have = sum(1 for r in RULES if r['examples'])
print('rules: %d | with verified mechanics: %d | rules with examples: %d (%s) | example slides: %d' % (len(RULES), sum(1 for r in RULES if r.get('literals') is not None), have, source, sum(len(r['examples']) for r in RULES)))
