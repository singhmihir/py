"""Content for 'Qualys CI Lookup Rules - CMDB Team Demo.pptx' (demo_data.json).

Concept slides, one explanation slide per rule (purpose, what it reads and returns, the matching
stages, its place in the chain) and up to three example slides per rule. Examples come from the
output of 'Lookup Rules - Demo Evidence Script.js' run on the client instance, pasted into
demo_examples_output.txt next to this file (the EX lines; demo_examples_override.txt, when present,
replaces the rules it contains). Only examples dedicated to their rule are kept: the CI could not
have been returned by any earlier rule (dedicated() below, the twin of the script's test) and the
rule returns the same CI when replayed. Every example opens with a "Why this rule" step built from
what the earlier rules' searches find for the item (the script's earlier list) or, for older output,
from the facts of the item and the CI. Rebuild with `python3 build_demo_data.py && node build_demo_deck.js`.
"""
import json, os, re, pickle, sys

HERE = os.path.dirname(os.path.abspath(__file__))
STORY = os.path.dirname(HERE)
BASE_URL = 'https://bofasecopsdev.service-now.com'
LB_EXPORTS = '/tmp/claude-0/-home-user-py/92674a7d-a733-5fc3-a7aa-42bdf76f593b/scratchpad/inc3/data.pkl'
OUTPUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, 'demo_examples_output.txt')
CONTROLLER_SUFFIXES = ['ilo', 'ilom', 'idrac', 'drac', 'ipmi', 'bmc', 'oob', 'mgmt', 'imm', 'cimc', 'rmm', 'con']

CONCEPTS = [
    dict(title='How every script runs', kicker='Key concepts', size=10.5, columns=[
        dict(heading='The contract and the search', bullets=[
            dict(title='Contract.', detail='process(rule, sourceValue, sourcePayload) returns one sys_id or null. sourceValue is the rule\'s source field (SERIAL_NUMBER, DNS or IP); the OS, DNS and IP come from the payload.'),
            dict(title='Normalisation.', detail='The value is coerced to a string and trimmed; names are lower-cased; the text before the first dot is the short host; an absent DNS or OS reads as empty, never as the string "undefined".'),
            dict(title='Ignored classes.', detail='The framework\'s _ignoreClass, else sn_sec_cmn.ignoreCIClass, added as sys_class_name NOT IN on every search. Exact class names, no hierarchy.'),
            dict(title='Exactly one.', detail='query() with no setLimit, then next() and hasNext(): a second row declines. The rules that walk records count distinct owning CIs instead, and two owners decline.'),
            dict(title='Address tie-break.', detail='Only the FQDN, host name with domain, layered DNS and device name rules break several candidates with the scanned IP. The address rules never tie-break.'),
            dict(title='Loopback and link-local.', detail='The address and virtual server rules refuse 127. and 169.254. before reading anything else.'),
            dict(title='Retired records.', detail='retired(): install_status 7, operational_status 6 or life cycle stage Retired. The virtual server rules set a retired twin aside; the platform property filterOutDecommissionedCI drops retired CIs after any rule.'),
        ]),
        dict(heading='Class from the scanned OS', bullets=[
            dict(title='classFor(OS).', detail='Lower-cased OS text; three or more "/"-separated guesses give no class. Keywords in order, first hit wins: esx; windows (with server) / windows; aix; solaris, sunos; hp-ux; netapp, ontap; printer, laserjet, jetdirect; red hat, linux, centos, ubuntu, suse, debian, fedora, euleros, oracle enterprise, amazon; nx-os, catos, cisco.'),
            dict(title='Classes.', detail='ESX Server, Windows Server or Computer, AIX Server, Solaris Server, HP-UX Server, Storage Server, Printer, Linux Server, Network Gear. Anything else: no class.'),
            dict(title='Class rules.', detail='Search the OS class and its sub-classes only, and decline without a class. Hardware rules search the whole cmdb_ci_hardware tree and keep the OS class as a preference.'),
            dict(title='Class agreement.', detail='agrees(cls): the CI class equals the OS class, sits beneath it or above it (parentsOf through sys_db_object.super_class). A Cisco IOS router therefore never lands on a Computer.'),
            dict(title='Appliances.', detail='In Layered DNS Match and Hostname Hardware Match a Linux fingerprint also agrees with Network Gear, Load Balancer and Storage Server records, because appliances answer scans as Linux.'),
            dict(title='Load balancer devices.', detail='A cmdb_ci_lb record is never accepted as the host behind a name or an address; the virtual server rules handle those addresses instead.'),
            dict(title='Host name agreement.', detail='The IP rules also require the CI\'s first name label to equal the scanned label, or to differ from it only by a hyphenated suffix such as -mgmt.'),
        ]),
    ]),
    dict(title='The signs the scripts look for', kicker='Key concepts', size=10.5, columns=[
        dict(heading='Serials, phones, controllers', bullets=[
            dict(title='Placeholder serials.', detail='Refused when shorter than four characters or one of: 0, none, n/a, na, unknown, empty, not specified, not available, no serial, default string, to be filled by o.e.m., system serial number, chassis serial number, 0123456789, 1234567890.'),
            dict(title='Cisco phones.', detail='DNS label ^sep([0-9a-f]{12})$: the twelve hex characters are the MAC, rebuilt in four spellings (64:F6:9D:D5:C9:B0, lower case, 64F69DD5C9B0, lower case). Search: a network adapter with that MAC owned by an IP Phone, then the phone\'s own mac_address, then the Unified CM device name SEP... in upper case.'),
            dict(title='Other phones and scanners.', detail='No MAC in the name (Avaya avx... stations, scanners). The host label is searched by name in IP Phone and Imaging Hardware only, outside the hardware tree. Declined when the OS gives a server or desktop class (Linux excepted) unless the OS text says phone; several hits: the one on the scanned address.'),
            dict(title='Management controllers.', detail='Label tail after the last hyphen in ilo, ilom, idrac, drac, ipmi, bmc, oob, mgmt, imm, cimc, rmm, con, or OS text with ilo, ilom, idrac, drac, remote access controller, imm, cimc, bmc, ipmi, lights out. The label before the hyphen is the server name, searched hardware-wide; a load balancer device is refused.'),
            dict(title='Network interfaces.', detail='DNS in a .network. domain, or a hyphen segment that is an interface marker: vlan, v, hsrp, vrrp, po, eth, gi, te, lo, mgmt, aom, vs, fab, whole or followed by digits. Prefixes are tried longest first on Network Gear and Load Balancer devices; two hits decline.'),
        ]),
        dict(heading='Virtual servers, names, addresses', bullets=[
            dict(title='Virtual server sign.', detail='OS text with f5, big-ip, big ip or netscaler, or a label segment vip or vs (vip, vip2, ...-vip, vs1). Load Balancer Service searched on fqdn, then name, then the label, then ip_address.'),
            dict(title='Twins.', detail='Several service records of one name are one virtual server recorded more than once (HA pair, test copy): kept to the one on the scanned address, then the live one. Two different names decline.'),
            dict(title='Member rule.', detail='Service to pools to pool members through cmdb_rel_ci, each member to its server record (in cmdb_ci_hardware, not ignored, not a balancer). One machine behind every member returns the server; a member the CMDB cannot place, several machines or two live records of one machine decline.'),
            dict(title='Service rule.', detail='Never reads the pool. Attaches the one live virtual server record; two live twins decline.'),
            dict(title='Names.', detail='FQDN rules: the whole dotted name on fqdn. FQDN Name rules: the whole dotted name on the name field. Host name rules: the first label on name. Domain rules: the first label on name and the rest on dns_domain. A bare label without a dot declines the FQDN rules.'),
            dict(title='Addresses.', detail='ip_address on the OS class, then on the hardware tree; then the adapter walk (cmdb_ci_network_adapter.ip_address to cmdb_ci) and the IP Address record walk (cmdb_ci_ip_address to nic.cmdb_ci), distinct owners counted, class and host name agreement on the one owner.'),
            dict(title='Last resort.', detail='FQDN Name Broad Match searches the whole cmdb_ci table by name when everything else declined, still one record only.'),
        ]),
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
        names = lambda text: ', '.join(dict.fromkeys(n.replace('USEM ', '') for n in re.findall(r'USEM [A-Z][A-Za-z ]+? Match', text) + re.findall(r'USEM Cisco IP Phone MAC', text)))
        entry['before_names'] = names(m['before']) or ('none, it opens the chain' if 'first rule' in m['before'].lower() or 'nothing custom' in m['before'].lower() else m['before'])
        entry['after_names'] = names(m['after']) or m['after']
        entry.update(purpose=m['purpose'], reads=m['reads'], returns=m['returns'], before=m['before'], after=m['after'],
                     mechanics=[dict(title=s['title'] + '.', detail=s['detail']) for s in m['mechanics']], declines=m['declines'], literals=m['literals'],
                     sibling=m.get('sibling_difference', ''))
    return entry


RULES = [rule_entry(o) for o in ORDERS]
for i, r in enumerate(RULES):
    r['before_names'] = RULES[i - 1]['name'].replace('USEM ', '') if i else 'none, it opens the chain'
    r['after_names'] = RULES[i + 1]['name'].replace('USEM ', '') if i + 1 < len(RULES) else "the platform's own rules (FQDN, NetBIOS, DNS)"

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


KIND = {'175': 'Serial Number Class Match', '180': 'Serial Number Hardware Match', '200': 'Cisco IP Phone MAC', '250': 'FQDN Class Match', '260': 'FQDN Hardware Match',
        '300': 'Hostname Domain Class Match', '310': 'Hostname Domain Hardware Match', '350': 'Layered DNS Match', '400': 'Hostname Class Match', '410': 'Hostname Hardware Match',
        '415': 'Device Name Match', '420': 'Management Interface Match', '430': 'Network Interface Name Match', '450': 'FQDN Name Hardware Match', '455': 'Load Balancer Member Match',
        '460': 'Load Balancer Service Match', '700': 'IP Class Match', '705': 'IP Hardware Match', '730': 'IP Adapter Match', '740': 'IP Layered Match', '850': 'FQDN Name Broad Match'}
FAMILY = [('Serial rules', ['175', '180']), ('Phone MAC rule', ['200']), ('FQDN rules', ['250', '260']), ('Host name with domain rules', ['300', '310']), ('Layered DNS rule', ['350']),
          ('Host name rules', ['400', '410']), ('Device name rule', ['415']), ('Controller rule', ['420']), ('Interface rule', ['430']), ('Whole fqdn name rule', ['450']),
          ('Member rule', ['455']), ('Service rule', ['460']), ('Address rules', ['700', '705']), ('Adapter rule', ['730']), ('IP Address record rule', ['740'])]
CLASS_OF = {'ESX Server': 'cmdb_ci_esx_server', 'Windows Server': 'cmdb_ci_win_server', 'Computer': 'cmdb_ci_computer', 'AIX Server': 'cmdb_ci_aix_server', 'Solaris Server': 'cmdb_ci_solaris_server',
            'HP-UX Server': 'cmdb_ci_hpux_server', 'Storage Server': 'cmdb_ci_storage_server', 'Printer': 'cmdb_ci_printer', 'Linux Server': 'cmdb_ci_linux_server', 'Network Gear': 'cmdb_ci_netgear'}
PARENTS = json.load(open(os.path.join(HERE, 'class_parents.json'))) if os.path.exists(os.path.join(HERE, 'class_parents.json')) else {}
JUNK_SERIALS = ['0', 'none', 'n/a', 'na', 'unknown', 'empty', 'not specified', 'not available', 'no serial', 'default string', 'to be filled by o.e.m.', 'system serial number', 'chassis serial number', '0123456789', '1234567890']


def under(cls, root):
    if not cls: return False
    if cls == root: return True
    if cls not in PARENTS:
        raise SystemExit('class hierarchy unknown for %s: add it to class_parents.json' % cls)
    return root in PARENTS[cls]


def junk_serial(s):
    return not s or len(s) < 4 or s in JUNK_SERIALS


def dedicated(order, item, ci):
    """'' when no rule before this one could have returned the CI and the rule's own sign is present; otherwise the reason.
    The twin of dedicated() in the evidence script, applied to output that predates it."""
    kind = KIND[order]
    dns = (item.get('dns') or '').strip().lower(); lbl = first_label(dns); domain = domain_of(dns)
    ip = (item.get('ip') or '').strip(); pref = CLASS_OF.get(class_from_os(item.get('os', '')), ''); serial = (item.get('serial') or '').strip().lower()
    name = (ci.get('name') or '').strip().lower(); fqdn = (ci.get('fqdn') or '').strip().lower(); cdom = (ci.get('dns_domain') or '').strip().lower()
    cserial = (ci.get('serial') or '').strip().lower(); cls = ci.get('cls', ''); cip = (ci.get('ip') or '').strip()
    address = kind.startswith('IP '); lb = kind.startswith('Load Balancer'); serial_rule = kind.startswith('Serial')
    after_fqdn = kind not in ('Serial Number Class Match', 'Serial Number Hardware Match', 'Cisco IP Phone MAC', 'FQDN Class Match', 'FQDN Hardware Match')
    after_domain = after_fqdn and kind not in ('Hostname Domain Class Match', 'Hostname Domain Hardware Match')
    after_host = kind in ('Management Interface Match', 'Network Interface Name Match', 'FQDN Name Hardware Match', 'FQDN Name Broad Match') or address
    sibling = kind in ('Serial Number Hardware Match', 'FQDN Hardware Match', 'Hostname Domain Hardware Match', 'Hostname Hardware Match', 'IP Hardware Match')
    hw = under(cls, 'cmdb_ci_hardware')
    if not dns and not address and not lb: return 'no DNS name'
    if not serial_rule and hw and not junk_serial(serial) and cserial == serial: return 'the record carries the scanned serial: a serial rule should have found it'
    if after_fqdn and hw and fqdn and fqdn == dns: return 'the record carries the scanned name as its fqdn: an FQDN rule should have found it'
    if after_domain and hw and dns and name == lbl and cdom and cdom == domain: return 'the record carries the scanned label and domain: a domain rule should have found it'
    if after_host and hw and dns and name == lbl: return 'the record is named with the scanned label: a host name rule should have found it'
    if kind in ('FQDN Name Hardware Match', 'FQDN Name Broad Match') and name != dns: return 'the record is not named with the whole fqdn'
    if kind == 'FQDN Name Broad Match' and hw: return 'a hardware record named with the fqdn: FQDN Name Hardware Match should have found it'
    if sibling and pref and under(cls, pref): return 'the record sits in the OS class %s: the class rule before this one should have found it' % pref.replace('cmdb_ci_', '')
    if kind in ('IP Adapter Match', 'IP Layered Match') and ip and cip == ip: return 'the record carries the scanned address itself: an address rule before this one should have found it'
    return ''


def why_from_earlier(order, earlier):
    """One clause per rule family from the findings of the earlier rules (the script's earlier list), siblings merged."""
    found = {e['order']: e['found'] for e in earlier}
    parts = []
    for label, orders in FAMILY:
        hits = [found[o] for o in orders if o in found]
        if not hits: continue
        hits = list(dict.fromkeys(hits))
        parts.append('%s: %s' % (label, ' / '.join(hits)))
    return parts


def why_from_facts(order, item, ci):
    """The same idea for output without the earlier list: why no rule before this one could have returned this CI, from the facts of the item and the CI."""
    kind = KIND[order]
    dns = (item.get('dns') or '').strip().lower(); lbl = first_label(dns); domain = domain_of(dns); os_text = item.get('os', '')
    pref_label = class_from_os(os_text); pref = CLASS_OF.get(pref_label, ''); serial = (item.get('serial') or '').strip()
    name = (ci.get('name') or '').strip(); fqdn = (ci.get('fqdn') or '').strip(); cdom = (ci.get('dns_domain') or '').strip(); cls = ci.get('cls', ''); cls_label = ci.get('cls_label') or cls
    hw = under(cls, 'cmdb_ci_hardware'); q = lambda v: '"%s"' % v
    parts = []
    if order == '175':
        return ['first rule of the chain: the serial is searched inside the OS class before any name or address is read']
    if kind.startswith('IP ') and not dns:
        parts.append('no DNS name reported, only the address: no serial, phone or name rule could run')
    else:
        if not serial: parts.append('no serial reported: serial rules skipped')
        elif junk_serial(serial.lower()): parts.append('serial %s is a placeholder: serial rules refuse it' % q(serial))
        elif hw: parts.append('the record does not carry the scanned serial %s' % q(serial))
        if order not in ('180', '200') and not re.match(r'^sep[0-9a-f]{12}$', lbl): parts.append('label is not sep + twelve hex characters: phone MAC rule skipped')
        if order not in ('180', '200', '250', '260') and hw:
            if not fqdn: parts.append('no fqdn on the record: FQDN rules could not find it')
            else: parts.append('fqdn %s differs from the scanned name: FQDN rules could not find it' % q(fqdn))
        if order in ('350', '400', '410', '415', '420', '430', '450', '455', '460', '700', '705', '730', '740', '850') and hw:
            if name.lower() != lbl: parts.append('named %s, not %s: host name rules could not find it' % (q(name), q(lbl)))
            elif cdom.lower() != domain: parts.append('named %s but %s: host name with domain rules could not confirm it' % (q(name), ('dns_domain ' + q(cdom)) if cdom else 'no dns_domain'))
        if order == '415': parts.append('%s sits outside the hardware tree the name rules search' % cls_label)
        if order == '850': parts.append('%s sits outside the hardware tree the name rules search' % cls_label)
    if order in ('180', '260', '310', '410', '705'):
        if not pref: parts.append('OS %s gives no class: the class rule before this one could not search' % q(os_text or 'not reported'))
        elif not under(cls, pref): parts.append('OS %s gives %s; the record is a %s, outside that class' % (q(os_text), pref_label, cls_label))
    if order == '455': parts.append('the OS or the name marks a virtual server: the hardware rules hand it to the load balancer rules')
    if order == '460': parts.append('the member rule ran first and could not name one machine behind the virtual server')
    if order == '730': parts.append('the CI holds %s on ip_address; the scanned address sits on an adapter record the address rules do not read' % (q(ci.get('ip')) if ci.get('ip') else 'no address'))
    if order == '740': parts.append('the address sits on an IP Address record, not on the CI or an adapter')
    return parts


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
    for key, label in [('fqdn', 'FQDN'), ('dns_domain', 'DNS domain'), ('ip_address', 'IP address'), ('ip', 'IP address'), ('serial_number', 'Serial number'), ('serial', 'Serial number'),
                       ('mac_address', 'MAC address'), ('mac', 'MAC address'), ('load_balancer', 'Load balancer'), ('model', 'Model'), ('install_status', 'Install status'), ('status', 'Install status'),
                       ('operational_status', 'Operational status'), ('operational', 'Operational status')]:
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


def condense(steps):
    """Shorter walk for the slide: the clues that found nothing become one line, a member's several paths to
    the same server become one mention, long record lists are cut to three."""
    out, misses = [], []
    for s in steps:
        title, detail = s['title'], s['detail']
        if title.startswith('Clue ') and detail.startswith('no service record'):
            misses.append(title.split(':')[1].strip().split(' = ')[0])
            continue
        if misses:
            out.append(dict(title='Clue%s %s' % ('s' if len(misses) > 1 else '', ', '.join(misses)), detail='no service record; next clue'))
            misses = []
        if title == 'Members':
            parts = detail.split(': ', 1)
            if len(parts) == 2:
                members = []
                for m in parts[1].split(' ; '):
                    if ' -> ' in m:
                        left, right = m.split(' -> ', 1)
                        hits = [h.strip() for h in right.split(', ')]
                        names, paths = [], []
                        for h in hits:
                            if ' via ' in h:
                                n, p = h.split(' via ', 1)
                                if n not in names: names.append(n)
                                if p not in paths: paths.append(p)
                        right = ', '.join(names) + (' (' + ', '.join(paths) + ')' if paths else '') if names else right
                        members.append(left + ' -> ' + right)
                    else:
                        members.append(m)
                detail = parts[0] + ': ' + ' ; '.join(members[:4]) + (' ; ...' if len(members) > 4 else '')
        if ' ; ' in detail and title.startswith(('Clue', 'Records', 'Pools', 'Adapter', 'IP Address', 'DNS Name')):
            head, sep, tail = detail.partition(': ')
            if sep:
                items = tail.split(' ; ')
                if len(items) > 3:
                    detail = head + ': ' + ' ; '.join(items[:3]) + ' ; ...'
        detail = detail.replace('name agrees with the scanned label ""', 'no scanned label to compare').replace('name agrees with ""', 'no scanned label to compare')
        out.append(dict(title=title, detail=detail))
    if misses:
        out.append(dict(title='Clue%s %s' % ('s' if len(misses) > 1 else '', ', '.join(misses)), detail='no service record'))
    return out


def example(order, item, ci, extra):
    steps = extra.get('steps')
    verdict = extra.get('verdict') or {}
    if 'proper' in extra:
        proper, why = bool(extra['proper']), extra.get('why', '')
    else:
        why = dedicated(order, item, ci) or ('' if verdict.get('same_as_today', True) else 'the rule replayed today returns something else') or ('' if ci.get('live', True) else 'the CI is retired now')
        proper = not why
    if steps:
        walk_lines = [dict(title=s['title'], detail=s['detail']) for s in condense(steps)]
        reasons = why_from_earlier(order, extra['earlier']) if extra.get('earlier') else why_from_facts(order, item, ci)
        if reasons:
            walk_lines.insert(0, dict(title='Why this rule', detail=' \u00b7 '.join(reasons)))
        if verdict and not verdict.get('same_as_today', True):
            walk_lines.append(dict(title='Replay today', detail='the rule now returns ' + (verdict.get('ci_label') or 'nothing') + '; the item still holds the CI matched earlier'))
    else:
        walk_lines = walk(order, item, ci, extra)
    return dict(number=item['number'], host=item.get('dns') or item.get('ip', ''),
                item_link='%s/sn_sec_cmn_src_ci_list.do?sysparm_query=number=%s' % (BASE_URL, item['number']),
                item_facts=item_facts(item), walk=walk_lines, path=extra.get('shape', ''), proper=proper, why=why,
                ci_name=ci.get('name', ''), ci_class=ci.get('cls_label') or ci.get('cls', ''),
                ci_link='%s/%s.do?sys_id=%s' % (BASE_URL, ci.get('cls') or 'cmdb_ci', ci.get('sys_id', '')), ci_facts=ci_facts(ci))


def from_script_output(path):
    """EX lines of the demo evidence script (or the earlier examples script), grouped by rule order; plus the matched counts."""
    examples, counts = {}, {}
    for line in open(path, encoding='utf-8', errors='ignore'):
        line = line.rstrip('\n')
        m = re.match(r'\s*== (\d+) .*?: (\d+) matched items', line)
        if m:
            counts[m.group(1)] = int(m.group(2))
        s = line.strip()
        if s.startswith('EX '):
            ex = json.loads(s[3:])
            if 'ci' in ex and 'cls_label' not in ex['ci']:
                ex['ci']['cls_label'] = ex['ci'].get('cls', '')
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
    source = os.path.basename(OUTPUT)
    OVERRIDE = os.path.join(HERE, 'demo_examples_override.txt')   # a targeted re-run: its rules replace the same rules of the main output
    if os.path.exists(OVERRIDE):
        more, more_counts = from_script_output(OVERRIDE)
        examples.update(more); counts.update(more_counts)
        source += ' + demo_examples_override.txt (' + ', '.join(sorted(more)) + ')'
else:
    examples = from_lb_exports()
    source = 'client exports of 17 Sep (load balancer rules only)'
dropped = []
for r in RULES:
    kept = []
    for x in examples.get(r['order'], []):
        (kept if x['proper'] else dropped).append(x if x['proper'] else (r['order'], x['number'], x['why']))
    r['examples'] = kept[:3]
    r['matched'] = counts.get(r['order'])

CHAIN = [[r['order'], r['name'].replace('USEM ', ''), r['reads'], r['returns']] for r in RULES]
data = dict(title='Qualys CI Lookup Rules', subtitle='How a scanned host finds its CI', concepts=CONCEPTS, chain=CHAIN, rules=RULES, example_source=source)
json.dump(data, open(sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, 'demo_data.json'), 'w'), indent=1)
have = sum(1 for r in RULES if r['examples'])
print('rules: %d | with verified mechanics: %d | rules with examples: %d (%s) | example slides: %d' % (len(RULES), sum(1 for r in RULES if r.get('literals') is not None), have, source, sum(len(r['examples']) for r in RULES)))
for order, number, why in dropped:
    print('  dropped %s %s: %s' % (order, number, why))
short = [(r['order'], len(r['examples'])) for r in RULES if len(r['examples']) < 3]
if short:
    print('  rules with fewer than three dedicated examples: ' + ', '.join('%s (%d)' % s for s in short))
