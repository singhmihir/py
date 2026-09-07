"""Local analysis of unmatched_profile.json: evidence categories in the sample."""
import json, os, re
from collections import Counter
HERE = os.path.dirname(os.path.abspath(__file__))
P = json.load(open(os.path.join(HERE, 'unmatched_profile.json')))
S = P['sample']; N = len(S)
def pct(n): return '%5.1f%%' % (100.0 * n / N)
print('sample rows', N, '| created', min(r['created'] for r in S), '->', max(r['created'] for r in S))
print('tracking method:', Counter(r['t'] for r in S).most_common())
print('placeholder class:', Counter(r['c'] for r in S).most_common())
print('has DNS %s | has NETBIOS %s | has QG_HOSTID %s | has serial %s | has cloud id %s' % tuple(pct(sum(1 for r in S if r[k])) for k in ('dns', 'nb', 'qg', 'sn', 'cloud')))
pats = [('no DNS (IP only)', lambda r: not r['dns']), ('DNS without dot', lambda r: r['dns'] and '.' not in r['dns']),
        ('.rpg domain', lambda r: r['dns'].lower().endswith('.rpg')), ('.network. domain', lambda r: '.network.' in r['dns'].lower()), ('.sdi.corp.', lambda r: '.sdi.corp.' in r['dns'].lower()),
        ('corp.bankofamerica.com', lambda r: r['dns'].lower().endswith('.corp.bankofamerica.com')), ('bankofamerica.com (any)', lambda r: r['dns'].lower().endswith('bankofamerica.com')), ('baml.com', lambda r: r['dns'].lower().endswith('baml.com')), ('bofa.com', lambda r: r['dns'].lower().endswith('bofa.com')),
        ('label has -vip / vip', lambda r: re.search(r'(^|-)vip(-|$|\.)', r['dns'].split('.')[0].lower()) is not None), ('label has -ilom/-idrac/-drac/-ipmi/-bmc/-oob/-mgmt/-rmm/-con', lambda r: re.search(r'-(ilom|idrac|drac|ipmi|bmc|oob|mgmt|rmm|con)$', r['dns'].split('.')[0].lower()) is not None),
        ('label has -temp', lambda r: r['dns'].split('.')[0].lower().endswith('-temp')), ('label has -vlan / -dhcp', lambda r: re.search(r'-(vlan|dhcp)', r['dns'].split('.')[0].lower()) is not None),
        ('asset-tag label (xH-1234567-001)', lambda r: re.match(r'^[a-z]h-\d{7}-\d{3}[a-z]?$', r['dns'].split('.')[0].lower()) is not None), ('sep phone label', lambda r: re.match(r'^sep[0-9a-f]{12}$', r['dns'].split('.')[0].lower()) is not None),
        ('OS F5', lambda r: 'f5' in r['os'].lower() or 'big-ip' in r['os'].lower() or 'big ip' in r['os'].lower()), ('OS empty/None', lambda r: r['os'] in ('', 'None')), ('OS multi-guess (3+ /)', lambda r: r['os'].count('/') >= 2),
        ('OS windows', lambda r: 'windows' in r['os'].lower()), ('OS linux family', lambda r: any(k in r['os'].lower() for k in ('linux', 'red hat', 'ubuntu', 'centos', 'suse', 'debian'))), ('OS esx', lambda r: 'esx' in r['os'].lower()), ('OS aix/solaris/hp-ux', lambda r: any(k in r['os'].lower() for k in ('aix', 'solaris', 'sunos', 'hp-ux'))),
        ('OS netapp', lambda r: 'netapp' in r['os'].lower()), ('OS cisco', lambda r: 'cisco' in r['os'].lower()), ('OS printer', lambda r: any(k in r['os'].lower() for k in ('printer', 'laserjet', 'jetdirect', 'lexmark'))),
        ('OS embedded/appliance words', lambda r: any(k in r['os'].lower() for k in ('qnx', 'camera', 'idrac', 'ilom', 'avocent', 'embedded', 'pdu', 'apc ', 'vxworks'))),
        ('NETBIOS equals DNS label', lambda r: r['nb'] and r['nb'].lower() == r['dns'].split('.')[0].lower()), ('NETBIOS differs from DNS label', lambda r: r['nb'] and r['dns'] and r['nb'].lower() != r['dns'].split('.')[0].lower())]
for label, f in pats:
    n = sum(1 for r in S if f(r)); print('%-58s %5d %s' % (label, n, pct(n)))
print('\ndomain suffix (last two labels) top 25:', Counter('.'.join(r['dns'].lower().split('.')[-2:]) for r in S if r['dns']).most_common(25))
print('\nlabel suffix after last hyphen top 30:', Counter(r['dns'].split('.')[0].lower().rsplit('-', 1)[1] for r in S if r['dns'] and '-' in r['dns'].split('.')[0]).most_common(30))
print('\nOS top 25 in sample:', Counter(r['os'] for r in S).most_common(25))
print('\nfull population OS top 30:', P['by_os'][:30]); print('netbios filled', P['netbios_filled'], '| resource_id filled', P['resource_id_filled'])
