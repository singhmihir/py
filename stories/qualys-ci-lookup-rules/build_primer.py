"""'Qualys CI Lookup Rules - Plain English Primer.xlsx': the vocabulary, one payload explained,
the chain, every rule's core idea with its sample payload, and a demo Q&A. Run with the
scratchpad as the working directory (the repository root shadows numpy)."""
import json, os
from openpyxl import Workbook
from openpyxl.styles import Font, Alignment, PatternFill, Border, Side
from openpyxl.utils import get_column_letter
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'Qualys CI Lookup Rules - Plain English Primer.xlsx')
CAP = {r['order']: r for r in json.load(open('/tmp/claude-0/-home-user-py/92674a7d-a733-5fc3-a7aa-42bdf76f593b/scratchpad/rules_capture.json'))}
F = 'Arial'; NAVY = '1F3864'; BLUE = 'DCE6F1'; GREY = 'F2F2F2'; GREEN = 'E2EFDA'; AMBER = 'FFF2CC'
thin = Side(style='thin', color='BFBFBF'); BOX = Border(left=thin, right=thin, top=thin, bottom=thin)
def font(sz=10, b=False, c='000000', i=False): return Font(name=F, size=sz, bold=b, color=c, italic=i)
def fill(c): return PatternFill('solid', fgColor=c)
wb = Workbook()

def title(ws, text, sub):
    ws['A1'] = text; ws['A1'].font = font(16, True, NAVY)
    ws['A2'] = sub; ws['A2'].font = font(10, False, '595959', True)
    ws.row_dimensions[1].height = 26
def table(ws, top, headers, rows, widths, fills=None, hfill=NAVY):
    for j, h in enumerate(headers, 1):
        c = ws.cell(row=top, column=j, value=h); c.font = font(10, True, 'FFFFFF'); c.fill = fill(hfill)
        c.alignment = Alignment(vertical='center', wrap_text=True); c.border = BOX
    for i, r in enumerate(rows):
        for j, v in enumerate(r, 1):
            c = ws.cell(row=top + 1 + i, column=j, value=v); c.font = font(10, j == 1 or (fills and fills == 'first' and j == 1))
            c.alignment = Alignment(vertical='top', wrap_text=True); c.border = BOX
            if i % 2: c.fill = fill(GREY)
    for j, w in enumerate(widths, 1): ws.column_dimensions[get_column_letter(j)].width = w
    ws.freeze_panes = ws.cell(row=top + 1, column=1)
def para(ws, row, text, b=False, c='000000', sz=10, height=None, span=6):
    ws.cell(row=row, column=1, value=text).font = font(sz, b, c)
    ws.cell(row=row, column=1).alignment = Alignment(wrap_text=True, vertical='top')
    ws.merge_cells(start_row=row, start_column=1, end_row=row, end_column=span)
    if height: ws.row_dimensions[row].height = height

# ------------------------------------------------------------ 1. Start here
ws = wb.active; ws.title = '1 Start here'
title(ws, 'Qualys CI lookup rules - the whole story in one page', 'Read this sheet first. Everything else is detail you can look up when a question comes.')
r = 4
for txt, b, h in [
 ('WHAT HAPPENS', True, 16),
 ('Qualys scans machines on the network. For every machine it sends ServiceNow a small packet of facts called the payload: the IP address, the DNS name, the operating system it detected, and sometimes a serial number or a NetBIOS name.', False, 44),
 ('ServiceNow has to answer one question for each payload: which record (CI) in our CMDB is this machine? The CI lookup rules answer it.', False, 30),
 ('The rules run one after another, in a fixed order. Each rule looks at one piece of evidence and searches the CMDB. The first rule that finds exactly one CI wins and the host is matched to it. A rule that finds nothing, or more than one CI, says "not me" and the next rule gets its turn. If no rule finds it, the host lands on the Unmatched list for a person to look at.', False, 58),
 ('', False, 8),
 ('THE THREE RULES OF THE GAME', True, 16),
 ('1. Strongest evidence first.  Serial number (never changes) before names (get reused) before IP addresses (get reused and shared).', False, 30),
 ('2. Never guess.  A rule returns a CI only when exactly one CI fits. Two candidates = decline. Wrong matches are worse than no match.', False, 30),
 ('3. Narrow first, then wide.  The OS text tells us the CMDB class (Red Hat -> Linux Server). A rule first searches inside that class; its "Hardware" twin then searches every hardware class, for hosts whose OS is unknown or whose CI is stored in a generic class.', False, 44),
 ('', False, 8),
 ('HOW TO SAY IT IN THE DEMO (30 seconds)', True, 16),
 ('"Each scanned host arrives with a few facts. We try to identify it the way a person would: first the serial number, then its name, then its address. At every step we accept a CI only when it is the single exact fit, so we never attach findings to the wrong server. Hosts that no rule can place stay in Unmatched. The three newest rules handle labels that are not a machine\'s own name: management controllers like iLO, switch interfaces, and load balancer virtual IPs."', False, 72),
 ('', False, 8),
 ('SHEETS', True, 16),
 ('2 Basics - the words (IP, hostname, domain, FQDN, DNS, serial, MAC, class...) in one line each, with a real example.', False, 18),
 ('3 One payload - a real payload with every field explained.', False, 18),
 ('4 The chain - the 19 rules in run order, one line each.', False, 18),
 ('5 Rules explained - the heart of each rule, its sample payload, what happens to the sample, and when it says no.', False, 18),
 ('6 Demo Q&A - likely questions with short answers, and what the unmatched hosts actually are.', False, 18)]:
    para(ws, r, txt, b, NAVY if b else '000000', 11 if b else 10, h); r += 1
for j, w in enumerate([22, 22, 22, 22, 22, 22], 1): ws.column_dimensions[get_column_letter(j)].width = w

# ------------------------------------------------------------ 2. Basics
ws = wb.create_sheet('2 Basics')
title(ws, 'The words, one line each', 'Examples are taken from real payloads in the feed.')
table(ws, 4, ['Term', 'In one line', 'Example', 'Why it matters for matching'], [
 ('Payload', 'The small packet of facts Qualys sends for one scanned host.', '{"IP": "171.128.225.96", "DNS": "ah-1047132-001.sdi.corp.bankofamerica.com", "OS": "Red Hat Enterprise Linux 9.8", ...}', 'Everything a rule can use is in here. Thin payloads (IP only) give the rules less to work with.'),
 ('IP address', 'The number a machine uses on the network, like a phone number.', '171.128.225.96', 'Weakest evidence: addresses move to other machines and are shared by load balancers. Used last.'),
 ('Hostname', 'The short name of a machine, like a first name.', 'ah-1047132-001', 'Many CIs are named with the hostname only. The same hostname can exist in two domains.'),
 ('Domain', 'The "area" a name belongs to, like a surname or a street.', 'sdi.corp.bankofamerica.com', 'Confirms which "ah-1047132-001" we mean. Some CIs keep it in the dns_domain field.'),
 ('FQDN (fully qualified domain name)', 'Hostname + domain, the complete name.', 'ah-1047132-001.sdi.corp.bankofamerica.com', 'The most precise name evidence. CIs may store it in the fqdn field, in the name field, or nowhere.'),
 ('DNS', 'The network\'s phone book: it turns names into IP addresses and back. In the payload, the DNS field holds the full name Qualys got from that phone book.', 'DNS = "ah-1047132-001.sdi.corp.bankofamerica.com"', 'The DNS field is the name evidence every name rule reads. 86% of hosts have one.'),
 ('DNS label', 'The first piece of the DNS name, before the first dot.', 'ah-1047132-001 (from the FQDN above)', 'Special labels tell us what the host is: "sep" + MAC = Cisco phone, "-ilo" = management controller, "-vlan705" = switch interface.'),
 ('NetBIOS name', 'The old Windows-style short name, upper case, max 15 characters.', 'WSAOI01ZEAPD1', 'Windows CIs are often named with it. Only 5% of hosts carry one.'),
 ('Serial number', 'The manufacturer\'s number stamped on the hardware (or given to a VM).', 'MXQ13005TC', 'Strongest evidence: it stays with the machine for life. Fake ones exist ("To be filled by O.E.M.") and are ignored. Only 0.3% of hosts report one.'),
 ('MAC address', 'The fixed id of a network card, 12 hex characters.', '64:F6:9D:D5:C9:B0', 'Cisco phones are named "SEP" + MAC, so the name can be turned back into a MAC and looked up.'),
 ('OS (operating system text)', 'What Qualys thinks the machine runs.', '"Red Hat Enterprise Linux 9.8"   or a guess like "Ubuntu / Tiny Core Linux / F5 Big-IP / Cisco IOS"', 'Tells the rule which CMDB class to search (Red Hat -> Linux Server). Empty for a third of hosts; a multi-guess for 5%. Then the class is unknown.'),
 ('Tracking method', 'How Qualys scanned the host.', 'AGENT (agent installed, rich facts) or IP (scanned over the network, thin facts)', 'Agent hosts carry serials and good names; network-scanned hosts are often IP only.'),
 ('CI, CMDB, class', 'CI = one record for one machine. CMDB = the database of all CIs. Class = the type of record.', 'Linux Server, Windows Server, ESX Server, IP Switch, IP Phone, Load Balancer Service', 'Rules search inside a class when the OS is known, so a Linux host cannot land on a Windows record with the same name.'),
 ('Hardware tree', 'The family of classes under "Hardware": every server, switch, printer, phone, storage box.', 'cmdb_ci_hardware and all its sub-classes', 'The "Hardware" twin of each rule searches this whole tree when the class is unknown.'),
 ('Generic class', 'A CI stored as plain "Server" or "Computer" instead of a specific class.', 'Server, Computer, UNIX Server', 'Common in loaded data. Never contradicts an OS, so a generic CI is accepted by the hardware-wide rules.'),
 ('Load balancer and VIP', 'A device that answers on one shared "virtual IP" on behalf of many servers behind it.', 'OS "F5 Big IP", DNS "crisp-tx.bankofamerica.com"', 'A VIP is not a server. The hardware rules refuse the balancer device; rule 460 maps the VIP to the Load Balancer Service CI.'),
 ('Management controller', 'A small computer inside a server for remote management (HP iLO, Dell iDRAC, IBM IMM, Cisco CIMC). It has its own name and IP.', 'tx6dd630001-ilo.bankofamerica.com, OS "HP iLO"', 'Its findings belong to the server, so rule 420 strips the "-ilo" and matches the server.'),
 ('Network interface / VLAN', 'A switch or router has many addresses, one per interface or VLAN, each scanned under its own label.', 'uspaltwrr01drm0119-cz04-hsrp-vlan705.network.bankofamerica.com', 'The device CI is named with the leading part only; rule 430 walks the label prefix by prefix.'),
 ('Unmatched', 'A scanned host no rule could place on a CI.', 'the Unmatched CI list', 'These are the hosts a person has to look at. The new rules were written from what the unmatched list is made of (sheet 6).'),
], [26, 46, 46, 52])

# ------------------------------------------------------------ 3. One payload
ws = wb.create_sheet('3 One payload')
title(ws, 'One real payload, field by field', 'This is the host from rule 1\'s sample. Fields marked "sometimes" are not sent for every host.')
table(ws, 4, ['Field', 'Value in this payload', 'What it is', 'Which rules use it'], [
 ('ID', '35832680', 'Qualys\' own number for the scanned host.', 'None of the custom rules (an out-of-box rule matches on a stored Qualys host id).'),
 ('IP', '171.128.225.96', 'The address the host was scanned on.', 'The address rules (700-740), the load balancer rule (460), and as a tie-breaker in the name rules.'),
 ('TRACKING_METHOD', 'AGENT', 'How it was scanned: AGENT or IP.', 'Not used to match; explains why a payload is rich or thin.'),
 ('OS', 'Red Hat Enterprise Linux 9.8', 'The operating system Qualys detected.', 'Turned into the CMDB class (Linux Server) by every "Class" rule; a veto in the hardware-wide hostname and IP rules; product words in 420 and 460.'),
 ('DNS', 'ah-1047132-001.sdi.corp.bankofamerica.com', 'The full name from DNS: hostname "ah-1047132-001" + domain "sdi.corp.bankofamerica.com".', 'Every name rule (200-450, 850) and the load balancer rule.'),
 ('SERIAL_NUMBER', 'VMware-42 1a 9c 3f 7d 2e 61 b8-55 04 e2 91 6a 27 c3 08', 'The serial (here a VMware virtual machine serial). Sometimes.', 'The two serial rules (175, 180). They run first.'),
 ('NETBIOS', 'WSAOI01ZEAPD1  (from another host; not in this payload)', 'The Windows short name. Sometimes.', 'An out-of-box rule; the custom rules read the DNS label instead.'),
 ('QG_HOSTID', '633769a4-0139-0002-e352-005056bf41ea  (sometimes)', 'The agent\'s host id.', 'An out-of-box rule, after the custom rules.'),
], [20, 44, 46, 60])
r = 14
para(ws, r, 'What the chain does with this payload: rule 1 (serial, inside Linux Server) finds the CI "ah-1047132-001" by its serial and stops. If the serial had been missing, rule 4 (FQDN) or rule 6 (hostname + domain) would have found the same CI by its name.', False, '000000', 10, 44, 4)

# ------------------------------------------------------------ 4. The chain
ws = wb.create_sheet('4 The chain')
title(ws, 'The 19 rules in run order', 'First rule to return a CI wins. Order = the rule\'s order number in ServiceNow. "Class" = inside the class the OS points at; "Hardware" = every hardware class.')
CHAIN = [
 ('175', 'Serial', 'SERIAL_NUMBER + OS', 'Class', 'The serial, inside the OS class.'),
 ('180', 'Serial', 'SERIAL_NUMBER', 'Hardware', 'The serial, anywhere in hardware (OS unknown or CI classed differently).'),
 ('200', 'Phone', 'DNS label', 'IP Phone CIs', '"sep" + MAC label -> the phone carrying that MAC.'),
 ('250', 'Name', 'DNS + OS + IP', 'Class', 'CI fqdn equals the scanned name; IP breaks a tie.'),
 ('260', 'Name', 'DNS + IP', 'Hardware', 'Same fqdn match, whole hardware tree.'),
 ('300', 'Name', 'DNS + OS + IP', 'Class', 'CI named with the hostname AND its domain agrees (dns_domain or fqdn).'),
 ('310', 'Name', 'DNS + IP', 'Hardware', 'Same hostname + domain match, whole hardware tree.'),
 ('350', 'Name', 'DNS + IP', 'Discovery records', 'Follow DNS Name record -> IP Address record -> adapter -> CI.'),
 ('400', 'Name', 'DNS + OS', 'Class', 'Hostname alone, inside the OS class (class stands in for the missing domain).'),
 ('410', 'Name', 'DNS + OS', 'Hardware', 'Hostname alone, whole tree, refused if the CI class contradicts the OS.'),
 ('420', 'New', 'DNS + OS', 'Hardware', 'Management controller label (name-ilo) -> strip the suffix -> the server.'),
 ('430', 'New', 'DNS + OS', 'Network Gear + Load Balancer devices', 'Interface label (device-cz04-hsrp-vlan705) -> longest prefix that names a device.'),
 ('450', 'Name', 'DNS', 'Hardware', 'CI named with the whole FQDN (appliance domains such as .rpg).'),
 ('460', 'New', 'IP + OS + DNS', 'Load Balancer Service CIs', 'VIP evidence (F5 / vip) -> the service by fqdn, name, label or IP.'),
 ('700', 'Address', 'IP + OS', 'Class', 'The address, inside the OS class.'),
 ('705', 'Address', 'IP + OS', 'Hardware', 'The address, whole tree; not a load balancer; class must not contradict the OS.'),
 ('730', 'Address', 'IP', 'Network Adapter records', 'Adapter carrying the address -> its owning CI.'),
 ('740', 'Address', 'IP', 'IP Address records', 'IP Address record -> adapter -> CI.'),
 ('850', 'Fallback', 'DNS', 'Every CI class', 'CI named with the whole FQDN anywhere, even outside hardware (e.g. a VM instance).'),
]
rows = [(o, CAP[o]['name'], g, ev, where, idea) for o, g, ev, where, idea in CHAIN]
table(ws, 4, ['Order', 'Rule', 'Group', 'Evidence used', 'Searches', 'The idea in one line'], rows, [8, 38, 10, 18, 26, 70])
para(ws, 25, 'After these come the out-of-box Qualys rules (host id, cloud resource id, FQDN, NetBIOS, DNS). Anything still unplaced goes to Unmatched.', True, NAVY, 10, 20, 6)

# ------------------------------------------------------------ 5. Rules explained
ws = wb.create_sheet('5 Rules explained')
title(ws, 'Every rule: the heart of it, a real sample, what happens, when it says no', 'Read one row at a time. The sample payload is the actual example used in the rule\'s own comments.')
def pl(o, keys=None):
    p = CAP[o]['payload']; keys = keys or [k for k in ['IP', 'OS', 'DNS', 'SERIAL_NUMBER', 'NETBIOS'] if k in p]
    return '\n'.join('%s: %s' % (k, p[k]) for k in keys)
LOGIC = {
 '175': ('Serial number first, inside the OS class.',
   'A serial is like a chassis number: it stays with the machine for life while names and addresses get reused. Step 1: throw away fake serials ("To be filled by O.E.M.", "0123456789", anything under 4 characters). Step 2: turn the OS text into a CMDB class (Red Hat -> Linux Server). Step 3: search that class for a CI with exactly this serial. Exactly one -> match.',
   'OS says Red Hat -> class Linux Server. The serial is found on one Linux Server, "ah-1047132-001". Matched.',
   'Serial is a placeholder; the OS gives no class (empty or a multi-guess); two CIs share the serial (a cloned VM).'),
 '180': ('The same serial search, across every hardware class.',
   'For hosts whose OS text is empty or a multi-guess, or whose CI sits in a generic class. Same fake-serial check, then the serial must belong to exactly one CI in the whole hardware tree.',
   'OS is a 7-way guess -> no class. Serial MXQ13005TC exists on exactly one CI in hardware, a generic Server "txr9gxcenah031". Matched.',
   'No serial in the payload; two CIs carry the serial.'),
 '200': ('Cisco phones are named "SEP" + their MAC address.',
   'If the DNS label is exactly "sep" + 12 hex characters, turn it back into a MAC (64:F6:9D:D5:C9:B0) and look for exactly one IP Phone CI carrying it: on its network adapter first, then on the phone record, then a phone named like the label. Any label that is not a phone label passes through untouched.',
   'Label "sep64f69dd5c9b0" -> MAC 64:F6:9D:D5:C9:B0 -> the adapter of IP Phone "SEP64F69DD5C9B0". Matched.',
   'Label is not "sep" + 12 hex (a server called "sepulveda01" is left alone); no phone or two phones carry the MAC.'),
 '250': ('The CI\'s fqdn field equals the scanned name, inside the OS class.',
   'The most precise name evidence there is. Collect every CI of the class whose fqdn equals the scanned name. One -> match. Several -> take the one that also carries the scanned IP, if exactly one does. Otherwise decline.',
   'OS says VMware ESXi -> class ESX Server. One ESX Server has fqdn "vsdnac22xsdi004.sdi.corp.bankofamerica.com". Matched.',
   'No CI stores the fqdn (many are named with the short name only); two CIs share the fqdn and the IP settles nothing; OS gives no class.'),
 '260': ('Same fqdn match, whole hardware tree.',
   'Identical logic to 250 but not limited to one class: for hosts whose OS is unknown, or whose CI is stored in a generic or different class.',
   'OS is a multi-guess -> no class. One hardware CI has that fqdn, the generic Server "txr9gxcenah031". Matched.',
   'No CI stores the fqdn; duplicates the IP cannot separate.'),
 '300': ('CI named with the hostname, and its own domain agrees.',
   'Many CIs are named "ah-1047132-001" only and keep the domain in the dns_domain field or in an fqdn that was never copied into the name. Split the scanned name into hostname + domain. Find CIs of the class named with the hostname; keep only those whose dns_domain or fqdn agrees with the scanned domain. That check keeps findings off a namesake in another domain. One -> match; IP breaks a tie.',
   'Hostname "ah-1047132-001", domain "sdi.corp.bankofamerica.com". One Linux Server has that name and dns_domain = that domain. Matched.',
   'The CI has no domain information at all (then rule 400 tries); two CIs agree and the IP does not settle it.'),
 '310': ('Same hostname + domain match, whole hardware tree.',
   'Identical logic to 300 across all hardware classes, for CIs stored as plain Server or Computer. Widening the search does not weaken the test: the CI\'s own domain must still agree.',
   'OS "Ubuntu/Linux" gives no clean class. A generic Server named "lrche01xtrapd01" has fqdn = the scanned name. Matched.',
   'No CI with that name carries the domain; duplicates.'),
 '350': ('Follow the discovery records: DNS Name -> IP Address -> adapter -> CI.',
   'Discovery sometimes does not write the name on the CI at all; it keeps a separate DNS Name record linked to an IP Address record, linked to a network adapter, linked to the CI. This rule follows that chain from the scanned name. Count the distinct CIs at the end: one -> match; several -> the one reached through the scanned IP. An alias resolves to the real machine because the chain ends on whatever device holds the address.',
   '"hklvteqoradbp3.hk.baml.com" -> DNS Name record -> IP Address 167.202.60.26 -> adapter eth0 -> Linux Server "hklvteqoradbp3". Matched.',
   'No DNS Name record; the name points to two devices and the IP does not pick one.'),
 '400': ('The hostname alone, inside the OS class.',
   'For CIs that carry only a short name and nothing about the domain. Everything from the first dot is dropped. With no domain to confirm, the class is the only safeguard against a namesake, so the name must be unique inside the class.',
   'OS says Windows Server 2016 -> class Windows Server. One Windows Server is named "WSAOI01ZEAPD1". Matched.',
   'OS gives no class; two Windows Servers share the name.'),
 '410': ('The hostname alone, whole tree, with a class veto.',
   'Search all hardware for exactly one CI with the hostname. Then a sanity check: if the OS says AIX and the CI found is a Windows Server, that is a namesake, refuse it. A generic class (Server, Computer, UNIX Server) never contradicts.',
   'OS "AIX 7.3". One CI named "va2ausapabw0", in the generic Server class. Accepted (it would also be accepted as AIX Server, refused as Windows Server). Matched.',
   'Two hardware CIs share the name; the single CI found is of a contradicting class.'),
 '420': ('NEW. Management controllers: strip the suffix, match the server.',
   'HP iLO, Dell iDRAC, IBM IMM, Cisco CIMC, BMC, IPMI are scanned under their own label = server name + a suffix ("-ilo"). Their findings belong to the server. If the label ends in a known suffix (or the OS text names a controller), strip the last segment and search the whole hardware tree for exactly one CI named like the rest. Never a load balancer.',
   'Label "tx6dd630001-ilo", OS "HP iLO". Suffix "-ilo" stripped -> "tx6dd630001" -> one Linux Server. Matched.',
   'No controller suffix and no controller word in the OS; the base name is shared by two CIs; the CI found is a load balancer.'),
 '430': ('NEW. Switch interfaces: walk the label prefix by prefix.',
   'Switches and routers are scanned per interface/VLAN; each label = device name + interface tail. First demand interface evidence (domain ".network." or a marker like vlan, hsrp, vrrp, po, eth, gi, te). Then try prefixes from longest to shortest against Network Gear and Load Balancer devices: "...-cz04-hsrp", then "...-cz04", then "uspaltwrr01drm0119". The first prefix that names exactly one device wins. Longest first stops "site-device-01" being cut down to "site".',
   'Label "uspaltwrr01drm0119-cz04-hsrp-vlan705" under .network. -> prefixes tried -> "uspaltwrr01drm0119" names one IP Switch. Matched.',
   'No interface evidence (ordinary server names with hyphens are left alone); a prefix names two devices.'),
 '450': ('CI named with the whole FQDN.',
   'Some loads name the CI with the complete FQDN instead of the short hostname, typically appliance domains ending in .rpg, so a short-name search can never find them. Compare the complete lower-cased DNS name with the name field across hardware; exactly one.',
   'One hardware CI is named exactly "lva40bneehcs01.ecomm.devicenp.rpg". Matched.',
   'The DNS value has no dot; no CI is named with the full string; two are.'),
 '460': ('NEW. A load balancer virtual IP is not a server.',
   'The hardware rules refuse the balancer device on purpose, because the findings describe the pool behind the VIP. This rule needs VIP evidence first: OS says F5 / Big-IP / NetScaler, or the label carries "vip"/"vs". Then it searches Load Balancer Service CIs with the strongest evidence first: the DNS name as fqdn, then as name, then the label as name, then the IP. The first step that finds exactly one service wins; a step that finds two stops the rule (weaker evidence must not pick a different service).',
   'OS "F5 Big IP", DNS "crisp-tx.bankofamerica.com". One Load Balancer Service has that fqdn: "crisp-tx". Matched.',
   'No VIP evidence (an ordinary server sharing an address with a VIP is never sent here); a step finds two services.'),
 '700': ('The address, inside the OS class. First address rule.',
   'Only reached when there is no serial and no usable name. Addresses are the weakest evidence, so two safeties: loopback (127.x) and link-local (169.254.x) are refused outright, and the search stays inside the OS class, where a VIP or a Windows box that inherited the address cannot appear.',
   'IP only, OS says VMware ESXi -> class ESX Server. One ESX Server has ip_address 30.162.178.21: "vsdnesxm21". Matched.',
   'OS gives no class; two CIs of the class share the address.'),
 '705': ('The address, whole tree, not a balancer, class must not contradict.',
   'Exactly one hardware CI on the address. Refuse it if it is a load balancer (the address is a VIP) or if its class contradicts the OS (generic classes never do).',
   'OS is a multi-guess -> no class. One hardware CI has ip_address 30.162.178.24, a generic Server. Matched.',
   'Address shared by several CIs; the CI is a load balancer; the class contradicts a known OS.'),
 '730': ('The address on a Network Adapter record.',
   'A server with several network cards keeps its addresses on Network Adapter records, not on the CI. Find adapters carrying the address; count the distinct owning CIs (one server with two cards counts once). One owner, not a balancer -> match.',
   'No CI record carries 30.162.178.22, but adapter "eth0" does; its owner is one Server. Matched.',
   'Adapters on two different CIs carry the address; the owner is a load balancer.'),
 '740': ('The address as its own IP Address record.',
   'Newer discovery writes each address as an IP Address record linked to the adapter, and the adapter itself may carry nothing. Read those records: IP Address -> adapter -> CI. Same counting as 730.',
   'Neither the Server nor its adapter holds 30.162.178.23; an IP Address record does -> adapter "eth0" -> the Server. Matched.',
   'Two devices at the end of the chain; a balancer.'),
 '850': ('Last and broad: the whole FQDN as the CI name, anywhere.',
   'The only rule that searches outside the hardware tree, deliberately last. A CI named with the full FQDN in any class, for example a Virtual Machine Instance. Exactly one, with placeholder classes still ignored.',
   '"lva40bneehcs02.ecomm.devicenp.rpg" is the name of one Virtual Machine Instance, which no hardware rule could see. Matched.',
   'Bare label without a dot; nothing named with the full string; two CIs are.'),
}
rows = []
for o, *_ in CHAIN:
    core, logic, sample_out, no = LOGIC[o]
    rows.append((o, CAP[o]['name'], CAP[o]['source'].replace('_', ' ').title().replace('Ip', 'IP') + (' (+ OS)' if 'OS' in CHAIN[[c[0] for c in CHAIN].index(o)][2] else ''), core, logic, pl(o), sample_out, no))
table(ws, 4, ['Order', 'Rule', 'Looks at', 'Heart of the rule', 'How it works', 'Sample payload', 'What happens to the sample', 'When it says no'], rows, [8, 30, 16, 32, 66, 46, 46, 42])
for i in range(5, 5 + len(rows)): ws.row_dimensions[i].height = 150

# ------------------------------------------------------------ 6. Demo Q&A
ws = wb.create_sheet('6 Demo Q&A')
title(ws, 'Questions you may get, and what the unmatched hosts actually are', 'Short answers you can say as they are.')
table(ws, 4, ['Question', 'Answer'], [
 ('Why serial number first?', 'It never changes. Names and IP addresses get reused when machines are rebuilt or replaced.'),
 ('What if two CIs have the same name, serial or address?', 'The rule says no. We never guess. A later rule with different evidence may still find it; otherwise the host waits in Unmatched for a person.'),
 ('Why does each rule have a "Class" version and a "Hardware" version?', 'Narrow first: inside the class the OS points at, where a namesake of another type cannot appear. Wide second: the whole hardware tree, for hosts whose OS is unknown (a third of the feed) or whose CI is stored as a generic Server.'),
 ('What is a class?', 'The type of CMDB record: Linux Server, Windows Server, ESX Server, IP Switch, IP Phone... The OS text tells us which one to search.'),
 ('What if the OS text is empty or a guess like "Ubuntu / F5 / Cisco IOS"?', 'Then there is no class. The class rule steps aside and the hardware-wide twin does the search, with extra checks (not a load balancer, no contradicting class).'),
 ('Why is the IP address used last?', 'It is the weakest fact: addresses move between machines and load balancers answer on shared virtual IPs. It is used only when there is no serial and no usable name.'),
 ('What do the three new rules add?', 'They handle labels that are not a machine\'s own name: management controllers (server-ilo -> the server), switch interfaces (device-vlan705 -> the switch), and load balancer virtual IPs (-> the Load Balancer Service CI). Together they cover the biggest groups on the unmatched list.'),
 ('Where do the suffix and marker lists live?', 'In the rule scripts themselves, as short lists at the top of the relevant stage. No custom system properties.'),
 ('What happens to a host no rule can place?', 'It stays on the Unmatched CI list. Nothing is attached to a wrong CI.'),
 ('How were the rules tested?', 'Each rule was run against fixture CIs for its positive case and its decline cases (nothing found, two found, wrong class, load balancer), and a sample of real unmatched payloads was run through the whole chain before and after.'),
], [52, 110])
r = 17
para(ws, r, 'What the 281,700 unmatched hosts are made of, and which rule now covers each group', True, NAVY, 11, 20, 2); r += 1
table(ws, r, ['Kind of host', 'Count', 'Covered by'], [
 ('Virtual IP of a load balancer', 71892, '460 (new)'),
 ('Host with a plain DNS name', 63089, '250 to 450'),
 ('Network device interface or VLAN', 47420, '430 (new)'),
 ('IP only, no DNS name', 39790, '700 to 740'),
 ('Cisco IP phone, SEP label', 30459, '200'),
 ('Windows workstation', 11679, '400 / 410'),
 ('Printer', 5341, '250 to 450'),
 ('Appliance or embedded device', 5164, '250 to 450'),
 ('Management controller', 4402, '420 (new)'),
 ('Storage system', 1350, '250 to 450'),
 ('Cisco phone, other label', 1056, 'none yet'),
 ('Network device by its own name', 59, '250 to 450'),
], [52, 12, 20])
for i in range(r + 1, r + 13): ws.cell(row=i, column=2).number_format = '#,##0'
ws.freeze_panes = 'A5'
for s in wb.worksheets: s.sheet_view.showGridLines = False
wb.save(OUT); print('written', OUT)
