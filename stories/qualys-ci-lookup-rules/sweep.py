"""Runs the platform's CIIdentify.identify() for the Qualys source over one sample payload per
rule (the payloads from the rule headers) and prints which rule and CI answered. Used before and
after a redeploy to show the chain behaves the same. `python3 sweep.py out.json`"""
import os, sys, json
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
QUALYS = 'ed44bdc453220300e8f9f745911c0801'
MULTI = 'Ubuntu / Tiny Core Linux / Linux 2.6.x / IBM ASM / HP StoreOnce / F5 Networks Big-IP / Cisco IOS Software'
CASES = [
    ('175 serial in class', {"ID": "35832680", "IP": "171.128.225.96", "TRACKING_METHOD": "AGENT", "OS": "Red Hat Enterprise Linux 9.8", "DNS": "ah-1047132-001.sdi.corp.bankofamerica.com", "SERIAL_NUMBER": "VMware-42 1a 9c 3f 7d 2e 61 b8-55 04 e2 91 6a 27 c3 08"}),
    ('180 serial, multi-guess OS', {"ID": "35920204", "IP": "171.135.28.125", "TRACKING_METHOD": "IP", "OS": MULTI, "DNS": "txr9gxcenah031.sdi.corp.bankofamerica.com", "SERIAL_NUMBER": "MXQ13005TC"}),
    ('200 phone', {"ID": "41277345", "IP": "30.144.62.108", "TRACKING_METHOD": "IP", "OS": "Cisco IP Phone", "DNS": "sep64f69dd5c9b0.voip.bankofamerica.com"}),
    ('250 fqdn in class', {"ID": "83047612", "IP": "30.206.199.36", "TRACKING_METHOD": "IP", "OS": "VMware ESXi 7.0.3 build 24723872", "DNS": "vsdnac22xsdi004.sdi.corp.bankofamerica.com"}),
    ('260 fqdn, multi-guess OS', {"ID": "35920204", "IP": "171.135.28.125", "TRACKING_METHOD": "IP", "OS": MULTI, "DNS": "txr9gxcenah031.sdi.corp.bankofamerica.com"}),
    ('300 host+domain in class', {"ID": "35832680", "IP": "171.128.225.96", "TRACKING_METHOD": "AGENT", "OS": "Red Hat Enterprise Linux 9.8", "DNS": "ah-1047132-001.sdi.corp.bankofamerica.com"}),
    ('310 host+domain hardware', {"ID": "35884392", "IP": "171.128.140.192", "TRACKING_METHOD": "IP", "OS": "Ubuntu/Linux", "DNS": "lrche01xtrapd01.sdi.corp.bankofamerica.com"}),
    ('350 layered dns', {"ID": "42773078", "IP": "167.202.60.26", "TRACKING_METHOD": "IP", "OS": "Red Hat Enterprise Linux Server 7.9", "DNS": "hklvteqoradbp3.hk.baml.com"}),
    ('400 hostname in class', {"ID": "35850078", "IP": "30.143.70.11", "TRACKING_METHOD": "IP", "OS": "Windows Server 2016 Standard 64 bit Edition Version 1607", "DNS": "wsaoi01zeapd1.sdi.corp.bankofamerica.com", "NETBIOS": "WSAOI01ZEAPD1"}),
    ('410 hostname hardware', {"ID": "80217765", "IP": "171.150.219.123", "TRACKING_METHOD": "IP", "OS": "AIX 7.3 TL3", "DNS": "va2ausapabw0.bankofamerica.com"}),
    ('420 ilo', {"ID": "1201534877", "IP": "159.185.200.11", "TRACKING_METHOD": "IP", "OS": "HP iLO", "DNS": "tx6dd630001-ilo.bankofamerica.com"}),
    ('430 interface', {"ID": "1187423005", "IP": "171.149.3.49", "TRACKING_METHOD": "IP", "OS": "Linux 2.6", "DNS": "uspaltwrr01drm0119-cz04-hsrp-vlan705.network.bankofamerica.com"}),
    ('450 full fqdn name', {"ID": "71973166", "IP": "164.91.209.12", "TRACKING_METHOD": "AGENT", "OS": "Red Hat Enterprise Linux 8.10", "DNS": "lva40bneehcs01.ecomm.devicenp.rpg"}),
    ('460 vip', {"ID": "1202267231", "IP": "171.203.142.26", "TRACKING_METHOD": "IP", "OS": "F5 Big IP", "DNS": "crisp-tx.bankofamerica.com"}),
    ('700 ip in class', {"ID": "83047621", "IP": "30.162.178.21", "TRACKING_METHOD": "IP", "OS": "VMware ESXi 7.0.3 build 24723872"}),
    ('705 ip hardware, no class', {"ID": "83047624", "IP": "30.162.178.24", "TRACKING_METHOD": "IP", "OS": MULTI}),
    ('730 ip adapter', {"ID": "83047622", "IP": "30.162.178.22", "TRACKING_METHOD": "IP", "OS": MULTI}),
    ('740 ip layered', {"ID": "83047623", "IP": "30.162.178.23", "TRACKING_METHOD": "IP", "OS": MULTI}),
    ('850 broad name', {"ID": "71973167", "IP": "164.91.209.13", "TRACKING_METHOD": "AGENT", "OS": "Red Hat Enterprise Linux 8.10", "DNS": "lva40bneehcs02.ecomm.devicenp.rpg"}),
    ('no evidence at all', {"ID": "1", "IP": "10.255.255.254", "TRACKING_METHOD": "IP", "OS": "Windows 10 Enterprise", "DNS": "nosuchhost-zz.corp.bankofamerica.com"}),
]
ui = SNUI(); ui.app('global')
r = ui.js('''
var o = {results: []}; var cases = %s; var ci = new sn_sec_cmn.CIIdentify();
for (var i = 0; i < cases.length; i++) {
    var res = null, err = '';
    try { res = ci.identify(%s, cases[i][1], true); } catch (ex) { err = '' + ex; }
    var out = {label: cases[i][0], rule: '', ci: '', cls: '', error: err};
    if (res && res.lookupRule) { var rr = new GlideRecord('sn_sec_cmn_ci_lookup_rule'); rr.get(res.lookupRule); out.rule = '' + rr.getValue('order') + ' ' + rr.getValue('name'); }
    if (res && res.ci && res.ci.mainCi) { var c = new GlideRecord('cmdb_ci'); c.get(res.ci.mainCi); out.ci = '' + c.getValue('name'); out.cls = '' + c.getValue('sys_class_name'); }
    o.results.push(out);
}
gs.print('X::' + JSON.stringify(o));''' % (json.dumps(CASES), json.dumps(QUALYS)))
for x in r['results']:
    print('%-28s -> %-40s %s %s %s' % (x['label'], x['rule'] or '(no match)', x['ci'], ('[' + x['cls'] + ']') if x['ci'] else '', ('ERROR ' + x['error']) if x['error'] else ''))
if len(sys.argv) > 1:
    json.dump(r['results'], open(sys.argv[1], 'w'), indent=1)
