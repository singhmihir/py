"""Variants of the BlueCat case, fixtures only (no rule changes): the primary name of the device with the
switch's own address, then the same two payloads once the retired duplicate is out of the way."""
import os, sys, json
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
from william_case import run
from sg_case import PAYLOAD, MARK
PRIMARY = dict(PAYLOAD, IP='171.147.117.140', DNS='sgsg02ppz1iptdr02.network.asia.bankofamerica.com', DNS_DATA='sgsg02ppz1iptdr02 network.asia.bankofamerica.com sgsg02ppz1iptdr02.network.asia.bankofamerica.com')
ui = SNUI(); ui.app('global')
print('== both records present, primary name and address of the device (the .140 placeholder of 21 Aug)')
run(ui, PRIMARY, 'SG primary host')
print('== retired Network Gear record renamed SGSG02PPZ1IPTDR02-DECOM (as its Remedy record is named)')
ui.js('''var g = new GlideRecord('cmdb_ci_netgear'); g.addQuery('comments', %s); g.addQuery('sys_class_name', 'cmdb_ci_netgear'); g.query(); while (g.next()) { g.setWorkflow(false); g.setValue('name', 'SGSG02PPZ1IPTDR02-DECOM'); g.update(); } gs.print('X::{}');''' % json.dumps(MARK))
run(ui, PAYLOAD, 'SG mgmt host')
run(ui, PRIMARY, 'SG primary host')
print('== retired record removed altogether')
ui.js('''var g = new GlideRecord('cmdb_ci_netgear'); g.addQuery('comments', %s); g.addQuery('sys_class_name', 'cmdb_ci_netgear'); g.query(); while (g.next()) { g.setWorkflow(false); g.deleteRecord(); } gs.print('X::{}');''' % json.dumps(MARK))
run(ui, PAYLOAD, 'SG mgmt host')
run(ui, PRIMARY, 'SG primary host')
print('== same, payload OS blank (what the chain does when the scan gives no OS)')
run(ui, dict(PAYLOAD, OS=''), 'SG mgmt host, no OS')
run(ui, dict(PRIMARY, OS=''), 'SG primary host, no OS')
