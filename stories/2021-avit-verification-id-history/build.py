"""SNOWUSEMTP-2021: Verification ID history on the application vulnerable item. Creates (or reuses) the Global update set
and captures in it: the u_verification_id field as a 4000-character string (shown as a multi-line text box), the script
include BOFA_SI_VerificationIdHistory and the before rule that keeps the history. Idempotent: re-running updates the
records in place. Usage: python3 build.py"""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__)); BASE = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI

NAME = 'SNOWUSEMTP-2021_MS_AVIT Verification ID History_V1.1'
DESC = ('Keeps every verification ID VAMP sends for an application vulnerable item: u_verification_id becomes a multi-line field '
        '(string, 4000) and a before rule adds each new ID on its own line under the earlier ones as "<ID> (MM-dd-yyyy HH:mm:ss)", oldest '
        'first, never twice. BOFA_SI_VerificationIdHistory.recordVerification(sourceAvitId, verificationId) finds the items by Source '
        'AVIT ID for the inbound integration.')
SI_NAME = 'BOFA_SI_VerificationIdHistory'
BR_NAME = 'BOFA_BR_AVIT_VerificationIdHistory'
SI = open(os.path.join(HERE, SI_NAME + '.js')).read()
BR = open(os.path.join(HERE, BR_NAME + '.js')).read()
ST_PATH = os.path.join(HERE, 'state.json')
ST = json.load(open(ST_PATH)) if os.path.exists(ST_PATH) else {}
if ST.get('name') != NAME:  # a new version starts its own set
    ST = dict(ST, set='')

ui = SNUI(); ui.app('global')
d = ui.js('''var o = {rows: []};
var us = new GlideRecord('sys_update_set');
if (%(set)s && us.get(%(set)s)) { us.setValue('state', 'in progress'); us.update(); }
else { us.initialize(); us.setValue('name', %(name)s); us.setValue('application', 'global'); us.setValue('description', %(desc)s); us.insert(); }
o.set = us.getUniqueValue(); new GlideUpdateSet().set(o.set);

var f = new GlideRecord('sys_dictionary'); f.addQuery('name', 'sn_vul_app_vulnerable_item'); f.addQuery('element', 'u_verification_id'); f.query();
if (!f.next()) { f.initialize(); f.setValue('name', 'sn_vul_app_vulnerable_item'); f.setValue('element', 'u_verification_id'); f.setValue('internal_type', 'string'); }
f.setValue('column_label', 'Verification ID'); f.setValue('max_length', 4000); f.setValue('active', true);
f.isNewRecord() ? f.insert() : f.update(); o.field = f.getUniqueValue();

var si = new GlideRecord('sys_script_include'); si.addQuery('api_name', 'global.' + %(si_name)s); si.query();
if (!si.next()) { si.initialize(); si.setValue('name', %(si_name)s); }
si.setValue('script', %(si)s); si.setValue('access', 'package_private'); si.setValue('active', true);
si.setValue('description', 'Verification ID history on the application vulnerable item (SNOWUSEMTP-2021).');
si.isNewRecord() ? si.insert() : si.update(); o.si = si.getUniqueValue();

var br = new GlideRecord('sys_script'); br.addQuery('name', %(br_name)s); br.addQuery('collection', 'sn_vul_app_vulnerable_item'); br.query();
if (!br.next()) { br.initialize(); br.setValue('name', %(br_name)s); br.setValue('collection', 'sn_vul_app_vulnerable_item'); }
br.setValue('when', 'before'); br.setValue('order', 1000); br.setValue('action_insert', true); br.setValue('action_update', true);
br.setValue('advanced', true); br.setValue('active', true); br.setValue('filter_condition', 'u_verification_idVALCHANGES^EQ');
br.setValue('script', %(br)s);
br.setValue('description', 'Keeps the Verification ID history: a single new ID is added under the earlier ones with the date (SNOWUSEMTP-2021).');
br.isNewRecord() ? br.insert() : br.update(); o.br = br.getUniqueValue();

var um = new GlideUpdateManager2(); um.saveRecord(f); um.saveRecord(si); um.saveRecord(br);
var doc = new GlideRecord('sys_documentation'); doc.addQuery('name', 'sn_vul_app_vulnerable_item'); doc.addQuery('element', 'u_verification_id'); doc.addQuery('language', 'en'); doc.query(); if (doc.next()) um.saveRecord(doc);
var ux = new GlideRecord('sys_update_xml'); ux.addQuery('update_set', o.set); ux.orderBy('sys_created_on'); ux.query();
while (ux.next()) o.rows.push(ux.getValue('type') + ' | ' + ux.getValue('name') + ' | ' + ux.getValue('action') + ' | ' + ux.application.getDisplayValue());
var cur = new GlideRecord('sys_dictionary'); cur.get(o.field); o.max_length = cur.getValue('max_length');
gs.print('X::' + JSON.stringify(o));''' % dict(set=json.dumps(ST.get('set', '')), name=json.dumps(NAME), desc=json.dumps(DESC),
                                               si_name=json.dumps(SI_NAME), si=json.dumps(SI), br_name=json.dumps(BR_NAME), br=json.dumps(BR)))
print('set', d['set'], '| field', d['field'], 'max_length', d['max_length'], '| si', d['si'], '| br', d['br'])
print('\n'.join('  ' + r for r in d['rows']))
bad = [r for r in d['rows'] if not r.endswith('| Global')]
assert not bad, 'rows outside Global: %s' % bad
json.dump({'set': d['set'], 'name': NAME, 'field': d['field'], 'si': d['si'], 'br': d['br']}, open(ST_PATH, 'w'), indent=1)
