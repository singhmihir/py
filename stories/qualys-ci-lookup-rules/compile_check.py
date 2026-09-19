"""Parses and runs every generated rule script on the instance with an empty sourceValue and
with its sample payload, so a syntax slip surfaces before the scripts are deployed."""
import os, sys, json, glob
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
HERE = os.path.dirname(os.path.abspath(__file__))
scripts = {os.path.basename(f)[:-3]: open(f).read() for f in sorted(glob.glob(os.path.join(HERE, 'rules', '*.js')))}
ui = SNUI(); ui.app('global')
r = ui.js('''
var o = []; var scripts = %s;
for (var name in scripts) {
    var res = 'ok';
    try {
        var rule = null, sourceValue = '', sourcePayload = {};
        var a = eval(scripts[name]);
        sourceValue = 'zz-no-such-value-zz.corp.bankofamerica.com'; sourcePayload = {IP: '10.255.255.253', OS: 'Red Hat Enterprise Linux 9.8', DNS: sourceValue, SERIAL_NUMBER: 'ZZNOSUCHSERIAL'};
        var b = eval(scripts[name]);
        res = 'ok (empty -> ' + a + ', unknown host -> ' + b + ')';
    } catch (ex) { res = 'ERROR ' + ex; }
    o.push(name + ': ' + res);
}
gs.print('X::' + JSON.stringify({out: o}));''' % json.dumps(scripts))
r = r['out']; print('\n'.join(r)); bad = [x for x in r if 'ERROR' in x]; print('scripts', len(r), 'errors', len(bad)); sys.exit(1 if bad else 0)
