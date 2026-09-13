"""Attaches one or more files to the drop-box incident, replacing any earlier attachment of the same
name. Usage: python3 attach.py <file> [<file> ...]"""
import os, sys, json, mimetypes
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI, INST
INCIDENT = 'b657ee9093064710e3aef0aefaba10c8'
ui = SNUI(); ui.app('global')
head = {'X-UserToken': ui.ck(), 'Accept': 'application/json'}
for path in sys.argv[1:]:
    name = os.path.basename(path)
    old = ui.s.get(INST + '/api/now/table/sys_attachment', params={'sysparm_query': 'table_sys_id=%s^file_name=%s' % (INCIDENT, name), 'sysparm_fields': 'sys_id'}, headers=head).json().get('result', [])
    for o in old:
        ui.s.delete(INST + '/api/now/attachment/' + o['sys_id'], headers=head)
    ctype = mimetypes.guess_type(name)[0] or 'application/octet-stream'
    r = ui.s.post(INST + '/api/now/attachment/file', params={'table_name': 'incident', 'table_sys_id': INCIDENT, 'file_name': name},
                  data=open(path, 'rb').read(), headers=dict(head, **{'Content-Type': ctype}))
    res = r.json().get('result', {})
    print('%s -> %s | %s bytes | replaced %d | %s' % (name, r.status_code, res.get('size_bytes'), len(old), res.get('sys_id')))
