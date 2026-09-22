"""Attaches files to the drop-box incident of this story, replacing any earlier attachment of the same
name, and adds a comment. Usage: python3 attach_1804.py [--comment <text file>] <file> [<file> ...]"""
import os, sys, mimetypes
HERE = os.path.dirname(os.path.abspath(__file__)); BASE = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI, INST
INCIDENT = '5689744193864f10e3aef0aefaba109e'
args = sys.argv[1:]; comment = None
if args and args[0] == '--comment': comment = open(args[1]).read().strip(); args = args[2:]
ui = SNUI(); ui.app('global')
head = {'X-UserToken': ui.ck(), 'Accept': 'application/json'}
for path in args:
    name = os.path.basename(path)
    old = ui.s.get(INST + '/api/now/table/sys_attachment', params={'sysparm_query': 'table_sys_id=%s^file_name=%s' % (INCIDENT, name), 'sysparm_fields': 'sys_id'}, headers=head).json().get('result', [])
    for o in old:
        ui.s.delete(INST + '/api/now/attachment/' + o['sys_id'], headers=head)
    ctype = mimetypes.guess_type(name)[0] or 'application/octet-stream'
    r = ui.s.post(INST + '/api/now/attachment/file', params={'table_name': 'incident', 'table_sys_id': INCIDENT, 'file_name': name},
                  data=open(path, 'rb').read(), headers=dict(head, **{'Content-Type': ctype}))
    res = r.json().get('result', {})
    print('%s -> %s | %s bytes | replaced %d | %s' % (name, r.status_code, res.get('size_bytes'), len(old), res.get('sys_id')))
if comment:
    r = ui.s.patch(INST + '/api/now/table/incident/' + INCIDENT, json={'comments': comment}, headers=dict(head, **{'Content-Type': 'application/json'}))
    print('comment -> %s | %d chars' % (r.status_code, len(comment)))
