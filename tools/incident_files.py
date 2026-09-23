"""Copies every file uploaded to the drop-box incidents into <out>/<incident>/ for a private repository: files over 5 MB
are stored compressed with xz, each file is checked against its size, and README.md + manifest.json (size, SHA-256,
upload time) are written. Usage: python3 tools/incident_files.py <out dir>"""
import os, sys, json, hashlib, subprocess
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from snui import SNUI, INST

INCIDENTS = {'INC0010003': 'Qualys CI lookup rules - client exports and run outputs',
             'INC0010004': 'Outbound integration stories - story files',
             'INC0010005': 'Qualys knowledge base and host detection responses',
             'INC0010013': 'SNOWUSEMTP-1639 - story files'}
UPLOADER = 'admin'
COMPRESS_OVER = 5 * 1048576
RAW_TYPES = ('.zip', '.docx', '.pptx', '.xlsx', '.png', '.jpg')

def main(out):
    ui = SNUI(); ui.app('global')
    head = {'X-UserToken': ui.ck(), 'Accept': 'application/json'}
    rows = ui.s.get(INST + '/api/now/table/sys_attachment', params={'sysparm_query': 'table_name=incident^sys_created_by=%s^ORDERBYsys_created_on' % UPLOADER,
                    'sysparm_fields': 'sys_id,file_name,size_bytes,table_sys_id,sys_created_on', 'sysparm_display_value': 'false', 'sysparm_limit': 5000}, headers=head).json()['result']
    numbers = {}
    for sid in set(r['table_sys_id'] for r in rows):
        numbers[sid] = ui.s.get(INST + '/api/now/table/incident/' + sid, params={'sysparm_fields': 'number'}, headers=head).json()['result']['number']
    manifest = []
    for r in rows:
        inc = numbers[r['table_sys_id']]
        if inc not in INCIDENTS: continue
        name = r['file_name'].replace('/', '_'); size = int(r['size_bytes'])
        pack = size > COMPRESS_OVER and not name.lower().endswith(RAW_TYPES)
        stored = os.path.join(inc, name + ('.xz' if pack else ''))
        os.makedirs(os.path.join(out, inc), exist_ok=True)
        data = ui.s.get(INST + '/api/now/attachment/%s/file' % r['sys_id'], headers={'X-UserToken': head['X-UserToken']}, timeout=900).content
        if len(data) != size: sys.exit('size mismatch for %s: %d of %d bytes' % (stored, len(data), size))
        if pack: data_out = subprocess.run(['xz', '-6', '-T0', '-c'], input=data, capture_output=True, check=True).stdout
        else: data_out = data
        open(os.path.join(out, stored), 'wb').write(data_out)
        manifest.append({'incident': inc, 'file_name': r['file_name'], 'stored_as': stored, 'bytes': size, 'sha256': hashlib.sha256(data).hexdigest(), 'uploaded': r['sys_created_on']})
        print('%s %d -> %d' % (stored, size, len(data_out)), flush=True)
    json.dump(manifest, open(os.path.join(out, 'manifest.json'), 'w'), indent=1)
    lines = ['# USEM incident files', '', 'Every file uploaded to the USEM drop-box incidents, in one folder per incident. Files over 5 MB are stored',
             'compressed with xz (`.xz`; open with `xz -dk <file>` or 7-Zip). `manifest.json` lists each file with its original',
             'size, SHA-256 and upload time.', '']
    for inc in sorted(INCIDENTS):
        rs = [x for x in manifest if x['incident'] == inc]
        if not rs: continue
        lines += ['## %s - %s (%d files, %.1f MB)' % (inc, INCIDENTS[inc], len(rs), sum(x['bytes'] for x in rs) / 1048576.0), '', '| Uploaded | File | Size |', '|---|---|---|']
        lines += ['| %s | [%s](<%s>) | %s |' % (x['uploaded'][:16], x['file_name'].replace('|', '\\|'), x['stored_as'],
                  '%.1f MB' % (x['bytes'] / 1048576.0) if x['bytes'] >= 1048576 else '%d KB' % max(1, x['bytes'] // 1024)) for x in rs] + ['']
    open(os.path.join(out, 'README.md'), 'w').write('\n'.join(lines))
    print(len(manifest), 'files')

if __name__ == '__main__':
    main(sys.argv[1])
