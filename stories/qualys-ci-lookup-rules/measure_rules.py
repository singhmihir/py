"""Runs measure_rules.js on the instance with small limits and prints its output (a dry run of the
read-only measurement script before it is handed over)."""
import os, sys, re, html
BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, 'tools'))
from snui import SNUI
HERE = os.path.dirname(os.path.abspath(__file__))
script = open(os.path.join(HERE, 'measure_rules.js')).read()
for k, v in [('MATCHED_LIMIT', sys.argv[1] if len(sys.argv) > 1 else '20'), ('UNMATCHED_LIMIT', sys.argv[2] if len(sys.argv) > 2 else '20'), ('DAYS', sys.argv[3] if len(sys.argv) > 3 else '0')]:
    script = re.sub(r'var %s = \d+;' % k, 'var %s = %s;' % (k, v), script)
ui = SNUI(); ui.app('global')
raw = ui.run(script)
text = html.unescape(re.sub(r'<[^>]+>', '', raw))
start = text.find('=== Qualys lookup rule measurement')
print(text[start:] if start >= 0 else text[-3000:])
