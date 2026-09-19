"""Checks that line_by_line_455_460.json covers every code line of rules 455 and 460 exactly once and in
order (comment-only and blank lines excluded), and prints the differences."""
import json, os, re, sys
HERE = os.path.dirname(os.path.abspath(__file__))
FILES = {'455': 'rules/455_USEM_Load_Balancer_Member_Match.js', '460': 'rules/460_USEM_Load_Balancer_Service_Match.js'}
def code_lines(path):
    s = open(os.path.join(HERE, path)).read(); s = s[s.index('(function process'):]
    return [l for l in s.split('\n') if l.strip() and not l.strip().startswith('//')]
data = json.load(open(os.path.join(HERE, 'line_by_line_455_460.json')))
ok = True
for r in data['rules']:
    want = code_lines(FILES[r['rule']]); got = [l['code'] for st in r['stages'] for l in st['lines']]
    norm = lambda x: re.sub(r'\s+', ' ', x.strip())
    w, g = [norm(x) for x in want], [norm(x) for x in got]
    missing = [x for x in w if x not in g]; extra = [x for x in g if x not in w]
    order_ok = [x for x in g if x in w] == [x for x in w if x in g]
    print('rule %s: script %d code lines, draft %d entries, missing %d, extra %d, order %s' % (r['rule'], len(w), len(g), len(missing), len(extra), 'ok' if order_ok else 'DIFFERS'))
    for x in missing: print('   missing:', x)
    for x in extra: print('   extra:  ', x)
    ok = ok and not missing and not extra and order_ok
print('COVERAGE OK' if ok else 'COVERAGE PROBLEMS'); sys.exit(0 if ok else 1)
