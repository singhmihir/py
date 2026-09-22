"""Import-ready record XML for the client instance: the builder under its existing sys_id with the
JSON-reading script. User, timestamp and mod-count fields are left out so the import stamps them.
The four property values are delivered as files, since their sys_ids on the client are not known."""
import os, re, html
try:
    import defusedxml.ElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
HERE = os.path.dirname(os.path.abspath(__file__)); STORY = os.path.dirname(HERE)
OUT = os.path.join(STORY, 'Remediation Task Payload Builder - Script Include.xml')
src = open(os.path.join(STORY, '..', 'kafka-producer-v2', 'original', 'BOA_SI_USEM_RemediationTaskPayloadBuilder.xml')).read()
rec = re.search(r'<sys_script_include action="INSERT_OR_UPDATE">.*?</sys_script_include>', src, re.S).group(0)
rec = re.sub(r'<(sys_created_by|sys_created_on|sys_updated_by|sys_updated_on|sys_mod_count)>[^<]*</\1>\n?', '', rec)
script = open(os.path.join(HERE, 'BOA_SI_USEM_RemediationTaskPayloadBuilder.js')).read().rstrip('\n')
rec = re.sub(r'<script><!\[CDATA\[.*?\]\]></script>', lambda m: '<script><![CDATA[' + script + ']]></script>', rec, flags=re.S)
desc = ('Builds the outbound Kafka payload for one remediation task. The fields per table come from the system property '
        'x_boar_bofa_usem_1.usem.cdp.remtask.fields.<table>, one servicenow_field=json_field pair per line in payload order; '
        'change_requests and exception_requests are derived.')
rec = re.sub(r'<description>.*?</description>|<description/>', '<description>' + html.escape(desc, quote=False) + '</description>', rec, flags=re.S)
content = '<?xml version="1.0" encoding="UTF-8"?>\n<unload>\n' + rec + '\n</unload>\n'
open(OUT, 'w').write(content)
r = ET.parse(OUT).getroot().find('sys_script_include')
assert r.findtext('script').rstrip('\n') == script and r.findtext('sys_id') == 'b037f7a33bc3cf50e973496ea5e45a82' and r.findtext('sys_scope') == '4ba447d22b43cb10cb55fbcc6e91bf0f'
assert r.findtext('api_name') == 'x_boar_bofa_usem_1.BOA_SI_USEM_RemediationTaskPayloadBuilder' and r.findtext('sys_updated_by') is None
low = content.lower(); hits = [t for t in ['dev390397', 'zk5lg9v', 'service-now.com', 'x_196061', 'bofasim', 'claude', 'anthropic', 'openai'] if t in low]
print('written:', OUT, len(content), 'bytes | sys_id', r.findtext('sys_id'), '| scope', r.findtext('sys_scope'), '| scrub', 'CLEAN' if not hits else hits)
