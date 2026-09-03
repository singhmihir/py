"""Minimal ServiceNow instance harness used for building and testing stories on the PDI.

Credentials are never stored in the repository. Set them in the environment:
    SN_INSTANCE  e.g. https://devXXXXXX.service-now.com   (defaults to the PDI noted in the working agreement)
    SN_USER      the working user id
    SN_PASSWORD  its password
"""
import html
import json
import os
import re
import sys

import requests

INST = os.environ.get('SN_INSTANCE', 'https://dev390397.service-now.com')
CA = os.environ.get('SN_CA_BUNDLE', '/root/.ccr/ca-bundle.crt')


class SNUI:
    def __init__(self, user=None, pw=None):
        user = user or os.environ.get('SN_USER')
        pw = pw or os.environ.get('SN_PASSWORD')
        if not user or not pw:
            raise RuntimeError('set SN_USER and SN_PASSWORD in the environment')
        self.s = requests.Session()
        self.s.verify = CA if os.path.exists(CA) else True
        r = self.s.post(INST + '/login.do', data={
            'user_name': user, 'user_password': pw,
            'sys_action': 'sysverb_login', 'sysparm_login_url': 'welcome.do',
            'remember_me': 'true', 'screensize': '1920x1080'})
        r.raise_for_status()
        if 'logged in' not in r.text.lower() and 'glide_user_activity' not in str(self.s.cookies):
            chk = self.s.get(INST + '/sys.scripts.do')
            if 'sysparm_ck' not in chk.text:
                raise RuntimeError('login failed for ' + user)

    def ck(self):
        """Session token, read from the background-script page."""
        r = self.s.get(INST + '/sys.scripts.do')
        m = re.search(r'name="sysparm_ck"[^>]*value="([^"]+)"', r.text) or re.search(r"sysparm_ck=([0-9a-f]{72,})", r.text)
        if not m:
            raise RuntimeError('no sysparm_ck; page said: ' + r.text[:300])
        return m.group(1)

    def app(self, app_id):
        """Switch the session's current application (what the UI picker does).

        Switching to 'global' also saves the user preference, because the
        picker alone does not persist it and a fresh login would otherwise
        come back in the last scoped application.
        """
        r = self.s.put(INST + '/api/now/ui/concoursepicker/application',
                       json={'app_id': app_id}, headers={'X-UserToken': self.ck()})
        r.raise_for_status()
        if app_id == 'global':
            self.s.post(INST + '/sys.scripts.do', data={
                'script': "gs.getUser().savePreference('apps.current_app', 'global');",
                'sysparm_ck': self.ck(), 'runscript': 'Run script',
                'quota_managed_transaction': 'on', 'sys_scope': 'global'}).raise_for_status()

    def run(self, script, scope='global'):
        """Run a background script. scope='global' posts sys_scope=global; any other
        value is a scope sys_id: the session app is switched to it for the call and
        back to global afterwards (posting sys_scope cross-scope is refused)."""
        data = {'script': script, 'sysparm_ck': self.ck(),
                'runscript': 'Run script', 'quota_managed_transaction': 'on'}
        switched = False
        if scope == 'global':
            data['sys_scope'] = 'global'
        else:
            self.app(scope)
            switched = True
        try:
            r = self.s.post(INST + '/sys.scripts.do', data=data)
            r.raise_for_status()
            txt = r.text
        finally:
            if switched:
                self.app('global')
        m = re.search(r'<PRE>(.*?)</PRE>', txt, re.S | re.I)
        out = html.unescape(re.sub(r'<[^>]+>', '', m.group(1))) if m else txt[:2000]
        return out.strip()

    def js(self, code, scope='global', marker='X'):
        """Run a script that prints '<marker>::{json}' and return the parsed object."""
        out = self.run(code, scope=scope)
        m = re.search(marker + r'::(\{.*\})', out, re.S)
        if not m:
            raise RuntimeError('NO MARKER; tail: ' + out[-1500:])
        return json.loads(m.group(1))

    def export_update_set(self, set_id, out_path):
        """Platform-native export (what the Export to XML button does), scrubbed of the
        working user id. Returns the number of updates in the file."""
        r = self.js('''var us = new GlideRecord('sys_update_set'); us.get(%s);
gs.print('X::' + JSON.stringify({rid: '' + new UpdateSetExport().exportUpdateSet(us)}));''' % json.dumps(set_id))
        resp = self.s.get(INST + '/export_update_set.do', params={
            'sysparm_sys_id': r['rid'], 'sysparm_delete_when_done': 'true',
            'sysparm_is_remote': 'false', 'sysparm_ck': self.ck()})
        content = resp.text.replace(os.environ.get('SN_USER', ''), 'admin')
        open(out_path, 'w').write(content)
        return content.count('<sys_update_xml ')

    def ui_import_test(self, xml_path, set_name):
        """Push an exported file through the same upload path as 'Import Update Set from
        XML', report the retrieved set's update names, then delete the retrieved copy."""
        import time
        content = open(xml_path).read()
        self.s.post(INST + '/sys_upload.do', data={
            'sysparm_ck': self.ck(), 'sysparm_target': 'sys_remote_update_set',
            'sysparm_referring_url': 'sys_remote_update_set_list.do', 'sysparm_encryption_context': ''},
            files={'attachFile': (os.path.basename(xml_path), content.encode(), 'text/xml')}, allow_redirects=True)
        time.sleep(3)
        return self.js('''
var o = {sets: []};
var rs = new GlideRecord('sys_remote_update_set'); rs.addQuery('name', %s); rs.addQuery('sys_created_on', '>', gs.minutesAgoStart(3)); rs.query();
while (rs.next()) {
    var names = []; var ux = new GlideRecord('sys_update_xml'); ux.addQuery('remote_update_set', rs.getUniqueValue()); ux.query();
    while (ux.next()) names.push('' + ux.getValue('target_name') + ':' + ux.getValue('action'));
    o.sets.push({state: '' + rs.state, app: '' + rs.application.getDisplayValue(), names: names});
    var dd = new GlideRecord('sys_update_xml'); dd.addQuery('remote_update_set', rs.getUniqueValue()); dd.query();
    while (dd.next()) dd.deleteRecord();
    rs.deleteRecord();
}
gs.print('X::' + JSON.stringify(o));''' % json.dumps(set_name))


if __name__ == '__main__':
    ui = SNUI()
    print(ui.run(sys.stdin.read(), sys.argv[1] if len(sys.argv) > 1 else 'global'))
