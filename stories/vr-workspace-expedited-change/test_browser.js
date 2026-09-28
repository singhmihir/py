// Drives the Create Change modal of the VR workspace for one application remediation task and prints one JSON line:
// the change type options offered, the fields shown for the chosen type and, when asked, the submission.
// Usage: node test_browser.js <task sys_id> <type label> <submit yes|no> <screenshot prefix>
const { open, login, INST } = require('./browser.js');
const [taskId, typeLabel, submit, shot] = process.argv.slice(2);
(async () => {
  const out = { task: taskId, type: typeLabel };
  const { b, p } = await open();
  try {
    await login(p);
    await p.goto(INST + '/now/vr/record/sn_vul_app_vulnerability/' + taskId, { waitUntil: 'load', timeout: 180000 });
    const button = p.getByRole('button', { name: 'Create Change', exact: true }).first();
    await button.waitFor({ timeout: 180000 }); await p.waitForTimeout(3000); await button.click();
    const heading = p.getByText('Create change request', { exact: true }).first();
    await heading.waitFor({ timeout: 120000 }); await p.waitForTimeout(8000);
    const picker = p.locator('now-select').first();
    await picker.click(); await p.waitForTimeout(2000);
    out.options = [...new Set((await p.locator('[role="option"]').allInnerTexts()).map((s) => s.split('\n')[0].trim()))];
    const option = p.locator('[role="option"][id$="change_type-option-' + typeLabel.toLowerCase() + '"]').locator('visible=true').first();
    await option.dispatchEvent('click');
    await p.waitForTimeout(4000);
    out.selected = (await picker.locator('button, [role="combobox"]').first().innerText()).split('\n')[0].trim();
    out.templateShown = await p.getByText('Standard change template').first().isVisible().catch(() => false);
    out.implementationShown = await p.getByText('Implementation plan', { exact: true }).first().isVisible().catch(() => false);
    const create = p.getByRole('button', { name: 'Create change request', exact: true }).first();
    out.createEnabled = await create.isEnabled();
    await p.screenshot({ path: shot + '_selected.png' });
    if (submit === 'yes') {
      await create.click();
      await heading.waitFor({ state: 'hidden', timeout: 180000 });
      await p.waitForTimeout(10000);
      out.submitted = true;
      await p.screenshot({ path: shot + '_after.png' });
    }
  } catch (e) { out.error = e.message.slice(0, 300); await p.screenshot({ path: shot + '_error.png' }).catch(() => {}); }
  await b.close();
  console.log('R::' + JSON.stringify(out));
})();
