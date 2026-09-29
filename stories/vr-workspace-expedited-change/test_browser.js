// Drives the Create Change dialog of the VR workspace for one remediation task and prints one JSON line: the change
// type options offered, for each type chosen in turn the fields shown, and, when asked, the submission of the last one.
// Usage: node test_browser.js <table> <task sys_id> <type label[,type label...]> <submit yes|no> <screenshot prefix>
const { open, login, INST } = require('./browser.js');
const [table, taskId, labels, submit, shot] = process.argv.slice(2);
(async () => {
  const out = { table: table, task: taskId, checks: {} };
  const { b, p } = await open();
  try {
    await login(p);
    await p.goto(INST + '/now/vr/record/' + table + '/' + taskId, { waitUntil: 'load', timeout: 180000 });
    const button = p.getByRole('button', { name: 'Create Change', exact: true }).first();
    await button.waitFor({ timeout: 180000 }); await p.waitForTimeout(3000); await button.click();
    const create = p.getByRole('button', { name: 'Create change request', exact: true }).first();
    await create.waitFor({ timeout: 120000 }); await p.waitForTimeout(8000);
    const picker = p.locator('now-select').first();
    for (const label of labels.split(',')) {
      await picker.click(); await p.waitForTimeout(2000);
      if (!out.options)
        out.options = [...new Set((await p.locator('[role="option"]').allInnerTexts()).map((s) => s.split('\n')[0].trim()))];
      await p.locator('[role="option"][id$="change_type-option-' + label.toLowerCase() + '"]').locator('visible=true').first().dispatchEvent('click');
      await p.waitForTimeout(4000);
      out.checks[label] = {
        selected: (await picker.locator('button, [role="combobox"]').first().innerText()).split('\n')[0].trim(),
        templateShown: await p.getByText('Standard change template').first().isVisible().catch(() => false),
        implementationShown: await p.getByText('Implementation plan', { exact: true }).first().isVisible().catch(() => false),
        createEnabled: await create.isEnabled(),
      };
      await p.screenshot({ path: shot + '_' + label + '.png' }).catch(() => {});
    }
    if (submit === 'yes') {
      await create.click();
      await create.waitFor({ state: 'hidden', timeout: 180000 });
      await p.waitForTimeout(10000);
      out.submitted = true;
      await p.screenshot({ path: shot + '_after.png' }).catch(() => {});
    }
  } catch (e) { out.error = e.message.slice(0, 300); await p.screenshot({ path: shot + '_error.png' }).catch(() => {}); }
  await b.close();
  console.log('R::' + JSON.stringify(out));
})();
