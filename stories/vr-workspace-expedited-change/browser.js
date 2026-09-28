// Shared browser setup: every request of the page goes through Playwright's own fetch with limited concurrency
// (Chrome's parallel tunnels through the local proxy fail with ERR_TOO_MANY_RETRIES).
const { chromium } = require('playwright');
const INST = 'https://dev390397.service-now.com';
async function open(limit = 4) {
  const b = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium-1194/chrome-linux/chrome', args: ['--no-sandbox', '--disable-component-update'], proxy: { server: process.env.HTTPS_PROXY } });
  const ctx = await b.newContext({ viewport: { width: 1600, height: 1000 }, ignoreHTTPSErrors: true });
  let active = 0; const queue = [];
  const run = () => { while (active < limit && queue.length) { const job = queue.shift(); active++; job().finally(() => { active--; run(); }); } };
  await ctx.route('**/*', (route) => new Promise((resolve) => {
    const u = route.request().url();
    if (!u.startsWith(INST)) { route.abort().catch(() => {}).finally(resolve); return; }
    queue.push(async () => {
      for (let i = 0; i < 3; i++) {
        try { const resp = await route.fetch({ timeout: 120000, maxRedirects: 20 }); await route.fulfill({ response: resp }); return resolve(); }
        catch (e) { if (i == 2) { await route.abort().catch(() => {}); return resolve(); } }
      }
    });
    run();
  }));
  const p = await ctx.newPage();
  return { b, ctx, p };
}
async function login(p) {
  await p.goto(INST + '/login.do', { waitUntil: 'load', timeout: 180000 });
  await p.fill('#user_name', process.env.SN_USER); await p.fill('#user_password', process.env.SN_PASSWORD);
  await Promise.all([p.waitForLoadState('load', { timeout: 180000 }).catch(() => {}), p.click('#sysverb_login')]);
  await p.waitForTimeout(5000);
}
module.exports = { open, login, INST };
