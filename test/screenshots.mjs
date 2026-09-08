/**
 * 제출용 화면 캡처 만들기 (개발용)
 *   실행: node test/screenshots.mjs  →  evidence/*.png
 */

import path from 'node:path';
import os from 'node:os';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

process.env.NODE_ENV = 'test';
process.env.STORE_FILE = path.join(os.tmpdir(), `passkey-shot-${Date.now()}.json`);

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(__dirname, '..', 'evidence');
fs.mkdirSync(OUT, { recursive: true });

const { createApp } = await import('../src/app.js');
const server = createApp().listen(0);
await new Promise((r) => server.once('listening', r));
const BASE = `http://localhost:${server.address().port}`;

const browser = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium' });
const context = await browser.newContext({ viewport: { width: 1280, height: 900 }, deviceScaleFactor: 2 });
const page = await context.newPage();
const cdp = await context.newCDPSession(page);
await cdp.send('WebAuthn.enable');
await cdp.send('WebAuthn.addVirtualAuthenticator', {
  options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
});

await page.goto(BASE);
await page.screenshot({ path: path.join(OUT, '01-공개영역과-잠긴-비공개영역.png'), fullPage: true });

await page.click('#btn-show-register');
await page.fill('#key-label', '노트북 크롬');
await page.click('#btn-register');
await page.waitForFunction(() => document.getElementById('locked-status').textContent.includes('등록 완료'), { timeout: 15000 });
await page.screenshot({ path: path.join(OUT, '02-등록직후-서버에-저장된-공개키.png'), fullPage: true });

await page.click('#btn-login');
await page.waitForSelector('#unlocked-view:not(.hidden)');
await cdp.send('WebAuthn.addVirtualAuthenticator', {
  options: { protocol: 'ctap2', transport: 'usb', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
});
await page.fill('#key-label-2', '보안키(두 번째)');
await page.click('#btn-add-key');
await page.waitForFunction(() => document.querySelectorAll('#passkey-rows tr').length === 2, { timeout: 15000 });
await page.screenshot({ path: path.join(OUT, '03-열린-비공개영역과-패스키-두-개-목록.png'), fullPage: true });

await page.locator('details.evidence summary').click();
await page.screenshot({ path: path.join(OUT, '04-요청응답-기록-패널.png'), fullPage: true });

// 좁은 화면에서도 가로 넘침이 없는지
const mobile = await browser.newContext({ viewport: { width: 375, height: 780 }, deviceScaleFactor: 2 });
const mpage = await mobile.newPage();
await mpage.goto(BASE);
const overflow = await mpage.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
console.log('375px 가로 넘침(px):', overflow);
await mpage.screenshot({ path: path.join(OUT, '05-모바일-375px.png'), fullPage: true });

await browser.close();
server.close();
fs.rmSync(process.env.STORE_FILE, { force: true });
console.log('캡처 저장 위치:', OUT);
