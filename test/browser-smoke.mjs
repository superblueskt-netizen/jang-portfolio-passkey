/**
 * 브라우저 실동작 검사 (개발용)
 * ---------------------------------------------------------------------------
 * Chrome의 가상 인증기(WebAuthn virtual authenticator)를 켜고,
 * 실제 페이지에서 등록 → 로그인 → 비공개 열람 → 로그아웃이 되는지 확인한다.
 * 콘솔 빨간 오류가 0건인지도 함께 본다.
 *   실행: node test/browser-smoke.mjs
 */

import path from 'node:path';
import os from 'node:os';
import fs from 'node:fs';
import { chromium } from 'playwright';

process.env.NODE_ENV = 'test';
process.env.STORE_FILE = path.join(os.tmpdir(), `passkey-smoke-${Date.now()}.json`);

const { createApp } = await import('../src/app.js');
const server = createApp().listen(0);
await new Promise((r) => server.once('listening', r));
const PORT = server.address().port;
const BASE = `http://localhost:${PORT}`;

const browser = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium' });
const context = await browser.newContext();
const page = await context.newPage();

const consoleErrors = [];
page.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(m.text()); });
page.on('pageerror', (e) => consoleErrors.push(String(e)));

// Chrome 가상 인증기 켜기
const cdp = await context.newCDPSession(page);
await cdp.send('WebAuthn.enable');
const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
  options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
});

const fail = (msg) => { console.error('❌ ' + msg); process.exitCode = 1; };
const ok = (msg) => console.log('✅ ' + msg);

await page.goto(BASE);

// 1) 잠긴 상태에서 비공개 내용이 화면에 없어야 한다
const bodyText = await page.textContent('body');
if (bodyText.includes('동네 로스터리')) fail('잠긴 화면에 비공개 내용이 보임'); else ok('잠긴 화면에 비공개 내용 없음');

// 2) 패스키 등록
await page.click('#btn-show-register');
await page.fill('#key-label', '테스트 노트북');
await page.click('#btn-register');
await page.waitForFunction(() => document.getElementById('locked-status').textContent.includes('등록 완료'), { timeout: 15000 });
ok('브라우저에서 패스키 등록 완료');

// 3) 패스키로 로그인
await page.click('#btn-login');
await page.waitForSelector('#unlocked-view:not(.hidden)', { timeout: 15000 });
ok('패스키로 로그인해 비공개 영역 열림');

const unlockedText = await page.textContent('#private-items');
if (!unlockedText.includes('동네 로스터리')) fail('비공개 항목이 표시되지 않음'); else ok('비공개 항목 표시됨');

const keyRows = await page.locator('#passkey-rows tr').count();
if (keyRows !== 1) fail(`패스키 목록 행 수가 ${keyRows}`); else ok('패스키 목록 표시됨 (이름·날짜·공개키)');

// 4) 두 번째 패스키 등록 (같은 인증기에는 excludeCredentials 때문에 막히므로
//    실제 상황처럼 '두 번째 기기'를 하나 더 붙인다)
await cdp.send('WebAuthn.addVirtualAuthenticator', {
  options: { protocol: 'ctap2', transport: 'usb', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
});
await page.fill('#key-label-2', '테스트 보안키');
await page.click('#btn-add-key');
await page.waitForFunction(() => document.querySelectorAll('#passkey-rows tr').length === 2, { timeout: 15000 });
ok('두 번째 패스키 등록됨 (목록 2개)');

// 5) 로그아웃 → 다시 잠김
await page.click('#btn-logout');
await page.waitForSelector('#locked-view:not(.hidden)', { timeout: 5000 });
const afterLogout = await page.textContent('body');
if (afterLogout.includes('동네 로스터리')) fail('로그아웃 후에도 비공개 내용이 남아 있음'); else ok('로그아웃하면 다시 잠김');

if (consoleErrors.length) { fail(`콘솔 오류 ${consoleErrors.length}건: ${consoleErrors.slice(0, 3).join(' | ')}`); }
else ok('콘솔 빨간 오류 0건');

await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId });
await browser.close();
server.close();
fs.rmSync(process.env.STORE_FILE, { force: true });
console.log('\n브라우저 검사 종료');
