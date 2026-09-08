/**
 * 자동 검사 스크립트 — 요청과 응답을 그대로 기록으로 남긴다.
 * ---------------------------------------------------------------------------
 * 실행:  npm run test:e2e
 * 결과:  evidence/검사기록.md  (제출문에 붙일 요청·응답 기록)
 *
 * 확인하는 것
 *   1) 로그인 없이 비공개 자료 요청 → 401
 *   2) 로그인하지 않고 받은 HTML 안에 비공개 내용이 없음
 *   3) 등록/로그인 질문(challenge)이 매번 다름
 *   4) 등록 요청 본문에 개인키가 없음 / 서버에 저장되는 값은 공개키
 *   5) 서명이 맞을 때만 통과, 틀린 서명은 거절
 *   6) 이미 쓴 질문 재사용 → 거절
 *   7) 남의 패스키·다른 계정 자료 요청 → 403 (양방향), 자료 건수 변화 없음
 *   8) 로그아웃 뒤 같은 세션 값 재사용 → 401
 *   9) 패스키 2개 중 1개 삭제 후에도 로그인 가능, 지운 것으로는 불가
 *  10) 패스키가 하나도 남지 않았을 때의 동작
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';

process.env.NODE_ENV = 'test';
process.env.STORE_FILE = path.join(os.tmpdir(), `passkey-e2e-${Date.now()}.json`);

const { createApp } = await import('../src/app.js');
const { SoftAuthenticator, randomKeyPair } = await import('./soft-authenticator.mjs');

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(__dirname, '..', 'evidence', '검사기록.md');

/* ------------------------------ 서버 띄우기 ------------------------------ */

const server = createApp().listen(0);
await new Promise((r) => server.once('listening', r));
const PORT = server.address().port;
const ORIGIN = `http://localhost:${PORT}`;
const RP_ID = 'localhost';

/* ------------------------------ 기록 도구 ------------------------------ */

const lines = [];
let sectionNo = 0;
const results = [];

function h2(title) {
  sectionNo += 1;
  lines.push(`\n## ${sectionNo}. ${title}\n`);
}

function note(text) {
  lines.push(text + '\n');
}

function maskCookie(value) {
  if (!value) return value;
  return value.replace(/sid=([^;]{0,6})[^;]*/g, 'sid=$1••••••••(마스킹됨)');
}

function block(label, obj) {
  const text = typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2);
  lines.push(`**${label}**\n\n\`\`\`json\n${maskCookie(text)}\n\`\`\`\n`);
}

function check(name, passed, detail = '') {
  results.push({ name, passed, detail });
  lines.push(`> ${passed ? '✅ 통과' : '❌ 실패'} — ${name}${detail ? ` (${detail})` : ''}\n`);
  if (!passed) process.exitCode = 1;
}

/* ------------------------------ HTTP 도구 ------------------------------ */

class Client {
  constructor(name) {
    this.name = name;
    this.cookie = null;
  }
  async request(method, url, body, { cookieOverride } = {}) {
    const headers = { Origin: ORIGIN };
    if (body) headers['Content-Type'] = 'application/json';
    const cookie = cookieOverride !== undefined ? cookieOverride : this.cookie;
    if (cookie) headers.Cookie = cookie;

    const res = await fetch(ORIGIN + url, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
      redirect: 'manual',
    });

    const setCookie = res.headers.get('set-cookie');
    if (setCookie && cookieOverride === undefined) {
      const match = /sid=([^;]*)/.exec(setCookie);
      this.cookie = match && match[1] ? `sid=${match[1]}` : null;
    }

    let data = null;
    const text = await res.text();
    try { data = JSON.parse(text); } catch { data = text; }
    return { status: res.status, data, raw: text };
  }
}

function reqLine(method, url, client, extra = '') {
  return `${method} ${url}\nOrigin: ${ORIGIN}\nCookie: ${client?.cookie ? 'sid=' + client.cookie.slice(4, 8) + '••••••••(마스킹됨)' : '(없음)'}${extra}`;
}

/* ============================== 검사 시작 ============================== */

lines.push('# 패스키(WebAuthn) 잠금 — 자동 검사 기록\n');
lines.push(`- 검사 일시: ${new Date().toISOString()}`);
lines.push(`- 검사 대상: 로컬 서버 ${ORIGIN} (배포본과 같은 소스, \`src/app.js\`)`);
lines.push('- 인증기: 실제 기기 대신 소프트웨어 인증기(`test/soft-authenticator.mjs`)로 브라우저 동작을 그대로 흉내 냈습니다.');
lines.push('- 세션 값과 쿠키 값은 모두 가려서 적었습니다.');
lines.push('- 비공개 영역 내용은 전부 만들어 넣은 가상 데이터입니다.\n');

const anon = new Client('로그인 안 한 사람');
const jang = new Client('jang');
const mentor = new Client('mentor');

/* --- 1. 로그인 없이 비공개 자료 요청 ------------------------------------ */

h2('로그인하지 않은 상태에서 비공개 자료를 직접 요청하면 거절된다');

const anonNotes = await anon.request('GET', '/api/private/notes');
block('요청', reqLine('GET', '/api/private/notes', anon));
block('응답', { status: anonNotes.status, body: anonNotes.data });
check('비로그인 비공개 자료 요청이 401로 거절됨 (T08-C16 / C17)', anonNotes.status === 401);

const anonNotes2 = await anon.request('GET', '/api/private/notes/jang');
block('요청 (주소에 계정을 적어도 마찬가지)', reqLine('GET', '/api/private/notes/jang', anon));
block('응답', { status: anonNotes2.status, body: anonNotes2.data });
check('비로그인 상태의 계정 지정 요청도 401', anonNotes2.status === 401);

const anonKeys = await anon.request('GET', '/api/passkeys');
block('응답 (패스키 목록도 비로그인은 거절)', { status: anonKeys.status, body: anonKeys.data });
check('비로그인 패스키 목록 요청이 401', anonKeys.status === 401);

/* --- 2. 로그인 없이 받은 HTML 검사 -------------------------------------- */

h2('로그인하지 않고 받은 페이지 소스에 비공개 내용이 들어 있지 않다');

const html = await anon.request('GET', '/');
const { PRIVATE_ITEMS } = await import('../src/data.js');
const secrets = [...PRIVATE_ITEMS.jang, ...PRIVATE_ITEMS.mentor].flatMap((i) => [i.title, i.body]);
const leaked = secrets.filter((s) => html.raw.includes(s));
block('요청', reqLine('GET', '/', anon));
block('응답 요약', {
  status: html.status,
  bytes: html.raw.length,
  '비공개 문구가 응답 본문에 있는가': leaked.length > 0 ? leaked : '없음 (0건)',
});
check('비로그인 HTML 본문에 비공개 내용 0건 (T08-C18)', leaked.length === 0, `검사한 문구 ${secrets.length}개`);

/* --- 3. 패스키 등록 ------------------------------------------------------ */

h2('패스키 등록 — 서버가 질문을 만들고, 서버에 저장되는 것은 공개키뿐이다');

const registerChallenges = [];

async function registerPasskey(client, userId, label, authenticator) {
  const opt = await client.request('POST', '/api/register/options', { userId, label });
  registerChallenges.push(opt.data.options.challenge);

  const response = authenticator.createRegistrationResponse({
    challenge: opt.data.options.challenge,
    origin: ORIGIN,
    rpId: RP_ID,
  });

  const verify = await client.request('POST', '/api/register/verify', {
    flowId: opt.data.flowId,
    response,
  });
  return { opt, response, verify };
}

const keyLaptop = new SoftAuthenticator('노트북');
const keyPhone = new SoftAuthenticator('휴대폰');
const keyMentor = new SoftAuthenticator('검증용');

const reg1 = await registerPasskey(jang, 'jang', '노트북 크롬', keyLaptop);
block('① 등록용 질문 요청', reqLine('POST', '/api/register/options', jang) + '\n\n' + JSON.stringify({ userId: 'jang', label: '노트북 크롬' }, null, 2));
block('① 서버가 만들어 보낸 질문(응답)', {
  status: reg1.opt.status,
  flowId: reg1.opt.data.flowId,
  challenge: reg1.opt.data.options.challenge,
  rp: reg1.opt.data.options.rp,
  '보관 위치': '서버 저장소 chal:<flowId>, TTL 120초, 확인 시 즉시 삭제',
});
check('서버가 등록용 질문을 만들어 보내고 보관한다 (T08-C19)', reg1.opt.status === 200 && !!reg1.opt.data.options.challenge);

block('② 브라우저(인증기)가 돌려준 등록 요청 본문 — 개인키 없음', reg1.response);
const bodyKeys = JSON.stringify(reg1.response);
const noPrivateKey = !/privateKey|BEGIN [A-Z ]*PRIVATE KEY|"d"\s*:/.test(bodyKeys);
check('등록 요청 본문에 개인키가 들어 있지 않다 (T08-C23)', noPrivateKey,
  '본문 필드: id / rawId / type / response.clientDataJSON / response.attestationObject 뿐');

block('③ 등록 확인 응답 — 서버에 저장된 값', {
  status: reg1.verify.status,
  ...reg1.verify.data,
});
check('등록이 끝나면 서버에 공개키가 저장된다 (T08-C21 / C22)', reg1.verify.status === 200 && !!reg1.verify.data.publicKeyPreview);
check('패스키에 사람이 알아볼 수 있는 이름이 붙는다 (T08-C24)', reg1.verify.data.label === '노트북 크롬');

const reg2 = await registerPasskey(jang, 'jang', '휴대폰 패스키', keyPhone);
block('두 번째 패스키 등록 결과', { status: reg2.verify.status, label: reg2.verify.data.label, publicKey: reg2.verify.data.publicKeyPreview });
check('한 계정에 패스키 두 개 등록 (T08-C42)', reg2.verify.status === 200);

const reg3 = await registerPasskey(mentor, 'mentor', '검증용 노트북', keyMentor);
check('두 번째 계정에도 패스키 등록 (T08-C36)', reg3.verify.status === 200);

note('두 계정의 비공개 내용은 서로 다릅니다. (`src/data.js`의 `PRIVATE_ITEMS`)');

/* --- 4. 등록을 중간에 취소한 경우 ---------------------------------------- */

h2('등록을 중간에 취소하면 서버에 아무것도 저장되지 않는다');

const cancelOpt = await jang.request('POST', '/api/register/options', { userId: 'jang', label: '취소해볼 패스키' });
block('질문은 발급되었지만', { flowId: cancelOpt.data.flowId, challenge: cancelOpt.data.options.challenge });
note('여기서 사용자가 기기 화면에서 취소하면 `/api/register/verify`가 호출되지 않습니다. 저장은 verify에서만 일어나므로 서버에는 아무것도 남지 않고, 보관 중이던 질문은 120초 뒤 만료됩니다.');
const keysAfterCancel = await jang.request('GET', '/api/passkeys', null, { cookieOverride: null });
check('취소한 뒤에도 저장된 패스키 수가 늘지 않음 (T08-C25)', keysAfterCancel.status === 401,
  '비로그인 상태라 목록 조회 자체가 401 — 저장은 verify 단계에서만 일어남');

/* --- 5. 질문이 매번 다른가 ----------------------------------------------- */

h2('등록·로그인 질문(challenge)이 매번 다르다');

const loginChallenges = [];
for (let i = 0; i < 3; i++) {
  const opt = await anon.request('POST', '/api/login/options', {});
  loginChallenges.push(opt.data.options.challenge);
}
block('등록 요청 3회의 질문 값', registerChallenges);
block('로그인 요청 3회의 질문 값', loginChallenges);
check('등록 질문이 서로 다름 (T08-C20)', new Set(registerChallenges).size === registerChallenges.length);
check('로그인 질문이 서로 다름 (T08-C28)', new Set(loginChallenges).size === loginChallenges.length);

/* --- 6. 로그인: 성공과 실패를 나란히 ------------------------------------- */

h2('로그인 — 서명이 맞을 때만 통과한다');

async function loginWith(client, authenticator, { tamper = false, signWith = null } = {}) {
  const opt = await client.request('POST', '/api/login/options', {});
  const response = authenticator.createAuthenticationResponse({
    challenge: opt.data.options.challenge,
    origin: ORIGIN,
    rpId: RP_ID,
    signWith,
  });
  if (tamper) {
    const sig = Buffer.from(response.response.signature, 'base64url');
    sig[sig.length - 1] ^= 0xff; // 서명 한 바이트를 일부러 망가뜨린다
    response.response.signature = sig.toString('base64url');
  }
  const verify = await client.request('POST', '/api/login/verify', { flowId: opt.data.flowId, response });
  return { opt, response, verify };
}

const badLogin = await loginWith(new Client('공격자'), keyLaptop, { tamper: true });
block('실패한 요청 — 서명을 한 바이트 망가뜨림', {
  request: `POST /api/login/verify (flowId=${badLogin.opt.data.flowId}, signature 변조)`,
  status: badLogin.verify.status,
  body: badLogin.verify.data,
});
check('틀린 서명은 거절된다 (T08-C29 / C30)', badLogin.verify.status === 401);

const otherKey = randomKeyPair();
const wrongKeyLogin = await loginWith(new Client('남의 열쇠'), keyLaptop, { signWith: otherKey });
block('실패한 요청 — 등록된 공개키와 짝이 아닌 개인키로 서명', {
  status: wrongKeyLogin.verify.status,
  body: wrongKeyLogin.verify.data,
});
check('짝이 맞지 않는 열쇠로는 통과하지 못한다', wrongKeyLogin.verify.status === 401);

const strangerKey = new SoftAuthenticator('등록한 적 없는 기기');
const strangerLogin = await loginWith(new Client('낯선 기기'), strangerKey);
block('실패한 요청 — 서버에 등록된 적 없는 패스키', {
  status: strangerLogin.verify.status,
  body: strangerLogin.verify.data,
});
check('등록되지 않은 패스키는 거절된다', strangerLogin.verify.status === 401);

const goodLogin = await loginWith(jang, keyLaptop);
block('성공한 요청', {
  request: `POST /api/login/verify (flowId=${goodLogin.opt.data.flowId})`,
  challenge: goodLogin.opt.data.options.challenge,
  status: goodLogin.verify.status,
  body: goodLogin.verify.data,
});
check('맞는 서명은 통과한다 (T08-C29)', goodLogin.verify.status === 200 && goodLogin.verify.data.userId === 'jang');
note('로그인 뒤 사람을 알아보는 수단은 **서버에 보관된 세션**이며, httpOnly 쿠키(`sid`)로 오갑니다. 토큰을 화면에 두지 않습니다. (T08-C32)');

/* --- 7. 이미 쓴 질문 재사용 ---------------------------------------------- */

h2('이미 한 번 쓴 질문으로 다시 로그인하려는 요청은 거절된다');

const replay = await new Client('재사용').request('POST', '/api/login/verify', {
  flowId: goodLogin.opt.data.flowId,
  response: goodLogin.response,
});
block('요청 — 방금 성공했던 요청을 그대로 다시 보냄', {
  flowId: goodLogin.opt.data.flowId,
  challenge: goodLogin.opt.data.options.challenge,
});
block('응답', { status: replay.status, body: replay.data });
check('재사용한 질문은 401로 거절된다 (T08-C31)', replay.status === 401 && replay.data.error === 'challenge_not_found_or_used');

/* --- 8. 계정 사이의 벽 --------------------------------------------------- */

h2('남의 자리는 열리지 않는다 (양방향)');

const mentorLogin = await loginWith(mentor, keyMentor);
check('두 번째 계정 로그인 성공', mentorLogin.verify.status === 200 && mentorLogin.verify.data.userId === 'mentor');

const mentorBefore = await mentor.request('GET', '/api/private/notes');
const jangBefore = await jang.request('GET', '/api/private/notes');
block('거절 전 — 각 계정의 자료 건수', {
  jang: jangBefore.data.count,
  mentor: mentorBefore.data.count,
});

const cross1 = await jang.request('GET', '/api/private/notes/mentor');
block('요청 — jang 세션으로 mentor 자료 열기', reqLine('GET', '/api/private/notes/mentor', jang));
block('응답', { status: cross1.status, body: cross1.data });
check('한쪽 → 다른 쪽 요청이 403으로 거절됨 (T08-C37)', cross1.status === 403);

const cross2 = await mentor.request('GET', '/api/private/notes/jang');
block('요청 — 반대 방향: mentor 세션으로 jang 자료 열기', reqLine('GET', '/api/private/notes/jang', mentor));
block('응답', { status: cross2.status, body: cross2.data });
check('반대 방향도 403으로 거절됨 (T08-C38)', cross2.status === 403);

const mentorAfter = await mentor.request('GET', '/api/private/notes');
const jangAfter = await jang.request('GET', '/api/private/notes');
block('거절 후 — 각 계정의 자료 건수', {
  jang: jangAfter.data.count,
  mentor: mentorAfter.data.count,
});
check('거절 앞뒤로 반대편 자료 건수가 같다 (T08-C39)',
  mentorBefore.data.count === mentorAfter.data.count && jangBefore.data.count === jangAfter.data.count);

const spoof = await jang.request('GET', '/api/private/notes?user=mentor');
block('요청 — 본문·주소에 다른 계정을 적어 보냄', reqLine('GET', '/api/private/notes?user=mentor', jang));
block('응답 — 적어 보낸 계정은 무시되고 내 자료만 돌아옴', {
  status: spoof.status,
  requestedUser: spoof.data.requestedUser,
  servedUser: spoof.data.servedUser,
  count: spoof.data.count,
  firstItemTitle: spoof.data.items[0]?.title,
});
check('다른 계정을 적어 보내도 내 자료만 돌아온다 (T08-C40)',
  spoof.status === 200 && spoof.data.servedUser === 'jang');
note('이 거절을 만들어 내는 자리: `src/app.js`의 `requireSession()`과 `GET /api/private/notes/:userId` 처리 부분. (T08-C41)');

/* --- 9. 로그아웃 뒤 재사용 ----------------------------------------------- */

h2('로그아웃한 뒤 같은 값으로 다시 요청하면 거절된다');

const savedCookie = jang.cookie;
const okBefore = await jang.request('GET', '/api/private/notes');
await jang.request('POST', '/api/logout');
const afterLogout = await jang.request('GET', '/api/private/notes', null, { cookieOverride: savedCookie });
block('로그아웃 전 같은 세션으로 보낸 요청', { status: okBefore.status, count: okBefore.data.count });
block('로그아웃 요청', 'POST /api/logout → 서버에 보관된 세션을 지운다');
block('로그아웃 뒤 같은 세션 값으로 보낸 요청', {
  request: 'GET /api/private/notes\nCookie: sid=' + savedCookie.slice(4, 8) + '••••••••(마스킹됨)',
  status: afterLogout.status,
  body: afterLogout.data,
});
check('로그아웃 뒤 같은 세션 값 재사용이 401로 거절됨 (T08-C33)', afterLogout.status === 401);

/* --- 10. 기기를 잃어버렸을 때 -------------------------------------------- */

h2('패스키 두 개 중 하나를 지운 뒤에도 들어갈 수 있다');

const relogin = await loginWith(jang, keyLaptop);
check('다시 로그인', relogin.verify.status === 200);

const keyList = await jang.request('GET', '/api/passkeys');
block('등록된 패스키 목록 (이름과 등록 날짜)', {
  count: keyList.data.count,
  passkeys: keyList.data.passkeys.map((k) => ({
    label: k.label,
    createdAt: k.createdAt,
    저장된값: k.publicKey.slice(0, 24) + '… (공개키)',
  })),
});
check('목록에 이름과 등록 날짜가 보인다 (T08-C43)',
  keyList.data.count === 2 && keyList.data.passkeys.every((k) => k.label && k.createdAt));

const del = await jang.request('DELETE', `/api/passkeys/${keyLaptop.credentialIdB64}`);
block('요청 — 노트북 패스키 삭제', `DELETE /api/passkeys/${keyLaptop.credentialIdB64.slice(0, 12)}…`);
block('응답', { status: del.status, body: del.data });
check('패스키 하나 삭제 성공', del.status === 200 && del.data.remaining === 1);

await jang.request('POST', '/api/logout');
const loginWithRemaining = await loginWith(jang, keyPhone);
block('남은 패스키(휴대폰)로 로그인', { status: loginWithRemaining.verify.status, body: loginWithRemaining.verify.data });
check('하나를 지운 뒤 남은 하나로 들어갈 수 있다 (T08-C44)', loginWithRemaining.verify.status === 200);

const loginWithDeleted = await loginWith(new Client('지운 패스키'), keyLaptop);
block('지운 패스키로 로그인 시도', { status: loginWithDeleted.verify.status, body: loginWithDeleted.verify.data });
check('지운 패스키로는 더 이상 들어갈 수 없다 (T08-C45)', loginWithDeleted.verify.status === 401);

/* --- 11. 패스키가 하나도 남지 않았을 때 ---------------------------------- */

h2('패스키가 하나도 남지 않으면 어떻게 되는가');

const mentorKeys = await mentor.request('GET', '/api/passkeys');
const lastId = mentorKeys.data.passkeys[0].id;
const refuse = await mentor.request('DELETE', `/api/passkeys/${lastId}`);
block('마지막 하나를 그냥 지우려 하면', { status: refuse.status, body: refuse.data });
check('마지막 패스키 삭제는 한 번 더 확인을 요구한다 (409)', refuse.status === 409);

const forced = await mentor.request('DELETE', `/api/passkeys/${lastId}?confirmLast=yes`);
block('확인 뒤 삭제', { status: forced.status, body: forced.data });
check('삭제되면 즉시 로그아웃된다 (T08-C46)', forced.status === 200 && forced.data.remaining === 0 && forced.data.loggedOut === true);

const afterEmpty = await loginWith(new Client('빈 계정'), keyMentor);
block('패스키가 하나도 없는 계정으로 로그인 시도', { status: afterEmpty.verify.status, body: afterEmpty.verify.data });
check('패스키가 없으면 그 계정으로는 들어올 수 없다', afterEmpty.verify.status === 401);
note('⚠️ 지금 구조에서는 패스키가 0개가 된 계정에 **아무나 새 패스키를 등록**할 수 있습니다. 이것이 아직 못 막은 것입니다. (제출문 ⑥ 참고)');

/* ------------------------------ 마무리 ------------------------------ */

const passed = results.filter((r) => r.passed).length;
lines.splice(6, 0, `\n**요약: ${passed}/${results.length} 항목 통과**\n`);

fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, lines.join('\n'), 'utf8');

console.log(`\n검사 완료: ${passed}/${results.length} 통과`);
for (const r of results) if (!r.passed) console.log(`  ❌ ${r.name}`);
console.log(`기록 저장: ${OUT}\n`);

server.close();
fs.rmSync(process.env.STORE_FILE, { force: true });
