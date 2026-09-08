/* 브라우저 쪽 코드
 * ---------------------------------------------------------------------------
 * 등록      : POST /api/register/options → navigator.credentials.create() → POST /api/register/verify
 * 로그인    : POST /api/login/options    → navigator.credentials.get()    → POST /api/login/verify
 * 로그아웃  : POST /api/logout
 * 비공개 조회: GET  /api/private/notes
 *
 * 비밀번호 입력칸은 어디에도 없다. 개인키도 이 코드가 만지지 않는다.
 * 브라우저가 개인키를 기기 안에서 다루고, 여기서는 서명 결과만 서버로 보낸다.
 */

/* ------------------------------ 작은 도구들 ------------------------------ */

const $ = (id) => document.getElementById(id);

const b64urlToBuf = (s) => {
  const pad = '='.repeat((4 - (s.length % 4)) % 4);
  const bin = atob((s + pad).replace(/-/g, '+').replace(/_/g, '/'));
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
};

const bufToB64url = (buf) => {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

/* 화면 아래 기록 패널 */
const logLines = [];
function log(title, detail) {
  const time = new Date().toISOString().substring(11, 19);
  logLines.push(`[${time}] ${title}\n${typeof detail === 'string' ? detail : JSON.stringify(detail, null, 2)}`);
  $('log').textContent = logLines.slice(-20).join('\n\n');
}

function setStatus(id, message, kind = '') {
  const el = $(id);
  el.textContent = message;
  el.className = 'status ' + kind;
}

async function api(method, url, body) {
  const res = await fetch(url, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
    credentials: 'same-origin',
  });
  let data = null;
  try { data = await res.json(); } catch { /* 본문 없음 */ }

  // 기록 패널에는 비공개 '내용'을 적지 않는다. 건수와 응답 코드만 남긴다.
  // (로그아웃 뒤에도 화면 어디에 비공개 내용이 남지 않게 하기 위함 — T08-C15)
  const forLog =
    url.startsWith('/api/private') && data && Array.isArray(data.items)
      ? { ...data, items: `(${data.items.length}건 — 내용은 기록에 남기지 않음)` }
      : data;
  log(`${method} ${url} → ${res.status}`, forLog ?? '(본문 없음)');
  return { status: res.status, data };
}

/* ------------------------------ 1. 등록 ------------------------------ */

async function registerPasskey(userId, label, statusId) {
  if (!window.PublicKeyCredential) {
    setStatus(statusId, '이 브라우저는 패스키를 지원하지 않습니다.', 'err');
    return;
  }
  if (!label) {
    setStatus(statusId, '패스키에 붙일 이름을 적어 주세요.', 'err');
    return;
  }

  setStatus(statusId, '서버에서 등록용 질문(challenge)을 받아오는 중…');
  const { status, data } = await api('POST', '/api/register/options', { userId, label });
  if (status !== 200) {
    setStatus(statusId, `등록용 질문을 받지 못했습니다: ${data?.message || status}`, 'err');
    return;
  }

  const { flowId, options } = data;
  setStatus(statusId, `이번 등록에 쓰는 질문: ${options.challenge}\n기기 화면의 안내를 따라 주세요.`);

  // 서버가 준 base64url 값을 브라우저가 요구하는 형태로 바꾼다.
  const publicKey = {
    ...options,
    challenge: b64urlToBuf(options.challenge),
    user: { ...options.user, id: b64urlToBuf(options.user.id) },
    excludeCredentials: (options.excludeCredentials || []).map((c) => ({
      ...c,
      id: b64urlToBuf(c.id),
    })),
  };

  let credential;
  try {
    credential = await navigator.credentials.create({ publicKey });
  } catch (err) {
    // 등록을 중간에 취소한 경우: 서버에는 아무것도 저장되지 않는다. (T08-C25)
    const message =
      err.name === 'InvalidStateError'
        ? '이 기기에는 이 계정의 패스키가 이미 있습니다. 두 번째 패스키는 다른 기기나 다른 브라우저에서 등록해 주세요. 서버에는 아무것도 저장되지 않았습니다.'
        : `등록이 취소되었습니다 (${err.name}). 서버에는 아무것도 저장되지 않았습니다. 보관 중이던 질문은 사용되지 않은 채 만료됩니다.`;
    setStatus(statusId, message, 'err');
    log('등록 중단', { error: err.name, savedOnServer: false });
    return;
  }

  const response = {
    id: credential.id,
    rawId: bufToB64url(credential.rawId),
    type: credential.type,
    clientExtensionResults: credential.getClientExtensionResults(),
    authenticatorAttachment: credential.authenticatorAttachment || undefined,
    response: {
      clientDataJSON: bufToB64url(credential.response.clientDataJSON),
      attestationObject: bufToB64url(credential.response.attestationObject),
      transports: credential.response.getTransports ? credential.response.getTransports() : [],
    },
  };

  // 이 요청 본문 어디에도 개인키는 없다. (T08-C23)
  log('등록 요청 본문 (개인키 없음 — 공개키와 서명만)', response);

  const verify = await api('POST', '/api/register/verify', { flowId, response });
  if (verify.status === 200) {
    setStatus(
      statusId,
      `패스키 "${verify.data.label}" 등록 완료.\n서버에 저장된 값(공개키): ${verify.data.publicKeyPreview}`,
      'ok',
    );
    await refreshIfUnlocked();
  } else {
    setStatus(statusId, `등록 실패: ${verify.data?.message || verify.status}`, 'err');
  }
}

/* ------------------------------ 2. 로그인 ----------------------------- */

async function loginWithPasskey() {
  if (!window.PublicKeyCredential) {
    setStatus('locked-status', '이 브라우저는 패스키를 지원하지 않습니다.', 'err');
    return;
  }

  setStatus('locked-status', '서버에서 새 질문(challenge)을 받아오는 중…');
  const { status, data } = await api('POST', '/api/login/options', {});
  if (status !== 200) {
    setStatus('locked-status', '질문을 받지 못했습니다.', 'err');
    return;
  }

  const { flowId, options } = data;
  setStatus('locked-status', `이번 로그인에 쓰는 질문: ${options.challenge}\n기기 화면의 안내를 따라 주세요.`);

  const publicKey = {
    ...options,
    challenge: b64urlToBuf(options.challenge),
    allowCredentials: (options.allowCredentials || []).map((c) => ({
      ...c,
      id: b64urlToBuf(c.id),
    })),
  };

  let assertion;
  try {
    assertion = await navigator.credentials.get({ publicKey });
  } catch (err) {
    setStatus('locked-status', `로그인이 취소되었습니다 (${err.name}).`, 'err');
    return;
  }

  const response = {
    id: assertion.id,
    rawId: bufToB64url(assertion.rawId),
    type: assertion.type,
    clientExtensionResults: assertion.getClientExtensionResults(),
    authenticatorAttachment: assertion.authenticatorAttachment || undefined,
    response: {
      clientDataJSON: bufToB64url(assertion.response.clientDataJSON),
      authenticatorData: bufToB64url(assertion.response.authenticatorData),
      signature: bufToB64url(assertion.response.signature),
      userHandle: assertion.response.userHandle ? bufToB64url(assertion.response.userHandle) : undefined,
    },
  };

  const verify = await api('POST', '/api/login/verify', { flowId, response });
  if (verify.status === 200) {
    setStatus('locked-status', '', '');
    await showUnlocked();
  } else {
    setStatus('locked-status', `들어오지 못했습니다: ${verify.data?.message || verify.status}`, 'err');
  }
}

/* --------------------------- 3. 화면 상태 전환 -------------------------- */

async function showUnlocked() {
  const me = await api('GET', '/api/me');
  if (!me.data?.authenticated) return showLocked();

  $('who').textContent = me.data.displayName;
  $('session-mask').textContent = `세션: ${me.data.session}`;
  $('locked-view').classList.add('hidden');
  $('unlocked-view').classList.remove('hidden');

  const notes = await api('GET', '/api/private/notes');
  const box = $('private-items');
  box.innerHTML = '';
  $('item-count').textContent = `(${notes.data.count}건)`;
  notes.data.items.forEach((item) => {
    const div = document.createElement('div');
    div.className = 'private-item';
    div.innerHTML = `<div class="kind"></div><strong></strong><p></p>`;
    div.querySelector('.kind').textContent = item.kind;
    div.querySelector('strong').textContent = item.title;
    div.querySelector('p').textContent = item.body;
    box.appendChild(div);
  });

  await refreshPasskeyList();
}

async function refreshIfUnlocked() {
  if (!$('unlocked-view').classList.contains('hidden')) await refreshPasskeyList();
}

async function refreshPasskeyList() {
  const list = await api('GET', '/api/passkeys');
  const tbody = $('passkey-rows');
  tbody.innerHTML = '';
  if (list.status !== 200) return;

  list.data.passkeys.forEach((key) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td></td><td></td><td class="mono"></td><td></td>`;
    tr.children[0].textContent = key.label;
    tr.children[1].textContent = new Date(key.createdAt).toLocaleString('ko-KR');
    tr.children[2].textContent = key.publicKey;
    const btn = document.createElement('button');
    btn.className = 'btn small danger';
    btn.textContent = '지우기';
    btn.onclick = () => deletePasskey(key.id, key.label, list.data.count);
    tr.children[3].appendChild(btn);
    tbody.appendChild(tr);
  });
}

async function deletePasskey(credId, label, total) {
  if (total <= 1) {
    const ok = confirm(
      `"${label}"은(는) 마지막 남은 패스키입니다.\n지우면 이 계정으로 다시 들어올 수 없습니다. 계속할까요?`,
    );
    if (!ok) return;
    const res = await api('DELETE', `/api/passkeys/${credId}?confirmLast=yes`);
    if (res.status === 200) {
      alert('패스키가 하나도 남지 않아 로그아웃되었습니다. 이 계정으로는 더 들어올 수 없습니다.');
      showLocked();
      setStatus('locked-status', '패스키가 하나도 남지 않은 계정입니다. 더 이상 들어올 수 없습니다.', 'err');
    }
    return;
  }

  if (!confirm(`"${label}" 패스키를 지울까요?`)) return;
  const res = await api('DELETE', `/api/passkeys/${credId}`);
  if (res.status === 200) {
    setStatus('unlocked-status', `"${label}" 패스키를 지웠습니다. 남은 패스키: ${res.data.remaining}개`, 'ok');
    await refreshPasskeyList();
  }
}

function showLocked() {
  // 화면에서 감추는 데 그치지 않고, 비공개 내용을 DOM에서 지운다.
  // (개발자 도구로 열어 봐도 남아 있지 않게 한다 — T08-C15)
  $('private-items').innerHTML = '';
  $('passkey-rows').innerHTML = '';
  $('who').textContent = '';
  $('session-mask').textContent = '';
  $('item-count').textContent = '';
  setStatus('unlocked-status', '');
  $('unlocked-view').classList.add('hidden');
  $('locked-view').classList.remove('hidden');
}

/* ------------------------------ 4. 연결 ------------------------------ */

$('btn-login').onclick = loginWithPasskey;
$('btn-show-register').onclick = () => $('register-box').classList.toggle('hidden');
$('btn-register').onclick = () =>
  registerPasskey($('user-select').value, $('key-label').value.trim(), 'locked-status');
$('btn-add-key').onclick = async () => {
  const me = await api('GET', '/api/me');
  if (!me.data?.authenticated) return showLocked();
  await registerPasskey(me.data.userId, $('key-label-2').value.trim(), 'unlocked-status');
};
$('btn-logout').onclick = async () => {
  await api('POST', '/api/logout');
  showLocked();
  setStatus('locked-status', '로그아웃했습니다. 비공개 영역이 다시 잠겼습니다.', 'ok');
};

// 첫 진입: 세션이 남아 있으면 열린 화면, 없으면 잠긴 화면.
(async () => {
  const me = await api('GET', '/api/me');
  if (me.data?.authenticated) await showUnlocked();
})();
