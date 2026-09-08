/**
 * 공개 소개 페이지 + 패스키(WebAuthn)로 잠근 비공개 영역 — 서버 본체
 * ===========================================================================
 * 네 흐름이 지나는 자리 (제출문 ③에서 참조)
 *   등록      : POST /api/register/options  → POST /api/register/verify
 *   로그인    : POST /api/login/options     → POST /api/login/verify
 *   로그아웃  : POST /api/logout
 *   비공개 조회: GET  /api/private/notes  (본인)  /  GET /api/private/notes/:userId (타계정 → 403)
 *
 * 원칙
 *   - challenge(일회용 질문)는 서버가 만들어 서버에 보관하고, 한 번 쓰면 즉시 버린다.
 *   - 서버가 저장하는 것은 공개키뿐이다. 개인키는 요청 본문에 들어오지 않는다.
 *   - 비공개 내용은 로그인 뒤 API로만 내려간다. HTML 소스에는 들어 있지 않다.
 */

import express from 'express';
import cookieParser from 'cookie-parser';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';

import { store, STORE_KIND } from './store.js';
import { USERS, getPrivateItems } from './data.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const RP_NAME = '장성혁 소개 페이지';
const SESSION_COOKIE = 'sid';

/* ------------------------- 출처(origin)와 rpID 결정 ------------------------- */

function resolveOrigin(req) {
  const origin = req.headers.origin;
  if (origin) return origin;
  const proto = (req.headers['x-forwarded-proto'] || req.protocol || 'https').split(',')[0];
  return `${proto}://${req.headers.host}`;
}

function isAllowedOrigin(origin) {
  let url;
  try {
    url = new URL(origin);
  } catch {
    return false;
  }
  const host = url.hostname;
  if (host === 'localhost' || host === '127.0.0.1') return true;
  if (host.endsWith('.vercel.app')) return true;
  const extra = (process.env.ALLOWED_ORIGINS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  return extra.includes(origin);
}

function rpContext(req) {
  const origin = resolveOrigin(req);
  if (!isAllowedOrigin(origin)) {
    const err = new Error(`허용되지 않은 출처: ${origin}`);
    err.status = 400;
    throw err;
  }
  return { origin, rpID: new URL(origin).hostname };
}

/* --------------------------------- 유틸 ---------------------------------- */

const b64url = (buf) => Buffer.from(buf).toString('base64url');
const fromB64url = (str) => new Uint8Array(Buffer.from(str, 'base64url'));

function newFlowId() {
  return crypto.randomUUID();
}

function maskedSid(sid) {
  // 기록에 세션 값이 그대로 남지 않도록 앞 4글자만 남기고 가린다. (T08-C34)
  return sid ? `${sid.slice(0, 4)}••••••••(마스킹됨)` : null;
}

async function currentSession(req) {
  const sid = req.cookies?.[SESSION_COOKIE];
  if (!sid) return null;
  const sess = await store.getSession(sid);
  if (!sess) return null;
  return { sid, userId: sess.userId };
}

async function requireSession(req, res) {
  const sess = await currentSession(req);
  if (!sess) {
    res.status(401).json({
      error: 'unauthenticated',
      message: '패스키로 들어오지 않은 요청입니다. 비공개 자료를 내려보내지 않습니다.',
    });
    return null;
  }
  return sess;
}

/* --------------------------------- 앱 ------------------------------------ */

export function createApp() {
  const app = express();
  app.use(express.json({ limit: '256kb' }));
  app.use(cookieParser());
  app.disable('x-powered-by');

  // 공개 정적 파일(소개 페이지). 이 안에는 비공개 내용이 들어 있지 않다. (T08-C18)
  app.use(express.static(path.join(__dirname, '..', 'public'), { extensions: ['html'] }));

  /* ----------------------------- 상태 확인 ------------------------------ */

  app.get('/api/health', (req, res) => {
    res.json({ ok: true, store: STORE_KIND, time: new Date().toISOString() });
  });

  /* ============================== 1. 등록 ============================== */

  // 서버가 등록용 질문(challenge)을 만들어 보내고, 확인할 때까지 서버에 보관한다. (T08-C19)
  app.post('/api/register/options', async (req, res, next) => {
    try {
      const { rpID } = rpContext(req);
      const userId = String(req.body?.userId || '').trim();
      const label = String(req.body?.label || '').trim().slice(0, 40);

      if (!USERS[userId]) {
        return res.status(400).json({ error: 'unknown_user', message: '계정을 고르세요.' });
      }
      if (!label) {
        return res
          .status(400)
          .json({ error: 'label_required', message: '패스키에 붙일 이름을 적어 주세요.' });
      }

      const existing = await store.listCredentials(userId);

      const options = await generateRegistrationOptions({
        rpName: RP_NAME,
        rpID,
        userID: new TextEncoder().encode(userId),
        userName: userId,
        userDisplayName: USERS[userId].displayName,
        attestationType: 'none',
        // 같은 기기에 이미 등록된 패스키는 제외해서 두 번째 등록이 막히지 않게 한다.
        excludeCredentials: existing.map((c) => ({ id: c.id, transports: c.transports })),
        authenticatorSelection: {
          residentKey: 'preferred',
          userVerification: 'preferred',
        },
      });

      const flowId = newFlowId();
      await store.putChallenge(flowId, {
        type: 'register',
        challenge: options.challenge,
        userId,
        label,
      });

      res.json({ flowId, options });
    } catch (err) {
      next(err);
    }
  });

  // 브라우저가 돌려준 공개키와 서명을 확인하고, 공개키만 저장한다. (T08-C21~C24)
  app.post('/api/register/verify', async (req, res, next) => {
    try {
      const { origin, rpID } = rpContext(req);
      const { flowId, response } = req.body || {};
      if (!flowId || !response) {
        return res.status(400).json({ error: 'bad_request' });
      }

      // 보관해 둔 질문을 꺼내면서 즉시 버린다 → 같은 질문은 두 번 통하지 않는다.
      const saved = await store.takeChallenge(flowId);
      if (!saved || saved.type !== 'register') {
        return res.status(401).json({
          error: 'challenge_not_found_or_used',
          message: '이미 사용했거나 만료된 질문입니다. 등록을 다시 시작하세요.',
        });
      }

      let verification;
      try {
        verification = await verifyRegistrationResponse({
          response,
          expectedChallenge: saved.challenge,
          expectedOrigin: origin,
          expectedRPID: rpID,
          requireUserVerification: false,
        });
      } catch (e) {
        return res.status(401).json({ error: 'verification_failed', message: e.message });
      }

      if (!verification.verified || !verification.registrationInfo) {
        return res.status(401).json({ error: 'verification_failed' });
      }

      const { credential, credentialDeviceType, credentialBackedUp } =
        verification.registrationInfo;

      await store.putCredential({
        id: credential.id, // base64url 문자열
        userId: saved.userId,
        publicKey: b64url(credential.publicKey), // ← 서버에 저장되는 값은 '공개키'다
        counter: credential.counter,
        transports: credential.transports || [],
        label: saved.label, // 사람이 알아볼 수 있는 이름 (T08-C24)
        createdAt: new Date().toISOString(),
        deviceType: credentialDeviceType, // singleDevice / multiDevice
        backedUp: credentialBackedUp, // 비밀번호 관리자에 동기화되었는지
      });

      res.json({
        verified: true,
        credentialId: credential.id,
        label: saved.label,
        storedValueKind: 'public-key (COSE, base64url). 비밀번호가 아니며 개인키도 아니다.',
        publicKeyPreview: b64url(credential.publicKey),
        deviceType: credentialDeviceType,
        backedUp: credentialBackedUp,
      });
    } catch (err) {
      next(err);
    }
  });

  /* ============================== 2. 로그인 ============================= */

  // 로그인할 때도 매번 새 질문을 만들어 보내고 서버에 보관한다. (T08-C27)
  app.post('/api/login/options', async (req, res, next) => {
    try {
      const { rpID } = rpContext(req);
      const options = await generateAuthenticationOptions({
        rpID,
        // allowCredentials를 비워 두어, 기기에 저장된 패스키로 계정을 알아낸다.
        allowCredentials: [],
        userVerification: 'preferred',
      });

      const flowId = newFlowId();
      await store.putChallenge(flowId, { type: 'login', challenge: options.challenge });

      res.json({ flowId, options });
    } catch (err) {
      next(err);
    }
  });

  // 저장해 둔 공개키로 서명을 확인한 뒤에만 통과시킨다. (T08-C29)
  app.post('/api/login/verify', async (req, res, next) => {
    try {
      const { origin, rpID } = rpContext(req);
      const { flowId, response } = req.body || {};
      if (!flowId || !response) return res.status(400).json({ error: 'bad_request' });

      const saved = await store.takeChallenge(flowId);
      if (!saved || saved.type !== 'login') {
        // 이미 한 번 쓴 질문으로 다시 로그인하려는 요청은 여기서 거절된다. (T08-C31)
        return res.status(401).json({
          error: 'challenge_not_found_or_used',
          message: '이미 사용했거나 만료된 질문입니다. 로그인을 다시 시작하세요.',
        });
      }

      const cred = await store.getCredential(response.id);
      if (!cred) {
        // 지운 패스키나 등록되지 않은 패스키로 들어오려는 요청. (T08-C45)
        return res.status(401).json({
          error: 'unknown_credential',
          message: '서버에 등록되지 않은 패스키입니다.',
        });
      }

      let verification;
      try {
        verification = await verifyAuthenticationResponse({
          response,
          expectedChallenge: saved.challenge,
          expectedOrigin: origin,
          expectedRPID: rpID,
          requireUserVerification: false,
          credential: {
            id: cred.id,
            publicKey: fromB64url(cred.publicKey),
            counter: cred.counter,
            transports: cred.transports,
          },
        });
      } catch (e) {
        return res.status(401).json({ error: 'verification_failed', message: e.message });
      }

      if (!verification.verified) {
        return res.status(401).json({ error: 'verification_failed' });
      }

      await store.updateCredentialCounter(cred.id, verification.authenticationInfo.newCounter);

      // 로그인 뒤 사람을 알아보는 수단: httpOnly 쿠키에 담긴 서버 세션 (T08-C32)
      const sid = crypto.randomBytes(32).toString('base64url');
      await store.putSession(sid, cred.userId);
      res.cookie(SESSION_COOKIE, sid, {
        httpOnly: true,
        sameSite: 'lax',
        secure: process.env.NODE_ENV !== 'test' && !/^http:\/\/localhost/.test(origin),
        maxAge: 1800 * 1000,
        path: '/',
      });

      res.json({
        verified: true,
        userId: cred.userId,
        displayName: USERS[cred.userId]?.displayName,
        usedCredentialLabel: cred.label,
        session: maskedSid(sid),
      });
    } catch (err) {
      next(err);
    }
  });

  /* ============================= 3. 로그아웃 =========================== */

  app.post('/api/logout', async (req, res) => {
    const sid = req.cookies?.[SESSION_COOKIE];
    if (sid) await store.deleteSession(sid); // 서버에서 세션을 지운다 → 같은 쿠키 재사용 불가 (T08-C33)
    res.clearCookie(SESSION_COOKIE, { path: '/' });
    res.json({ ok: true });
  });

  // 첫 화면에서 "지금 들어와 있는가"만 묻는 자리.
  // 비공개 자료가 아니라 상태만 알려주므로 200으로 답한다(콘솔에 붉은 줄이 생기지 않게).
  app.get('/api/me', async (req, res) => {
    const sess = await currentSession(req);
    if (!sess) return res.json({ authenticated: false });
    res.json({
      authenticated: true,
      userId: sess.userId,
      displayName: USERS[sess.userId]?.displayName,
      session: maskedSid(sess.sid),
    });
  });

  /* ========================== 4. 비공개 자료 조회 ======================== */

  // 본인 자료만 내려준다. 로그인하지 않았으면 401.
  app.get('/api/private/notes', async (req, res) => {
    const sess = await requireSession(req, res);
    if (!sess) return;
    // 쿼리로 다른 계정을 적어 보내도 무시하고 세션 주인의 자료만 돌려준다. (T08-C40)
    const items = getPrivateItems(sess.userId);
    res.json({
      userId: sess.userId,
      requestedUser: req.query.user ?? null,
      servedUser: sess.userId,
      count: items.length,
      items,
      notice: '아래 내용은 과제용으로 만들어 넣은 가상 데이터입니다.',
    });
  });

  // 주소에 다른 계정을 적어 보내면 403으로 거절한다. (T08-C37 / C38 / C41)
  app.get('/api/private/notes/:userId', async (req, res) => {
    const sess = await requireSession(req, res);
    if (!sess) return;
    if (req.params.userId !== sess.userId) {
      return res.status(403).json({
        error: 'forbidden_other_account',
        message: '다른 계정의 비공개 자료는 열어 줄 수 없습니다.',
        sessionUser: sess.userId,
        requestedUser: req.params.userId,
      });
    }
    const items = getPrivateItems(sess.userId);
    res.json({ userId: sess.userId, count: items.length, items });
  });

  /* ========================== 5. 패스키 목록·삭제 ======================== */

  app.get('/api/passkeys', async (req, res) => {
    const sess = await requireSession(req, res);
    if (!sess) return;
    const creds = await store.listCredentials(sess.userId);
    res.json({
      count: creds.length,
      passkeys: creds.map((c) => ({
        id: c.id,
        label: c.label,
        createdAt: c.createdAt,
        lastUsedAt: c.lastUsedAt || null,
        publicKey: c.publicKey, // 서버에 저장된 값이 공개키임을 화면에서 그대로 보인다
        deviceType: c.deviceType,
        backedUp: c.backedUp,
      })),
    });
  });

  app.delete('/api/passkeys/:credId', async (req, res) => {
    const sess = await requireSession(req, res);
    if (!sess) return;

    const target = await store.getCredential(req.params.credId);
    if (!target) return res.status(404).json({ error: 'not_found' });
    if (target.userId !== sess.userId) {
      // 남의 패스키는 지울 수 없다.
      return res.status(403).json({ error: 'forbidden_other_account' });
    }

    const before = await store.listCredentials(sess.userId);
    const lastOne = before.length <= 1;
    if (lastOne && req.query.confirmLast !== 'yes') {
      return res.status(409).json({
        error: 'last_passkey',
        message:
          '마지막 남은 패스키입니다. 지우면 이 계정으로 다시 들어올 수 없습니다. 그래도 지우려면 confirmLast=yes를 붙여 주세요.',
      });
    }

    await store.deleteCredential(sess.userId, req.params.credId);
    const after = await store.listCredentials(sess.userId);

    if (after.length === 0) {
      // 패스키가 하나도 남지 않으면 즉시 로그아웃되고, 그 계정으로는 더 들어올 수 없다. (T08-C46)
      await store.deleteSession(sess.sid);
      res.clearCookie(SESSION_COOKIE, { path: '/' });
    }

    res.json({ ok: true, remaining: after.length, loggedOut: after.length === 0 });
  });

  /* ------------------------------ 오류 처리 ----------------------------- */

  app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
    const status = err.status || 500;
    if (status >= 500) console.error(err);
    res.status(status).json({ error: 'server_error', message: err.message });
  });

  return app;
}
