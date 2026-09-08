/**
 * 저장소 어댑터
 * ---------------------------------------------------------------------------
 * - Vercel(서버리스)에서는 Upstash Redis(=Vercel KV) REST API를 사용한다.
 *   환경변수: KV_REST_API_URL / KV_REST_API_TOKEN
 *   (또는 UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN)
 * - 환경변수가 없으면(로컬 개발·자동 테스트) 파일 기반 저장소로 동작한다.
 *
 * 저장하는 것:
 *   cred:<credentialId>  -> { userId, publicKey(base64url), counter, label, createdAt, transports }
 *   user:<userId>:creds  -> [credentialId, ...]
 *   chal:<flowId>        -> { type:'register'|'login', challenge, userId, createdAt }  (TTL 120초, 1회용)
 *   sess:<sid>           -> { userId, createdAt }                                       (TTL 1800초)
 *
 * 중요: 개인키는 어디에도 저장되지 않는다. 서버가 받는 것은 공개키뿐이다.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const KV_URL = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL || '';
const KV_TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN || '';

export const STORE_KIND = KV_URL && KV_TOKEN ? 'upstash-redis' : 'file';

/* ------------------------------ Upstash 백엔드 ----------------------------- */

async function kvCommand(command) {
  const res = await fetch(KV_URL, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${KV_TOKEN}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(command),
  });
  if (!res.ok) throw new Error(`KV error ${res.status}`);
  const json = await res.json();
  return json.result;
}

const upstashBackend = {
  async get(key) {
    const raw = await kvCommand(['GET', key]);
    return raw ? JSON.parse(raw) : null;
  },
  async set(key, value, ttlSeconds) {
    const cmd = ['SET', key, JSON.stringify(value)];
    if (ttlSeconds) cmd.push('EX', String(ttlSeconds));
    await kvCommand(cmd);
  },
  async del(key) {
    await kvCommand(['DEL', key]);
  },
};

/* -------------------------------- 파일 백엔드 ------------------------------- */

const FILE_PATH =
  process.env.STORE_FILE || path.join(os.tmpdir(), 'passkey-portfolio-store.json');

function readFileStore() {
  try {
    return JSON.parse(fs.readFileSync(FILE_PATH, 'utf8'));
  } catch {
    return {};
  }
}

function writeFileStore(data) {
  fs.mkdirSync(path.dirname(FILE_PATH), { recursive: true });
  fs.writeFileSync(FILE_PATH, JSON.stringify(data, null, 2));
}

const fileBackend = {
  async get(key) {
    const db = readFileStore();
    const entry = db[key];
    if (!entry) return null;
    if (entry.expiresAt && Date.now() > entry.expiresAt) {
      delete db[key];
      writeFileStore(db);
      return null;
    }
    return entry.value;
  },
  async set(key, value, ttlSeconds) {
    const db = readFileStore();
    db[key] = { value, expiresAt: ttlSeconds ? Date.now() + ttlSeconds * 1000 : null };
    writeFileStore(db);
  },
  async del(key) {
    const db = readFileStore();
    delete db[key];
    writeFileStore(db);
  },
};

const backend = STORE_KIND === 'upstash-redis' ? upstashBackend : fileBackend;

/* ------------------------------ 공개 API(내부용) ----------------------------- */

export const store = {
  // --- 일회용 질문(challenge) ------------------------------------------------
  /** 서버가 만든 challenge를 서버에 보관한다. TTL 120초. */
  async putChallenge(flowId, payload) {
    await backend.set(`chal:${flowId}`, { ...payload, createdAt: Date.now() }, 120);
  },
  /** challenge를 꺼내면서 즉시 삭제한다(1회용). 없으면 null → 재사용 요청은 거절된다. */
  async takeChallenge(flowId) {
    const value = await backend.get(`chal:${flowId}`);
    if (value) await backend.del(`chal:${flowId}`);
    return value;
  },

  // --- 자격증명(공개키) ------------------------------------------------------
  async putCredential(cred) {
    await backend.set(`cred:${cred.id}`, cred);
    const list = (await backend.get(`user:${cred.userId}:creds`)) || [];
    if (!list.includes(cred.id)) {
      list.push(cred.id);
      await backend.set(`user:${cred.userId}:creds`, list);
    }
  },
  async getCredential(credId) {
    return backend.get(`cred:${credId}`);
  },
  async updateCredentialCounter(credId, counter) {
    const cred = await backend.get(`cred:${credId}`);
    if (!cred) return;
    cred.counter = counter;
    cred.lastUsedAt = new Date().toISOString();
    await backend.set(`cred:${credId}`, cred);
  },
  async listCredentials(userId) {
    const ids = (await backend.get(`user:${userId}:creds`)) || [];
    const out = [];
    for (const id of ids) {
      const cred = await backend.get(`cred:${id}`);
      if (cred) out.push(cred);
    }
    return out;
  },
  async deleteCredential(userId, credId) {
    const cred = await backend.get(`cred:${credId}`);
    if (!cred || cred.userId !== userId) return false;
    await backend.del(`cred:${credId}`);
    const ids = (await backend.get(`user:${userId}:creds`)) || [];
    await backend.set(
      `user:${userId}:creds`,
      ids.filter((id) => id !== credId),
    );
    return true;
  },

  // --- 세션 ----------------------------------------------------------------
  async putSession(sid, userId) {
    await backend.set(`sess:${sid}`, { userId, createdAt: Date.now() }, 1800);
  },
  async getSession(sid) {
    return backend.get(`sess:${sid}`);
  },
  async deleteSession(sid) {
    await backend.del(`sess:${sid}`);
  },
};
