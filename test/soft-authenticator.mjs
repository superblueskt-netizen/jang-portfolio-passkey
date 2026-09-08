/**
 * 자동 검사용 소프트웨어 인증기(가상 패스키)
 * ---------------------------------------------------------------------------
 * 실제 기기(지문/화면잠금) 대신, 브라우저가 하는 일을 코드로 똑같이 흉내 낸다.
 *   - 열쇠 한 쌍(P-256)을 만든다 → 개인키는 이 객체 안에만 남는다
 *   - 등록: 공개키를 담은 attestationObject를 만들어 돌려준다
 *   - 로그인: 서버가 준 질문(challenge)에 개인키로 서명해 돌려준다
 * 이 파일은 검사 기록을 만들기 위한 것이고, 실제 서비스 코드가 아니다.
 */

import crypto from 'node:crypto';

/* ------------------------------ 아주 작은 CBOR 인코더 ------------------------------ */

function head(major, length) {
  if (length < 24) return Buffer.from([(major << 5) | length]);
  if (length < 256) return Buffer.from([(major << 5) | 24, length]);
  if (length < 65536) {
    const b = Buffer.alloc(3);
    b[0] = (major << 5) | 25;
    b.writeUInt16BE(length, 1);
    return b;
  }
  const b = Buffer.alloc(5);
  b[0] = (major << 5) | 26;
  b.writeUInt32BE(length, 1);
  return b;
}

function cbor(value) {
  if (typeof value === 'number') {
    return value >= 0 ? head(0, value) : head(1, -value - 1);
  }
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    const buf = Buffer.from(value);
    return Buffer.concat([head(2, buf.length), buf]);
  }
  if (typeof value === 'string') {
    const buf = Buffer.from(value, 'utf8');
    return Buffer.concat([head(3, buf.length), buf]);
  }
  if (value instanceof Map) {
    const parts = [head(5, value.size)];
    for (const [k, v] of value) parts.push(cbor(k), cbor(v));
    return Buffer.concat(parts);
  }
  throw new Error('지원하지 않는 CBOR 타입');
}

/* ------------------------------- 소프트웨어 인증기 ------------------------------- */

const b64url = (buf) => Buffer.from(buf).toString('base64url');

export class SoftAuthenticator {
  /**
   * @param {string} name 사람이 알아보기 위한 이름(로그용)
   */
  constructor(name) {
    this.name = name;
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    this.privateKey = privateKey; // ← 이 값은 절대 서버로 보내지 않는다
    this.publicKey = publicKey;
    this.credentialId = crypto.randomBytes(32);
    this.counter = 0;
  }

  get credentialIdB64() {
    return b64url(this.credentialId);
  }

  /** COSE 형식 공개키 (ES256) */
  #cosePublicKey() {
    const jwk = this.publicKey.export({ format: 'jwk' });
    const x = Buffer.from(jwk.x, 'base64url');
    const y = Buffer.from(jwk.y, 'base64url');
    const map = new Map([
      [1, 2],   // kty: EC2
      [3, -7],  // alg: ES256
      [-1, 1],  // crv: P-256
      [-2, x],
      [-3, y],
    ]);
    return cbor(map);
  }

  #clientDataJSON(type, challenge, origin) {
    return Buffer.from(
      JSON.stringify({ type, challenge, origin, crossOrigin: false }),
      'utf8',
    );
  }

  #authData(rpId, flags, includeAttestedData) {
    const rpIdHash = crypto.createHash('sha256').update(rpId).digest();
    const flagsBuf = Buffer.from([flags]);
    const counterBuf = Buffer.alloc(4);
    counterBuf.writeUInt32BE(this.counter, 0);
    if (!includeAttestedData) return Buffer.concat([rpIdHash, flagsBuf, counterBuf]);

    const aaguid = Buffer.alloc(16, 0);
    const idLen = Buffer.alloc(2);
    idLen.writeUInt16BE(this.credentialId.length, 0);
    return Buffer.concat([
      rpIdHash,
      flagsBuf,
      counterBuf,
      aaguid,
      idLen,
      this.credentialId,
      this.#cosePublicKey(),
    ]);
  }

  /** 등록 응답 만들기 (navigator.credentials.create 결과에 해당) */
  createRegistrationResponse({ challenge, origin, rpId }) {
    const clientDataJSON = this.#clientDataJSON('webauthn.create', challenge, origin);
    // flags: UP(0x01) + UV(0x04) + AT(0x40)
    const authData = this.#authData(rpId, 0x45, true);
    const attestationObject = cbor(
      new Map([
        ['fmt', 'none'],
        ['attStmt', new Map()],
        ['authData', authData],
      ]),
    );

    return {
      id: this.credentialIdB64,
      rawId: this.credentialIdB64,
      type: 'public-key',
      clientExtensionResults: {},
      response: {
        clientDataJSON: b64url(clientDataJSON),
        attestationObject: b64url(attestationObject),
        transports: ['internal'],
      },
    };
  }

  /**
   * 로그인 응답 만들기 (navigator.credentials.get 결과에 해당)
   * @param {object} opts
   * @param {crypto.KeyObject} [opts.signWith] 다른 열쇠로 서명하고 싶을 때(=남의 패스키 흉내)
   */
  createAuthenticationResponse({ challenge, origin, rpId, userHandle, signWith }) {
    this.counter += 1;
    const clientDataJSON = this.#clientDataJSON('webauthn.get', challenge, origin);
    const authData = this.#authData(rpId, 0x05, false); // UP + UV
    const clientDataHash = crypto.createHash('sha256').update(clientDataJSON).digest();

    const signature = crypto.sign(
      'sha256',
      Buffer.concat([authData, clientDataHash]),
      signWith || this.privateKey,
    );

    return {
      id: this.credentialIdB64,
      rawId: this.credentialIdB64,
      type: 'public-key',
      clientExtensionResults: {},
      response: {
        clientDataJSON: b64url(clientDataJSON),
        authenticatorData: b64url(authData),
        signature: b64url(signature),
        userHandle: userHandle ? b64url(Buffer.from(userHandle, 'utf8')) : undefined,
      },
    };
  }
}

export function randomKeyPair() {
  return crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey;
}
