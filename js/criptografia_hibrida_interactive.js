/*
 * Ejemplo E4 · Intercambio de claves híbrido
 *
 * Contenido:
 *   1. Keccak / SHA3-256 / SHA3-512 / SHAKE128 / SHAKE256 (FIPS 202).
 *   2. ML-KEM-512/768/1024 (FIPS 203), implementación didáctica en JavaScript:
 *      correcta (contrastada con vectores de kyber-py), pero NO auditada ni de
 *      tiempo constante. No usar fuera de este ejemplo.
 *   3. HKDF (RFC 5869) y el key schedule de TLS 1.3 (RFC 8446) sobre HMAC de WebCrypto.
 *   4. Grupos híbridos de RFC 10024 (X25519MLKEM768, SecP256r1MLKEM768,
 *      SecP384r1MLKEM1024) con X25519/ECDH reales de WebCrypto.
 *   5. Combinadores (XOR, concatenación sin contexto, X-Wing, universal) y un
 *      oráculo de desencapsulado para ilustrar por qué importa la seguridad IND-CCA.
 *   6. Interfaz (solo si hay document). Sin innerHTML: todo con textContent.
 *
 * Las funciones puras se exportan con module.exports para probarlas con node.
 */
(function () {
  'use strict';

  const cryptoObj = globalThis.crypto;
  const subtle = cryptoObj && cryptoObj.subtle;
  const te = new TextEncoder();

  // ---------------------------------------------------------------------------
  // Utilidades de bytes
  // ---------------------------------------------------------------------------
  function concat(...arrs) {
    let len = 0;
    for (const a of arrs) len += a.length;
    const out = new Uint8Array(len);
    let off = 0;
    for (const a of arrs) { out.set(a, off); off += a.length; }
    return out;
  }
  function hex(b) {
    let s = '';
    for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
    return s;
  }
  function fromHex(h) {
    const out = new Uint8Array(h.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(2 * i, 2), 16);
    return out;
  }
  function equalBytes(a, b) {
    if (a.length !== b.length) return false;
    let d = 0;
    for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
    return d === 0;
  }
  function xorBytes(a, b) {
    const out = new Uint8Array(a.length);
    for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
    return out;
  }
  function randomBytes(n) {
    const b = new Uint8Array(n);
    cryptoObj.getRandomValues(b);
    return b;
  }

  // ---------------------------------------------------------------------------
  // 1. Keccak-f[1600] con carriles de 64 bits como pares (lo, hi) de 32 bits
  // ---------------------------------------------------------------------------
  const RC = [
    0x00000001, 0x00000000, 0x00008082, 0x00000000, 0x0000808a, 0x80000000, 0x80008000, 0x80000000,
    0x0000808b, 0x00000000, 0x80000001, 0x00000000, 0x80008081, 0x80000000, 0x00008009, 0x80000000,
    0x0000008a, 0x00000000, 0x00000088, 0x00000000, 0x80008009, 0x00000000, 0x8000000a, 0x00000000,
    0x8000808b, 0x00000000, 0x0000008b, 0x80000000, 0x00008089, 0x80000000, 0x00008003, 0x80000000,
    0x00008002, 0x80000000, 0x00000080, 0x80000000, 0x0000800a, 0x00000000, 0x8000000a, 0x80000000,
    0x80008081, 0x80000000, 0x00008080, 0x80000000, 0x80000001, 0x00000000, 0x80008008, 0x80000000,
  ];
  // Desplazamientos de rotación r[x + 5y]
  const ROT = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];

  function keccakF(s) {
    const C = new Uint32Array(10);
    const B = new Uint32Array(50);
    for (let round = 0; round < 24; round++) {
      // theta
      for (let x = 0; x < 5; x++) {
        C[2 * x] = s[2 * x] ^ s[2 * x + 10] ^ s[2 * x + 20] ^ s[2 * x + 30] ^ s[2 * x + 40];
        C[2 * x + 1] = s[2 * x + 1] ^ s[2 * x + 11] ^ s[2 * x + 21] ^ s[2 * x + 31] ^ s[2 * x + 41];
      }
      for (let x = 0; x < 5; x++) {
        const x1 = (x + 1) % 5, x4 = (x + 4) % 5;
        const lo1 = C[2 * x1], hi1 = C[2 * x1 + 1];
        const dlo = C[2 * x4] ^ ((lo1 << 1) | (hi1 >>> 31));
        const dhi = C[2 * x4 + 1] ^ ((hi1 << 1) | (lo1 >>> 31));
        for (let y = 0; y < 25; y += 5) {
          s[2 * (x + y)] ^= dlo;
          s[2 * (x + y) + 1] ^= dhi;
        }
      }
      // rho + pi
      for (let x = 0; x < 5; x++) {
        for (let y = 0; y < 5; y++) {
          const i = x + 5 * y;
          const lo = s[2 * i], hi = s[2 * i + 1];
          const n = ROT[i];
          let rlo, rhi;
          if (n === 0) { rlo = lo; rhi = hi; }
          else if (n < 32) { rlo = (lo << n) | (hi >>> (32 - n)); rhi = (hi << n) | (lo >>> (32 - n)); }
          else if (n === 32) { rlo = hi; rhi = lo; }
          else { const m = n - 32; rlo = (hi << m) | (lo >>> (32 - m)); rhi = (lo << m) | (hi >>> (32 - m)); }
          const j = y + 5 * ((2 * x + 3 * y) % 5);
          B[2 * j] = rlo;
          B[2 * j + 1] = rhi;
        }
      }
      // chi
      for (let y = 0; y < 25; y += 5) {
        for (let x = 0; x < 5; x++) {
          const a = x + y, b = ((x + 1) % 5) + y, c = ((x + 2) % 5) + y;
          s[2 * a] = B[2 * a] ^ (~B[2 * b] & B[2 * c]);
          s[2 * a + 1] = B[2 * a + 1] ^ (~B[2 * b + 1] & B[2 * c + 1]);
        }
      }
      // iota
      s[0] ^= RC[2 * round];
      s[1] ^= RC[2 * round + 1];
    }
  }

  function keccak(rate, ds, input, outLen) {
    const s = new Uint32Array(50);
    const xorByte = (pos, v) => {
      const lane = pos >> 3, k = pos & 7;
      if (k < 4) s[2 * lane] ^= v << (8 * k);
      else s[2 * lane + 1] ^= v << (8 * (k - 4));
    };
    let off = 0;
    while (input.length - off >= rate) {
      for (let i = 0; i < rate; i++) xorByte(i, input[off + i]);
      keccakF(s);
      off += rate;
    }
    const rem = input.length - off;
    for (let i = 0; i < rem; i++) xorByte(i, input[off + i]);
    xorByte(rem, ds);
    xorByte(rate - 1, 0x80);
    keccakF(s);
    const out = new Uint8Array(outLen);
    let o = 0;
    for (;;) {
      for (let i = 0; i < rate && o < outLen; i++, o++) {
        const lane = i >> 3, k = i & 7;
        const w = k < 4 ? s[2 * lane] : s[2 * lane + 1];
        out[o] = (w >>> (8 * (k & 3))) & 0xff;
      }
      if (o >= outLen) break;
      keccakF(s);
    }
    return out;
  }
  const sha3_256 = (m) => keccak(136, 0x06, m, 32);
  const sha3_512 = (m) => keccak(72, 0x06, m, 64);
  const shake128 = (m, n) => keccak(168, 0x1f, m, n);
  const shake256 = (m, n) => keccak(136, 0x1f, m, n);

  // ---------------------------------------------------------------------------
  // 2. ML-KEM (FIPS 203)
  // ---------------------------------------------------------------------------
  const Q = 3329;
  const PARAMS = {
    512: { name: 'ML-KEM-512', k: 2, eta1: 3, eta2: 2, du: 10, dv: 4 },
    768: { name: 'ML-KEM-768', k: 3, eta1: 2, eta2: 2, du: 10, dv: 4 },
    1024: { name: 'ML-KEM-1024', k: 4, eta1: 2, eta2: 2, du: 11, dv: 5 },
  };
  for (const key of Object.keys(PARAMS)) {
    const p = PARAMS[key];
    p.ekLen = 384 * p.k + 32;
    p.dkLen = 768 * p.k + 96;
    p.ctLen = 32 * (p.du * p.k + p.dv);
  }

  const modq = (x) => ((x % Q) + Q) % Q;
  function bitRev7(i) {
    let r = 0;
    for (let b = 0; b < 7; b++) r |= ((i >> b) & 1) << (6 - b);
    return r;
  }
  function powmod(b, e) {
    let r = 1;
    b = modq(b);
    while (e > 0) { if (e & 1) r = (r * b) % Q; b = (b * b) % Q; e >>= 1; }
    return r;
  }
  const ZETAS = new Int32Array(128);
  const GAMMAS = new Int32Array(128);
  for (let i = 0; i < 128; i++) {
    ZETAS[i] = powmod(17, bitRev7(i));
    GAMMAS[i] = powmod(17, 2 * bitRev7(i) + 1);
  }

  function ntt(fIn) {
    const f = Int32Array.from(fIn);
    let i = 1;
    for (let len = 128; len >= 2; len >>= 1) {
      for (let start = 0; start < 256; start += 2 * len) {
        const zeta = ZETAS[i++];
        for (let j = start; j < start + len; j++) {
          const t = (zeta * f[j + len]) % Q;
          f[j + len] = modq(f[j] - t);
          f[j] = (f[j] + t) % Q;
        }
      }
    }
    return f;
  }
  function invNtt(fIn) {
    const f = Int32Array.from(fIn);
    let i = 127;
    for (let len = 2; len <= 128; len <<= 1) {
      for (let start = 0; start < 256; start += 2 * len) {
        const zeta = ZETAS[i--];
        for (let j = start; j < start + len; j++) {
          const t = f[j];
          f[j] = (t + f[j + len]) % Q;
          f[j + len] = (zeta * modq(f[j + len] - t)) % Q;
        }
      }
    }
    for (let j = 0; j < 256; j++) f[j] = (f[j] * 3303) % Q;
    return f;
  }
  function mulNtt(f, g) {
    const h = new Int32Array(256);
    for (let i = 0; i < 128; i++) {
      const a0 = f[2 * i], a1 = f[2 * i + 1], b0 = g[2 * i], b1 = g[2 * i + 1];
      h[2 * i] = (a0 * b0 + ((a1 * b1) % Q) * GAMMAS[i]) % Q;
      h[2 * i + 1] = (a0 * b1 + a1 * b0) % Q;
    }
    return h;
  }
  function addPoly(a, b) {
    const c = new Int32Array(256);
    for (let i = 0; i < 256; i++) c[i] = (a[i] + b[i]) % Q;
    return c;
  }
  function subPoly(a, b) {
    const c = new Int32Array(256);
    for (let i = 0; i < 256; i++) c[i] = modq(a[i] - b[i]);
    return c;
  }

  function byteEncode(F, d) {
    const out = new Uint8Array(32 * d);
    let bit = 0;
    for (let i = 0; i < 256; i++) {
      const a = F[i];
      for (let j = 0; j < d; j++, bit++) {
        if ((a >> j) & 1) out[bit >> 3] |= 1 << (bit & 7);
      }
    }
    return out;
  }
  function byteDecode(B, d) {
    const F = new Int32Array(256);
    const m = d === 12 ? Q : 1 << d;
    let bit = 0;
    for (let i = 0; i < 256; i++) {
      let a = 0;
      for (let j = 0; j < d; j++, bit++) a |= ((B[bit >> 3] >> (bit & 7)) & 1) << j;
      F[i] = a % m;
    }
    return F;
  }
  // Compress_d(x) = ⌈(2^d/q)·x⌋ mod 2^d ; Decompress_d(y) = ⌈(q/2^d)·y⌋ (FIPS 203, §4.2.1)
  function compress(F, d) {
    const out = new Int32Array(256);
    const mask = (1 << d) - 1;
    for (let i = 0; i < 256; i++) out[i] = Math.floor((F[i] * (1 << (d + 1)) + Q) / (2 * Q)) & mask;
    return out;
  }
  function decompress(F, d) {
    const out = new Int32Array(256);
    for (let i = 0; i < 256; i++) out[i] = (Q * F[i] + (1 << (d - 1))) >> d;
    return out;
  }

  function sampleNtt(seed34) {
    let len = 168 * 5;
    for (;;) {
      const C = shake128(seed34, len);
      const a = new Int32Array(256);
      let j = 0;
      for (let i = 0; i + 3 <= C.length && j < 256; i += 3) {
        const d1 = C[i] + 256 * (C[i + 1] & 15);
        const d2 = (C[i + 1] >> 4) + 16 * C[i + 2];
        if (d1 < Q) a[j++] = d1;
        if (d2 < Q && j < 256) a[j++] = d2;
      }
      if (j === 256) return a;
      len *= 2; // SHAKE es un XOF: el prefijo no cambia, solo pedimos más bytes
    }
  }
  function sampleCbd(B, eta) {
    const f = new Int32Array(256);
    for (let i = 0; i < 256; i++) {
      let x = 0, y = 0;
      for (let j = 0; j < eta; j++) {
        const b1 = 2 * i * eta + j, b2 = 2 * i * eta + eta + j;
        x += (B[b1 >> 3] >> (b1 & 7)) & 1;
        y += (B[b2 >> 3] >> (b2 & 7)) & 1;
      }
      f[i] = modq(x - y);
    }
    return f;
  }
  const prf = (eta, s, n) => shake256(concat(s, Uint8Array.of(n)), 64 * eta);

  function genMatrix(rho, k) {
    const A = [];
    for (let i = 0; i < k; i++) {
      A.push([]);
      for (let j = 0; j < k; j++) A[i].push(sampleNtt(concat(rho, Uint8Array.of(j, i))));
    }
    return A;
  }

  function kpkeKeyGen(p, d) {
    const g = sha3_512(concat(d, Uint8Array.of(p.k)));
    const rho = g.slice(0, 32), sigma = g.slice(32);
    const A = genMatrix(rho, p.k);
    let n = 0;
    const s = [], e = [];
    for (let i = 0; i < p.k; i++) s.push(ntt(sampleCbd(prf(p.eta1, sigma, n++), p.eta1)));
    for (let i = 0; i < p.k; i++) e.push(ntt(sampleCbd(prf(p.eta1, sigma, n++), p.eta1)));
    const parts = [], sParts = [];
    for (let i = 0; i < p.k; i++) {
      let t = e[i];
      for (let j = 0; j < p.k; j++) t = addPoly(t, mulNtt(A[i][j], s[j]));
      parts.push(byteEncode(t, 12));
      sParts.push(byteEncode(s[i], 12));
    }
    return { ek: concat(...parts, rho), dkPke: concat(...sParts) };
  }

  function kpkeEncrypt(p, ek, m, r) {
    const k = p.k;
    const t = [];
    for (let i = 0; i < k; i++) t.push(byteDecode(ek.subarray(384 * i, 384 * (i + 1)), 12));
    const rho = ek.subarray(384 * k, 384 * k + 32);
    const A = genMatrix(rho, k);
    let n = 0;
    const y = [], e1 = [];
    for (let i = 0; i < k; i++) y.push(ntt(sampleCbd(prf(p.eta1, r, n++), p.eta1)));
    for (let i = 0; i < k; i++) e1.push(sampleCbd(prf(p.eta2, r, n++), p.eta2));
    const e2 = sampleCbd(prf(p.eta2, r, n++), p.eta2);
    const c1 = [];
    for (let i = 0; i < k; i++) {
      let acc = new Int32Array(256);
      for (let j = 0; j < k; j++) acc = addPoly(acc, mulNtt(A[j][i], y[j])); // Aᵀ·y
      const u = addPoly(invNtt(acc), e1[i]);
      c1.push(byteEncode(compress(u, p.du), p.du));
    }
    let acc = new Int32Array(256);
    for (let j = 0; j < k; j++) acc = addPoly(acc, mulNtt(t[j], y[j]));
    const mu = decompress(byteDecode(m, 1), 1);
    const v = addPoly(addPoly(invNtt(acc), e2), mu);
    const c2 = byteEncode(compress(v, p.dv), p.dv);
    return concat(...c1, c2);
  }

  function kpkeDecrypt(p, dkPke, c) {
    const k = p.k;
    const lenU = 32 * p.du;
    let acc = new Int32Array(256);
    for (let i = 0; i < k; i++) {
      const u = decompress(byteDecode(c.subarray(lenU * i, lenU * (i + 1)), p.du), p.du);
      const s = byteDecode(dkPke.subarray(384 * i, 384 * (i + 1)), 12);
      acc = addPoly(acc, mulNtt(s, ntt(u)));
    }
    const v = decompress(byteDecode(c.subarray(lenU * k), p.dv), p.dv);
    const w = subPoly(v, invNtt(acc));
    return byteEncode(compress(w, 1), 1);
  }

  function mlkemKeyGenInternal(level, d, z) {
    const p = PARAMS[level];
    const { ek, dkPke } = kpkeKeyGen(p, d);
    const dk = concat(dkPke, ek, sha3_256(ek), z);
    return { ek, dk };
  }
  function mlkemKeyGen(level) {
    return mlkemKeyGenInternal(level, randomBytes(32), randomBytes(32));
  }
  // Comprobación de módulo de la clave de encapsulado (FIPS 203, §7.2)
  function mlkemCheckEk(level, ek) {
    const p = PARAMS[level];
    if (ek.length !== p.ekLen) return false;
    for (let i = 0; i < p.k; i++) {
      const chunk = ek.subarray(384 * i, 384 * (i + 1));
      if (!equalBytes(byteEncode(byteDecode(chunk, 12), 12), chunk)) return false;
    }
    return true;
  }
  function mlkemEncapsInternal(level, ek, m) {
    const p = PARAMS[level];
    const g = sha3_512(concat(m, sha3_256(ek)));
    const K = g.slice(0, 32), r = g.slice(32);
    const c = kpkeEncrypt(p, ek, m, r);
    return { K, c };
  }
  function mlkemEncaps(level, ek) {
    if (!mlkemCheckEk(level, ek)) throw new Error('Clave de encapsulado no válida');
    return mlkemEncapsInternal(level, ek, randomBytes(32));
  }
  function mlkemDecaps(level, dk, c) {
    const p = PARAMS[level];
    if (c.length !== p.ctLen || dk.length !== p.dkLen) throw new Error('Longitudes no válidas');
    const k = p.k;
    const dkPke = dk.subarray(0, 384 * k);
    const ek = dk.subarray(384 * k, 768 * k + 32);
    const h = dk.subarray(768 * k + 32, 768 * k + 64);
    const z = dk.subarray(768 * k + 64, 768 * k + 96);
    const m2 = kpkeDecrypt(p, dkPke, c);
    const g = sha3_512(concat(m2, h));
    const K2 = g.slice(0, 32), r2 = g.slice(32);
    const Kbar = shake256(concat(z, c), 32);
    const c2 = kpkeEncrypt(p, ek, m2, r2);
    // Rechazo implícito: si el cifrado recalculado no coincide, se devuelve J(z‖c).
    return equalBytes(c, c2) ? K2 : Kbar;
  }

  // ---------------------------------------------------------------------------
  // 3. HKDF (RFC 5869) y key schedule de TLS 1.3 (RFC 8446 §7.1), SHA-256
  // ---------------------------------------------------------------------------
  async function hmacSha256(key, data) {
    // Una clave HMAC vacía equivale a HashLen ceros (RFC 2104 rellena con ceros).
    const k = await subtle.importKey('raw', key.length ? key : new Uint8Array(32), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return new Uint8Array(await subtle.sign('HMAC', k, data));
  }
  async function sha256(data) {
    return new Uint8Array(await subtle.digest('SHA-256', data));
  }
  const hkdfExtract = (salt, ikm) => hmacSha256(salt, ikm);
  async function hkdfExpand(prk, info, len) {
    const out = new Uint8Array(len);
    let t = new Uint8Array(0);
    let off = 0;
    for (let i = 1; off < len; i++) {
      t = await hmacSha256(prk, concat(t, info, Uint8Array.of(i)));
      out.set(t.subarray(0, Math.min(t.length, len - off)), off);
      off += t.length;
    }
    return out;
  }
  function hkdfLabel(label, context, len) {
    const full = te.encode('tls13 ' + label);
    return concat(Uint8Array.of(len >> 8, len & 255, full.length), full, Uint8Array.of(context.length), context);
  }
  const hkdfExpandLabel = (secret, label, context, len) => hkdfExpand(secret, hkdfLabel(label, context, len), len);
  async function deriveSecret(secret, label, messages) {
    return hkdfExpandLabel(secret, label, await sha256(messages), 32);
  }
  async function tls13Schedule(sharedSecret, transcript) {
    const zeros = new Uint8Array(32);
    const early = await hkdfExtract(new Uint8Array(0), zeros);
    const derived = await deriveSecret(early, 'derived', new Uint8Array(0));
    const handshake = await hkdfExtract(derived, sharedSecret);
    const cHs = await deriveSecret(handshake, 'c hs traffic', transcript);
    const sHs = await deriveSecret(handshake, 's hs traffic', transcript);
    return { early, derived, handshake, cHs, sHs };
  }

  // ---------------------------------------------------------------------------
  // 4. Componentes clásicos (WebCrypto) y grupos híbridos (RFC 10024)
  // ---------------------------------------------------------------------------
  const CLASSICAL = {
    x25519: { name: 'X25519', alg: { name: 'X25519' }, pkLen: 32, ssLen: 32, bits: 256 },
    p256: { name: 'P-256', alg: { name: 'ECDH', namedCurve: 'P-256' }, pkLen: 65, ssLen: 32, bits: 256 },
    p384: { name: 'P-384', alg: { name: 'ECDH', namedCurve: 'P-384' }, pkLen: 97, ssLen: 48, bits: 384 },
  };
  // pqFirst: orden de concatenación de RFC 10024 (ML-KEM primero solo en X25519MLKEM768).
  const GROUPS = {
    'x25519-768': { name: 'X25519MLKEM768', codepoint: '0x11EC', cl: 'x25519', pq: 768, pqFirst: true },
    'p256-768': { name: 'SecP256r1MLKEM768', codepoint: '0x11EB', cl: 'p256', pq: 768, pqFirst: false },
    'p384-1024': { name: 'SecP384r1MLKEM1024', codepoint: '0x11ED', cl: 'p384', pq: 1024, pqFirst: false },
    x25519: { name: 'x25519 (solo clásico)', codepoint: '0x001D', cl: 'x25519', pq: null },
    mlkem768: { name: 'MLKEM768 (solo PQC)', codepoint: '0x0201', cl: null, pq: 768 },
  };

  async function classicalGenerate(clId) {
    const c = CLASSICAL[clId];
    const kp = await subtle.generateKey(c.alg, true, ['deriveBits']);
    const pk = new Uint8Array(await subtle.exportKey('raw', kp.publicKey));
    return { privateKey: kp.privateKey, pk };
  }
  async function classicalDerive(clId, privateKey, peerPkBytes) {
    const c = CLASSICAL[clId];
    const pub = await subtle.importKey('raw', peerPkBytes, c.alg, true, []);
    const alg = c.alg.name === 'X25519' ? { name: 'X25519', public: pub } : { name: 'ECDH', public: pub };
    return new Uint8Array(await subtle.deriveBits(alg, privateKey, c.bits));
  }
  async function supportsX25519() {
    try {
      const kp = await subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
      const pk = await subtle.exportKey('raw', kp.publicKey);
      await subtle.deriveBits({ name: 'X25519', public: kp.publicKey }, kp.privateKey, 256);
      return pk.byteLength === 32;
    } catch (e) {
      return false;
    }
  }

  // "Handshake" TLS 1.3 simplificado: solo intercambio de claves y key schedule.
  async function runHandshake(groupId) {
    const g = GROUPS[groupId];
    const now = () => (globalThis.performance ? globalThis.performance.now() : Date.now());
    const t0 = now();
    const clientRandom = randomBytes(32), serverRandom = randomBytes(32);
    const pqP = g.pq ? PARAMS[g.pq] : null;
    const clLen = g.cl ? CLASSICAL[g.cl].pkLen : 0;
    // Cliente: genera sus claves y compone key_share
    const cl = g.cl ? await classicalGenerate(g.cl) : null;
    const kem = g.pq ? mlkemKeyGen(g.pq) : null;
    const hybrid = !!(g.cl && g.pq);
    const clientShare = hybrid ? (g.pqFirst ? concat(kem.ek, cl.pk) : concat(cl.pk, kem.ek)) : (g.cl ? cl.pk : kem.ek);
    // Servidor: separa la share, encapsula y hace (EC)DH
    let peerEk = null, peerCl = null;
    if (hybrid) {
      if (g.pqFirst) { peerEk = clientShare.slice(0, pqP.ekLen); peerCl = clientShare.slice(pqP.ekLen); }
      else { peerCl = clientShare.slice(0, clLen); peerEk = clientShare.slice(clLen); }
    } else if (g.cl) peerCl = clientShare; else peerEk = clientShare;
    let srvCl = null, ssClS = null, enc = null;
    if (g.cl) {
      srvCl = await classicalGenerate(g.cl);
      ssClS = await classicalDerive(g.cl, srvCl.privateKey, peerCl);
    }
    if (g.pq) enc = mlkemEncaps(g.pq, peerEk);
    const serverShare = hybrid ? (g.pqFirst ? concat(enc.c, srvCl.pk) : concat(srvCl.pk, enc.c)) : (g.cl ? srvCl.pk : enc.c);
    const ssServer = hybrid ? (g.pqFirst ? concat(enc.K, ssClS) : concat(ssClS, enc.K)) : (g.cl ? ssClS : enc.K);
    // Cliente: recupera ambos secretos a partir de la share del servidor
    let ssClC = null, ssPqC = null;
    if (g.cl) {
      const srvPk = hybrid ? (g.pqFirst ? serverShare.slice(pqP.ctLen) : serverShare.slice(0, clLen)) : serverShare;
      ssClC = await classicalDerive(g.cl, cl.privateKey, srvPk);
    }
    if (g.pq) {
      const ct = hybrid ? (g.pqFirst ? serverShare.slice(0, pqP.ctLen) : serverShare.slice(clLen)) : serverShare;
      ssPqC = mlkemDecaps(g.pq, kem.dk, ct);
    }
    const ssClient = hybrid ? (g.pqFirst ? concat(ssPqC, ssClC) : concat(ssClC, ssPqC)) : (g.cl ? ssClC : ssPqC);
    // Transcript simplificado: ClientHello ≈ random ‖ share; ServerHello ≈ random ‖ share
    const transcript = concat(clientRandom, clientShare, serverRandom, serverShare);
    const schedC = await tls13Schedule(ssClient, transcript);
    const schedS = await tls13Schedule(ssServer, transcript);
    return {
      group: g, clientRandom, serverRandom, clientShare, serverShare,
      ssCl: ssClC, ssPq: ssPqC, ssClient, ssServer, transcript, schedC, schedS,
      agree: equalBytes(schedC.cHs, schedS.cHs), ms: now() - t0,
    };
  }

  // El atacante ve el transcript; conoce los secretos de los componentes rotos y adivina el resto.
  async function attackerView(run, knowsCl, knowsPq) {
    const g = run.group;
    const clPart = g.cl ? (knowsCl ? run.ssCl : randomBytes(run.ssCl.length)) : null;
    const pqPart = g.pq ? (knowsPq ? run.ssPq : randomBytes(32)) : null;
    const guess = g.cl && g.pq ? (g.pqFirst ? concat(pqPart, clPart) : concat(clPart, pqPart)) : (g.cl ? clPart : pqPart);
    const sched = await tls13Schedule(guess, run.transcript);
    return { guess, cHs: sched.cHs, success: equalBytes(sched.cHs, run.schedC.cHs) };
  }

  // ---------------------------------------------------------------------------
  // 5. Combinadores KEM y oráculo de desencapsulado (clásico + ML-KEM-768)
  // ---------------------------------------------------------------------------
  const XWING_LABEL = Uint8Array.of(0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c); // "\.//^\"
  const UNIV_LABEL = te.encode('curso-pqc universal combiner');
  // Todos devuelven 32 bytes. ssM/ctM/ekM: ML-KEM; ssX/ctX/pkX: componente clásico (ctX = clave efímera).
  const COMBINERS = {
    xor: { name: 'XOR: ss_M ⊕ ss_X', f: (a) => xorBytes(a.ssM, a.ssX.subarray(0, 32)) },
    cat: { name: 'SHA3-256(ss_M ‖ ss_X)', f: (a) => sha3_256(concat(a.ssM, a.ssX)) },
    xwing: { name: 'X-Wing: SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ etiqueta)', f: (a) => sha3_256(concat(a.ssM, a.ssX, a.ctX, a.pkX, XWING_LABEL)) },
    univ: { name: 'Universal: SHA3-256(ss_M ‖ ss_X ‖ ct_M ‖ ct_X ‖ ek_M ‖ pk_X ‖ etiqueta)', f: (a) => sha3_256(concat(a.ssM, a.ssX, a.ctM, a.ctX, a.ekM, a.pkX, UNIV_LABEL)) },
  };

  // Receptor con claves estáticas (p. ej. HPKE o un servidor que reutiliza su clave KEM).
  async function makeReceiver(clId) {
    const kem = mlkemKeyGen(768);
    const x = await classicalGenerate(clId);
    return { clId, kem, x };
  }
  async function hybridEncaps(rcv, combinerId) {
    const e = mlkemEncaps(768, rcv.kem.ek);
    const eph = await classicalGenerate(rcv.clId);
    const ssX = await classicalDerive(rcv.clId, eph.privateKey, rcv.x.pk);
    const parts = { ssM: e.K, ssX, ctM: e.c, ctX: eph.pk, ekM: rcv.kem.ek, pkX: rcv.x.pk };
    return { ctM: e.c, ctX: eph.pk, K: COMBINERS[combinerId].f(parts), parts };
  }
  // Oráculo IND-CCA: desencapsula cualquier (ctM, ctX) salvo el reto exacto.
  function makeOracle(rcv, combinerId, challenge) {
    let queries = 0;
    return {
      get queries() { return queries; },
      async decaps(ctM, ctX) {
        queries++;
        if (equalBytes(ctM, challenge.ctM) && equalBytes(ctX, challenge.ctX)) return { refused: true };
        const ssM = mlkemDecaps(768, rcv.kem.dk, ctM);
        let ssX;
        try { ssX = await classicalDerive(rcv.clId, rcv.x.privateKey, ctX); }
        catch (e) { return { error: 'WebCrypto rechaza la clave pública clásica maleada' }; }
        return { K: COMBINERS[combinerId].f({ ssM, ssX, ctM, ctX, ekM: rcv.kem.ek, pkX: rcv.x.pk }) };
      },
    };
  }

  // Ataques. Los componentes "rotos" se simulan revelando al atacante el secreto del reto.
  const ATTACKS = {
    // A: X25519 ignora el bit 255 de la coordenada u (RFC 7748 §5): mismo ss_X con ct_X distinto.
    flip: {
      name: 'A · Malear ct_X (bit 255)',
      breaks: 'ninguno',
      async run(ctx) {
        if (ctx.rcv.clId !== 'x25519') return { note: 'Requiere X25519: con P-256 no existe esta maleabilidad de codificación.' };
        const ctX2 = ctx.ch.ctX.slice();
        ctX2[31] ^= 0x80;
        const r = await ctx.oracle.decaps(ctx.ch.ctM, ctX2);
        if (r.error || r.refused) return { note: r.error || 'consulta rechazada' };
        return { guess: r.K, steps: ['consulta (ct_M*, ct_X* con el bit 255 invertido) → el oráculo devuelve K′ y el atacante apuesta K* = K′'] };
      },
    },
    // B: con ss_X* conocido (CRQC), mezclar ct_M* con un ct_X propio y despejar ss_M* (funciona con XOR).
    mix: {
      name: 'B · CRQC rompe el clásico + ct_X propio',
      breaks: 'clásico (CRQC simulado)',
      async run(ctx) {
        const eph = await classicalGenerate(ctx.rcv.clId);
        const ssX2 = await classicalDerive(ctx.rcv.clId, eph.privateKey, ctx.rcv.x.pk);
        const r = await ctx.oracle.decaps(ctx.ch.ctM, eph.pk);
        if (r.error || r.refused) return { note: r.error || 'consulta rechazada' };
        const ssMguess = xorBytes(r.K, ssX2.subarray(0, 32)); // si K′ = ss_M* ⊕ ss_X′
        const ssXstar = ctx.ch.parts.ssX; // lo que aportaría el CRQC
        const guess = COMBINERS[ctx.combinerId].f({ ssM: ssMguess, ssX: ssXstar, ctM: ctx.ch.ctM, ctX: ctx.ch.ctX, ekM: ctx.rcv.kem.ek, pkX: ctx.rcv.x.pk });
        return { guess, steps: ['el CRQC (simulado) revela ss_X*', 'consulta (ct_M*, ct_X′) con ct_X′ efímero del atacante, cuyo ss_X′ conoce', 'supone K′ = ss_M* ⊕ ss_X′, despeja ss_M* y recalcula K*'] };
      },
    },
    // C: con ss_M* conocido (ML-KEM roto), mezclar un ct_M propio con ct_X* (funciona con XOR).
    mixpq: {
      name: 'C · ML-KEM roto + ct_M propio',
      breaks: 'PQ (criptoanálisis simulado)',
      async run(ctx) {
        const e = mlkemEncaps(768, ctx.rcv.kem.ek);
        const r = await ctx.oracle.decaps(e.c, ctx.ch.ctX);
        if (r.error || r.refused) return { note: r.error || 'consulta rechazada' };
        const ssXguess = concat(xorBytes(r.K, e.K), ctx.ch.parts.ssX.subarray(32));
        const guess = COMBINERS[ctx.combinerId].f({ ssM: ctx.ch.parts.ssM, ssX: ssXguess, ctM: ctx.ch.ctM, ctX: ctx.ch.ctX, ekM: ctx.rcv.kem.ek, pkX: ctx.rcv.x.pk });
        return { guess, steps: ['el criptoanálisis (simulado) revela ss_M*', 'consulta (ct_M′, ct_X*) con ct_M′ encapsulado por el atacante, cuyo ss_M′ conoce', 'supone K′ = ss_M′ ⊕ ss_X*, despeja ss_X* y recalcula K*'] };
      },
    },
    // D: malear ct_M. ML-KEM responde con rechazo implícito J(z‖c′), que no revela nada.
    flippq: {
      name: 'D · Malear ct_M (1 bit)',
      breaks: 'ninguno',
      async run(ctx) {
        const ctM2 = ctx.ch.ctM.slice();
        ctM2[0] ^= 0x01;
        const r = await ctx.oracle.decaps(ctM2, ctx.ch.ctX);
        if (r.error || r.refused) return { note: r.error || 'consulta rechazada' };
        return { guess: r.K, steps: ['consulta (ct_M* con 1 bit invertido, ct_X*) → ML-KEM aplica rechazo implícito; el atacante apuesta K* = K′'] };
      },
    },
  };

  async function runCombinerAttack(clId, combinerId, attackId) {
    const rcv = await makeReceiver(clId);
    const ch = await hybridEncaps(rcv, combinerId);
    const oracle = makeOracle(rcv, combinerId, ch);
    const res = await ATTACKS[attackId].run({ rcv, ch, oracle, combinerId });
    return { rcv, ch, res, success: !!res.guess && equalBytes(res.guess, ch.K), queries: oracle.queries };
  }

  // ---------------------------------------------------------------------------
  // 6. Tamaños (bytes) para la calculadora
  // ---------------------------------------------------------------------------
  // key_share en TLS 1.3: RFC 8446 (ECDHE), RFC 10024 (híbridos), draft-ietf-tls-mlkem (solo ML-KEM).
  const KEX_SIZES = {
    x25519: { name: 'x25519', client: 32, server: 32, ss: 32, kind: 'clásico' },
    p256: { name: 'secp256r1 (P-256)', client: 65, server: 65, ss: 32, kind: 'clásico' },
    p384: { name: 'secp384r1 (P-384)', client: 97, server: 97, ss: 48, kind: 'clásico' },
    mlkem512: { name: 'MLKEM512', client: 800, server: 768, ss: 32, kind: 'PQC' },
    mlkem768: { name: 'MLKEM768', client: 1184, server: 1088, ss: 32, kind: 'PQC' },
    mlkem1024: { name: 'MLKEM1024', client: 1568, server: 1568, ss: 32, kind: 'PQC' },
    x25519mlkem768: { name: 'X25519MLKEM768', client: 1216, server: 1120, ss: 64, kind: 'híbrido' },
    p256mlkem768: { name: 'SecP256r1MLKEM768', client: 1249, server: 1153, ss: 64, kind: 'híbrido' },
    p384mlkem1024: { name: 'SecP384r1MLKEM1024', client: 1665, server: 1665, ss: 80, kind: 'híbrido' },
  };
  // Clave pública y firma en bytes brutos (sin codificación X.509). ECDSA: firma DER típica.
  const SIG_SIZES = {
    ecdsa256: { name: 'ECDSA P-256', pk: 65, sig: 72 },
    ed25519: { name: 'Ed25519', pk: 32, sig: 64 },
    rsa2048: { name: 'RSA-2048', pk: 256, sig: 256 },
    mldsa44: { name: 'ML-DSA-44', pk: 1312, sig: 2420 },
    mldsa65: { name: 'ML-DSA-65', pk: 1952, sig: 3309 },
    mldsa87: { name: 'ML-DSA-87', pk: 2592, sig: 4627 },
    slh128s: { name: 'SLH-DSA-SHA2-128s', pk: 32, sig: 7856 },
  };
  // Modelo: hoja + intermedia (2 claves públicas), firma de la hoja, firma de la intermedia,
  // CertificateVerify y n SCT de Certificate Transparency, todas con el mismo algoritmo.
  function authBytes(sigId, nSct) {
    const s = SIG_SIZES[sigId];
    return { pks: 2 * s.pk, sigs: (3 + nSct) * s.sig, total: 2 * s.pk + (3 + nSct) * s.sig };
  }

  const API = {
    concat, hex, fromHex, equalBytes, xorBytes, randomBytes,
    sha3_256, sha3_512, shake128, shake256,
    PARAMS, mlkemKeyGenInternal, mlkemKeyGen, mlkemEncapsInternal, mlkemEncaps, mlkemDecaps, mlkemCheckEk,
    hkdfExtract, hkdfExpand, hkdfExpandLabel, deriveSecret, tls13Schedule,
    CLASSICAL, GROUPS, supportsX25519, runHandshake, attackerView,
    COMBINERS, ATTACKS, runCombinerAttack, KEX_SIZES, SIG_SIZES, authBytes,
  };
  if (typeof module !== 'undefined' && module.exports) module.exports = API;
  if (typeof document === 'undefined') return;

  // ---------------------------------------------------------------------------
  // 7. Interfaz
  // ---------------------------------------------------------------------------
  const $ = (id) => document.getElementById(id);
  const fmt = (n) => (n >= 10000 ? String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ' ') : String(n));
  function short(b, n) {
    const h = hex(b);
    const lim = n || 24;
    return h.length > 2 * lim ? h.slice(0, lim) + '…' + h.slice(-8) : h;
  }
  function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); }
  function line(out, parts) {
    for (const p of parts) {
      if (typeof p === 'string') out.appendChild(document.createTextNode(p));
      else {
        const s = document.createElement('span');
        if (p[1]) s.className = p[1];
        s.textContent = p[0];
        out.appendChild(s);
      }
    }
    out.appendChild(document.createTextNode('\n'));
  }
  function setStat(id, value) { const el = $(id); if (el) el.textContent = value; }

  let lastRun = null;
  let x25519ok = false;

  async function renderAttacker() {
    const out = $('hs-attack-out');
    if (!out) return;
    clear(out);
    if (!lastRun) { line(out, [['Ejecuta primero el handshake.', 'dim']]); return; }
    const g = lastRun.group;
    const knowsCl = $('hs-leak-t').checked && !!g.cl;
    const knowsPq = $('hs-leak-pq').checked && !!g.pq;
    const v = await attackerView(lastRun, knowsCl, knowsPq);
    line(out, [['Atacante pasivo: ha grabado ClientHello y ServerHello (transcript completo).', 'dim']]);
    if (g.cl) line(out, ['ss clásico: ', knowsCl ? ['conocido (CRQC)', 'bad'] : ['desconocido → lo adivina al azar', 'ok']]);
    if (g.pq) line(out, ['ss PQ:      ', knowsPq ? ['conocido (ML-KEM roto)', 'bad'] : ['desconocido → lo adivina al azar', 'ok']]);
    line(out, ['c hs traffic (atacante) = ', [short(v.cHs, 20), v.success ? 'bad' : 'dim']]);
    line(out, ['c hs traffic (real)     = ', [short(lastRun.schedC.cHs, 20), 'hl']]);
    if (v.success) {
      line(out, [['→ Clave de sesión comprometida: todos los componentes del grupo están rotos.', 'bad']]);
    } else {
      const left = [];
      if (g.cl && !knowsCl) left.push(CLASSICAL[g.cl].name + ' (clásico)');
      if (g.pq && !knowsPq) left.push(PARAMS[g.pq].name + ' (PQ)');
      line(out, [['→ La clave sigue protegida por ' + left.join(' y ') + '. Adivinar el secreto que falta tiene probabilidad ≈ 2⁻²⁵⁶ por intento.', 'ok']]);
    }
  }

  async function doHandshake() {
    const out = $('hs-out');
    const btn = $('hs-run');
    const groupId = $('hs-group').value;
    btn.disabled = true;
    clear(out);
    line(out, [['Calculando…', 'dim']]);
    try {
      const r = await runHandshake(groupId);
      lastRun = r;
      clear(out);
      const g = r.group;
      line(out, [['Grupo ' + g.name + ' · NamedGroup ' + g.codepoint, 'hl']]);
      line(out, [['— ClientHello.key_share —', 'dim']]);
      if (g.cl && g.pq) line(out, ['orden: ' + (g.pqFirst ? 'ek ML-KEM ‖ pk ' + CLASSICAL[g.cl].name : 'pk ' + CLASSICAL[g.cl].name + ' ‖ ek ML-KEM')]);
      line(out, ['client_share (' + fmt(r.clientShare.length) + ' B) = ', [short(r.clientShare), '']]);
      line(out, [['— ServerHello.key_share —', 'dim']]);
      if (g.cl && g.pq) line(out, ['orden: ' + (g.pqFirst ? 'ct ML-KEM ‖ pk ' + CLASSICAL[g.cl].name : 'pk ' + CLASSICAL[g.cl].name + ' ‖ ct ML-KEM')]);
      line(out, ['server_share (' + fmt(r.serverShare.length) + ' B) = ', [short(r.serverShare), '']]);
      line(out, [['— Secretos compartidos —', 'dim']]);
      if (g.cl) line(out, ['ss ' + CLASSICAL[g.cl].name + ' (' + r.ssCl.length + ' B) = ', [short(r.ssCl, 16), '']]);
      if (g.pq) line(out, ['ss ' + PARAMS[g.pq].name + ' (32 B) = ', [short(r.ssPq, 16), '']]);
      line(out, ['entrada (EC)DHE a HKDF-Extract (' + r.ssClient.length + ' B) = ', [short(r.ssClient, 16), '']]);
      line(out, [['— Key schedule de TLS 1.3 (SHA-256) —', 'dim']]);
      line(out, ['handshake_secret = HKDF-Extract(derived, ss) = ', [short(r.schedC.handshake, 16), '']]);
      line(out, ['Derive-Secret(·, "c hs traffic", transcript): el hash cubre ' + fmt(r.transcript.length) + ' B, ambas shares incluidas']);
      line(out, ['c hs traffic (cliente)  = ', [short(r.schedC.cHs, 20), 'hl']]);
      line(out, ['c hs traffic (servidor) = ', [short(r.schedS.cHs, 20), 'hl']]);
      line(out, [r.agree ? ['✓ Ambos extremos derivan la misma clave de tráfico.', 'ok'] : ['✗ Las claves no coinciden.', 'bad']]);
      setStat('hs-st-client', fmt(r.clientShare.length) + ' B');
      setStat('hs-st-server', fmt(r.serverShare.length) + ' B');
      setStat('hs-st-ss', r.ssClient.length + ' B');
      setStat('hs-st-time', Math.max(1, Math.round(r.ms)) + ' ms');
      $('hs-leak-t').disabled = !g.cl;
      $('hs-leak-pq').disabled = !g.pq;
      await renderAttacker();
    } catch (e) {
      clear(out);
      line(out, [['Error: ' + e.message, 'bad']]);
    } finally {
      btn.disabled = false;
    }
  }

  function resetHandshake() {
    lastRun = null;
    const out = $('hs-out');
    clear(out);
    line(out, [['Elige un grupo y pulsa «Ejecutar handshake».', 'dim']]);
    ['hs-st-client', 'hs-st-server', 'hs-st-ss', 'hs-st-time'].forEach((id) => setStat(id, '—'));
    $('hs-leak-t').checked = false;
    $('hs-leak-pq').checked = false;
    $('hs-leak-t').disabled = false;
    $('hs-leak-pq').disabled = false;
    renderAttacker();
  }

  async function doCombiner() {
    const out = $('cb-out');
    const btn = $('cb-run');
    btn.disabled = true;
    clear(out);
    line(out, [['Calculando…', 'dim']]);
    const combinerId = $('cb-comb').value;
    const attackId = $('cb-attack').value;
    try {
      const clId = x25519ok ? 'x25519' : 'p256';
      const r = await runCombinerAttack(clId, combinerId, attackId);
      clear(out);
      line(out, [['Receptor con claves estáticas ML-KEM-768 + ' + CLASSICAL[clId].name, 'hl']]);
      line(out, ['combinador: ' + COMBINERS[combinerId].name]);
      line(out, ['reto: ct_M* (' + fmt(r.ch.ctM.length) + ' B) = ', [short(r.ch.ctM, 12), ''], '   ct_X* = ', [short(r.ch.ctX, 12), '']]);
      line(out, ['K* (oculta al atacante) = ', [short(r.ch.K, 20), 'hl']]);
      line(out, ['componente roto: ' + ATTACKS[attackId].breaks]);
      if (r.res.note) {
        line(out, [[r.res.note, 'dim']]);
      } else {
        for (const s of r.res.steps) line(out, ['· ' + s]);
        line(out, ['K del atacante          = ', [short(r.res.guess, 20), r.success ? 'bad' : 'dim']]);
        line(out, [r.success
          ? ['✗ El atacante obtiene K*: con este combinador el KEM híbrido no es IND-CCA.', 'bad']
          : ['✓ El atacante no obtiene K*: la consulta produce una clave independiente de K*.', 'ok']]);
      }
      line(out, [['consultas al oráculo: ' + r.queries + ' (el reto exacto está prohibido)', 'dim']]);
      setStat('cb-st-result', r.res.note ? 'n/a' : (r.success ? 'roto' : 'resiste'));
    } catch (e) {
      clear(out);
      line(out, [['Error: ' + e.message, 'bad']]);
    } finally {
      btn.disabled = false;
    }
  }

  async function doMatrix() {
    const tbody = $('cb-matrix-body');
    const btn = $('cb-matrix');
    if (!tbody) return;
    btn.disabled = true;
    clear(tbody);
    const clId = x25519ok ? 'x25519' : 'p256';
    const shortNames = { xor: 'XOR', cat: 'SHA3(ss_M ‖ ss_X)', xwing: 'X-Wing', univ: 'Universal' };
    try {
      for (const cid of Object.keys(COMBINERS)) {
        const tr = document.createElement('tr');
        const th = document.createElement('th');
        th.scope = 'row';
        th.textContent = shortNames[cid];
        tr.appendChild(th);
        for (const aid of Object.keys(ATTACKS)) {
          const r = await runCombinerAttack(clId, cid, aid);
          const td = document.createElement('td');
          const b = document.createElement('span');
          if (r.res.note) { b.className = 'badge info'; b.textContent = 'n/a'; }
          else if (r.success) { b.className = 'badge broken'; b.textContent = 'roto'; }
          else { b.className = 'badge final'; b.textContent = 'resiste'; }
          td.appendChild(b);
          tr.appendChild(td);
        }
        tbody.appendChild(tr);
      }
    } finally {
      btn.disabled = false;
    }
  }

  function renderSizes() {
    const kex = KEX_SIZES[$('sz-kex').value];
    const sigId = $('sz-sig').value;
    const nSct = $('sz-sct').checked ? 2 : 0;
    const auth = authBytes(sigId, nSct);
    const baseAuth = authBytes('ecdsa256', nSct);
    const ch = 300 + kex.client; // ~300 B de otros campos del ClientHello: suposición ilustrativa
    const s2c = kex.server + auth.total;
    setStat('sz-st-c2s', fmt(kex.client) + ' B');
    setStat('sz-st-s2c', fmt(kex.server) + ' B');
    setStat('sz-st-auth', fmt(auth.total) + ' B');
    setStat('sz-st-ch', '≈ ' + fmt(ch) + ' B');
    const out = $('sz-out');
    clear(out);
    line(out, [[kex.name + ' (' + kex.kind + ')', 'hl'], ' · secreto compartido de ' + kex.ss + ' B']);
    line(out, ['key share cliente → servidor: ' + fmt(kex.client) + ' B  (×' + (kex.client / 32).toFixed(1).replace('.', ',') + ' respecto a x25519)']);
    line(out, ['key share servidor → cliente: ' + fmt(kex.server) + ' B']);
    line(out, ['autenticación ' + SIG_SIZES[sigId].name + ': 2 claves públicas (' + fmt(auth.pks) + ' B) + ' + (3 + nSct) + ' firmas (' + fmt(auth.sigs) + ' B) = ' + fmt(auth.total) + ' B']);
    line(out, [['referencia ECDSA P-256 con el mismo modelo: ' + fmt(baseAuth.total) + ' B', 'dim']]);
    const mss = 1460;
    line(out, [ch > mss
      ? ['ClientHello ≈ ' + fmt(ch) + ' B > 1460 B (MSS típico): ocupa 2 segmentos TCP.', 'bad']
      : ['ClientHello ≈ ' + fmt(ch) + ' B: cabe en un segmento TCP.', 'ok']]);
    const initcwnd = 10 * mss;
    line(out, [s2c > initcwnd
      ? ['Vuelo del servidor (solo criptografía) ≈ ' + fmt(s2c) + ' B > 10 × MSS = ' + fmt(initcwnd) + ' B: probable ida y vuelta extra.', 'bad']
      : ['Vuelo del servidor (solo criptografía) ≈ ' + fmt(s2c) + ' B ≤ 10 × MSS = ' + fmt(initcwnd) + ' B.', 'ok']]);
    const bars = $('sz-bars');
    clear(bars);
    const maxV = Math.max(authBytes('slh128s', 2).total, 1);
    const rows = [
      ['Key share cliente', kex.client],
      ['Key share servidor', kex.server],
      ['Autenticación del servidor', auth.total],
    ];
    for (const [label, v] of rows) {
      const wrap = document.createElement('div');
      const lab = document.createElement('small');
      lab.textContent = label + ' · ' + fmt(v) + ' B';
      const bar = document.createElement('div');
      bar.className = 'bar';
      const span = document.createElement('span');
      span.style.width = Math.max(0.5, (100 * v) / maxV).toFixed(1) + '%';
      bar.appendChild(span);
      wrap.appendChild(lab);
      wrap.appendChild(bar);
      bars.appendChild(wrap);
    }
  }

  async function init() {
    const support = $('hyb-support');
    if (!subtle) {
      if (support) support.textContent = 'Este navegador no expone WebCrypto (crypto.subtle); la demo necesita un contexto seguro (https, localhost o file://).';
      return;
    }
    x25519ok = await supportsX25519();
    if (support) {
      support.textContent = x25519ok
        ? 'Tu navegador implementa X25519 en WebCrypto: la demo usa claves X25519 reales.'
        : 'Tu navegador no implementa X25519 en WebCrypto: se usa ECDH P-256 (SecP256r1MLKEM768) y el ataque A no aplica.';
    }
    const sel = $('hs-group');
    if (sel) {
      if (!x25519ok) {
        for (const opt of Array.from(sel.options)) if (opt.value.startsWith('x25519')) opt.disabled = true;
        sel.value = 'p256-768';
      }
      $('hs-run').addEventListener('click', doHandshake);
      $('hs-reset').addEventListener('click', resetHandshake);
      $('hs-leak-t').addEventListener('change', renderAttacker);
      $('hs-leak-pq').addEventListener('change', renderAttacker);
      sel.addEventListener('change', resetHandshake);
      resetHandshake();
    }
    if ($('cb-run')) {
      const resetCb = () => {
        clear($('cb-out'));
        line($('cb-out'), [['Elige combinador y ataque y pulsa «Lanzar ataque».', 'dim']]);
        clear($('cb-matrix-body'));
        setStat('cb-st-result', '—');
      };
      $('cb-run').addEventListener('click', doCombiner);
      $('cb-matrix').addEventListener('click', doMatrix);
      $('cb-reset').addEventListener('click', resetCb);
      resetCb();
    }
    if ($('sz-kex')) {
      ['sz-kex', 'sz-sig', 'sz-sct'].forEach((id) => $(id).addEventListener('change', renderSizes));
      renderSizes();
    }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
