/* ML-DSA didáctico: "Fiat–Shamir con abortos" estructuralmente fiel a FIPS 204.
   - Aritmética real en Z_q[X]/(X^n + 1); con q = 8 380 417 y n = 256 se usa la NTT de FIPS 204.
   - KeyGen, Sign y Verify siguen los algoritmos 6-8 de FIPS 204 (Power2Round, Decompose,
     HighBits/LowBits, MakeHint/UseHint, SampleInBall, rechazos, μ con contexto).
   - SIMPLIFICACIONES (declaradas en la página): SHAKE-128/256 se sustituyen por un XOF casero
     construido con SHA-256 en modo contador; no hay empaquetado de bits (los tamaños se calculan
     con las fórmulas de FIPS 204); nada es de tiempo constante. NO usar para proteger nada.
   Vanilla ES2020, sin dependencias. Exporta la lógica pura para probarla con node. */
(function (root) {
  'use strict';

  // ---------------------------------------------------------------- SHA-256 (FIPS 180-4)
  const K256 = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);

  function sha256(msg) {
    const len = msg.length;
    const padLen = ((len + 9 + 63) >> 6) << 6;
    const p = new Uint8Array(padLen);
    p.set(msg);
    p[len] = 0x80;
    const bits = len * 8;
    const dv = new DataView(p.buffer);
    dv.setUint32(padLen - 8, Math.floor(bits / 0x100000000));
    dv.setUint32(padLen - 4, bits >>> 0);
    const h = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
    const w = new Uint32Array(64);
    for (let off = 0; off < padLen; off += 64) {
      for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + 4 * i);
      for (let i = 16; i < 64; i++) {
        const a = w[i - 15], b = w[i - 2];
        const s0 = ((a >>> 7) | (a << 25)) ^ ((a >>> 18) | (a << 14)) ^ (a >>> 3);
        const s1 = ((b >>> 17) | (b << 15)) ^ ((b >>> 19) | (b << 13)) ^ (b >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }
      let [A, B, C, D, E, F, G, Hh] = h;
      for (let i = 0; i < 64; i++) {
        const S1 = ((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7));
        const ch = (E & F) ^ (~E & G);
        const t1 = (Hh + S1 + ch + K256[i] + w[i]) >>> 0;
        const S0 = ((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10));
        const maj = (A & B) ^ (A & C) ^ (B & C);
        const t2 = (S0 + maj) >>> 0;
        Hh = G; G = F; F = E; E = (D + t1) >>> 0; D = C; C = B; B = A; A = (t1 + t2) >>> 0;
      }
      h[0] = (h[0] + A) >>> 0; h[1] = (h[1] + B) >>> 0; h[2] = (h[2] + C) >>> 0; h[3] = (h[3] + D) >>> 0;
      h[4] = (h[4] + E) >>> 0; h[5] = (h[5] + F) >>> 0; h[6] = (h[6] + G) >>> 0; h[7] = (h[7] + Hh) >>> 0;
    }
    const out = new Uint8Array(32);
    const odv = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) odv.setUint32(4 * i, h[i]);
    return out;
  }

  function concat(...parts) {
    let n = 0;
    for (const p of parts) n += p.length;
    const out = new Uint8Array(n);
    let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  }
  const u8 = (...xs) => Uint8Array.from(xs);
  const u16le = (x) => u8(x & 255, (x >> 8) & 255);
  const utf8 = (s) => new TextEncoder().encode(s);
  const hex = (b, max) => {
    let s = '';
    const m = max ? Math.min(max, b.length) : b.length;
    for (let i = 0; i < m; i++) s += b[i].toString(16).padStart(2, '0');
    return m < b.length ? s + '…' : s;
  };
  const eqBytes = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

  // XOF didáctico: SHA-256(semilla ‖ contador de 4 bytes), bloques concatenados. Sustituye a SHAKE-128/256.
  class Xof {
    constructor(seed) { this.seed = seed; this.ctr = 0; this.buf = new Uint8Array(0); this.pos = 0; }
    byte() {
      if (this.pos >= this.buf.length) {
        const c = this.ctr++;
        this.buf = sha256(concat(this.seed, u8(c & 255, (c >> 8) & 255, (c >> 16) & 255, (c >>> 24) & 255)));
        this.pos = 0;
      }
      return this.buf[this.pos++];
    }
    bytes(n) { const o = new Uint8Array(n); for (let i = 0; i < n; i++) o[i] = this.byte(); return o; }
  }
  const H = (data, outLen) => new Xof(data).bytes(outLen);

  // ---------------------------------------------------------------- parámetros
  const Q = 8380417;
  const PRESETS = {
    toy: { name: 'Juguete (n = 16, q = 7681)', q: 7681, n: 16, k: 2, l: 2, eta: 1, tau: 4, gamma1: 256, gamma2: 480, d: 5, omega: 8, lambda: 64, toy: true },
    'ML-DSA-44': { name: 'ML-DSA-44', q: Q, n: 256, k: 4, l: 4, eta: 2, tau: 39, gamma1: 1 << 17, gamma2: (Q - 1) / 88, d: 13, omega: 80, lambda: 128 },
    'ML-DSA-65': { name: 'ML-DSA-65', q: Q, n: 256, k: 6, l: 5, eta: 4, tau: 49, gamma1: 1 << 19, gamma2: (Q - 1) / 32, d: 13, omega: 55, lambda: 192 },
    'ML-DSA-87': { name: 'ML-DSA-87', q: Q, n: 256, k: 8, l: 7, eta: 2, tau: 60, gamma1: 1 << 19, gamma2: (Q - 1) / 32, d: 13, omega: 75, lambda: 256 },
  };

  function makeParams(presetId, gamma1Shift) {
    const p = Object.assign({}, PRESETS[presetId]);
    p.id = presetId;
    if (gamma1Shift) p.gamma1 = p.gamma1 >> gamma1Shift;
    p.beta = p.tau * p.eta;
    p.m = (p.q - 1) / (2 * p.gamma2); // número de valores posibles de HighBits
    p.useNtt = p.q === Q && p.n === 256;
    p.qbits = Math.ceil(Math.log2(p.q));
    return p;
  }

  // Tamaños codificados según FIPS 204 (pkEncode, skEncode, sigEncode).
  function sizes(p) {
    const bitlen = (x) => Math.floor(Math.log2(x)) + 1;
    const t1bits = bitlen(p.q - 1) - p.d;
    const pk = 32 + (p.n * p.k * t1bits) / 8;
    const zbits = 1 + bitlen(p.gamma1 - 1);
    const sig = p.lambda / 4 + (p.l * p.n * zbits) / 8 + p.omega + p.k;
    const etabits = bitlen(2 * p.eta);
    const sk = 32 + 32 + 64 + (p.n * (p.l + p.k) * etabits) / 8 + (p.n * p.k * p.d) / 8;
    return { pk, sig, sk };
  }

  // Probabilidad de aceptación (aprox.: coeficientes independientes y uniformes) y repeticiones esperadas.
  function theory(p) {
    const pz = Math.pow((2 * (p.gamma1 - p.beta) - 1) / (2 * p.gamma1 - 1), p.n * p.l);
    const pr = Math.pow((2 * (p.gamma2 - p.beta) - 1) / (2 * p.gamma2), p.n * p.k);
    return { pz, pr, accept: pz * pr, reps: 1 / (pz * pr), fipsApprox: Math.exp(p.n * p.beta * (p.l / p.gamma1 + p.k / p.gamma2)) };
  }

  // ---------------------------------------------------------------- aritmética modular
  const mod = (a, q) => { const r = a % q; return r < 0 ? r + q : r; };
  // Representante centrado en (−α/2, α/2] (mod±).
  function modpm(a, alpha) {
    let r = mod(a, alpha);
    if (r > Math.floor(alpha / 2)) r -= alpha;
    return r;
  }
  const mulmod = (a, b, q) => (a * b) % q; // a, b < 2^23 ⇒ producto < 2^46, exacto en double

  // NTT de FIPS 204 (algoritmos 41-42), ζ = 1753.
  const ZETAS = (() => {
    const z = new Array(256);
    const brv8 = (x) => { let r = 0; for (let i = 0; i < 8; i++) r |= ((x >> i) & 1) << (7 - i); return r; };
    const pow = (b, e) => { let r = 1; b %= Q; while (e > 0) { if (e & 1) r = mulmod(r, b, Q); b = mulmod(b, b, Q); e >>= 1; } return r; };
    for (let k = 0; k < 256; k++) z[k] = pow(1753, brv8(k));
    return z;
  })();
  function ntt(a) {
    const w = a.slice();
    let m = 0;
    for (let len = 128; len >= 1; len >>= 1) {
      for (let start = 0; start < 256; start += 2 * len) {
        const z = ZETAS[++m];
        for (let j = start; j < start + len; j++) {
          const t = mulmod(z, w[j + len], Q);
          w[j + len] = mod(w[j] - t, Q);
          w[j] = (w[j] + t) % Q;
        }
      }
    }
    return w;
  }
  function intt(a) {
    const w = a.slice();
    let m = 256;
    for (let len = 1; len < 256; len <<= 1) {
      for (let start = 0; start < 256; start += 2 * len) {
        const z = Q - ZETAS[--m];
        for (let j = start; j < start + len; j++) {
          const t = w[j];
          w[j] = (t + w[j + len]) % Q;
          w[j + len] = mulmod(z, mod(t - w[j + len], Q), Q);
        }
      }
    }
    for (let j = 0; j < 256; j++) w[j] = mulmod(w[j], 8347681, Q); // 256^−1 mod q
    return w;
  }

  // Producto negacíclico de libro (X^n = −1). Coeficientes en [0, q).
  function polyMulSchool(a, b, p) {
    const n = p.n, q = p.q, c = new Array(n).fill(0);
    for (let i = 0; i < n; i++) {
      if (a[i] === 0) continue;
      for (let j = 0; j < n; j++) {
        const k = i + j, t = mulmod(a[i], b[j], q);
        if (k < n) c[k] = (c[k] + t) % q; else c[k - n] = mod(c[k - n] - t, q);
      }
    }
    return c;
  }
  const polyAdd = (a, b, q) => a.map((x, i) => (x + b[i]) % q);
  const polySub = (a, b, q) => a.map((x, i) => mod(x - b[i], q));
  const toModQ = (a, q) => a.map((x) => mod(x, q));
  const normInf = (a, q) => a.reduce((m, x) => Math.max(m, Math.abs(modpm(x, q))), 0);
  const vecNorm = (v, q) => v.reduce((m, a) => Math.max(m, normInf(a, q)), 0);
  const maxAbs = (v) => v.reduce((m, a) => a.reduce((mm, x) => Math.max(mm, Math.abs(x)), m), 0);

  // Â·v. Con NTT, A se guarda ya transformada (como Â en FIPS 204).
  function matVec(A, v, p) {
    const q = p.q;
    if (p.useNtt) {
      const vh = v.map(ntt);
      return A.map((row) => {
        const acc = new Array(256).fill(0);
        row.forEach((a, j) => { const b = vh[j]; for (let i = 0; i < 256; i++) acc[i] = (acc[i] + mulmod(a[i], b[i], Q)) % Q; });
        return intt(acc);
      });
    }
    return A.map((row) => row.reduce((acc, a, j) => polyAdd(acc, polyMulSchool(a, v[j], p), q), new Array(p.n).fill(0)));
  }
  // c (τ coeficientes ±1) por a: producto disperso, O(τ·n).
  function cMul(c, a, p) {
    const n = p.n, q = p.q, out = new Array(n).fill(0);
    for (let i = 0; i < n; i++) {
      if (!c[i]) continue;
      for (let j = 0; j < n; j++) {
        const k = i + j, v = c[i] * a[j];
        if (k < n) out[k] += v; else out[k - n] -= v;
      }
    }
    return out.map((x) => mod(x, q));
  }

  // ---------------------------------------------------------------- muestreo (algoritmos 29-34, adaptados al XOF didáctico)
  function expandA(rho, p) {
    const bits = p.qbits, mask = (1 << bits) - 1, nb = Math.ceil(bits / 8);
    const A = [];
    for (let i = 0; i < p.k; i++) {
      const row = [];
      for (let j = 0; j < p.l; j++) {
        const x = new Xof(concat(rho, u8(j, i)));
        const a = [];
        while (a.length < p.n) {
          let v = 0;
          for (let b = 0; b < nb; b++) v |= x.byte() << (8 * b);
          v &= mask;
          if (v < p.q) a.push(v); // rechazo: uniforme en Z_q
        }
        // FIPS 204 (RejNTTPoly) interpreta estos valores directamente como Â en dominio NTT;
        // aquí se interpretan como A y luego se transforma: la distribución es la misma.
        row.push(a);
      }
      A.push(row);
    }
    return A;
  }
  function expandS(rhoPrime, p) {
    const base = 2 * p.eta + 1, lim = base * Math.floor(256 / base);
    const poly = (r) => {
      const x = new Xof(concat(rhoPrime, u16le(r)));
      const a = [];
      while (a.length < p.n) { const b = x.byte(); if (b < lim) a.push(p.eta - (b % base)); }
      return a;
    };
    const s1 = [], s2 = [];
    for (let r = 0; r < p.l; r++) s1.push(poly(r));
    for (let r = 0; r < p.k; r++) s2.push(poly(p.l + r));
    return { s1, s2 };
  }
  function expandMask(rho2, kappa, p) {
    const bits = Math.log2(p.gamma1) + 1, mask = 2 ** bits - 1; // γ1 potencia de 2
    const y = [];
    for (let r = 0; r < p.l; r++) {
      const x = new Xof(concat(rho2, u16le(kappa + r)));
      const a = [];
      for (let i = 0; i < p.n; i++) { const v = (x.byte() | (x.byte() << 8) | (x.byte() << 16)) & mask; a.push(p.gamma1 - v); }
      y.push(a); // coeficientes en [−γ1 + 1, γ1]
    }
    return y;
  }
  function sampleInBall(ctilde, p) {
    const x = new Xof(ctilde);
    const signs = x.bytes(8);
    const c = new Array(p.n).fill(0);
    const jmask = (1 << Math.ceil(Math.log2(p.n))) - 1;
    let sb = 0;
    for (let i = p.n - p.tau; i < p.n; i++) {
      let j;
      do { j = x.byte() & jmask; } while (j > i);
      c[i] = c[j];
      c[j] = ((signs[sb >> 3] >> (sb & 7)) & 1) ? -1 : 1;
      sb++;
    }
    return c;
  }

  // ---------------------------------------------------------------- descomposición (algoritmos 35-40)
  function power2Round(r, d, q) {
    const rp = mod(r, q), r0 = modpm(rp, 1 << d);
    return [(rp - r0) / (1 << d), r0];
  }
  function decompose(r, p) {
    const rp = mod(r, p.q), alpha = 2 * p.gamma2;
    let r0 = modpm(rp, alpha), r1;
    if (rp - r0 === p.q - 1) { r1 = 0; r0 -= 1; } else r1 = (rp - r0) / alpha;
    return [r1, r0];
  }
  const highBits = (r, p) => decompose(r, p)[0];
  const lowBits = (r, p) => decompose(r, p)[1];
  const makeHint = (z, r, p) => (highBits(r, p) !== highBits(r + z, p) ? 1 : 0);
  function useHint(h, r, p) {
    const [r1, r0] = decompose(r, p);
    if (h === 1 && r0 > 0) return (r1 + 1) % p.m;
    if (h === 1 && r0 <= 0) return mod(r1 - 1, p.m);
    return r1;
  }

  // ---------------------------------------------------------------- codificaciones mínimas (sin empaquetar bits)
  const encPolys = (v) => Uint8Array.from(v.flat().flatMap((x) => [x & 255, (x >> 8) & 255, (x >> 16) & 255]));
  const encW1 = (w1) => Uint8Array.from(w1.flat());
  const pkBytes = (pk) => concat(pk.rho, encPolys(pk.t1));

  // ---------------------------------------------------------------- algoritmos principales
  function randomBytes(n) {
    const b = new Uint8Array(n);
    root.crypto.getRandomValues(b);
    return b;
  }

  function expandAhat(rho, p) {
    const A = expandA(rho, p);
    return p.useNtt ? A.map((row) => row.map(ntt)) : A;
  }

  function keyGen(p, xi) {
    xi = xi || randomBytes(32);
    const seed = H(concat(xi, u8(p.k, p.l)), 128);
    const rho = seed.slice(0, 32), rhoPrime = seed.slice(32, 96), K = seed.slice(96, 128);
    const A = expandAhat(rho, p);
    const { s1, s2 } = expandS(rhoPrime, p);
    const As1 = matVec(A, s1.map((a) => toModQ(a, p.q)), p);
    const t = As1.map((a, i) => polyAdd(a, toModQ(s2[i], p.q), p.q));
    const t1 = [], t0 = [];
    t.forEach((a) => {
      const hi = [], lo = [];
      a.forEach((x) => { const [r1, r0] = power2Round(x, p.d, p.q); hi.push(r1); lo.push(r0); });
      t1.push(hi); t0.push(lo);
    });
    const pk = { rho, t1 };
    const tr = H(pkBytes(pk), 64);
    return { pk, sk: { rho, K, tr, s1, s2, t0 }, A, t, xi };
  }

  // M' = 0 ‖ |ctx| ‖ ctx ‖ M (ML-DSA "puro", algoritmo 2 de FIPS 204).
  function formatMessage(msg, ctx) {
    if (ctx.length > 255) throw new Error('el contexto admite como máximo 255 bytes');
    return concat(u8(0, ctx.length), ctx, msg);
  }

  function signInternal(sk, A, Mp, rnd, p, opts) {
    const q = p.q;
    const mu = H(concat(sk.tr, Mp), 64);
    const rho2 = H(concat(sk.K, rnd, mu), 64);
    const s1q = sk.s1.map((a) => toModQ(a, q)), s2q = sk.s2.map((a) => toModQ(a, q)), t0q = sk.t0.map((a) => toModQ(a, q));
    const attempts = [];
    const maxAttempts = (opts && opts.maxAttempts) || 1000;
    for (let kappa = 0, it = 0; it < maxAttempts; kappa += p.l, it++) {
      const y = expandMask(rho2, kappa, p);
      const w = matVec(A, y.map((a) => toModQ(a, q)), p);
      const w1 = w.map((a) => a.map((x) => highBits(x, p)));
      const ctilde = H(concat(mu, encW1(w1)), p.lambda / 4);
      const c = sampleInBall(ctilde, p);
      const cs1 = s1q.map((a) => cMul(c, a, p));
      const cs2 = s2q.map((a) => cMul(c, a, p));
      const z = y.map((a, i) => a.map((x, j) => modpm(x + cs1[i][j], q))); // representante centrado
      const wcs2 = w.map((a, i) => polySub(a, cs2[i], q));
      const r0 = wcs2.map((a) => a.map((x) => lowBits(x, p)));
      const rec = { kappa, zMax: maxAbs(z), r0Max: maxAbs(r0), ct0Max: null, hints: null, reason: null };
      if (opts && opts.onZ) opts.onZ(z, cs1.map((a) => a.map((x) => modpm(x, q))));
      attempts.push(rec);
      if (rec.zMax >= p.gamma1 - p.beta) { rec.reason = 'z'; continue; }
      if (rec.r0Max >= p.gamma2 - p.beta) { rec.reason = 'r0'; continue; }
      const ct0 = t0q.map((a) => cMul(c, a, p));
      rec.ct0Max = vecNorm(ct0, q);
      // h = MakeHint(−c·t0, w − c·s2 + c·t0)
      const h = ct0.map((a, i) => a.map((x, j) => makeHint(mod(-x, q), (wcs2[i][j] + x) % q, p)));
      rec.hints = h.flat().reduce((s, x) => s + x, 0);
      if (rec.ct0Max >= p.gamma2) { rec.reason = 'ct0'; continue; }
      if (rec.hints > p.omega) { rec.reason = 'h'; continue; }
      rec.reason = 'ok';
      return { sig: { ctilde, z, h }, attempts, trace: { mu, y, w, w1, c, cs1, r0 } };
    }
    return { sig: null, attempts };
  }

  function sign(sk, A, msg, ctx, p, deterministic, opts) {
    const rnd = deterministic ? new Uint8Array(32) : randomBytes(32);
    return signInternal(sk, A, formatMessage(msg, ctx), rnd, p, opts);
  }

  function verify(pk, msg, ctx, sig, p, Acache) {
    const q = p.q, detail = {};
    if (!sig || !sig.z || !sig.h || !sig.ctilde) return { ok: false, why: 'firma mal formada' };
    let Mp;
    try { Mp = formatMessage(msg, ctx); } catch (e) { return { ok: false, why: e.message }; }
    const A = Acache || expandAhat(pk.rho, p);
    const tr = H(pkBytes(pk), 64);
    const mu = H(concat(tr, Mp), 64);
    const c = sampleInBall(sig.ctilde, p);
    detail.zMax = maxAbs(sig.z);
    detail.hints = sig.h.flat().reduce((s, x) => s + x, 0);
    if (detail.zMax >= p.gamma1 - p.beta) return Object.assign(detail, { ok: false, why: '‖z‖∞ ≥ γ1 − β' });
    if (detail.hints > p.omega) return Object.assign(detail, { ok: false, why: 'demasiadas pistas (> ω)' });
    const Az = matVec(A, sig.z.map((a) => toModQ(a, q)), p);
    const ct1 = pk.t1.map((a) => cMul(c, a.map((x) => mod(x * 2 ** p.d, q)), p));
    const wApprox = Az.map((a, i) => polySub(a, ct1[i], q)); // = w − c·s2 + c·t0
    const w1p = wApprox.map((a, i) => a.map((x, j) => useHint(sig.h[i][j], x, p)));
    const ct2 = H(concat(mu, encW1(w1p)), p.lambda / 4);
    detail.ctildePrime = ct2;
    const ok = eqBytes(ct2, sig.ctilde);
    return Object.assign(detail, { ok, why: ok ? 'c̃′ = H(μ ‖ w1′) coincide con c̃' : 'c̃′ ≠ c̃: el compromiso w1′ reconstruido no corresponde' });
  }

  const API = { sha256, H, Xof, PRESETS, makeParams, sizes, theory, mod, modpm, ntt, intt, polyMulSchool, cMul, matVec, expandA, expandAhat, expandS, expandMask, sampleInBall, power2Round, decompose, highBits, lowBits, makeHint, useHint, keyGen, sign, signInternal, verify, formatMessage, utf8, hex, concat };
  if (typeof module !== 'undefined' && module.exports) module.exports = API;
  root.MLDSAToy = API;

  // ================================================================ interfaz
  if (typeof document === 'undefined') return;

  const $ = (id) => document.getElementById(id);
  // Convenciones del curso: coma decimal y espacio fino no separable para los miles.
  const group = (str) => str.replace(/\B(?=(\d{3})+(?!\d))/g, '\u202f');
  const fmt = (x) => (typeof x === 'number' ? (x < 0 ? '−' : '') + group(String(Math.abs(Math.round(x)))) : String(x));
  const fmtDec = (x, d) => { const [i, f] = Math.abs(x).toFixed(d).split('.'); return (x < 0 ? '−' : '') + group(i) + (f ? ',' + f : ''); };
  function el(tag, cls, text) { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }
  function line(out, parts) {
    parts.forEach(([t, c]) => out.appendChild(c ? el('span', c, t) : document.createTextNode(t)));
    out.appendChild(document.createTextNode('\n'));
  }
  const coefs = (a, k) => '[' + a.slice(0, k).join(', ') + (a.length > k ? ', …' : '') + ']';
  const SVGNS = 'http://www.w3.org/2000/svg';
  function svgEl(tag, attrs, text) {
    const e = document.createElementNS(SVGNS, tag);
    for (const k in attrs) e.setAttribute(k, attrs[k]);
    if (text != null) e.textContent = text;
    return e;
  }

  function initMain() {
    const sel = $('mldsa-param');
    if (!sel) return;
    const g1sel = $('mldsa-g1'), msgIn = $('mldsa-msg'), ctxIn = $('mldsa-ctx'), det = $('mldsa-det');
    const bKey = $('mldsa-keygen'), bSign = $('mldsa-sign'), bVer = $('mldsa-verify'), bTamper = $('mldsa-tamper'), tamperSel = $('mldsa-tamper-what'), bBatch = $('mldsa-batch'), bReset = $('mldsa-reset');
    const out = $('mldsa-out'), attemptsBody = $('mldsa-attempts'), statPk = $('mldsa-st-pk'), statSig = $('mldsa-st-sig'), statAtt = $('mldsa-st-att'), statTh = $('mldsa-st-th');
    const batchOut = $('mldsa-batch-out'), histo = $('mldsa-histo');
    let P = null, keys = null, lastSig = null, lastMsg = null, lastCtx = null, busy = false;

    function params() { P = makeParams(sel.value, Number(g1sel.value)); return P; }
    function reset() {
      keys = null; lastSig = null;
      params();
      const s = sizes(P), th = theory(P);
      statPk.textContent = fmt(s.pk) + ' B';
      statSig.textContent = fmt(s.sig) + ' B';
      statTh.textContent = fmtDec(th.reps, 2);
      statAtt.textContent = '—';
      out.textContent = '';
      attemptsBody.textContent = '';
      const tr = el('tr'), td = el('td', 'muted', 'Todavía no se ha firmado nada.'); td.colSpan = 6; tr.appendChild(td); attemptsBody.appendChild(tr);
      bSign.disabled = true; bVer.disabled = true; bTamper.disabled = true; bBatch.disabled = true;
      line(out, [['Parámetros: ' + P.name + ' · q = ' + fmt(P.q) + ' · n = ' + P.n + ' · (k, ℓ) = (' + P.k + ', ' + P.l + ') · η = ' + P.eta + ' · τ = ' + P.tau + ' · β = τη = ' + P.beta, 'dim']]);
      line(out, [['γ1 = ' + fmt(P.gamma1) + ' · γ2 = ' + fmt(P.gamma2) + ' · d = ' + P.d + ' · ω = ' + P.omega, 'dim']]);
      line(out, [['Pulsa «Generar claves».', 'dim']]);
    }

    function doKeyGen() {
      params();
      const t0 = performance.now();
      keys = keyGen(P);
      const ms = performance.now() - t0;
      lastSig = null;
      out.textContent = '';
      const show = P.n <= 16 ? 16 : 8;
      line(out, [['KeyGen', 'hl'], ['  ' + P.name + (P.gamma1 !== PRESETS[P.id].gamma1 ? ' (γ1 modificado)' : '') + ' · ' + fmtDec(ms, 1) + ' ms', 'dim']]);
      line(out, [['ξ     = ' + hex(keys.xi, 16), 'dim']]);
      line(out, [['ρ     = ' + hex(keys.pk.rho, 16) + '   semilla pública que expande A (' + P.k + '×' + P.l + ' polinomios)']]);
      line(out, [['s1[0] = ' + coefs(keys.sk.s1[0], show) + '   coeficientes en [−η, η]']]);
      line(out, [['s2[0] = ' + coefs(keys.sk.s2[0], show)]]);
      line(out, [['t[0]  = ' + coefs(keys.t[0], show) + '   t = A·s1 + s2 (mod q)']]);
      line(out, [['t1[0] = ' + coefs(keys.pk.t1[0], show) + '   Power2Round(t, d): va a la clave pública', 'ok']]);
      line(out, [['t0[0] = ' + coefs(keys.sk.t0[0], show) + '   bits bajos: se quedan en la clave privada', 'dim']]);
      bSign.disabled = false; bBatch.disabled = false; bVer.disabled = true; bTamper.disabled = true;
    }

    const REASON = { z: '‖z‖∞ ≥ γ1 − β', r0: '‖LowBits(w − c·s2)‖∞ ≥ γ2 − β', ct0: '‖c·t0‖∞ ≥ γ2', h: 'pistas > ω', ok: 'aceptada' };
    function renderAttempts(atts) {
      attemptsBody.textContent = '';
      const lim = 40;
      atts.slice(0, lim).forEach((a, i) => {
        const tr = el('tr');
        tr.appendChild(el('td', 'num', String(i + 1)));
        tr.appendChild(el('td', 'num nowrap', fmt(a.zMax) + (a.zMax >= P.gamma1 - P.beta ? ' ✗' : ' ✓')));
        tr.appendChild(el('td', 'num nowrap', a.reason === 'z' ? '—' : fmt(a.r0Max) + (a.r0Max >= P.gamma2 - P.beta ? ' ✗' : ' ✓')));
        tr.appendChild(el('td', 'num nowrap', a.ct0Max == null ? '—' : fmt(a.ct0Max) + (a.ct0Max >= P.gamma2 ? ' ✗' : ' ✓')));
        tr.appendChild(el('td', 'num nowrap', a.hints == null ? '—' : fmt(a.hints) + (a.hints > P.omega ? ' ✗' : ' ✓')));
        tr.appendChild(el('td', null, a.reason === 'ok' ? 'Aceptada' : 'Rechazo: ' + REASON[a.reason]));
        attemptsBody.appendChild(tr);
      });
      if (atts.length > lim) { const tr = el('tr'); const td = el('td', 'muted', '… ' + (atts.length - lim) + ' intentos más'); td.colSpan = 6; tr.appendChild(td); attemptsBody.appendChild(tr); }
    }

    function doSign() {
      if (!keys || busy) return;
      lastMsg = utf8(msgIn.value); lastCtx = utf8(ctxIn.value);
      let res;
      try { res = sign(keys.sk, keys.A, lastMsg, lastCtx, P, det.checked); } catch (e) { out.textContent = ''; line(out, [['Error: ' + e.message, 'bad']]); return; }
      renderAttempts(res.attempts);
      statAtt.textContent = String(res.attempts.length);
      out.textContent = '';
      if (!res.sig) { line(out, [['Se agotaron los intentos sin firma válida.', 'bad']]); return; }
      lastSig = res.sig;
      const t = res.trace, show = P.n <= 16 ? 16 : 8;
      line(out, [['Sign', 'hl'], ['  ' + (det.checked ? 'determinista (rnd = 32 bytes a cero)' : 'con cobertura, «hedged» (rnd aleatorio)') + ' · ' + res.attempts.length + ' intento(s)', 'dim']]);
      line(out, [['μ     = ' + hex(t.mu, 16) + '   H(tr ‖ 0 ‖ |ctx| ‖ ctx ‖ M)', 'dim']]);
      line(out, [['y[0]  = ' + coefs(t.y[0], show) + '   máscara en [−γ1+1, γ1] (intento aceptado)']]);
      line(out, [['w1[0] = ' + coefs(t.w1[0], show) + '   HighBits(A·y), valores en [0, ' + (P.m - 1) + ']']]);
      line(out, [['c̃     = ' + hex(lastSig.ctilde, 16) + '   H(μ ‖ w1)']]);
      const nz = []; t.c.forEach((x, i) => { if (x) nz.push((x > 0 ? '+' : '−') + 'X^' + i); });
      line(out, [['c     = ' + nz.slice(0, 8).join(' ') + (nz.length > 8 ? ' …' : '') + '   (' + nz.length + ' coeficientes ±1)']]);
      line(out, [['z[0]  = ' + coefs(lastSig.z[0], show) + '   z = y + c·s1', 'ok']]);
      const hc = lastSig.h.flat().reduce((s, x) => s + x, 0);
      line(out, [['h     : ' + hc + ' pista(s) a 1 entre ' + P.n * P.k + ' posiciones (máximo ω = ' + P.omega + ')']]);
      line(out, [['Firma σ = (c̃, z, h). Pulsa «Verificar» o prueba una manipulación.', 'dim']]);
      bVer.disabled = false; bTamper.disabled = false;
    }

    function showVerify(label, pk, msg, ctx, sig) {
      const r = verify(pk, msg, ctx, sig, P, pk === keys.pk ? keys.A : null);
      line(out, [['Verify', 'hl'], ['  ' + label, 'dim']]);
      if (r.zMax != null) line(out, [['‖z‖∞ = ' + fmt(r.zMax) + ' (debe ser < ' + fmt(P.gamma1 - P.beta) + ') · pistas = ' + r.hints + ' (≤ ' + P.omega + ')', 'dim']]);
      if (r.ctildePrime) line(out, [['c̃′    = ' + hex(r.ctildePrime, 16), 'dim']]);
      line(out, [[r.ok ? '✓ Firma válida: ' + r.why : '✗ Firma rechazada: ' + r.why, r.ok ? 'ok' : 'bad']]);
    }
    function doVerify() {
      if (!lastSig) return;
      line(out, [['']]);
      showVerify('mensaje y contexto que hay ahora en el formulario', keys.pk, utf8(msgIn.value), utf8(ctxIn.value), lastSig);
    }
    function doTamper() {
      if (!lastSig) return;
      const what = tamperSel.value;
      let pk = keys.pk, msg = lastMsg, ctx = lastCtx, label = '';
      const sig = { ctilde: lastSig.ctilde.slice(), z: lastSig.z.map((a) => a.slice()), h: lastSig.h.map((a) => a.slice()) };
      if (what === 'msg') { msg = concat(lastMsg, utf8('!')); label = 'mensaje con un «!» añadido'; }
      else if (what === 'z') { sig.z[0][3] += 1; label = 'z[0][3] + 1'; }
      else if (what === 'c') { sig.ctilde[0] ^= 1; label = 'un bit de c̃ invertido'; }
      else if (what === 'h') { sig.h[0][5] ^= 1; label = 'una pista invertida'; }
      else if (what === 'ctx') { ctx = concat(lastCtx, utf8('-otro')); label = 'contexto distinto'; }
      else if (what === 'pk') { pk = keyGen(P).pk; label = 'otra clave pública'; }
      line(out, [['']]);
      showVerify('manipulación: ' + label, pk, msg, ctx, sig);
    }

    function doBatch() {
      if (!keys || busy) return;
      busy = true;
      const N = P.n === 256 ? (P.k >= 8 ? 60 : 150) : 400;
      bBatch.disabled = true; bSign.disabled = true; bKey.disabled = true;
      batchOut.textContent = '';
      histo.textContent = '';
      // Ventana del borde de |z|: [γ1 − 3β, γ1 + β), plegando el lado negativo sobre el positivo.
      const lo = P.gamma1 - 3 * P.beta, hi = P.gamma1 + P.beta, bins = 16, width = (hi - lo) / bins;
      const beyond = { all: { pos: 0, neg: 0 }, acc: { pos: 0, neg: 0 } }; // |z_i| ≥ γ1 según el signo relativo de (c·s1)_i
      const hAll = { pos: new Array(bins).fill(0), neg: new Array(bins).fill(0) };
      const hAcc = { pos: new Array(bins).fill(0), neg: new Array(bins).fill(0) };
      const counts = { z: 0, r0: 0, ct0: 0, h: 0, ok: 0 };
      let totalAtt = 0, i = 0, failed = 0;
      const t0 = performance.now();
      function step() {
        const until = performance.now() + 40;
        while (i < N && performance.now() < until) {
          const buf = [];
          const res = sign(keys.sk, keys.A, utf8('mensaje ' + i), new Uint8Array(0), P, false, {
            onZ: (z, cs1) => {
              const loc = { pos: new Array(bins).fill(0), neg: new Array(bins).fill(0), bPos: 0, bNeg: 0 };
              z.forEach((a, r) => a.forEach((x, j) => {
                const v = cs1[r][j];
                if (v === 0) return;
                const s = x >= 0 ? 1 : -1, xx = x * s, vv = v * s;
                if (xx >= P.gamma1) { if (vv > 0) loc.bPos++; else loc.bNeg++; }
                if (xx < lo || xx >= hi) return;
                const b = Math.floor((xx - lo) / width);
                (vv > 0 ? loc.pos : loc.neg)[b]++;
              }));
              buf.push(loc);
            },
          });
          if (!res.sig) failed++;
          res.attempts.forEach((a, k) => {
            if (a.reason) counts[a.reason]++;
            const loc = buf[k];
            for (let b = 0; b < bins; b++) { hAll.pos[b] += loc.pos[b]; hAll.neg[b] += loc.neg[b]; }
            beyond.all.pos += loc.bPos; beyond.all.neg += loc.bNeg;
            if (a.reason === 'ok') {
              for (let b = 0; b < bins; b++) { hAcc.pos[b] += loc.pos[b]; hAcc.neg[b] += loc.neg[b]; }
              beyond.acc.pos += loc.bPos; beyond.acc.neg += loc.bNeg;
            }
          });
          totalAtt += res.attempts.length;
          i++;
        }
        if (i < N) { batchOut.textContent = ''; line(batchOut, [['Firmando… ' + i + ' / ' + N, 'dim']]); requestAnimationFrame(step); return; }
        const ms = performance.now() - t0, th = theory(P);
        batchOut.textContent = '';
        line(batchOut, [[N + ' firmas · ' + totalAtt + ' intentos · ' + fmtDec(ms / N, 1) + ' ms por firma (JavaScript didáctico)', 'hl']]);
        line(batchOut, [['Intentos por firma: observado ' + fmtDec(totalAtt / N, 2) + ' · modelo ' + fmtDec(th.reps, 2) + ' · aproximación de FIPS 204 exp(nβ(ℓ/γ1 + k/γ2)) = ' + fmtDec(th.fipsApprox, 2)]]);
        line(batchOut, [['Rechazos por ‖z‖∞ ≥ γ1 − β:           ' + counts.z + '   (modelo: ' + fmtDec(100 * (1 - th.pz), 1) + ' % de los intentos)']]);
        line(batchOut, [['Rechazos por ‖LowBits‖∞ ≥ γ2 − β:     ' + counts.r0]]);
        line(batchOut, [['Rechazos por ‖c·t0‖∞ ≥ γ2:            ' + counts.ct0]]);
        line(batchOut, [['Rechazos por pistas > ω:              ' + counts.h]]);
        line(batchOut, [['']]);
        line(batchOut, [['Fuga sin rechazo: ' + fmt(beyond.all.pos + beyond.all.neg) + ' coeficientes con |z_i| ≥ γ1 en todos los intentos; en ' + fmt(beyond.all.pos) + ' de ellos (c·s1)_i tiene el signo de z_i y en ' + fmt(beyond.all.neg) + ' el contrario.', 'bad']]);
        line(batchOut, [['  Cada uno revela con certeza el signo de (c·s1)_i, una desigualdad lineal en s1 con c público.', 'dim']]);
        line(batchOut, [['Con rechazo: ' + fmt(beyond.acc.pos + beyond.acc.neg) + ' coeficientes con |z_i| ≥ γ1 en las firmas publicadas.', 'ok']]);
        if (failed) line(batchOut, [[failed + ' firma(s) agotaron el límite de intentos.', 'bad']]);
        drawHisto(hAll, hAcc, lo, width, bins);
        busy = false;
        bBatch.disabled = false; bSign.disabled = false; bKey.disabled = false;
      }
      requestAnimationFrame(step);
    }

    function drawHisto(hAll, hAcc, lo, width, bins) {
      histo.textContent = '';
      const W = 720, Hh = 150, padL = 20, gap = 30, panelW = (W - padL - gap) / 2;
      const svg = svgEl('svg', { viewBox: `0 0 ${W} ${Hh + 90}`, role: 'img', 'aria-labelledby': 'mldsa-histo-t' });
      svg.appendChild(svgEl('title', { id: 'mldsa-histo-t' }, 'Histograma de |z_i| cerca de γ1, separando los coeficientes según el signo relativo de (c·s1)_i, antes y después del rechazo'));
      const thr = P.gamma1 - P.beta;
      [['Todos los intentos (sin rechazo)', hAll], ['Firmas publicadas (con rechazo)', hAcc]].forEach(([title, h], pi) => {
        const x0 = padL + pi * (panelW + gap);
        const max = Math.max(1, ...h.pos, ...h.neg);
        const bw = panelW / bins;
        svg.appendChild(svgEl('text', { x: x0, y: 14, class: 'svg-text' }, title));
        for (let b = 0; b < bins; b++) {
          const hp = (h.pos[b] / max) * Hh, hn = (h.neg[b] / max) * Hh;
          svg.appendChild(svgEl('rect', { x: x0 + b * bw + 0.5, y: 24 + Hh - hp, width: Math.max(bw / 2 - 0.5, 0.5), height: hp, class: 'svg-signal' }));
          svg.appendChild(svgEl('rect', { x: x0 + b * bw + bw / 2, y: 24 + Hh - hn, width: Math.max(bw / 2 - 0.5, 0.5), height: hn, class: 'svg-amber' }));
        }
        const xThr = x0 + ((thr - lo) / (width * bins)) * panelW;
        const xG = x0 + ((P.gamma1 - lo) / (width * bins)) * panelW;
        svg.appendChild(svgEl('line', { x1: xThr, x2: xThr, y1: 20, y2: 24 + Hh, class: 'svg-stroke-ink', 'stroke-dasharray': '4 3' }));
        svg.appendChild(svgEl('line', { x1: xG, x2: xG, y1: 20, y2: 24 + Hh, class: 'svg-line', 'stroke-dasharray': '2 3' }));
        svg.appendChild(svgEl('line', { x1: x0, x2: x0 + panelW, y1: 24 + Hh, y2: 24 + Hh, class: 'svg-line' }));
        svg.appendChild(svgEl('text', { x: xThr, y: 24 + Hh + 14, class: 'svg-muted', 'text-anchor': 'middle' }, 'γ1−β'));
        svg.appendChild(svgEl('text', { x: xG + 4, y: 24 + Hh + 26, class: 'svg-muted', 'text-anchor': 'start' }, 'γ1'));
        svg.appendChild(svgEl('text', { x: x0, y: 24 + Hh + 14, class: 'svg-muted' }, 'γ1−3β'));
      });
      const yl = Hh + 70;
      svg.appendChild(svgEl('rect', { x: padL, y: yl - 9, width: 10, height: 10, class: 'svg-signal' }));
      svg.appendChild(svgEl('text', { x: padL + 14, y: yl, class: 'svg-muted' }, '(c·s1)_i empuja z_i hacia el borde'));
      svg.appendChild(svgEl('rect', { x: padL + 240, y: yl - 9, width: 10, height: 10, class: 'svg-amber' }));
      svg.appendChild(svgEl('text', { x: padL + 254, y: yl, class: 'svg-muted' }, '(c·s1)_i empuja z_i hacia el centro'));
      histo.appendChild(svg);
    }

    sel.addEventListener('change', reset);
    g1sel.addEventListener('change', reset);
    bReset.addEventListener('click', () => { if (!busy) reset(); });
    bKey.addEventListener('click', doKeyGen);
    bSign.addEventListener('click', doSign);
    bVer.addEventListener('click', doVerify);
    bTamper.addEventListener('click', doTamper);
    bBatch.addEventListener('click', doBatch);
    reset();
  }

  // Calculadora de Power2Round / Decompose / pistas.
  function initDecomp() {
    const sel = $('dec-param');
    if (!sel) return;
    const rIn = $('dec-r'), zIn = $('dec-z'), out = $('dec-out');
    function run() {
      const p = makeParams(sel.value, 0);
      const r = mod(Math.round(Number(rIn.value) || 0), p.q), z = Math.round(Number(zIn.value) || 0);
      out.textContent = '';
      const [a1, a0] = power2Round(r, p.d, p.q);
      const [r1, r0] = decompose(r, p);
      line(out, [['q = ' + fmt(p.q) + ' · d = ' + p.d + ' · γ2 = ' + fmt(p.gamma2) + ' (2γ2 = ' + fmt(2 * p.gamma2) + ') · HighBits ∈ [0, ' + (p.m - 1) + ']', 'dim']]);
      line(out, [['Power2Round(' + fmt(r) + ') = (' + a1 + ', ' + a0 + ')   ' + a1 + '·2^' + p.d + ' + (' + a0 + ') = ' + fmt(a1 * 2 ** p.d + a0)]]);
      line(out, [['Decompose(' + fmt(r) + ')   = (' + r1 + ', ' + r0 + ')   ' + r1 + '·' + fmt(2 * p.gamma2) + ' + (' + r0 + ') ≡ ' + fmt(mod(r1 * 2 * p.gamma2 + r0, p.q)) + ' (mod q)']]);
      if (r - modpm(r, 2 * p.gamma2) === p.q - 1) line(out, [['Caso especial: r − r0 = q − 1, así que r1 = 0 y r0 se reduce en 1.', 'hl']]);
      if (Math.abs(z) > p.gamma2) { line(out, [['|z| debe ser ≤ γ2 para que la pista funcione.', 'bad']]); return; }
      const hint = makeHint(mod(z, p.q), r, p), hb = highBits(r + z, p), uh = useHint(hint, r, p);
      line(out, [['HighBits(r + z) = ' + hb + ' · HighBits(r) = ' + r1 + '  ⇒  h = MakeHint(z, r) = ' + hint]]);
      line(out, [['UseHint(h, r) = ' + uh + (uh === hb ? '   ✓ recupera HighBits(r + z) sin conocer z' : '   ✗'), uh === hb ? 'ok' : 'bad']]);
    }
    [sel, rIn, zIn].forEach((e) => e.addEventListener('input', run));
    run();
  }

  // Experimento 1D: por qué hay que rechazar.
  function initLeak() {
    const sIn = $('leak-s');
    if (!sIn) return;
    const sLab = $('leak-s-val'), nSel = $('leak-n'), btn = $('leak-run'), out = $('leak-out'), fig = $('leak-fig');
    const G = 64, B = 8; // γ = 64, β = 8 (didáctico)
    function rndInt(m) { const b = new Uint32Array(1); root.crypto.getRandomValues(b); return b[0] % m; } // m ≤ 128: sesgo despreciable
    function run() {
      const s = Number(sIn.value), N = Number(nSel.value);
      sLab.textContent = String(s);
      const all = [], acc = [];
      for (let i = 0; i < N; i++) {
        const c = rndInt(2) ? 1 : -1, y = rndInt(2 * G) - G + 1; // y ∈ [−γ+1, γ]
        const z = y + c * s;
        all.push(c * z); // público: c y z, luego c·z = c·y + s
        if (Math.abs(z) < G - B) acc.push(c * z);
      }
      const est = (a) => (Math.max(...a) + Math.min(...a) - 1) / 2;
      out.textContent = '';
      line(out, [['Secreto s = ' + s + ' · γ = ' + G + ' · β = ' + B + ' · ' + N + ' firmas simuladas', 'dim']]);
      line(out, [['Sin rechazo: c·z ∈ [' + Math.min(...all) + ', ' + Math.max(...all) + ']  ⇒  ŝ = (máx + mín − 1)/2 = ' + fmtDec(est(all), 1), 'bad']]);
      if (acc.length) line(out, [['Con rechazo (|z| < γ − β): ' + acc.length + ' aceptadas, c·z ∈ [' + Math.min(...acc) + ', ' + Math.max(...acc) + ']  ⇒  ŝ = ' + fmtDec(est(acc), 1), 'ok']]);
      line(out, [['Con rechazo, c·z es uniforme en [−' + (G - B - 1) + ', ' + (G - B - 1) + '] sea cual sea s: la salida no depende del secreto.', 'dim']]);
      fig.textContent = '';
      const W = 720, Hh = 80, svg = svgEl('svg', { viewBox: `0 0 ${W} ${2 * Hh + 84}`, role: 'img', 'aria-labelledby': 'leak-fig-t' });
      svg.appendChild(svgEl('title', { id: 'leak-fig-t' }, 'Histogramas de c·z sin rechazo (desplazado por el secreto) y con rechazo (centrado)'));
      const lo = -G - B, hi = G + B, span = hi - lo + 1, x0 = 90, bw = (W - x0 - 10) / span;
      const xOf = (v) => x0 + (v - lo + 0.5) * bw;
      [['Sin rechazo', all, 0], ['Con rechazo', acc, 1]].forEach(([t, arr, k]) => {
        const cnt = new Array(span).fill(0);
        arr.forEach((v) => cnt[v - lo]++);
        const max = Math.max(1, ...cnt), y0 = 6 + k * (Hh + 40);
        svg.appendChild(svgEl('text', { x: 0, y: y0 + Hh / 2 + 14, class: 'svg-muted' }, t));
        cnt.forEach((c, i) => {
          const h = (c / max) * Hh;
          svg.appendChild(svgEl('rect', { x: x0 + i * bw, y: y0 + 14 + Hh - h, width: Math.max(bw - 0.6, 0.5), height: h, class: k ? 'svg-signal' : 'svg-amber' }));
        });
        svg.appendChild(svgEl('line', { x1: x0, x2: x0 + span * bw, y1: y0 + 14 + Hh, y2: y0 + 14 + Hh, class: 'svg-line' }));
        const marks = k ? [[-(G - B - 1), '−(γ−β−1)'], [0, '0'], [G - B - 1, 'γ−β−1']] : [[-G + 1 + s, '−γ+1+s'], [0, '0'], [G + s, 'γ+s']];
        marks.forEach(([v, lab]) => {
          svg.appendChild(svgEl('line', { x1: xOf(v), x2: xOf(v), y1: y0 + 14, y2: y0 + 14 + Hh, class: 'svg-stroke-ink', 'stroke-dasharray': '3 3' }));
          svg.appendChild(svgEl('text', { x: xOf(v), y: y0 + 14 + Hh + 13, class: 'svg-muted', 'text-anchor': 'middle' }, lab));
        });
      });
      fig.appendChild(svg);
    }
    btn.addEventListener('click', run);
    sIn.addEventListener('input', () => { sLab.textContent = sIn.value; });
    run();
  }

  function init() { initMain(); initDecomp(); initLeak(); }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})(typeof globalThis !== 'undefined' ? globalThis : window);
