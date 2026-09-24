/* ML-KEM paso a paso — demo educativa del Curso de Criptografía Post-Cuántica.
 *
 * Contiene tres piezas independientes, sin dependencias:
 *   1. Keccak / SHA-3 / SHAKE (FIPS 202) en JavaScript puro.
 *   2. MLKEM: implementación completa de FIPS 203 (n = 256, q = 3329, NTT, codificación de bytes
 *      oficial). Se ha comprobado contra los vectores ACVP de NIST, pero NO es de tiempo constante
 *      ni ha sido auditada: úsese solo para aprender.
 *   3. Toy: un K-PKE + transformación FO «de juguete» con n, k, η, du y dv configurables,
 *      multiplicación de polinomios ingenua en Z_q[X]/(X^n + 1) y acceso a todos los valores
 *      intermedios (ruido, redondeo…). Su formato de bytes NO es el de FIPS 203.
 *
 * La interfaz (al final del fichero) solo se ejecuta en el navegador. En Node.js el módulo
 * exporta { Keccak, MLKEM, Toy } para las pruebas.
 */
(function (root) {
  'use strict';

  /* ------------------------------------------------------------------------------------------
   * 1. Keccak-f[1600] con carriles de 64 bits representados como pares (lo, hi) de 32 bits.
   * ---------------------------------------------------------------------------------------- */
  const RC = (function () {
    // Constantes de ronda generadas con el LFSR de FIPS 202 (Alg. 5), para no copiarlas a mano.
    const out = new Uint32Array(48);
    let R = 1;
    const rcBit = () => { const b = R & 1; R <<= 1; if (R & 0x100) R ^= 0x171; return b; };
    for (let i = 0; i < 24; i++) {
      let lo = 0, hi = 0;
      for (let j = 0; j < 7; j++) {
        const pos = (1 << j) - 1;
        if (rcBit()) { if (pos < 32) lo |= (1 << pos); else hi |= (1 << (pos - 32)); }
      }
      out[2 * i] = lo >>> 0; out[2 * i + 1] = hi >>> 0;
    }
    return out;
  })();
  // Desplazamientos ρ indexados como ROT[x + 5y].
  const ROT = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];

  function keccakF(s) {
    const C = new Uint32Array(10), B = new Uint32Array(50);
    for (let round = 0; round < 24; round++) {
      // θ
      for (let x = 0; x < 5; x++) {
        C[2 * x] = s[2 * x] ^ s[2 * x + 10] ^ s[2 * x + 20] ^ s[2 * x + 30] ^ s[2 * x + 40];
        C[2 * x + 1] = s[2 * x + 1] ^ s[2 * x + 11] ^ s[2 * x + 21] ^ s[2 * x + 31] ^ s[2 * x + 41];
      }
      for (let x = 0; x < 5; x++) {
        const x1 = (x + 1) % 5, x4 = (x + 4) % 5;
        const lo = C[2 * x1], hi = C[2 * x1 + 1];
        const dlo = C[2 * x4] ^ ((lo << 1) | (hi >>> 31));
        const dhi = C[2 * x4 + 1] ^ ((hi << 1) | (lo >>> 31));
        for (let y = 0; y < 25; y += 5) { s[2 * (x + y)] ^= dlo; s[2 * (x + y) + 1] ^= dhi; }
      }
      // ρ y π: B[y, 2x + 3y] = rot(A[x, y], r[x, y])
      for (let x = 0; x < 5; x++) {
        for (let y = 0; y < 5; y++) {
          const idx = x + 5 * y, r = ROT[idx];
          let lo = s[2 * idx], hi = s[2 * idx + 1], nlo, nhi;
          if (r === 0) { nlo = lo; nhi = hi; }
          else if (r < 32) { nlo = (lo << r) | (hi >>> (32 - r)); nhi = (hi << r) | (lo >>> (32 - r)); }
          else if (r === 32) { nlo = hi; nhi = lo; }
          else { const t = r - 32; nlo = (hi << t) | (lo >>> (32 - t)); nhi = (lo << t) | (hi >>> (32 - t)); }
          const X = y, Y = (2 * x + 3 * y) % 5, j = X + 5 * Y;
          B[2 * j] = nlo; B[2 * j + 1] = nhi;
        }
      }
      // χ
      for (let y = 0; y < 25; y += 5) {
        for (let x = 0; x < 5; x++) {
          const a = 2 * (x + y), b = 2 * (((x + 1) % 5) + y), c = 2 * (((x + 2) % 5) + y);
          s[a] = B[a] ^ (~B[b] & B[c]);
          s[a + 1] = B[a + 1] ^ (~B[b + 1] & B[c + 1]);
        }
      }
      // ι
      s[0] ^= RC[2 * round]; s[1] ^= RC[2 * round + 1];
    }
  }

  // Esponja con absorción completa y exprimido incremental (necesario para SHAKE128 en SampleNTT).
  function sponge(rate, ds, input) {
    const s = new Uint32Array(50);
    const blk = new Uint8Array(rate);
    const xorBlock = (bytes) => {
      for (let i = 0; i < rate; i += 4) {
        const w = bytes[i] | (bytes[i + 1] << 8) | (bytes[i + 2] << 16) | (bytes[i + 3] << 24);
        s[i >> 2] ^= w;
      }
      keccakF(s);
    };
    let off = 0;
    for (; off + rate <= input.length; off += rate) xorBlock(input.subarray(off, off + rate));
    blk.fill(0); blk.set(input.subarray(off));
    blk[input.length - off] ^= ds; blk[rate - 1] ^= 0x80;
    xorBlock(blk);
    let buf = new Uint8Array(rate), pos = rate, first = true;
    return {
      squeeze(n) {
        const out = new Uint8Array(n);
        for (let i = 0; i < n; i++) {
          if (pos === rate) {
            if (!first) keccakF(s);
            first = false;
            for (let j = 0; j < rate; j++) buf[j] = (s[j >> 2] >>> (8 * (j & 3))) & 0xff;
            pos = 0;
          }
          out[i] = buf[pos++];
        }
        return out;
      },
    };
  }

  const Keccak = {
    sha3_256: (m) => sponge(136, 0x06, m).squeeze(32),
    sha3_512: (m) => sponge(72, 0x06, m).squeeze(64),
    shake128: (m, n) => sponge(168, 0x1f, m).squeeze(n),
    shake256: (m, n) => sponge(136, 0x1f, m).squeeze(n),
    shake128Xof: (m) => sponge(168, 0x1f, m),
  };

  /* ------------------------------------------------------------------------------------------
   * Utilidades comunes
   * ---------------------------------------------------------------------------------------- */
  const Q = 3329;
  const mod = (a, m) => { const r = a % m; return r < 0 ? r + m : r; };
  const concat = (...arrs) => {
    const len = arrs.reduce((a, b) => a + b.length, 0);
    const out = new Uint8Array(len); let o = 0;
    for (const a of arrs) { out.set(a, o); o += a.length; }
    return out;
  };
  const bytesEqual = (a, b) => {
    if (a.length !== b.length) return false;
    let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
    return d === 0;
  };
  const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
  const fromHex = (h) => { const o = new Uint8Array(h.length / 2); for (let i = 0; i < o.length; i++) o[i] = parseInt(h.substr(2 * i, 2), 16); return o; };
  // Compress_d(x) = ⌈(2^d / q)·x⌋ mod 2^d  y  Decompress_d(y) = ⌈(q / 2^d)·y⌋ (FIPS 203, ec. 4.7–4.8)
  const compress = (x, d) => Math.floor((x * (1 << (d + 1)) + Q) / (2 * Q)) % (1 << d);
  const decompress = (y, d) => Math.floor((y * Q * 2 + (1 << d)) / (1 << (d + 1)));
  const centered = (x) => { const r = mod(x, Q); return r > (Q >> 1) ? r - Q : r; };

  // ByteEncode_d / ByteDecode_d (FIPS 203, Alg. 5 y 6) generalizados a n coeficientes.
  function byteEncode(F, d) {
    const n = F.length, out = new Uint8Array(Math.ceil((n * d) / 8));
    let bit = 0;
    for (let i = 0; i < n; i++) {
      let a = F[i];
      for (let j = 0; j < d; j++, bit++) { out[bit >> 3] |= (a & 1) << (bit & 7); a >>= 1; }
    }
    return out;
  }
  function byteDecode(B, d, n) {
    const F = new Int32Array(n), m = d < 12 ? (1 << d) : Q;
    let bit = 0;
    for (let i = 0; i < n; i++) {
      let a = 0;
      for (let j = 0; j < d; j++, bit++) a |= ((B[bit >> 3] >> (bit & 7)) & 1) << j;
      F[i] = a % m;
    }
    return F;
  }
  // SamplePolyCBD_η (Alg. 8): f_i = Σ b[2iη + j] − Σ b[2iη + η + j]
  function samplePolyCBD(B, eta, n) {
    const f = new Int32Array(n);
    const bit = (k) => (B[k >> 3] >> (k & 7)) & 1;
    for (let i = 0; i < n; i++) {
      let x = 0, y = 0;
      for (let j = 0; j < eta; j++) { x += bit(2 * i * eta + j); y += bit(2 * i * eta + eta + j); }
      f[i] = mod(x - y, Q);
    }
    return f;
  }
  const prf = (eta, s, b, n) => Keccak.shake256(concat(s, Uint8Array.of(b)), (2 * eta * n) / 8);
  // Muestreo uniforme por rechazo con SHAKE128 (Alg. 7): dos candidatos de 12 bits por cada 3 bytes.
  function sampleUniform(seed34, n) {
    const xof = Keccak.shake128Xof(seed34), a = new Int32Array(n);
    let j = 0;
    while (j < n) {
      const C = xof.squeeze(3);
      const d1 = C[0] + 256 * (C[1] & 15), d2 = (C[1] >> 4) + 16 * C[2];
      if (d1 < Q) a[j++] = d1;
      if (d2 < Q && j < n) a[j++] = d2;
    }
    return a;
  }
  const G = (x) => { const h = Keccak.sha3_512(x); return [h.slice(0, 32), h.slice(32)]; };
  const H = (x) => Keccak.sha3_256(x);
  const J = (x) => Keccak.shake256(x, 32);

  /* ------------------------------------------------------------------------------------------
   * 2. ML-KEM según FIPS 203 (n = 256)
   * ---------------------------------------------------------------------------------------- */
  const PARAMS = {
    'ML-KEM-512': { k: 2, eta1: 3, eta2: 2, du: 10, dv: 4 },
    'ML-KEM-768': { k: 3, eta1: 2, eta2: 2, du: 10, dv: 4 },
    'ML-KEM-1024': { k: 4, eta1: 2, eta2: 2, du: 11, dv: 5 },
  };
  const N = 256;
  const bitRev7 = (i) => { let r = 0; for (let b = 0; b < 7; b++) r |= ((i >> b) & 1) << (6 - b); return r; };
  const powmod = (b, e) => { let r = 1; b %= Q; while (e > 0) { if (e & 1) r = (r * b) % Q; b = (b * b) % Q; e >>= 1; } return r; };
  const ZETAS = Int32Array.from({ length: 128 }, (_, i) => powmod(17, bitRev7(i)));
  const GAMMAS = Int32Array.from({ length: 128 }, (_, i) => powmod(17, 2 * bitRev7(i) + 1));

  function ntt(fIn) { // Alg. 9
    const f = Int32Array.from(fIn); let i = 1;
    for (let len = 128; len >= 2; len >>= 1) {
      for (let start = 0; start < 256; start += 2 * len) {
        const z = ZETAS[i++];
        for (let j = start; j < start + len; j++) {
          const t = (z * f[j + len]) % Q;
          f[j + len] = mod(f[j] - t, Q); f[j] = (f[j] + t) % Q;
        }
      }
    }
    return f;
  }
  function nttInv(fIn) { // Alg. 10
    const f = Int32Array.from(fIn); let i = 127;
    for (let len = 2; len <= 128; len <<= 1) {
      for (let start = 0; start < 256; start += 2 * len) {
        const z = ZETAS[i--];
        for (let j = start; j < start + len; j++) {
          const t = f[j];
          f[j] = (t + f[j + len]) % Q;
          f[j + len] = mod(z * mod(f[j + len] - t, Q), Q);
        }
      }
    }
    for (let j = 0; j < 256; j++) f[j] = (f[j] * 3303) % Q;
    return f;
  }
  function multiplyNTTs(f, g) { // Alg. 11 y 12
    const h = new Int32Array(256);
    for (let i = 0; i < 128; i++) {
      const a0 = f[2 * i], a1 = f[2 * i + 1], b0 = g[2 * i], b1 = g[2 * i + 1];
      h[2 * i] = (a0 * b0 + ((a1 * b1) % Q) * GAMMAS[i]) % Q;
      h[2 * i + 1] = (a0 * b1 + a1 * b0) % Q;
    }
    return h;
  }
  const addPoly = (a, b) => a.map((x, i) => (x + b[i]) % Q);
  const subPoly = (a, b) => a.map((x, i) => mod(x - b[i], Q));

  function genMatrixNTT(rho, k) {
    const A = [];
    for (let i = 0; i < k; i++) {
      A.push([]);
      for (let j = 0; j < k; j++) A[i].push(sampleUniform(concat(rho, Uint8Array.of(j, i)), N));
    }
    return A;
  }

  function kpkeKeyGen(p, d) { // Alg. 13
    const [rho, sigma] = G(concat(d, Uint8Array.of(p.k)));
    const A = genMatrixNTT(rho, p.k);
    let nonce = 0;
    const s = [], e = [];
    for (let i = 0; i < p.k; i++) s.push(samplePolyCBD(prf(p.eta1, sigma, nonce++, N), p.eta1, N));
    for (let i = 0; i < p.k; i++) e.push(samplePolyCBD(prf(p.eta1, sigma, nonce++, N), p.eta1, N));
    const sh = s.map(ntt), eh = e.map(ntt);
    const th = [];
    for (let i = 0; i < p.k; i++) {
      let acc = new Int32Array(N);
      for (let j = 0; j < p.k; j++) acc = addPoly(acc, multiplyNTTs(A[i][j], sh[j]));
      th.push(addPoly(acc, eh[i]));
    }
    const ek = concat(...th.map((t) => byteEncode(t, 12)), rho);
    const dk = concat(...sh.map((t) => byteEncode(t, 12)));
    return { ek, dk };
  }

  function kpkeEncrypt(p, ek, m, r) { // Alg. 14
    const k = p.k, th = [];
    for (let i = 0; i < k; i++) th.push(byteDecode(ek.subarray(384 * i, 384 * (i + 1)), 12, N));
    const rho = ek.subarray(384 * k, 384 * k + 32);
    const A = genMatrixNTT(rho, k);
    let nonce = 0;
    const y = [], e1 = [];
    for (let i = 0; i < k; i++) y.push(samplePolyCBD(prf(p.eta1, r, nonce++, N), p.eta1, N));
    for (let i = 0; i < k; i++) e1.push(samplePolyCBD(prf(p.eta2, r, nonce++, N), p.eta2, N));
    const e2 = samplePolyCBD(prf(p.eta2, r, nonce++, N), p.eta2, N);
    const yh = y.map(ntt);
    const u = [];
    for (let i = 0; i < k; i++) {
      let acc = new Int32Array(N);
      for (let j = 0; j < k; j++) acc = addPoly(acc, multiplyNTTs(A[j][i], yh[j])); // Âᵀ
      u.push(addPoly(nttInv(acc), e1[i]));
    }
    const mu = byteDecode(m, 1, N).map((b) => decompress(b, 1));
    let acc = new Int32Array(N);
    for (let j = 0; j < k; j++) acc = addPoly(acc, multiplyNTTs(th[j], yh[j]));
    const v = addPoly(addPoly(nttInv(acc), e2), mu);
    const c1 = concat(...u.map((ui) => byteEncode(ui.map((x) => compress(x, p.du)), p.du)));
    const c2 = byteEncode(v.map((x) => compress(x, p.dv)), p.dv);
    return concat(c1, c2);
  }

  function kpkeDecrypt(p, dk, c) { // Alg. 15
    const k = p.k, lenC1 = 32 * p.du * k;
    const u = [];
    for (let i = 0; i < k; i++) {
      u.push(byteDecode(c.subarray(32 * p.du * i, 32 * p.du * (i + 1)), p.du, N).map((x) => decompress(x, p.du)));
    }
    const v = byteDecode(c.subarray(lenC1), p.dv, N).map((x) => decompress(x, p.dv));
    let acc = new Int32Array(N);
    for (let i = 0; i < k; i++) acc = addPoly(acc, multiplyNTTs(byteDecode(dk.subarray(384 * i, 384 * (i + 1)), 12, N), ntt(u[i])));
    const w = subPoly(v, nttInv(acc));
    return byteEncode(w.map((x) => compress(x, 1)), 1);
  }

  const randomBytes = (n) => {
    const b = new Uint8Array(n);
    const c = (typeof globalThis !== 'undefined' && globalThis.crypto) ? globalThis.crypto : null;
    if (c && c.getRandomValues) c.getRandomValues(b);
    else throw new Error('No hay generador aleatorio criptográfico disponible');
    return b;
  };

  const MLKEM = {
    PARAMS,
    sizes(name) {
      const p = PARAMS[name];
      return { ek: 384 * p.k + 32, dk: 768 * p.k + 96, ct: 32 * (p.du * p.k + p.dv), ss: 32 };
    },
    keyGenInternal(name, d, z) { // Alg. 16
      const p = PARAMS[name];
      const { ek, dk } = kpkeKeyGen(p, d);
      return { ek, dk: concat(dk, ek, H(ek), z) };
    },
    encapsInternal(name, ek, m) { // Alg. 17
      const p = PARAMS[name];
      const [K, r] = G(concat(m, H(ek)));
      return { K, c: kpkeEncrypt(p, ek, m, r) };
    },
    decapsInternal(name, dk, c) { // Alg. 18
      const p = PARAMS[name], k = p.k;
      const dkPKE = dk.subarray(0, 384 * k), ekPKE = dk.subarray(384 * k, 768 * k + 32);
      const h = dk.subarray(768 * k + 32, 768 * k + 64), z = dk.subarray(768 * k + 64, 768 * k + 96);
      const m2 = kpkeDecrypt(p, dkPKE, c);
      const [K2, r2] = G(concat(m2, h));
      const Kbar = J(concat(z, c));
      const c2 = kpkeEncrypt(p, ekPKE, m2, r2);
      return bytesEqual(c, c2) ? K2 : Kbar;
    },
    // Comprobaciones de entrada de FIPS 203 §7.2 y §7.3
    checkEncapsulationKey(name, ek) {
      const k = PARAMS[name].k;
      if (ek.length !== 384 * k + 32) return false;
      for (let i = 0; i < k; i++) {
        const seg = ek.subarray(384 * i, 384 * (i + 1));
        if (!bytesEqual(byteEncode(byteDecode(seg, 12, N), 12), seg)) return false;
      }
      return true;
    },
    checkDecapsulationKey(name, dk) {
      const k = PARAMS[name].k;
      if (dk.length !== 768 * k + 96) return false;
      return bytesEqual(H(dk.subarray(384 * k, 768 * k + 32)), dk.subarray(768 * k + 32, 768 * k + 64));
    },
    keyGen(name) { return this.keyGenInternal(name, randomBytes(32), randomBytes(32)); },
    encaps(name, ek) {
      if (!this.checkEncapsulationKey(name, ek)) throw new Error('Clave de encapsulamiento no válida');
      return this.encapsInternal(name, ek, randomBytes(32));
    },
    decaps(name, dk, c) {
      if (c.length !== this.sizes(name).ct) throw new Error('Longitud de cifrado incorrecta');
      if (!this.checkDecapsulationKey(name, dk)) throw new Error('Clave de desencapsulamiento no válida');
      return this.decapsInternal(name, dk, c);
    },
  };

  /* ------------------------------------------------------------------------------------------
   * 3. Modelo de juguete: mismo esquema, n pequeño y todos los intermedios a la vista.
   *    Diferencias con FIPS 203: multiplicación ingenua en el dominio de coeficientes (sin NTT),
   *    A se muestrea directamente como coeficientes, y η, du, dv se pueden forzar a voluntad.
   * ---------------------------------------------------------------------------------------- */
  function polyMulNegacyclic(a, b) { // en Z_q[X]/(X^n + 1)
    const n = a.length, c = new Array(n).fill(0);
    for (let i = 0; i < n; i++) {
      if (a[i] === 0) continue;
      for (let j = 0; j < n; j++) {
        const t = a[i] * b[j], idx = i + j;
        if (idx < n) c[idx] += t; else c[idx - n] -= t;
      }
    }
    return Int32Array.from(c, (x) => mod(x, Q));
  }
  const matVec = (A, v, transpose) => {
    const k = v.length, n = v[0].length, out = [];
    for (let i = 0; i < k; i++) {
      let acc = new Int32Array(n);
      for (let j = 0; j < k; j++) acc = addPoly(acc, polyMulNegacyclic(transpose ? A[j][i] : A[i][j], v[j]));
      out.push(acc);
    }
    return out;
  };
  const dot = (a, b) => {
    let acc = new Int32Array(a[0].length);
    for (let j = 0; j < a.length; j++) acc = addPoly(acc, polyMulNegacyclic(a[j], b[j]));
    return acc;
  };

  const Toy = {
    Q, compress, decompress, centered, polyMulNegacyclic,
    // p = { n, k, eta1, eta2, du, dv }
    keyGen(p, d) {
      d = d || randomBytes(32);
      const [rho, sigma] = G(concat(d, Uint8Array.of(p.k, p.n & 0xff)));
      const A = [];
      for (let i = 0; i < p.k; i++) { A.push([]); for (let j = 0; j < p.k; j++) A[i].push(sampleUniform(concat(rho, Uint8Array.of(j, i)), p.n)); }
      let nonce = 0; const s = [], e = [];
      for (let i = 0; i < p.k; i++) s.push(samplePolyCBD(prf(p.eta1, sigma, nonce++, p.n), p.eta1, p.n));
      for (let i = 0; i < p.k; i++) e.push(samplePolyCBD(prf(p.eta1, sigma, nonce++, p.n), p.eta1, p.n));
      const As = matVec(A, s, false);
      const t = As.map((x, i) => addPoly(x, e[i]));
      const ek = concat(...t.map((ti) => byteEncode(ti, 12)), rho);
      const dkPKE = concat(...s.map((si) => byteEncode(si, 12)));
      return { rho, A, s, e, t, ek, dkPKE };
    },
    parseEk(p, ek) {
      const L = (12 * p.n) / 8, t = [];
      for (let i = 0; i < p.k; i++) t.push(byteDecode(ek.subarray(L * i, L * (i + 1)), 12, p.n));
      const rho = ek.subarray(L * p.k, L * p.k + 32), A = [];
      for (let i = 0; i < p.k; i++) { A.push([]); for (let j = 0; j < p.k; j++) A[i].push(sampleUniform(concat(rho, Uint8Array.of(j, i)), p.n)); }
      return { t, A };
    },
    encrypt(p, ek, m, r) {
      const { t, A } = this.parseEk(p, ek);
      let nonce = 0; const y = [], e1 = [];
      for (let i = 0; i < p.k; i++) y.push(samplePolyCBD(prf(p.eta1, r, nonce++, p.n), p.eta1, p.n));
      for (let i = 0; i < p.k; i++) e1.push(samplePolyCBD(prf(p.eta2, r, nonce++, p.n), p.eta2, p.n));
      const e2 = samplePolyCBD(prf(p.eta2, r, nonce++, p.n), p.eta2, p.n);
      const u = matVec(A, y, true).map((x, i) => addPoly(x, e1[i]));
      const mu = byteDecode(m, 1, p.n).map((b) => decompress(b, 1));
      const v = addPoly(addPoly(dot(t, y), e2), mu);
      const uc = u.map((ui) => ui.map((x) => compress(x, p.du)));
      const vc = v.map((x) => compress(x, p.dv));
      const c = concat(...uc.map((x) => byteEncode(x, p.du)), byteEncode(vc, p.dv));
      return { y, e1, e2, mu, u, v, uc, vc, c };
    },
    decrypt(p, dkPKE, c) {
      const L = (12 * p.n) / 8, Lu = (p.du * p.n) / 8, s = [], u2 = [];
      for (let i = 0; i < p.k; i++) s.push(byteDecode(dkPKE.subarray(L * i, L * (i + 1)), 12, p.n));
      for (let i = 0; i < p.k; i++) u2.push(byteDecode(c.subarray(Lu * i, Lu * (i + 1)), p.du, p.n).map((x) => decompress(x, p.du)));
      const v2 = byteDecode(c.subarray(Lu * p.k), p.dv, p.n).map((x) => decompress(x, p.dv));
      const su = dot(s, u2);
      const w = subPoly(v2, su);
      const bits = w.map((x) => compress(x, 1));
      return { u2, v2, su, w, bits, m: byteEncode(bits, 1) };
    },
    // Una ejecución completa de K-PKE con todos los intermedios y el ruido de descifrado.
    run(p, m) {
      const kg = this.keyGen(p);
      m = m || randomBytes(p.n / 8);
      const enc = this.encrypt(p, kg.ek, m, randomBytes(32));
      const dec = this.decrypt(p, kg.dkPKE, enc.c);
      const noise = Array.from(dec.w, (x, i) => centered(x - enc.mu[i]));
      const mBits = byteDecode(m, 1, p.n);
      const errors = Array.from(dec.bits).reduce((acc, b, i) => acc + (b !== mBits[i] ? 1 : 0), 0);
      return { kg, enc, dec, m, mBits, noise, errors };
    },
    sizes(p) {
      return { ek: (12 * p.n * p.k) / 8 + 32, dkPKE: (12 * p.n * p.k) / 8, ct: (p.n * (p.du * p.k + p.dv)) / 8 };
    },
    // Transformación FO con rechazo implícito, idéntica en estructura a los Alg. 16–18.
    kemKeyGen(p) {
      const kg = this.keyGen(p), z = randomBytes(32);
      return { ek: kg.ek, dk: { dkPKE: kg.dkPKE, ek: kg.ek, h: H(kg.ek), z } };
    },
    kemEncaps(p, ek, m) {
      m = m || randomBytes(p.n / 8);
      const [K, r] = G(concat(m, H(ek)));
      return { K, c: this.encrypt(p, ek, m, r).c, m };
    },
    kemDecaps(p, dk, c) {
      const dec = this.decrypt(p, dk.dkPKE, c);
      const [K2, r2] = G(concat(dec.m, dk.h));
      const Kbar = J(concat(dk.z, c));
      const c2 = this.encrypt(p, dk.ek, dec.m, r2).c;
      const ok = bytesEqual(c, c2);
      return { K: ok ? K2 : Kbar, accepted: ok, m2: dec.m, Kprime: K2, Kbar, c2 };
    },
  };

  const api = { Keccak, MLKEM, Toy, util: { toHex, fromHex, concat, bytesEqual, byteEncode, byteDecode, randomBytes } };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.MLKEMDemo = api;

  /* ------------------------------------------------------------------------------------------
   * Interfaz (solo navegador)
   * ---------------------------------------------------------------------------------------- */
  if (typeof document === 'undefined') return;

  const SVGNS = 'http://www.w3.org/2000/svg';
  const $ = (id) => document.getElementById(id);
  const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
  const svgEl = (tag, attrs, text) => {
    const e = document.createElementNS(SVGNS, tag);
    for (const k in attrs) e.setAttribute(k, attrs[k]);
    if (text != null) e.textContent = text;
    return e;
  };
  const clear = (node) => { while (node.firstChild) node.removeChild(node.firstChild); };
  const fmt = (x) => String(x).replace('.', ',');
  const polyStr = (f, max) => {
    const arr = Array.from(f).slice(0, max).map((x) => centered(x));
    return '[' + arr.join(', ') + (f.length > max ? ', …' : '') + ']';
  };
  const line = (out, text, cls) => { const s = el('span', cls || null, text); out.appendChild(s); out.appendChild(document.createTextNode('\n')); };

  function readParams() {
    const n = parseInt($('mk-n').value, 10), k = parseInt($('mk-k').value, 10);
    const eta1 = parseInt($('mk-eta1').value, 10), eta2 = parseInt($('mk-eta2').value, 10);
    const du = parseInt($('mk-du').value, 10), dv = parseInt($('mk-dv').value, 10);
    $('mk-eta1-v').textContent = eta1; $('mk-eta2-v').textContent = eta2;
    return { n, k, eta1, eta2, du, dv };
  }

  // Círculo Z_q: 0 arriba, q/2 abajo; la región verde es la que se descodifica como el bit enviado.
  function drawCircle(svg, run) {
    clear(svg);
    svg.appendChild(svgEl('title', { id: svg.id + '-t' }, 'Coeficientes de w sobre el círculo Z_q y zonas de decisión'));
    const cx = 150, cy = 150, R = 110;
    const arc = (a0, a1, cls) => {
      const p = (a) => [cx + R * Math.sin(a), cy - R * Math.cos(a)];
      const [x0, y0] = p(a0), [x1, y1] = p(a1);
      const large = (a1 - a0) > Math.PI ? 1 : 0;
      svg.appendChild(svgEl('path', { d: `M ${x0} ${y0} A ${R} ${R} 0 ${large} 1 ${x1} ${y1}`, class: cls, 'stroke-width': 14, fill: 'none' }));
    };
    arc(-Math.PI / 2, Math.PI / 2, 'svg-stroke-signal');       // se descodifica como 0
    arc(Math.PI / 2, 3 * Math.PI / 2, 'svg-stroke-amber');     // se descodifica como 1
    svg.appendChild(svgEl('text', { x: cx, y: cy - R - 16, 'text-anchor': 'middle', class: 'svg-text' }, '0'));
    svg.appendChild(svgEl('text', { x: cx, y: cy + R + 26, 'text-anchor': 'middle', class: 'svg-text' }, '⌈q/2⌋ = 1665'));
    svg.appendChild(svgEl('text', { x: cx + R + 12, y: cy + 4, class: 'svg-muted' }, 'q/4'));
    svg.appendChild(svgEl('text', { x: cx - R - 34, y: cy + 4, class: 'svg-muted' }, '3q/4'));
    svg.appendChild(svgEl('text', { x: cx, y: cy - 8, 'text-anchor': 'middle', class: 'svg-muted' }, 'verde → 0'));
    svg.appendChild(svgEl('text', { x: cx, y: cy + 10, 'text-anchor': 'middle', class: 'svg-muted' }, 'ámbar → 1'));
    const w = run.dec.w, lim = Math.min(w.length, 256);
    for (let i = 0; i < lim; i++) {
      const a = (2 * Math.PI * w[i]) / Q;
      const r = R - 22 - (i % 4) * 6;
      const bad = run.dec.bits[i] !== run.mBits[i];
      svg.appendChild(svgEl('circle', {
        cx: cx + r * Math.sin(a), cy: cy - r * Math.cos(a), r: bad ? 5 : 3.2,
        class: bad ? 'svg-danger' : (run.mBits[i] ? 'svg-amber' : 'svg-signal'),
      }));
    }
  }

  // Histograma del ruido (w − ⌈q/2⌋·m) con las fronteras de decisión ±q/4.
  function drawHistogram(svg, samples, titleText) {
    clear(svg);
    svg.appendChild(svgEl('title', { id: svg.id + '-t' }, titleText));
    const W = 600, Hh = 190, pad = 30, bins = 60, lo = -Q / 2, hi = Q / 2;
    const counts = new Array(bins).fill(0);
    for (const x of samples) { const b = Math.min(bins - 1, Math.floor(((x - lo) / (hi - lo)) * bins)); counts[b]++; }
    const max = Math.max(1, ...counts);
    const bw = (W - 2 * pad) / bins;
    svg.appendChild(svgEl('line', { x1: pad, y1: Hh - pad, x2: W - pad, y2: Hh - pad, class: 'svg-line' }));
    counts.forEach((c, i) => {
      if (!c) return;
      const h = Math.max(1, ((Hh - 2 * pad) * Math.sqrt(c)) / Math.sqrt(max));
      const center = lo + (i + 0.5) * ((hi - lo) / bins);
      const cls = Math.abs(center) > Q / 4 ? 'svg-danger' : 'svg-signal';
      svg.appendChild(svgEl('rect', { x: pad + i * bw + 0.5, y: Hh - pad - h, width: bw - 1, height: h, class: cls }));
    });
    const xOf = (v) => pad + ((v - lo) / (hi - lo)) * (W - 2 * pad);
    for (const v of [-Q / 4, Q / 4]) {
      svg.appendChild(svgEl('line', { x1: xOf(v), y1: 12, x2: xOf(v), y2: Hh - pad, class: 'svg-stroke-amber', 'stroke-dasharray': '4 3' }));
    }
    svg.appendChild(svgEl('text', { x: xOf(Q / 4) + 4, y: 22, class: 'svg-muted' }, '+q/4 ≈ 832'));
    svg.appendChild(svgEl('text', { x: xOf(-Q / 4) - 70, y: 22, class: 'svg-muted' }, '−q/4 ≈ −832'));
    for (const v of [-1664, -832, 0, 832, 1664]) {
      svg.appendChild(svgEl('text', { x: xOf(v), y: Hh - pad + 16, 'text-anchor': 'middle', class: 'svg-muted' }, String(v)));
    }
    svg.appendChild(svgEl('text', { x: W - pad, y: Hh - 2, 'text-anchor': 'end', class: 'svg-muted' }, 'ruido de descifrado (altura ∝ √frecuencia)'));
  }

  function statBox(row, value, label) {
    const d = el('div', 'stat'); d.appendChild(el('b', null, value)); d.appendChild(el('small', null, label)); row.appendChild(d);
  }

  function renderRun() {
    const p = readParams();
    const run = Toy.run(p);
    const maxNoise = Math.max(...run.noise.map(Math.abs));
    const sz = Toy.sizes(p);
    const row = $('mk-stats'); clear(row);
    statBox(row, `${sz.ek} B`, 'ek (formato de juguete)');
    statBox(row, `${sz.ct} B`, 'cifrado c');
    statBox(row, String(maxNoise), 'máx. |ruido|');
    statBox(row, String(Math.floor(Q / 4) - maxNoise), 'margen hasta q/4');
    statBox(row, `${run.errors} / ${p.n}`, 'bits erróneos');

    drawCircle($('mk-circle'), run);
    drawHistogram($('mk-hist1'), run.noise, 'Histograma del ruido de esta ejecución');

    // Tabla de los primeros coeficientes
    const tb = $('mk-coefs'); clear(tb);
    const lim = Math.min(p.n, 16);
    for (let i = 0; i < lim; i++) {
      const tr = el('tr');
      const bad = run.dec.bits[i] !== run.mBits[i];
      [i, run.mBits[i], run.dec.w[i], run.noise[i], run.dec.bits[i]].forEach((v, j) => {
        const td = el('td', 'num', String(v));
        if (j === 4 && bad) td.textContent = v + ' ✗';
        tr.appendChild(td);
      });
      tb.appendChild(tr);
    }

    const out = $('mk-log'); clear(out);
    const s = run.kg, e = run.enc;
    line(out, `Parámetros: n=${p.n}, k=${p.k}, q=${Q}, η1=${p.eta1}, η2=${p.eta2}, du=${p.du}, dv=${p.dv}`, 'hl');
    line(out, '── KeyGen ──', 'dim');
    line(out, `ρ = ${toHex(s.rho).slice(0, 32)}…   (A se expande desde ρ con SHAKE128)`);
    line(out, `A[0][0] = ${polyStr(s.A[0][0], 8)}`);
    line(out, `s[0]    = ${polyStr(s.s[0], 16)}   ← CBD(η1), coeficientes pequeños`);
    line(out, `e[0]    = ${polyStr(s.e[0], 16)}`);
    line(out, `t[0] = (A·s + e)[0] = ${polyStr(s.t[0], 8)}   ← parece uniforme (MLWE)`);
    line(out, '── Encrypt(ek, m, r) ──', 'dim');
    line(out, `m       = ${run.mBits.slice(0, 32).join('')}${p.n > 32 ? '…' : ''}`);
    line(out, `y[0]    = ${polyStr(e.y[0], 16)}   e2 = ${polyStr(e.e2, 8)}`);
    line(out, `u[0] = (Aᵀy + e1)[0] = ${polyStr(e.u[0], 8)}`);
    line(out, `v = tᵀy + e2 + ⌈q/2⌋·m = ${polyStr(e.v, 8)}`);
    line(out, `Compress_du(u[0]) = [${Array.from(e.uc[0]).slice(0, 8).join(', ')}, …]   Compress_dv(v) = [${Array.from(e.vc).slice(0, 8).join(', ')}, …]`);
    line(out, '── Decrypt(dk, c) ──', 'dim');
    line(out, `w = v' − sᵀu' = ${polyStr(run.dec.w, 8)}`);
    line(out, `ruido = w − ⌈q/2⌋·m = eᵀy + e2 − sᵀe1 + (errores de compresión) = ${polyStr(run.noise, 12)}`);
    line(out, `m' = Compress_1(w) = ${Array.from(run.dec.bits).slice(0, 32).join('')}${p.n > 32 ? '…' : ''}`);
    line(out, run.errors === 0 ? '✓ m\' = m: descifrado correcto' : `✗ ${run.errors} bit(s) erróneos: fallo de descifrado`, run.errors === 0 ? 'ok' : 'bad');
  }

  let trialJob = 0;
  function runTrials() {
    const p = readParams();
    const total = parseInt($('mk-trials').value, 10);
    const job = ++trialJob;
    const all = []; let done = 0, fails = 0, badBits = 0, maxAbs = 0;
    const out = $('mk-trials-out'); clear(out);
    const bar = $('mk-trials-bar');
    const step = () => {
      if (job !== trialJob) return;
      const t0 = performance.now();
      while (done < total && performance.now() - t0 < 40) {
        const r = Toy.run(p);
        for (const x of r.noise) { if (all.length < 200000) all.push(x); const a = Math.abs(x); if (a > maxAbs) maxAbs = a; }
        if (r.errors) { fails++; badBits += r.errors; }
        done++;
      }
      bar.style.width = `${(100 * done) / total}%`;
      if (done < total) { setTimeout(step, 0); return; }
      drawHistogram($('mk-hist2'), all, 'Histograma acumulado del ruido');
      clear(out);
      line(out, `${done} ejecuciones de K-PKE con n=${p.n}, k=${p.k}, η1=${p.eta1}, η2=${p.eta2}, du=${p.du}, dv=${p.dv}`, 'hl');
      line(out, `Descifrados fallidos: ${fails} (${fmt(((100 * fails) / done).toFixed(2))} %)   bits erróneos: ${badBits} de ${done * p.n}`, fails ? 'bad' : 'ok');
      line(out, `Máximo |ruido| observado: ${maxAbs}   (frontera: q/4 ≈ 832)`);
      if (!fails) line(out, 'Con parámetros reales la probabilidad de fallo es ≤ 2^−138,8: nunca la observará empíricamente.', 'dim');
    };
    step();
  }

  // Transformación FO con los mismos parámetros del modelo de juguete
  let foState = null;
  function foRun(tamper) {
    const p = readParams();
    const out = $('mk-fo-out'); clear(out);
    if (!foState || !tamper) {
      const kp = Toy.kemKeyGen(p);
      const enc = Toy.kemEncaps(p, kp.ek);
      foState = { p, kp, enc };
    }
    const { kp, enc } = foState;
    let c = enc.c;
    line(out, `Encaps: m aleatorio → (K, r) = G(m ‖ H(ek)) → c = Encrypt(ek, m, r)`, 'dim');
    line(out, `K (emisor)      = ${toHex(enc.K)}`);
    if (tamper) {
      c = Uint8Array.from(c);
      const pos = (randomBytes(2)[0] * 256 + randomBytes(1)[0]) % (c.length * 8);
      c[pos >> 3] ^= 1 << (pos & 7);
      line(out, `Adversario: invierte el bit ${pos} de c`, 'hl');
    }
    const d = Toy.kemDecaps(foState.p, kp.dk, c);
    line(out, `Decaps: m' = Decrypt(dk, c);  (K', r') = G(m' ‖ h);  c' = Encrypt(ek, m', r')`, 'dim');
    line(out, `m' ${bytesEqual(d.m2, enc.m) ? '= m' : '≠ m'}   c' ${d.accepted ? '= c' : '≠ c'}`);
    if (d.accepted) {
      line(out, `K (receptor)    = ${toHex(d.K)}`, 'ok');
      line(out, bytesEqual(d.K, enc.K) ? '✓ claves iguales' : '✗ claves distintas (fallo de descifrado)', bytesEqual(d.K, enc.K) ? 'ok' : 'bad');
    } else {
      line(out, `Rechazo implícito: K̄ = J(z ‖ c) = ${toHex(d.K)}`, 'bad');
      line(out, 'El receptor no emite ningún error: devuelve una clave pseudoaleatoria que el adversario no puede', 'dim');
      line(out, 'distinguir ni predecir, y el protocolo superior (p. ej., TLS) fallará más tarde al autenticar.', 'dim');
    }
  }

  // ML-KEM real (FIPS 203)
  function realRun() {
    const name = $('mk-real-set').value;
    const out = $('mk-real-out'); clear(out);
    const t0 = performance.now();
    const kp = MLKEM.keyGen(name);
    const t1 = performance.now();
    const { K, c } = MLKEM.encaps(name, kp.ek);
    const t2 = performance.now();
    const K2 = MLKEM.decaps(name, kp.dk, c);
    const t3 = performance.now();
    const sz = MLKEM.sizes(name);
    const row = $('mk-real-stats'); clear(row);
    statBox(row, `${kp.ek.length} B`, 'clave de encapsulamiento ek');
    statBox(row, `${kp.dk.length} B`, 'clave de desencapsulamiento dk');
    statBox(row, `${c.length} B`, 'cifrado c');
    statBox(row, `${K.length} B`, 'secreto compartido K');
    line(out, `${name}: tamaños esperados FIPS 203 → ek ${sz.ek}, dk ${sz.dk}, c ${sz.ct}, K ${sz.ss} bytes`, 'hl');
    line(out, `ek = ${toHex(kp.ek).slice(0, 64)}…`);
    line(out, `c  = ${toHex(c).slice(0, 64)}…`);
    line(out, `K (Encaps) = ${toHex(K)}`);
    line(out, `K (Decaps) = ${toHex(K2)}`, bytesEqual(K, K2) ? 'ok' : 'bad');
    line(out, `Tiempos en este navegador (JS sin optimizar): KeyGen ${fmt((t1 - t0).toFixed(1))} ms · Encaps ${fmt((t2 - t1).toFixed(1))} ms · Decaps ${fmt((t3 - t2).toFixed(1))} ms`, 'dim');
  }

  // Vector ACVP (ML-KEM-512, keyGen, tcId 1) incluido para verificar la implementación.
  const ACVP_512 = {
    d: '47B893474672BA92E4B12EE44FB32953AF8E8503B5FB471D1614FB8A021A660A',
    z: '1F8CB39E9E30BC458A0DC5408884B1187FB217018DF760FA57317703B844A0A9',
    ekHash: '3A389831056ED8FD81476869245782689C84B3CE90FE6A9E78D0A380FD6A1573',
    dkHash: 'C26AFF5B9F97B5B9CA824755D053A1B1AECE2B965AF6BFBD527B77EA22538468',
  };
  function acvpCheck() {
    const out = $('mk-real-out'); clear(out);
    const kp = MLKEM.keyGenInternal('ML-KEM-512', fromHex(ACVP_512.d), fromHex(ACVP_512.z));
    const he = toHex(H(kp.ek)).toUpperCase(), hd = toHex(H(kp.dk)).toUpperCase();
    line(out, 'Vector ACVP de NIST: ML-KEM-keyGen-FIPS203, ML-KEM-512, tcId 1', 'hl');
    line(out, `d = ${ACVP_512.d}`); line(out, `z = ${ACVP_512.z}`);
    line(out, `SHA3-256(ek) calculado = ${he}`);
    line(out, `SHA3-256(ek) esperado  = ${ACVP_512.ekHash}`, he === ACVP_512.ekHash ? 'ok' : 'bad');
    line(out, `SHA3-256(dk) calculado = ${hd}`);
    line(out, `SHA3-256(dk) esperado  = ${ACVP_512.dkHash}`, hd === ACVP_512.dkHash ? 'ok' : 'bad');
    line(out, he === ACVP_512.ekHash && hd === ACVP_512.dkHash ? '✓ La implementación JS reproduce el vector oficial bit a bit.' : '✗ No coincide.', he === ACVP_512.ekHash && hd === ACVP_512.dkHash ? 'ok' : 'bad');
  }

  function preset(name) {
    const p = PARAMS[name];
    $('mk-n').value = '256'; $('mk-k').value = String(p.k);
    $('mk-eta1').value = String(p.eta1); $('mk-eta2').value = String(p.eta2);
    $('mk-du').value = String(p.du); $('mk-dv').value = String(p.dv);
    renderRun();
  }

  function init() {
    if (!$('demo-kpke')) return;
    ['mk-n', 'mk-k', 'mk-eta1', 'mk-eta2', 'mk-du', 'mk-dv'].forEach((id) => $(id).addEventListener('input', () => { readParams(); }));
    $('mk-run').addEventListener('click', renderRun);
    $('mk-reset').addEventListener('click', () => {
      $('mk-n').value = '16'; $('mk-k').value = '2'; $('mk-eta1').value = '3'; $('mk-eta2').value = '2';
      $('mk-du').value = '10'; $('mk-dv').value = '4'; renderRun();
    });
    document.querySelectorAll('[data-mk-preset]').forEach((b) => b.addEventListener('click', () => preset(b.getAttribute('data-mk-preset'))));
    $('mk-trials-run').addEventListener('click', runTrials);
    $('mk-fo-run').addEventListener('click', () => foRun(false));
    $('mk-fo-tamper').addEventListener('click', () => foRun(true));
    $('mk-real-run').addEventListener('click', realRun);
    $('mk-real-acvp').addEventListener('click', acvpCheck);
    readParams();
    renderRun();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})(typeof window !== 'undefined' ? window : globalThis);
