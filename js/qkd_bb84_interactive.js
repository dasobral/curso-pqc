/* Simulador BB84 — Curso de Criptografía Post-Cuántica (ejemplos/qkd_bb84.html).
   Vanilla ES2020, sin dependencias. El núcleo (BB84) es puro y se puede probar con node:
     node -e "const c=require('./js/qkd_bb84_interactive.js'); console.log(c.run({n:4000}).lenFinite)"
   Modelo didáctico: fotones individuales ideales (sin pérdidas ni multifotón), ruido de canal
   como inversión de bit con probabilidad e, y ataque de interceptación-reenvío con probabilidad p. */
(function () {
  'use strict';

  // ---------- Utilidades puras ----------

  // PRNG con semilla (mulberry32): reproducible, suficiente para una simulación. NO criptográfico.
  function rng(seed) {
    let a = seed >>> 0;
    return function () {
      a = (a + 0x6d2b79f5) >>> 0;
      let t = a;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }
  const bit = (r) => (r() < 0.5 ? 0 : 1);

  // Entropía binaria h(x) = -x log2 x - (1-x) log2(1-x)
  function h2(x) {
    if (x <= 0 || x >= 1) return 0;
    return -x * Math.log2(x) - (1 - x) * Math.log2(1 - x);
  }

  // Tasa asintótica de Shor–Preskill para BB84 con corrección ideal: r = 1 - 2h(Q)
  function shorPreskill(q) {
    return Math.max(0, 1 - 2 * h2(q));
  }

  // QBER teórico con ruido e e interceptación-reenvío con probabilidad p (Eve aporta p/4)
  function qberTheory(p, e) {
    const qe = p / 4;
    return qe * (1 - e) + (1 - qe) * e;
  }

  // Intervalo de Wilson al 95 % para una proporción
  function wilson(k, n, z = 1.96) {
    if (n === 0) return [0, 1];
    const ph = k / n;
    const d = 1 + (z * z) / n;
    const c = (ph + (z * z) / (2 * n)) / d;
    const w = (z * Math.sqrt((ph * (1 - ph)) / n + (z * z) / (4 * n * n))) / d;
    return [Math.max(0, c - w), Math.min(1, c + w)];
  }

  // Cota superior de Hoeffding: Q <= Q^ + sqrt(ln(1/eps) / (2k)) con probabilidad >= 1 - eps
  function hoeffdingUpper(qhat, k, eps) {
    if (k === 0) return 0.5;
    return Math.min(0.5, qhat + Math.sqrt(Math.log(1 / eps) / (2 * k)));
  }

  function shuffle(arr, r) {
    for (let i = arr.length - 1; i > 0; i--) {
      const j = Math.floor(r() * (i + 1));
      const t = arr[i]; arr[i] = arr[j]; arr[j] = t;
    }
    return arr;
  }

  // ---------- Fase cuántica ----------

  // Base 0 = rectilínea (+), base 1 = diagonal (×). Estados: 0+ = H, 1+ = V, 0× = D (+45°), 1× = A (−45°).
  function quantumPhase({ n, noise, pEve }, r) {
    const aBit = new Uint8Array(n), aBas = new Uint8Array(n);
    const eOn = new Uint8Array(n), eBas = new Uint8Array(n), eBit = new Uint8Array(n);
    const bBas = new Uint8Array(n), bBit = new Uint8Array(n);
    for (let i = 0; i < n; i++) {
      aBit[i] = bit(r); aBas[i] = bit(r);
      let sBit = aBit[i], sBas = aBas[i]; // estado que viaja por la fibra
      if (r() < pEve) {
        eOn[i] = 1; eBas[i] = bit(r);
        eBit[i] = eBas[i] === sBas ? sBit : bit(r); // base incorrecta: resultado aleatorio
        sBit = eBit[i]; sBas = eBas[i];             // Eve reenvía lo que midió, en su base
      }
      bBas[i] = bit(r);
      let m = bBas[i] === sBas ? sBit : bit(r);
      if (r() < noise) m ^= 1;                      // ruido del canal/detector
      bBit[i] = m;
    }
    return { aBit, aBas, eOn, eBas, eBit, bBas, bBit };
  }

  // ---------- Corrección de errores: BINARY y Cascade ----------

  // Búsqueda binaria de un error en un bloque de paridad impar. Devuelve {pos, leaked, trace}.
  function binarySearch(a, b, idx) {
    let lo = 0, hi = idx.length, leaked = 0;
    const trace = [];
    while (hi - lo > 1) {
      const mid = (lo + hi) >> 1;
      let pa = 0, pb = 0;
      for (let t = lo; t < mid; t++) { pa ^= a[idx[t]]; pb ^= b[idx[t]]; }
      leaked++;
      trace.push({ lo, mid, hi, pa, pb });
      if (pa !== pb) hi = mid; else lo = mid;
    }
    return { pos: idx[lo], leaked, trace };
  }

  // Cascade (Brassard–Salvail, 1993). passes: número de pasadas; k1: tamaño de bloque de la
  // primera pasada (se dobla en cada una). backtrack = true activa el efecto «cascada»: al corregir
  // un bit en la pasada p, los bloques de pasadas anteriores que lo contienen pasan a tener paridad
  // distinta y se corrigen a su vez. Con backtrack = false se obtiene BINARY multipasada simple.
  function cascade(aKey, bKeyIn, k1, passes, r, backtrack = true) {
    const b = Uint8Array.from(bKeyIn);
    const n = aKey.length;
    let leaked = 0, corrected = 0;
    const log = [];
    let firstTrace = null;
    const P = []; // por pasada: { blocks: [idx[]], blockOf: Int32Array, aPar: Uint8Array }
    const bParity = (idx) => { let x = 0; for (const i of idx) x ^= b[i]; return x; };
    let order = Array.from({ length: n }, (_, i) => i);
    let k = k1;
    for (let p = 0; p < passes; p++) {
      if (p > 0) order = shuffle(order.slice(), r); // permutación pública
      const blocks = [], blockOf = new Int32Array(n);
      for (let s = 0; s < n; s += k) {
        const idx = order.slice(s, Math.min(n, s + k));
        for (const i of idx) blockOf[i] = blocks.length;
        blocks.push(idx);
      }
      const aPar = Uint8Array.from(blocks, (idx) => { let x = 0; for (const i of idx) x ^= aKey[i]; return x; });
      leaked += blocks.length; // Alice publica la paridad de cada bloque
      P.push({ blocks, blockOf, aPar });
      const queue = [];
      blocks.forEach((idx, j) => { if (bParity(idx) !== aPar[j]) queue.push([p, j]); });
      const oddBlocks = queue.length;
      let fixedHere = 0;
      while (queue.length) {
        const [q, j] = queue.pop();
        const idx = P[q].blocks[j];
        if (bParity(idx) === P[q].aPar[j]) continue; // ya corregido por otra vía
        const res = binarySearch(aKey, b, idx);
        leaked += res.leaked;
        b[res.pos] ^= 1;
        corrected++; fixedHere++;
        if (!firstTrace) firstTrace = { pass: q + 1, size: idx.length, pos: res.pos, trace: res.trace };
        if (backtrack) {
          for (let qq = 0; qq <= p; qq++) {
            if (qq === q) continue;
            const jj = P[qq].blockOf[res.pos];
            if (bParity(P[qq].blocks[jj]) !== P[qq].aPar[jj]) queue.push([qq, jj]);
          }
        }
      }
      let residual = 0;
      for (let i = 0; i < n; i++) residual += aKey[i] ^ b[i];
      log.push({ pass: p + 1, k, blocks: blocks.length, oddBlocks, fixed: fixedHere, residual });
      k = Math.min(2 * k, n);
    }
    return { bKey: b, leaked, corrected, log, firstTrace };
  }

  // ---------- Amplificación de privacidad: hash de Toeplitz ----------

  function pack(bits) {
    const w = new Uint32Array((bits.length + 31) >> 5);
    for (let i = 0; i < bits.length; i++) if (bits[i]) w[i >> 5] |= 1 << (i & 31);
    return w;
  }
  function get32(words, off) {
    const wi = off >> 5, sh = off & 31;
    const lo = wi < words.length ? words[wi] >>> sh : 0;
    const hi = sh && wi + 1 < words.length ? words[wi + 1] << (32 - sh) : 0;
    return (lo | hi) >>> 0;
  }
  function parity32(x) {
    x ^= x >>> 16; x ^= x >>> 8; x ^= x >>> 4; x ^= x >>> 2; x ^= x >>> 1;
    return x & 1;
  }
  // T es m×n con T[i][j] = seed[j - i + m - 1] (constante en cada diagonal): la fila i es el
  // tramo contiguo seed[m-1-i .. m-1-i+n-1]. y = T·x sobre GF(2). La semilla tiene n+m-1 bits.
  function toeplitzHash(xBits, seedBits, m) {
    const n = xBits.length;
    if (seedBits.length !== n + m - 1) throw new Error('seed length must be n+m-1');
    const x = pack(xBits), s = pack(seedBits);
    const y = new Uint8Array(m);
    const nw = x.length;
    const tailMask = n & 31 ? (1 << (n & 31)) - 1 : 0xffffffff;
    for (let i = 0; i < m; i++) {
      const base = m - 1 - i;
      let acc = 0;
      for (let w = 0; w < nw; w++) {
        const xw = w === nw - 1 ? x[w] & tailMask : x[w];
        acc ^= get32(s, base + 32 * w) & xw;
      }
      y[i] = parity32(acc);
    }
    return y;
  }
  // Versión directa O(mn) para comprobar la anterior
  function toeplitzNaive(xBits, seedBits, m) {
    const n = xBits.length, y = new Uint8Array(m);
    for (let i = 0; i < m; i++) {
      let acc = 0;
      for (let j = 0; j < n; j++) acc ^= seedBits[j - i + m - 1] & xBits[j];
      y[i] = acc;
    }
    return y;
  }

  function toHex(bits, maxBits = 64) {
    let s = '';
    const L = Math.min(bits.length, maxBits) & ~3;
    for (let i = 0; i < L; i += 4) s += ((bits[i] << 3) | (bits[i + 1] << 2) | (bits[i + 2] << 1) | bits[i + 3]).toString(16);
    return s;
  }

  // ---------- Protocolo completo ----------

  function run(opts) {
    const o = Object.assign({ n: 4000, noise: 0.02, pEve: 0, sampleFrac: 0.2, threshold: 0.11,
      eps: 1e-3, epsPA: 1e-10, passes: 4, backtrack: true, seed: 12345 }, opts || {});
    const r = rng(o.seed);
    const q = quantumPhase(o, r);
    const n = o.n;

    // 1) Cribado (sifting): Bob anuncia bases por el canal clásico autenticado
    const sifted = [];
    for (let i = 0; i < n; i++) if (q.aBas[i] === q.bBas[i]) sifted.push(i);
    let trueErr = 0;
    for (const i of sifted) trueErr += q.aBit[i] ^ q.bBit[i];

    // 2) Estimación de parámetros: se revela una muestra aleatoria y se descarta
    const perm = shuffle(sifted.slice(), r);
    const k = Math.round(o.sampleFrac * sifted.length);
    const sample = perm.slice(0, k).sort((x, y) => x - y);
    const keyIdx = perm.slice(k).sort((x, y) => x - y);
    let sampleErr = 0;
    for (const i of sample) sampleErr += q.aBit[i] ^ q.bBit[i];
    const qhat = k ? sampleErr / k : 0;
    const role = new Uint8Array(n); // 0 descartado, 1 muestra, 2 clave
    for (const i of sample) role[i] = 1;
    for (const i of keyIdx) role[i] = 2;

    const aRaw = Uint8Array.from(keyIdx, (i) => q.aBit[i]);
    const bRaw = Uint8Array.from(keyIdx, (i) => q.bBit[i]);
    let rawErr = 0;
    for (let i = 0; i < aRaw.length; i++) rawErr += aRaw[i] ^ bRaw[i];

    const res = { opts: o, q, sifted, sample, keyIdx, role, trueErr,
      qTrue: sifted.length ? trueErr / sifted.length : 0,
      qTheory: qberTheory(o.pEve, o.noise), k, sampleErr, qhat,
      ci: wilson(sampleErr, k), qU: hoeffdingUpper(qhat, k, o.eps),
      nRaw: aRaw.length, rawErr, aborted: k === 0 || qhat > o.threshold };
    if (res.aborted || aRaw.length < 8) { res.aborted = true; return res; }

    // 3) Reconciliación (corrección de errores). Brassard–Salvail: k1 ≈ 0,73/Q
    const k1 = Math.max(4, Math.min(aRaw.length, Math.round(0.73 / Math.max(qhat, 0.005))));
    const ec = cascade(aRaw, bRaw, k1, o.passes, r, o.backtrack);
    let residual = 0;
    for (let i = 0; i < aRaw.length; i++) residual += aRaw[i] ^ ec.bKey[i];
    res.k1 = k1; res.ec = ec; res.residual = residual;
    const hRaw = h2(rawErr / aRaw.length);
    res.fEC = hRaw > 0 ? ec.leaked / (aRaw.length * hRaw) : null;

    // 4) Amplificación de privacidad
    const nr = aRaw.length;
    res.lenAsym = Math.floor(nr * shorPreskill(qhat));
    const mFinite = Math.floor(nr * (1 - h2(res.qU)) - ec.leaked - 2 * Math.log2(1 / o.epsPA));
    res.lenFinite = Math.max(0, mFinite);
    const m = res.lenFinite;
    if (m > 0) {
      const seed = Uint8Array.from({ length: nr + m - 1 }, () => bit(r));
      res.kA = toeplitzHash(aRaw, seed, m);
      res.kB = toeplitzHash(ec.bKey, seed, m);
      let diff = 0;
      for (let i = 0; i < m; i++) diff += res.kA[i] ^ res.kB[i];
      res.finalDiff = diff;
    }
    return res;
  }

  // Barrido de p para la curva QBER(p)
  function sweep({ n, noise, seed, steps = 11 }) {
    const pts = [];
    for (let s = 0; s < steps; s++) {
      const p = s / (steps - 1);
      const r = rng((seed + 7919 * s) >>> 0);
      const q = quantumPhase({ n, noise, pEve: p }, r);
      let sift = 0, err = 0;
      for (let i = 0; i < n; i++) if (q.aBas[i] === q.bBas[i]) { sift++; err += q.aBit[i] ^ q.bBit[i]; }
      pts.push({ p, q: sift ? err / sift : 0 });
    }
    return pts;
  }

  const core = { rng, h2, shorPreskill, qberTheory, wilson, hoeffdingUpper, quantumPhase,
    binarySearch, cascade, toeplitzHash, toeplitzNaive, toHex, run, sweep };
  if (typeof module !== 'undefined' && module.exports) module.exports = core;
  if (typeof document === 'undefined') return;

  // ---------- Interfaz ----------

  const pct = (x, d = 1) => (100 * x).toFixed(d).replace('.', ',') + '\u00a0%';
  const epsTxt = (e) => ({ 0.01: '10⁻²', 0.001: '10⁻³', 0.000001: '10⁻⁶' })[e] || String(e);
  const fmt = (x) => String(x).replace(/\B(?=(\d{3})+(?!\d))/g, ' ');
  const $ = (id) => document.getElementById(id);
  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }
  function line(parent, parts) {
    for (const [cls, t] of parts) parent.appendChild(el('span', cls || null, t));
    parent.appendChild(document.createTextNode('\n'));
  }
  const STATE = ['H', 'V', 'D', 'A']; // índice = base*2 + bit
  const BAS = ['+', '×'];

  function init() {
    const root = $('demo-bb84');
    if (!root) return;
    const ctl = {
      n: $('bb-n'), noise: $('bb-noise'), eve: $('bb-eve'), sample: $('bb-sample'),
      thr: $('bb-thr'), eps: $('bb-eps'), passes: $('bb-passes'), bt: $('bb-bt'),
    };
    let seed = 12345;

    function readOpts() {
      return {
        n: +ctl.n.value, noise: +ctl.noise.value / 100, pEve: +ctl.eve.value / 100,
        sampleFrac: +ctl.sample.value / 100, threshold: +ctl.thr.value / 100,
        eps: +ctl.eps.value, passes: +ctl.passes.value, backtrack: ctl.bt.value === '1', seed,
      };
    }
    function labels() {
      $('bb-n-out').textContent = fmt(ctl.n.value);
      $('bb-noise-out').textContent = (+ctl.noise.value).toFixed(1).replace('.', ',') + '\u00a0%';
      $('bb-eve-out').textContent = ctl.eve.value + '\u00a0%';
      $('bb-sample-out').textContent = ctl.sample.value + '\u00a0%';
      $('bb-thr-out').textContent = (+ctl.thr.value).toFixed(1).replace('.', ',') + '\u00a0%';
      $('bb-seed').textContent = 'Semilla ' + seed;
    }
    const stat = (id, v) => { $(id).textContent = v; };

    function renderTable(res) {
      const tbody = $('bb-rows');
      tbody.replaceChildren();
      const q = res.q, N = Math.min(32, res.opts.n);
      for (let i = 0; i < N; i++) {
        const tr = document.createElement('tr');
        const match = q.aBas[i] === q.bBas[i];
        const err = match && q.aBit[i] !== q.bBit[i];
        const cells = [
          String(i + 1), String(q.aBit[i]), BAS[q.aBas[i]], STATE[q.aBas[i] * 2 + q.aBit[i]],
          q.eOn[i] ? BAS[q.eBas[i]] + ' → ' + q.eBit[i] : '—',
          BAS[q.bBas[i]], String(q.bBit[i]), match ? 'sí' : 'no',
          !match ? 'descarte' : res.role[i] === 1 ? 'muestra' : 'clave',
        ];
        cells.forEach((c, j) => tr.appendChild(el('td', j === 0 ? 'num' : null, c)));
        const last = el('td');
        if (match) last.appendChild(el('span', err ? 'badge broken' : 'badge final', err ? 'error' : 'ok'));
        tr.appendChild(last);
        tbody.appendChild(tr);
      }
    }

    function renderBits(res) {
      const host = $('bb-bits');
      host.replaceChildren();
      const q = res.q, N = Math.min(96, res.opts.n);
      for (let i = 0; i < N; i++) {
        const match = q.aBas[i] === q.bBas[i];
        const s = el('span', !match ? 'off' : q.aBit[i] !== q.bBit[i] ? 'bad' : 'ok', String(q.bBit[i]));
        s.title = 'Fotón ' + (i + 1) + (match ? (res.role[i] === 1 ? ' · muestra' : ' · clave') : ' · bases distintas');
        host.appendChild(s);
      }
    }

    function renderLog(res) {
      const out = $('bb-out');
      out.replaceChildren();
      const o = res.opts;
      let eveN = 0; for (let i = 0; i < o.n; i++) eveN += res.q.eOn[i];
      line(out, [['hl', '1 · Transmisión cuántica'], [null, `  ${fmt(o.n)} fotones · ruido ${pct(o.noise)} · Eve intercepta ${pct(o.pEve, 0)} (${fmt(eveN)} fotones)`]]);
      line(out, [['hl', '2 · Cribado'], [null, `  bases coincidentes: ${fmt(res.sifted.length)} (${pct(res.sifted.length / o.n)}; esperado 50 %)`]]);
      line(out, [['dim', `    QBER real del cribado (solo visible en la simulación): ${pct(res.qTrue, 2)} · teoría ${pct(res.qTheory, 2)}`]]);
      line(out, [['hl', '3 · Estimación de parámetros'], [null, `  muestra k = ${fmt(res.k)} · errores = ${res.sampleErr}`]]);
      line(out, [[null, `    Q̂ = ${pct(res.qhat, 2)} · IC Wilson 95 % [${pct(res.ci[0], 2)}, ${pct(res.ci[1], 2)}] · Hoeffding (ε = ${epsTxt(o.eps)}): Q ≤ ${pct(res.qU, 2)}`]]);
      if (res.aborted) {
        line(out, [['bad', `    ABORTAR: Q̂ = ${pct(res.qhat, 2)} > umbral ${pct(o.threshold, 1)} (o muestra vacía). No se genera clave.`]]);
        return;
      }
      line(out, [['ok', `    Q̂ ≤ umbral ${pct(o.threshold, 1)} → continuar con ${fmt(res.nRaw)} bits de clave bruta (${res.rawErr} errores reales).`]]);
      line(out, [['hl', '4 · Reconciliación ' + (o.backtrack ? '(Cascade)' : '(BINARY sin retroceso)')], [null, `  k₁ = round(0,73/Q̂) = ${res.k1}`]]);
      for (const L of res.ec.log) {
        line(out, [[null, `    pasada ${L.pass}: ${L.blocks} bloques de ${L.k} bits · paridad distinta en ${L.oddBlocks} · bits corregidos ${L.fixed} · errores restantes ${L.residual}`]]);
      }
      if (res.ec.firstTrace) {
        const t = res.ec.firstTrace;
        line(out, [['dim', `    Traza del primer bloque con paridad distinta (pasada ${t.pass}, ${t.size} bits):`]]);
        for (const s of t.trace.slice(0, 10)) {
          line(out, [['dim', `      posiciones [${s.lo},${s.mid}) paridad A=${s.pa} B=${s.pb} → el error está en [${s.pa !== s.pb ? s.lo + ',' + s.mid : s.mid + ',' + s.hi})`]]);
        }
        line(out, [['dim', `      bit localizado: posición ${t.pos} de la clave bruta; Bob lo invierte.`]]);
      }
      const fTxt = res.fEC ? res.fEC.toFixed(2).replace('.', ',') : '—';
      line(out, [[null, `    paridades reveladas (leak_EC): ${fmt(res.ec.leaked)} bits · eficiencia f = leak/(n·h(Q)) ≈ ${fTxt}`]]);
      line(out, [[res.residual ? 'bad' : 'ok', res.residual
        ? `    Quedan ${res.residual} errores (bloques con número par de errores). La verificación por hash fallaría: más pasadas o abortar.`
        : '    Claves idénticas tras la reconciliación (en la práctica se verifica con un hash universal).']]);
      line(out, [['hl', '5 · Amplificación de privacidad (Toeplitz)']]);
      line(out, [[null, `    asintótico  ℓ = n·(1 − 2h(Q̂)) = ${fmt(res.lenAsym)} bits`]]);
      line(out, [[null, `    didáctico   ℓ = n·(1 − h(Q_U)) − leak_EC − 2·log₂(1/ε_PA) = ${fmt(res.lenFinite)} bits`]]);
      if (res.lenFinite > 0) {
        line(out, [['dim', `    semilla pública de ${fmt(res.nRaw + res.lenFinite - 1)} bits → matriz de Toeplitz ${fmt(res.lenFinite)} × ${fmt(res.nRaw)}`]]);
        line(out, [['ok', `    K_A = ${toHex(res.kA)}…`]]);
        line(out, [[res.finalDiff ? 'bad' : 'ok', `    K_B = ${toHex(res.kB)}…  ${res.finalDiff ? '(distintas en ' + res.finalDiff + ' bits)' : '(iguales)'}`]]);
      } else {
        line(out, [['bad', '    Longitud final ≤ 0: con estos parámetros no se puede extraer clave.']]);
      }
    }

    function renderStats(res) {
      stat('bb-s-sift', fmt(res.sifted.length));
      stat('bb-s-qber', pct(res.qhat, 2));
      stat('bb-s-theory', pct(res.qTheory, 2));
      stat('bb-s-raw', res.aborted ? '—' : fmt(res.nRaw));
      stat('bb-s-leak', res.aborted ? '—' : fmt(res.ec.leaked));
      stat('bb-s-final', res.aborted ? 'abortado' : fmt(res.lenFinite));
      const frac = res.aborted ? 0 : res.lenFinite / res.opts.n;
      const ideal = 0.5 * (1 - res.opts.sampleFrac); // cribado × fracción no muestreada
      $('bb-bar').style.width = Math.min(100, (100 * frac) / ideal).toFixed(1) + '%';
      $('bb-bar-txt').textContent = `Rendimiento: ${res.aborted ? 0 : fmt(res.lenFinite)} bits finales por cada ${fmt(res.opts.n)} fotones enviados (${pct(frac, 2)}). La barra llega al 100 % en el máximo ideal, ${pct(ideal, 0)}: cribado del 50 % sin la muestra revelada.`;
    }

    // Gráfica QBER(p) en SVG
    const NS = 'http://www.w3.org/2000/svg';
    function svgEl(tag, attrs, text) {
      const e = document.createElementNS(NS, tag);
      for (const k in attrs) e.setAttribute(k, attrs[k]);
      if (text !== undefined) e.textContent = text;
      return e;
    }
    function renderPlot(opts) {
      const g = $('bb-plot-g');
      g.replaceChildren();
      const X0 = 70, X1 = 640, Y0 = 250, Y1 = 20, QMAX = 0.35;
      const sx = (p) => X0 + (X1 - X0) * p;
      const sy = (q) => Y0 - (Y0 - Y1) * (Math.min(q, QMAX) / QMAX);
      for (let t = 0; t <= 7; t++) {
        const v = t * 0.05;
        g.appendChild(svgEl('line', { x1: X0, x2: X1, y1: sy(v), y2: sy(v), class: 'svg-line', 'stroke-dasharray': '2 4' }));
        g.appendChild(svgEl('text', { x: X0 - 8, y: sy(v) + 4, 'text-anchor': 'end', class: 'svg-muted' }, t * 5 + '\u00a0%'));
      }
      for (let t = 0; t <= 4; t++) {
        g.appendChild(svgEl('text', { x: sx(t / 4), y: Y0 + 18, 'text-anchor': 'middle', class: 'svg-muted' }, t * 25 + '\u00a0%'));
      }
      g.appendChild(svgEl('text', { x: (X0 + X1) / 2, y: Y0 + 36, 'text-anchor': 'middle', class: 'svg-text' }, 'Probabilidad de interceptación p'));
      g.appendChild(svgEl('text', { x: 16, y: (Y0 + Y1) / 2, 'text-anchor': 'middle', class: 'svg-text', transform: `rotate(-90 16 ${(Y0 + Y1) / 2})` }, 'QBER'));
      g.appendChild(svgEl('line', { x1: X0, x2: X1, y1: Y0, y2: Y0, class: 'svg-stroke-ink' }));
      g.appendChild(svgEl('line', { x1: X0, x2: X0, y1: Y0, y2: Y1, class: 'svg-stroke-ink' }));
      g.appendChild(svgEl('line', { x1: X0, x2: X1, y1: sy(opts.threshold), y2: sy(opts.threshold), class: 'svg-stroke-amber', 'stroke-width': 1.5, 'stroke-dasharray': '6 4' }));
      g.appendChild(svgEl('text', { x: X0 + 6, y: sy(opts.threshold) - 6, class: 'svg-muted' }, 'umbral ' + pct(opts.threshold, 1)));
      const tp = [0, 1].map((p) => `${sx(p).toFixed(1)},${sy(qberTheory(p, opts.noise)).toFixed(1)}`).join(' ');
      g.appendChild(svgEl('polyline', { points: tp, class: 'svg-stroke-signal', 'stroke-width': 2 }));
      g.appendChild(svgEl('text', { x: sx(0.62), y: sy(qberTheory(0.55, opts.noise)) + 26, class: 'svg-text' }, 'teoría: e + (1 − 2e)·p/4'));
      const nS = Math.min(opts.n, 20000);
      for (const pt of sweep({ n: nS, noise: opts.noise, seed: opts.seed })) {
        g.appendChild(svgEl('circle', { cx: sx(pt.p), cy: sy(pt.q), r: 4, class: 'svg-ink' }));
      }
      g.appendChild(svgEl('circle', { cx: sx(opts.pEve), cy: sy(qberTheory(opts.pEve, opts.noise)), r: 8, class: 'svg-stroke-amber', 'stroke-width': 2 }));
      const pc = opts.noise < opts.threshold ? Math.min(1, (4 * (opts.threshold - opts.noise)) / (1 - 2 * opts.noise)) : 0;
      $('bb-plot-txt').textContent = `Con ruido e = ${pct(opts.noise)}, el QBER esperado cruza el umbral para p ≈ ${pct(pc, 1)}${pc >= 1 ? ' (no lo cruza: Eve puede interceptar todo sin superar el umbral)' : ''}. Puntos: simulación con ${fmt(nS)} fotones por valor de p; círculo ámbar: configuración actual.`;
    }

    function go() {
      labels();
      const opts = readOpts();
      const res = run(opts);
      renderStats(res); renderTable(res); renderBits(res); renderLog(res); renderPlot(opts);
    }

    $('bb-run').addEventListener('click', () => { seed = (Math.random() * 4294967296) >>> 0; go(); });
    $('bb-reset').addEventListener('click', () => {
      ctl.n.value = 4000; ctl.noise.value = 2; ctl.eve.value = 0; ctl.sample.value = 20;
      ctl.thr.value = 11; ctl.eps.value = '0.001'; ctl.passes.value = 4; ctl.bt.value = '1'; seed = 12345; go();
    });
    for (const k of Object.keys(ctl)) ctl[k].addEventListener('input', go);
    go();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
