// Ejemplo E1 · Simulación clásica de la reducción de Shor para N pequeños.
// Todo se calcula en el navegador con aritmética exacta (BigInt no es necesario: N ≤ 1023).
// Lo único "cuántico" que se imita es la distribución ideal de la medida tras la QFT inversa,
// que aquí se calcula con una fórmula cerrada en lugar de evolucionar un vector de estado.
(function () {
  'use strict';

  // ---------- Funciones puras (probadas con node) ----------
  const N_MAX = 1023;

  function gcd(a, b) {
    a = Math.abs(a); b = Math.abs(b);
    while (b) { [a, b] = [b, a % b]; }
    return a;
  }

  // a^e mod m sin desbordar (m ≤ 2^15, productos < 2^30)
  function modPow(a, e, m) {
    let r = 1 % m, b = a % m;
    while (e > 0) {
      if (e & 1) r = (r * b) % m;
      b = (b * b) % m;
      e = Math.floor(e / 2);
    }
    return r;
  }

  function isPrime(n) {
    if (n < 2) return false;
    for (let d = 2; d * d <= n; d++) if (n % d === 0) return false;
    return true;
  }

  // Devuelve [p, k] si n = p^k con k ≥ 2 y p primo; si no, null
  function primePower(n) {
    for (let p = 2; p * p <= n; p++) {
      if (n % p) continue;
      let m = n, k = 0;
      while (m % p === 0) { m /= p; k++; }
      return m === 1 && k >= 2 ? [p, k] : null;
    }
    return null;
  }

  // Clasifica N: 'ok' (impar compuesto, no potencia de primo) o el motivo del rechazo
  function classifyN(n) {
    if (!Number.isInteger(n) || n < 15 || n > N_MAX) return { ok: false, why: `N debe ser un entero entre 15 y ${N_MAX}.` };
    if (n % 2 === 0) return { ok: false, why: `N es par: el factor 2 se obtiene sin Shor (N = 2 × ${n / 2}).` };
    if (isPrime(n)) return { ok: false, why: 'N es primo: no hay nada que factorizar.' };
    const pp = primePower(n);
    if (pp) return { ok: false, why: `N = ${pp[0]}^${pp[1]} es potencia de un primo; se detecta clásicamente con raíces enteras y Shor no la necesita.` };
    return { ok: true };
  }

  // Orden multiplicativo por fuerza bruta: menor r > 0 con a^r ≡ 1 (mod N)
  function order(a, n) {
    if (gcd(a, n) !== 1) return null;
    let x = a % n, r = 1;
    while (x !== 1) { x = (x * a) % n; r++; }
    return r;
  }

  // Resultado del paso clásico final dado el orden r
  function factorsFromOrder(a, r, n) {
    if (r % 2 === 1) return { ok: false, kind: 'odd', half: null };
    const half = modPow(a, r / 2, n);
    if (half === n - 1) return { ok: false, kind: 'minus1', half };
    const p = gcd(half - 1, n), q = gcd(half + 1, n);
    return { ok: true, kind: 'ok', half, p, q };
  }

  // Menor t con 2^t ≥ N^2 (garantiza que las fracciones continuas recuperan s/r)
  function phaseQubits(n) {
    let t = 0;
    while (2 ** t < n * n) t++;
    return t;
  }

  // Distribución ideal de la medida del registro de fase (Q = 2^t) para el orden r.
  // Tras medir el registro de trabajo con resultado a^x0, el registro de fase queda en
  // la superposición uniforme de x0, x0 + r, …; hay (Q mod r) desplazamientos con
  // M = ceil(Q/r) términos y el resto con M = floor(Q/r). Para cada uno,
  // P(y | x0) = |Σ_j e^{-2πi j r y / Q}|² / (M · Q) y P(y) = Σ_x0 (M/Q) · P(y | x0).
  function idealDistribution(r, Q) {
    const probs = new Float64Array(Q);
    const mHi = Math.ceil(Q / r), mLo = Math.floor(Q / r);
    const nHi = Q % r, nLo = r - nHi;
    const geo2 = (M, y) => {
      const theta = Math.PI * r * y / Q;
      const s = Math.sin(theta);
      if (Math.abs(s) < 1e-12) return M * M;
      const v = Math.sin(M * theta) / s;
      return v * v;
    };
    for (let y = 0; y < Q; y++) {
      let p = nLo * geo2(mLo, y);
      if (nHi) p += nHi * geo2(mHi, y);
      probs[y] = p / (Q * Q);
    }
    return probs;
  }

  // Convergentes p/q de la fracción continua de num/den
  function convergents(num, den) {
    const out = [];
    const coeffs = [];
    let a = num, b = den;
    while (b) { const q = Math.floor(a / b); coeffs.push(q); [a, b] = [b, a - q * b]; }
    let pPrev = 1, p = coeffs[0], qPrev = 0, q = 1;
    out.push({ a: coeffs[0], p, q });
    for (let i = 1; i < coeffs.length; i++) {
      [pPrev, p] = [p, coeffs[i] * p + pPrev];
      [qPrev, q] = [q, coeffs[i] * q + qPrev];
      out.push({ a: coeffs[i], p, q });
    }
    return out;
  }

  // Si a^R ≡ 1, el orden divide a R: se eliminan factores primos de R mientras a^(R/p) ≡ 1.
  // (Paso clásico y barato; evita devolver un múltiplo del orden.)
  function minimalOrder(a, R, n) {
    let m = R;
    for (let p = 2; p <= m; p++) {
      while (m % p === 0 && modPow(a, m / p, n) === 1) m /= p;
    }
    return m;
  }

  // Recupera un candidato a orden a partir de la medida y. Recorre los convergentes con
  // denominador < N (salvo 0/1, que no informa) y prueba el denominador q y sus múltiplos
  // k·q con k ≤ 4 (por si gcd(s, r) > 1 y la fracción aparece simplificada).
  function orderFromMeasurement(y, Q, a, n) {
    const conv = convergents(y, Q);
    for (const c of conv) {
      if (c.q >= n) break;
      if (c.p === 0) continue; // s = 0 no aporta información sobre r
      for (let k = 1; k <= 4 && k * c.q < n; k++) {
        const R = k * c.q;
        if (modPow(a, R, n) === 1) {
          const r = minimalOrder(a, R, n);
          return { r, via: c, k, conv, reduced: r !== R ? R : null };
        }
      }
    }
    return { r: null, via: null, k: 0, conv };
  }

  // Muestra un índice según la distribución (búsqueda binaria en la acumulada)
  function sampler(probs) {
    const cdf = new Float64Array(probs.length);
    let acc = 0;
    for (let i = 0; i < probs.length; i++) { acc += probs[i]; cdf[i] = acc; }
    return (u) => {
      const target = u * acc;
      let lo = 0, hi = cdf.length - 1;
      while (lo < hi) { const mid = (lo + hi) >> 1; if (cdf[mid] < target) lo = mid + 1; else hi = mid; }
      return lo;
    };
  }

  // Estadística sobre todas las bases a coprimas con N
  function surveyBases(n) {
    const stats = { total: 0, ok: 0, odd: 0, minus1: 0, lucky: 0 };
    for (let a = 2; a <= n - 2; a++) {
      if (gcd(a, n) !== 1) { stats.lucky++; continue; }
      stats.total++;
      const res = factorsFromOrder(a, order(a, n), n);
      stats[res.kind]++;
    }
    return stats;
  }

  const api = { gcd, modPow, isPrime, primePower, classifyN, order, factorsFromOrder, phaseQubits, idealDistribution, convergents, minimalOrder, orderFromMeasurement, sampler, surveyBases };
  if (typeof module !== 'undefined' && module.exports) { module.exports = api; return; }

  // ---------- Interfaz ----------
  const SVG_NS = 'http://www.w3.org/2000/svg';
  const fmt = (x, d = 4) => x.toFixed(d).replace('.', ',');
  const pct = (x) => `${(100 * x).toFixed(1).replace('.', ',')} %`;

  function h(tag, attrs = {}, text) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
    if (text !== undefined) node.textContent = text;
    return node;
  }
  function s(tag, attrs = {}, text) {
    const node = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, String(v));
    if (text !== undefined) node.textContent = text;
    return node;
  }
  function span(cls, text) { return h('span', cls ? { class: cls } : {}, text); }
  function line(out, ...parts) {
    for (const p of parts) out.append(typeof p === 'string' ? document.createTextNode(p) : p);
    out.append(document.createTextNode('\n'));
  }

  function svgFrame(w, hgt, titleText) {
    const svg = s('svg', { viewBox: `0 0 ${w} ${hgt}`, role: 'img' });
    svg.append(s('title', {}, titleText));
    return svg;
  }

  // Gráfico de la secuencia f(x) = a^x mod N
  function drawSequence(host, a, n, r) {
    const count = Math.min(64, Math.max(3 * r + 1, 24));
    const W = 720, H = 220, L = 44, R = 12, T = 14, B = 34;
    const svg = svgFrame(W, H, `Secuencia ${a}^x mod ${n} para x = 0…${count - 1}; periodo r = ${r}`);
    const pw = (W - L - R) / count, ph = H - T - B;
    const yOf = (v) => T + ph - (v / (n - 1)) * ph;
    svg.append(s('line', { x1: L, y1: T + ph, x2: W - R, y2: T + ph, class: 'svg-line' }));
    svg.append(s('line', { x1: L, y1: T, x2: L, y2: T + ph, class: 'svg-line' }));
    svg.append(s('text', { x: L - 6, y: T + 4, 'text-anchor': 'end', class: 'svg-muted' }, String(n - 1)));
    svg.append(s('text', { x: L - 6, y: T + ph + 4, 'text-anchor': 'end', class: 'svg-muted' }, '0'));
    // bandas de periodo
    for (let x0 = 0; x0 < count; x0 += r) {
      const x = L + x0 * pw;
      svg.append(s('line', { x1: x, y1: T, x2: x, y2: T + ph, class: 'svg-stroke-amber', 'stroke-dasharray': '3 3', 'stroke-width': 1 }));
    }
    let pts = '';
    for (let x = 0; x < count; x++) {
      const v = modPow(a, x, n);
      const cx = L + (x + 0.5) * pw, cy = yOf(v);
      pts += `${cx.toFixed(1)},${cy.toFixed(1)} `;
      svg.append(s('circle', { cx: cx.toFixed(1), cy: cy.toFixed(1), r: v === 1 ? 4 : 3, class: v === 1 ? 'svg-amber' : 'svg-signal' }));
    }
    svg.insertBefore(s('polyline', { points: pts.trim(), class: 'svg-line', 'stroke-width': 1 }), svg.childNodes[1]);
    const step = count > 32 ? 8 : 4;
    for (let x = 0; x < count; x += step) {
      svg.append(s('text', { x: (L + (x + 0.5) * pw).toFixed(1), y: H - 16, 'text-anchor': 'middle', class: 'svg-muted' }, String(x)));
    }
    svg.append(s('text', { x: W - R, y: H - 2, 'text-anchor': 'end', class: 'svg-muted' }, `x   (líneas discontinuas cada r = ${r}; puntos ámbar: f(x) = 1)`));
    host.replaceChildren(svg);
  }

  // Histograma de la distribución ideal y de las medidas simuladas
  function drawPeaks(host, probs, Q, r, hits) {
    const W = 720, H = 240, L = 44, R = 12, T = 14, B = 40;
    const bins = Math.min(Q, 256), per = Q / bins;
    const binP = new Float64Array(bins), binHits = new Float64Array(bins);
    for (let y = 0; y < Q; y++) binP[Math.floor(y / per)] += probs[y];
    let totalHits = 0;
    for (const [y, c] of hits) { binHits[Math.floor(y / per)] += c; totalHits += c; }
    let maxP = 0;
    for (let i = 0; i < bins; i++) maxP = Math.max(maxP, binP[i], totalHits ? binHits[i] / totalHits : 0);
    const svg = svgFrame(W, H, `Probabilidad ideal de medir y en el registro de fase (Q = ${Q}); picos cerca de múltiplos de Q/r = ${fmt(Q / r, 2)}`);
    const pw = (W - L - R) / bins, ph = H - T - B;
    svg.append(s('line', { x1: L, y1: T + ph, x2: W - R, y2: T + ph, class: 'svg-line' }));
    svg.append(s('line', { x1: L, y1: T, x2: L, y2: T + ph, class: 'svg-line' }));
    svg.append(s('text', { x: L - 6, y: T + 4, 'text-anchor': 'end', class: 'svg-muted' }, pct(maxP)));
    for (let i = 0; i < bins; i++) {
      const hgt = (binP[i] / maxP) * ph;
      if (hgt > 0.2) svg.append(s('rect', { x: (L + i * pw).toFixed(2), y: (T + ph - hgt).toFixed(2), width: Math.max(pw * 0.8, 2.5).toFixed(2), height: hgt.toFixed(2), class: 'svg-signal', opacity: 0.85 }));
    }
    if (totalHits) {
      for (let i = 0; i < bins; i++) {
        if (!binHits[i]) continue;
        const cy = T + ph - (binHits[i] / totalHits / maxP) * ph;
        svg.append(s('circle', { cx: (L + (i + 0.5) * pw).toFixed(2), cy: cy.toFixed(2), r: 3.2, class: 'svg-amber' }));
      }
    }
    for (let s0 = 0; s0 <= r; s0++) {
      if (r > 16 && s0 % Math.ceil(r / 8) !== 0 && s0 !== r) continue;
      const x = L + (s0 * Q / r) / per * pw;
      svg.append(s('text', { x: x.toFixed(1), y: T + ph + 14, 'text-anchor': 'middle', class: 'svg-muted' }, s0 === 0 ? '0' : `${s0}Q/r`));
    }
    svg.append(s('text', { x: W - R, y: H - 4, 'text-anchor': 'end', class: 'svg-muted' }, totalHits ? `barras: probabilidad ideal · puntos ámbar: frecuencia de ${totalHits} medidas simuladas` : 'barras: probabilidad ideal (agrupada si Q > 256)'));
    host.replaceChildren(svg);
  }

  function init() {
    const root = document.getElementById('demo-shor');
    if (!root) return;
    const $ = (sel) => root.querySelector(sel);
    const nIn = $('#shor-n'), aIn = $('#shor-a'), shotsIn = $('#shor-shots');
    const out = $('#shor-out'), cfOut = $('#shor-cf'), survey = $('#shor-survey');
    const seqHost = $('#shor-seq'), peakHost = $('#shor-peaks');
    const statN = $('#stat-n'), statT = $('#stat-t'), statR = $('#stat-r'), statP = $('#stat-p');
    let state = null;

    function randomA(n) {
      let a;
      do { a = 2 + Math.floor(Math.random() * (n - 3)); } while (gcd(a, n) !== 1);
      return a;
    }

    function reset(msg) {
      state = null;
      out.replaceChildren();
      cfOut.replaceChildren();
      seqHost.replaceChildren();
      peakHost.replaceChildren();
      survey.replaceChildren();
      [statN, statT, statR, statP].forEach((e) => { e.textContent = '—'; });
      if (msg) line(out, span('dim', msg));
    }

    function run() {
      const n = Number(nIn.value);
      out.replaceChildren();
      cfOut.replaceChildren();
      const cls = classifyN(n);
      if (!cls.ok) { reset(); line(out, span('bad', cls.why)); return; }
      let a = Number(aIn.value);
      if (!Number.isInteger(a) || a < 2 || a > n - 2) { a = randomA(n); aIn.value = String(a); }
      statN.textContent = String(n);
      line(out, span('dim', '# 1. Comprobaciones clásicas'));
      line(out, `N = ${n}: impar, compuesto y no es potencia de un primo.`);
      const g = gcd(a, n);
      line(out, span('dim', '# 2. Elegir a y calcular gcd(a, N)'));
      if (g !== 1) {
        line(out, `gcd(${a}, ${n}) = `, span('ok', String(g)), ` → factor encontrado sin ordenador cuántico: ${n} = ${g} × ${n / g}.`);
        line(out, span('dim', 'Con N grande esto ocurre con probabilidad despreciable. Elige otro a para ver el caso interesante.'));
        [statT, statR, statP].forEach((e) => { e.textContent = '—'; });
        seqHost.replaceChildren(); peakHost.replaceChildren();
        state = null;
        line(cfOut, span('dim', 'Con gcd(a, N) > 1 no hace falta la parte cuántica: no hay nada que medir.'));
        drawSurvey(n);
        return;
      }
      line(out, `gcd(${a}, ${n}) = 1 → hay que hallar el orden de ${a} módulo ${n}.`);
      const r = order(a, n);
      const t = phaseQubits(n), Q = 2 ** t;
      statT.textContent = `${t} + ${Math.ceil(Math.log2(n + 1))}`;
      statR.textContent = String(r);
      line(out, span('dim', '# 3. Orden por fuerza bruta (lo que el ordenador cuántico evita)'));
      line(out, `r = ord_${n}(${a}) = `, span('hl', String(r)), `   (${a}^${r} mod ${n} = 1; se han hecho ${r} multiplicaciones)`);
      line(out, span('dim', `# 4. Parte cuántica simulada: t = ${t} qubits de fase (Q = 2^${t} = ${Q} ≥ N² = ${n * n})`));
      line(out, `Los picos de probabilidad están en y ≈ s·Q/r = s·${fmt(Q / r, 2)}, s = 0…${r - 1}.`);
      const res = factorsFromOrder(a, r, n);
      line(out, span('dim', '# 5. Paso clásico final'));
      if (res.kind === 'odd') {
        line(out, span('bad', `r = ${r} es impar`), ': no existe a^(r/2). Fallo; repetir con otro a.');
      } else if (res.kind === 'minus1') {
        line(out, `${a}^(${r}/2) mod ${n} = ${res.half} = N − 1 ≡ −1: `, span('bad', 'solo da factores triviales'), ` (gcd(${res.half - 1}, ${n}) = ${gcd(res.half - 1, n)}, gcd(${res.half + 1}, ${n}) = ${n}). Fallo; repetir con otro a.`);
      } else {
        line(out, `x = ${a}^(${r}/2) mod ${n} = ${res.half}   (x² ≡ 1 y x ≢ ±1)`);
        line(out, `gcd(x − 1, N) = gcd(${res.half - 1}, ${n}) = `, span('ok', String(res.p)), `   gcd(x + 1, N) = gcd(${res.half + 1}, ${n}) = `, span('ok', String(res.q)));
        line(out, span('ok', `${n} = ${res.p} × ${res.q}`));
      }
      statP.textContent = res.ok ? `${res.p} × ${res.q}` : (res.kind === 'odd' ? 'fallo: r impar' : 'fallo: −1');
      const probs = idealDistribution(r, Q);
      state = { n, a, r, t, Q, probs, draw: sampler(probs), hits: new Map() };
      drawSequence(seqHost, a, n, r);
      drawPeaks(peakHost, probs, Q, r, state.hits);
      line(cfOut, span('dim', 'Pulsa «Medir» para simular una medida del registro de fase y recuperar r con fracciones continuas.'));
      drawSurvey(n);
    }

    function measure() {
      if (!state || state.n !== Number(nIn.value) || state.a !== Number(aIn.value)) run();
      if (!state) return;
      const shots = Math.max(1, Math.min(1000, Number(shotsIn.value) || 1));
      const { n, a, Q } = state;
      const found = new Map();
      let lastY = 0;
      for (let i = 0; i < shots; i++) {
        const y = state.draw(Math.random());
        lastY = y;
        state.hits.set(y, (state.hits.get(y) || 0) + 1);
        const rec = orderFromMeasurement(y, Q, a, n).r;
        const key = rec === null ? 'ninguno' : String(rec);
        found.set(key, (found.get(key) || 0) + 1);
      }
      drawPeaks(peakHost, state.probs, Q, state.r, state.hits);
      cfOut.replaceChildren();
      const rec = orderFromMeasurement(lastY, Q, a, n);
      line(cfOut, span('dim', `# Última medida: y = ${lastY}   y/Q = ${lastY}/${Q} = ${fmt(lastY / Q, 6)}`));
      line(cfOut, 'Convergentes de la fracción continua (se descartan denominadores ≥ N):');
      for (const c of rec.conv) {
        const tag = rec.via && c.q === rec.via.q ? span('hl', '  ← candidato') : (c.q >= n ? span('dim', '  (q ≥ N, stop)') : '');
        line(cfOut, `  [a=${c.a}]  ${c.p}/${c.q}`, tag);
        if (c.q >= n) break;
      }
      if (rec.r === null) {
        line(cfOut, span('bad', 'Ningún denominador verifica a^q ≡ 1: medida inútil (p. ej. y = 0 da s = 0). Se repite.'));
      } else {
        let extra = rec.k > 1 ? ` (el convergente dio q = ${rec.via.q}; como gcd(s, r) > 1, se prueba ${rec.k}·q = ${rec.k * rec.via.q})` : '';
        if (rec.reduced) extra += ` y, como ${a}^${rec.reduced} ≡ 1 pero ${rec.reduced} no es mínimo, se reduce a su divisor ${rec.r}`;
        line(cfOut, 'Orden recuperado: ', span('ok', `r = ${rec.r}`), extra, `; comprobación ${a}^${rec.r} mod ${n} = ${modPow(a, rec.r, n)}.`);
      }
      const summary = [...found.entries()].sort((x, y) => y[1] - x[1]).map(([k, v]) => `r=${k}: ${v}`).join('  ·  ');
      line(cfOut, span('dim', `# Resumen de ${shots} medida(s) de esta tanda: ${summary}`));
    }

    function drawSurvey(n) {
      const st = surveyBases(n);
      survey.replaceChildren();
      const row = h('div', { class: 'stat-row' });
      const add = (v, label) => { const d = h('div', { class: 'stat' }); d.append(h('b', {}, v), h('small', {}, label)); row.append(d); };
      add(pct(st.ok / st.total), `bases a coprimas que factorizan (${st.ok}/${st.total})`);
      add(String(st.odd), 'con r impar');
      add(String(st.minus1), 'con a^(r/2) ≡ −1');
      add(String(st.lucky), 'con gcd(a, N) > 1');
      survey.append(row);
      const bar = h('div', { class: 'bar', title: 'Fracción de bases con éxito' });
      bar.append(h('span', { style: `width:${(100 * st.ok / st.total).toFixed(1)}%` }));
      survey.append(bar);
    }

    $('#shor-run').addEventListener('click', run);
    $('#shor-measure').addEventListener('click', measure);
    $('#shor-random').addEventListener('click', () => {
      const n = Number(nIn.value);
      if (classifyN(n).ok) { aIn.value = String(randomA(n)); run(); }
    });
    $('#shor-reset').addEventListener('click', () => { nIn.value = '15'; aIn.value = '7'; shotsIn.value = '1'; run(); });
    root.querySelectorAll('[data-preset]').forEach((b) => b.addEventListener('click', () => {
      const [n, a] = b.dataset.preset.split(',');
      nIn.value = n; aIn.value = a; run();
    }));
    run();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})();
