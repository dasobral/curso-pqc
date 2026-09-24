# Guía de autoría del curso

Sitio estático sin dependencias: HTML a mano, `css/styles.css`, `js/course-data.js` y `js/course.js`.
Sin CDNs ni fuentes externas; la única librería de terceros es KaTeX, copiada en `vendor/katex/` (MIT). Todo el contenido está en español
(de España), con terminología técnica en inglés cuando es la de uso habitual (KEM, *handshake*,
*harvest now, decrypt later*), marcada en cursiva la primera vez.

## Estructura del sitio

| Ruta | Contenido |
| --- | --- |
| `index.html` | Portada del curso |
| `programa.html` | Programa, calendario, evaluación |
| `temas/index.html`, `temas/temaN/index.html` | Índice de temas y los seis temas |
| `ejemplos/index.html`, `ejemplos/*.html` | Ejemplos interactivos (demos JS en el navegador) |
| `guias/index.html`, `guias/*.html` | Guías de laboratorio (Python / OpenSSL / liboqs) |
| `recursos/index.html` | Bibliografía, estándares, herramientas |
| `glosario.html` | Glosario |
| `busqueda.html` | Búsqueda en cliente |
| `js/<nombre>.js` | JS de cada demo interactiva (vanilla, sin dependencias) |

El orden, títulos cortos e identificadores de página viven en `js/course-data.js`. El menú
lateral, el índice "En esta página", el paginador anterior/siguiente, los botones de copiar y
los anclajes de los títulos los genera `js/course.js`. El contenido debe leerse completo sin JS.

## Esqueleto de página

`data-root` es la ruta relativa a la raíz (`''`, `'../'` o `'../../'`). `data-page` es el `id`
del elemento en `course-data.js`. Sustituye `{R}` por la misma ruta relativa. Marca con
`aria-current="page"` el enlace de la sección actual en `.site-nav`.

```html
<!doctype html>
<html lang="es" data-root="{R}" data-page="tema1">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Tema 1 · Criptografía moderna y la amenaza cuántica — Curso PQC</title>
  <meta name="description" content="Una frase que resuma la página.">
  <link rel="icon" href="{R}assets/favicon.svg" type="image/svg+xml">
  <link rel="stylesheet" href="{R}css/styles.css?v=2026092402">
  <script src="{R}js/course-data.js?v=2026092402" defer></script>
  <script src="{R}js/course.js?v=2026092402" defer></script>
</head>
<body>
  <a class="skip-link" href="#contenido">Saltar al contenido</a>
  <header class="site-header">
    <div class="header-inner">
      <a class="brand" href="{R}index.html" aria-label="Inicio del curso">
        <span class="brand-mark">pqc<span>.</span></span>
        <span class="brand-name">Criptografía<br>post-cuántica</span>
      </a>
      <nav class="site-nav" aria-label="Secciones">
        <a href="{R}index.html">Inicio</a>
        <a href="{R}programa.html">Programa</a>
        <a href="{R}temas/index.html">Temas</a>
        <a href="{R}ejemplos/index.html">Ejemplos</a>
        <a href="{R}guias/index.html">Laboratorios</a>
        <a href="{R}recursos/index.html">Recursos</a>
      </nav>
      <form class="header-search" role="search" action="{R}busqueda.html">
        <label class="visually-hidden" for="q">Buscar en el curso</label>
        <input id="q" name="q" type="search" placeholder="Buscar…" autocomplete="off">
      </form>
      <button class="menu-toggle" type="button" aria-expanded="false">Menú</button>
    </div>
  </header>

  <div class="layout">
    <nav class="course-nav" aria-label="Índice del curso"></nav>
    <main id="contenido" class="content">
      <nav class="breadcrumb" aria-label="Ruta">
        <ol><li><a href="{R}index.html">Inicio</a></li><li><a href="{R}temas/index.html">Temas</a></li><li aria-current="page">Tema 1</li></ol>
      </nav>
      <header class="page-head">
        <p class="eyebrow">Tema 01 · 2 horas</p>
        <h1>Criptografía moderna y la <em>amenaza cuántica</em></h1>
        <p class="lede">Una o dos frases que digan qué aprenderá el lector y por qué importa.</p>
        <dl class="page-meta">
          <div><dt>Duración</dt><dd>2 h</dd></div>
          <div><dt>Nivel</dt><dd>Introductorio</dd></div>
          <div><dt>Requisitos</dt><dd>Aritmética modular</dd></div>
          <div><dt>Actualizado</dt><dd>Septiembre 2026</dd></div>
        </dl>
      </header>

      <article class="prose">
        <h2 id="objetivos"><span class="sec">1.0</span>Objetivos</h2>
        …
      </article>

      <nav class="pager" aria-label="Paginación"></nav>
    </main>
    <aside class="toc" aria-label="En esta página"></aside>
  </div>

  <footer class="site-footer">
    <div class="footer-inner">
      <p><strong>Curso de Criptografía Post-Cuántica</strong> · Daniel Sobral Blanco · Actualizado en septiembre de 2026</p>
      <div class="footer-links">
        <a href="{R}glosario.html">Glosario</a>
        <a href="{R}recursos/index.html">Recursos</a>
        <a href="https://github.com/dasobral/curso-pqc">Código fuente</a>
        <a href="https://dasobral.github.io/">dasobral.github.io</a>
      </div>
    </div>
  </footer>
</body>
</html>
```

Páginas sin índice lateral derecho (índices de sección): `<div class="layout no-toc">` y sin
`<aside class="toc">`.

Cuando cambies `css/styles.css` o un fichero de `js/`, actualiza el parámetro `?v=` en todas las
páginas (GitHub Pages permite que el navegador guarde en caché estos ficheros durante 10 minutos o
más; sin el parámetro, un visitante puede ver HTML nuevo con CSS antiguo).

## Componentes

Títulos: un único `h1` en `.page-head`. Dentro de `.prose` usa `h2` para secciones numeradas
(`<span class="sec">3.2</span>` opcional antes del texto) y `h3`/`h4` para subsecciones. Da
`id` estable y corto a cada `h2` (en minúsculas, con guiones, sin tildes) para enlazar desde
otras páginas; si falta, JS lo genera.

```html
<!-- Avisos: callout (teal, idea clave), .note (gris), .warning (ámbar), .danger (rojo), .update (novedad 2025-2026) -->
<div class="callout warning"><span class="callout-title">Cuidado</span><p>…</p></div>
<div class="callout update"><span class="callout-title">Novedad · marzo 2025</span><p>…</p></div>

<!-- Definición / teorema / problema -->
<div class="definition"><span class="def-title"><b>Definición</b>Learning With Errors (LWE)</span><p>…</p></div>

<!-- Fórmulas: LaTeX renderizado con KaTeX (vendor/katex, se carga solo si la página tiene \( o \[).
     En línea \( … \); en bloque <div class="equation">\[ … \tag{3.1} \]</div>. Nunca $…$.
     Macros: \Z \R \F \N. Escapa < > & como &lt; &gt; &amp;. Sin LaTeX en SVG, pre/code ni en texto que reescribe una demo. -->
<div class="equation">\[ \mathbf{t} = \mathbf{A}\mathbf{s} + \mathbf{e} \pmod{q} \tag{3.1} \]</div>
<p>En línea: \(R_q = \Z_q[X]/(X^{256}+1)\)</p>

<!-- Código: añade data-lang. El botón Copiar lo añade JS. Resaltado manual opcional: tok-c (comentario), tok-k (palabra clave), tok-s (cadena), tok-n (número), tok-f (función) -->
<pre data-lang="python"><code>…</code></pre>
<pre class="terminal" data-lang="shell"><code>$ openssl version</code></pre>

<!-- Tablas: siempre dentro de .table-wrap; números alineados con class="num" -->
<div class="table-wrap"><table><caption>Tamaños en bytes (FIPS 203)</caption><thead><tr><th>…</th><th class="num">…</th></tr></thead><tbody>…</tbody></table></div>

<!-- Ejercicio con solución desplegable -->
<div class="exercise"><span class="ex-title">Ejercicio 1.3 <span class="level">Básico</span></span><p>…</p>
  <details><summary>Solución</summary><div class="details-body"><p>…</p></div></details></div>

<!-- Desplegable genérico: SIEMPRE con .details-body dentro -->
<details><summary>Para saber más</summary><div class="details-body"><p>…</p></div></details>

<!-- Ideas clave al final de cada tema -->
<aside class="key-points"><span class="kp-title">Ideas clave</span><ul><li>…</li></ul></aside>

<!-- Cronología -->
<ol class="timeline"><li><span class="when">Ago 2024</span>…</li><li class="future"><span class="when">2030</span>…</li></ol>

<!-- Estado de un estándar -->
<span class="badge final">Estándar final</span> <span class="badge draft">Borrador</span> <span class="badge broken">Roto</span> <span class="badge info">Informativo</span>

<!-- Figura con SVG en línea: usa las clases svg-* (svg-box, svg-box-signal, svg-text, svg-muted, svg-line, svg-stroke-signal…) para respetar la paleta -->
<figure class="diagram"><svg viewBox="0 0 720 220" role="img" aria-labelledby="f1t"><title id="f1t">…</title>…</svg><figcaption><b>Figura 1.1.</b> …</figcaption></figure>

<!-- Referencias numeradas -->
<ol class="refs"><li>Autor. <a href="…">Título</a>. <span class="src">Editorial, año.</span></li></ol>

<!-- Tarjetas (índices) -->
<div class="card-grid"><a class="card" href="…"><span class="card-kicker">Tema 01</span><h3 class="card-title">…</h3><p>…</p><span class="card-foot"><span>2 h</span><span>Introductorio</span></span></a></div>

<!-- Dos columnas que se apilan -->
<div class="grid-2"><div class="callout note">…</div><div class="callout note">…</div></div>
```

## Demos interactivas

Estructura, con JS en `js/<nombre>.js` cargado con `defer` al final del `<head>` (después de
`course.js`). Sin `alert`, `prompt` ni `confirm`; sin `innerHTML` con datos del usuario.

```html
<section class="demo" id="demo-bb84" aria-labelledby="demo-bb84-t">
  <div class="demo-head"><p class="demo-title" id="demo-bb84-t">Simulador BB84</p><button class="btn ghost" type="button">Reiniciar</button></div>
  <div class="demo-body">
    <div class="controls">
      <label class="field">Fotones<input type="range" min="8" max="256" value="64"></label>
      <label class="field">Espía (Eve)<select><option>No</option><option>Sí</option></select></label>
      <button class="btn" type="button">Ejecutar</button>
    </div>
    <div class="stat-row"><div class="stat"><b>11,2 %</b><small>QBER</small></div></div>
    <div class="bits"><span class="ok">1</span><span class="bad">0</span><span class="off">·</span></div>
    <div class="output" aria-live="polite"></div>
  </div>
</section>
```

Dentro de `.output`: `<span class="ok">`, `.bad`, `.dim`, `.hl`. Barras: `<div class="bar"><span style="width:40%"></span></div>`.

## Estilo del texto

- Español de España, registro académico claro. Frases cortas. Nada de relleno ni entusiasmo.
- Cifras con coma decimal y espacio fino o punto para miles solo cuando ayude (`1 184 bytes`).
- Fechas absolutas. Distingue siempre "estándar final", "borrador" y "propuesta".
- Cita la fuente primaria (FIPS, RFC, NIST IR, artículo) para cada dato que pueda envejecer.
- No inventes referencias, cifras, versiones ni fechas. Si no está verificado, no lo pongas.
