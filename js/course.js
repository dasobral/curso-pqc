// Progressive enhancement for every page: course nav, on-this-page TOC,
// pager, heading anchors, copy buttons, mobile menu and site search.
(function () {
  'use strict';

  const root = document.documentElement.dataset.root || '';
  const pageId = document.documentElement.dataset.page || '';
  const course = window.COURSE;
  const el = (tag, attrs = {}, text) => {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
    if (text !== undefined) node.textContent = text;
    return node;
  };
  const slug = (s) => s.toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '')
    .replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 60);

  function flatItems() {
    return course.groups.flatMap((g) => g.items.filter((i) => !i.hidden).map((i) => ({ ...i, group: g })));
  }

  // ---------- Course navigation (sidebar) ----------
  function buildCourseNav() {
    const host = document.querySelector('.course-nav');
    if (!host || !course) return;
    const details = el('details');
    const summary = el('summary', {}, 'Índice del curso');
    const body = el('div', { class: 'details-body' });
    for (const group of course.groups) {
      const items = group.items.filter((i) => !i.hidden);
      if (!items.length) continue;
      const wrap = el('div', { class: 'nav-group' });
      wrap.append(el('p', { class: 'nav-group-title' }, group.title));
      const list = el('ol');
      for (const item of items) {
        const a = el('a', { href: root + item.path });
        if (item.num) { a.append(el('span', { class: 'num' }, item.num)); } else { a.classList.add('plain'); }
        a.append(el('span', {}, item.title));
        if (item.id === pageId) a.setAttribute('aria-current', 'page');
        const li = el('li');
        li.append(a);
        list.append(li);
      }
      wrap.append(list);
      body.append(wrap);
    }
    details.append(summary, body);
    if (window.matchMedia('(min-width: 961px)').matches) details.open = true;
    host.replaceChildren(details);
  }

  // ---------- Heading ids, anchors and TOC ----------
  function buildToc() {
    const prose = document.querySelector('.prose');
    const host = document.querySelector('.toc');
    if (!prose) return;
    const heads = [...prose.querySelectorAll('h2, h3')].filter((h) => !h.closest('.demo, .key-points, details, .exercise'));
    const used = new Set([...document.querySelectorAll('[id]')].map((n) => n.id));
    for (const h of heads) {
      if (!h.id) {
        let id = slug(h.textContent) || 'seccion';
        let n = 2;
        while (used.has(id)) id = `${slug(h.textContent)}-${n++}`;
        h.id = id;
        used.add(id);
      }
      const a = el('a', { class: 'anchor', href: `#${h.id}`, 'aria-label': 'Enlace a esta sección' }, '#');
      h.append(a);
    }
    if (!host || heads.length < 2) { if (host) host.remove(); return; }
    host.append(el('p', { class: 'toc-title' }, 'En esta página'));
    const list = el('ol');
    const links = new Map();
    for (const h of heads) {
      const li = el('li', { class: h.tagName === 'H3' ? 'lvl-3' : 'lvl-2' });
      const clone = h.cloneNode(true);
      clone.querySelectorAll('.anchor, .sec').forEach((n) => n.remove());
      const a = el('a', { href: `#${h.id}` }, clone.textContent.trim());
      li.append(a);
      list.append(li);
      links.set(h, a);
    }
    host.append(list);
    const progress = el('div', { class: 'toc-progress', 'aria-hidden': 'true' });
    const bar = el('span');
    progress.append(bar);
    host.append(progress);

    const update = () => {
      let current = heads[0];
      for (const h of heads) { if (h.getBoundingClientRect().top < 140) current = h; }
      links.forEach((a, h) => a.classList.toggle('active', h === current));
      const max = document.documentElement.scrollHeight - window.innerHeight;
      bar.style.width = `${max > 0 ? Math.min(100, (window.scrollY / max) * 100) : 0}%`;
    };
    let ticking = false;
    window.addEventListener('scroll', () => {
      if (!ticking) { requestAnimationFrame(() => { update(); ticking = false; }); ticking = true; }
    }, { passive: true });
    update();
  }

  // ---------- Previous / next ----------
  function buildPager() {
    const host = document.querySelector('.pager');
    if (!host || !course) return;
    const items = flatItems();
    const idx = items.findIndex((i) => i.id === pageId);
    if (idx < 0) return;
    const make = (item, cls, label) => {
      const a = el('a', { class: cls, href: root + item.path });
      a.append(el('small', {}, label), el('span', {}, (item.num ? item.num + ' · ' : '') + item.title));
      return a;
    };
    if (idx > 0) host.append(make(items[idx - 1], 'prev', '← Anterior'));
    if (idx < items.length - 1) host.append(make(items[idx + 1], 'next', 'Siguiente →'));
  }

  // ---------- Code blocks: copy button ----------
  function enhanceCode() {
    document.querySelectorAll('pre > code').forEach((code) => {
      const pre = code.parentElement;
      if (pre.querySelector('.copy-btn')) return;
      const btn = el('button', { class: 'copy-btn', type: 'button' }, 'Copiar');
      btn.addEventListener('click', async () => {
        try {
          await navigator.clipboard.writeText(code.innerText);
          btn.textContent = 'Copiado';
        } catch (_) {
          btn.textContent = 'Error';
        }
        setTimeout(() => { btn.textContent = 'Copiar'; }, 1600);
      });
      pre.append(btn);
    });
  }

  // ---------- Header: mobile menu + search box ----------
  function enhanceHeader() {
    const header = document.querySelector('.site-header');
    const toggle = document.querySelector('.menu-toggle');
    if (header && toggle) {
      toggle.addEventListener('click', () => {
        const open = header.classList.toggle('open');
        toggle.setAttribute('aria-expanded', String(open));
        toggle.textContent = open ? 'Cerrar' : 'Menú';
      });
    }
    document.querySelectorAll('.header-search').forEach((form) => {
      form.addEventListener('submit', (e) => {
        e.preventDefault();
        const q = form.querySelector('input').value.trim();
        if (q) window.location.href = `${root}busqueda.html?q=${encodeURIComponent(q)}`;
      });
    });
  }

  // ---------- Search page: fetch every page and match sections ----------
  async function runSearch() {
    const box = document.querySelector('#search-page');
    if (!box || !course) return;
    const input = box.querySelector('input');
    const status = box.querySelector('.search-status');
    const results = box.querySelector('.search-results');
    const params = new URLSearchParams(window.location.search);
    input.value = params.get('q') || '';

    const norm = (s) => s.toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '');
    let index = null;
    async function loadIndex() {
      if (index) return index;
      status.textContent = 'Indexando el curso…';
      const pages = course.groups.flatMap((g) => g.items.map((i) => ({ ...i, group: g.title })))
        .concat(course.groups.filter((g) => g.index).map((g) => ({ id: g.id, path: g.index, title: g.title, group: 'Índice' })))
        .filter((p) => p.id !== 'busqueda');
      const parser = new DOMParser();
      const entries = [];
      await Promise.all(pages.map(async (p) => {
        try {
          const res = await fetch(root + p.path);
          if (!res.ok) return;
          const doc = parser.parseFromString(await res.text(), 'text/html');
          const main = doc.querySelector('main') || doc.body;
          main.querySelectorAll('script, style, .pager, .breadcrumb, nav').forEach((n) => n.remove());
          let section = { heading: p.title, id: '', text: '' };
          const flush = () => { if (section.text.trim()) entries.push({ page: p, ...section, norm: norm(section.heading + ' ' + section.text) }); };
          const walker = doc.createTreeWalker(main, NodeFilter.SHOW_ELEMENT);
          for (let node = walker.nextNode(); node; node = walker.nextNode()) {
            if (/^H[1-3]$/.test(node.tagName)) {
              flush();
              const id = node.id || (node.tagName !== 'H1' ? slug(node.textContent) : '');
              section = { heading: node.textContent.replace('#', '').trim(), id, text: '' };
            } else if (/^(P|LI|TD|TH|DD|DT|FIGCAPTION|SUMMARY|PRE|BLOCKQUOTE)$/.test(node.tagName)) {
              section.text += ' ' + node.textContent;
            }
          }
          flush();
        } catch (_) { /* file:// or network error */ }
      }));
      index = entries;
      return index;
    }

    const escapeHtml = (s) => s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
    function snippet(text, terms) {
      const clean = text.replace(/\s+/g, ' ').trim();
      const n = norm(clean);
      const pos = Math.max(0, n.indexOf(terms[0]));
      const start = Math.max(0, pos - 70);
      let out = escapeHtml((start > 0 ? '…' : '') + clean.slice(start, start + 220) + (clean.length > start + 220 ? '…' : ''));
      for (const t of terms) {
        const re = new RegExp(`(${t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');
        out = out.replace(re, '<mark>$1</mark>');
      }
      return out;
    }

    async function search() {
      const q = input.value.trim();
      results.replaceChildren();
      if (!q) { status.textContent = 'Escribe un término: por ejemplo «ML-KEM», «retículo» o «harvest now».'; return; }
      const idx = await loadIndex();
      if (!idx.length) { status.textContent = 'La búsqueda necesita servir el sitio por HTTP (por ejemplo, python3 -m http.server).'; return; }
      const terms = norm(q).split(/\s+/).filter(Boolean);
      const scored = idx.map((e) => {
        let score = 0;
        for (const t of terms) {
          if (!e.norm.includes(t)) return null;
          score += (norm(e.heading).includes(t) ? 5 : 0) + e.norm.split(t).length - 1;
        }
        return { e, score };
      }).filter(Boolean).sort((a, b) => b.score - a.score).slice(0, 40);
      status.textContent = scored.length ? `${scored.length} resultado${scored.length === 1 ? '' : 's'} para «${q}»` : `Sin resultados para «${q}».`;
      for (const { e } of scored) {
        const li = el('li');
        li.append(el('span', { class: 'where' }, `${e.page.group} · ${e.page.title}`));
        li.append(el('a', { href: root + e.page.path + (e.id ? '#' + e.id : '') }, e.heading));
        const p = el('p');
        p.innerHTML = snippet(e.text, terms);
        li.append(p);
        results.append(li);
      }
    }
    box.querySelector('form').addEventListener('submit', (ev) => {
      ev.preventDefault();
      history.replaceState(null, '', `?q=${encodeURIComponent(input.value.trim())}`);
      search();
    });
    search();
  }

  document.addEventListener('DOMContentLoaded', () => {
    buildCourseNav();
    buildToc();
    buildPager();
    enhanceCode();
    enhanceHeader();
    runSearch();
  });
})();
