// Single source of truth for the course structure: sidebar, pager and search index.
// Paths are relative to the site root.
window.COURSE = {
  title: 'Curso de Criptografía Post-Cuántica',
  updated: 'septiembre de 2026',
  groups: [
    {
      id: 'curso',
      title: 'Curso',
      items: [
        { id: 'inicio', path: 'index.html', title: 'Inicio' },
        { id: 'programa', path: 'programa.html', title: 'Programa y plan de estudio' },
      ],
    },
    {
      id: 'temas',
      title: 'Temas',
      index: 'temas/index.html',
      items: [
        { id: 'tema1', num: '01', path: 'temas/tema1/index.html', title: 'Criptografía moderna y la amenaza cuántica', hours: 2 },
        { id: 'tema2', num: '02', path: 'temas/tema2/index.html', title: 'PKI, TLS y la infraestructura de Internet', hours: 2 },
        { id: 'tema3', num: '03', path: 'temas/tema3/index.html', title: 'Fundamentos matemáticos de la PQC', hours: 4 },
        { id: 'tema4', num: '04', path: 'temas/tema4/index.html', title: 'Estándares: ML-KEM, ML-DSA, SLH-DSA y más', hours: 3 },
        { id: 'tema5', num: '05', path: 'temas/tema5/index.html', title: 'Migración, hibridación e implementación', hours: 3 },
        { id: 'tema6', num: '06', path: 'temas/tema6/index.html', title: 'Distribución cuántica de claves (QKD)', hours: 2 },
      ],
    },
    {
      id: 'ejemplos',
      title: 'Ejemplos interactivos',
      index: 'ejemplos/index.html',
      items: [
        { id: 'ej-shor', num: 'E1', path: 'ejemplos/algoritmo_shor.html', title: 'Algoritmo de Shor' },
        { id: 'ej-mlkem', num: 'E2', path: 'ejemplos/ml_kem.html', title: 'ML-KEM paso a paso' },
        { id: 'ej-mldsa', num: 'E3', path: 'ejemplos/ml_dsa.html', title: 'ML-DSA paso a paso' },
        { id: 'ej-hibrida', num: 'E4', path: 'ejemplos/criptografia_hibrida.html', title: 'Intercambio híbrido' },
        { id: 'ej-bb84', num: 'E5', path: 'ejemplos/qkd_bb84.html', title: 'Protocolo BB84' },
      ],
    },
    {
      id: 'guias',
      title: 'Laboratorios',
      index: 'guias/index.html',
      items: [
        { id: 'lab-shor', num: 'L1', path: 'guias/algoritmo_shor.html', title: 'Shor y el fin de RSA' },
        { id: 'lab-mlkem', num: 'L2', path: 'guias/ml_kem.html', title: 'ML-KEM en la práctica' },
        { id: 'lab-mldsa', num: 'L3', path: 'guias/ml_dsa.html', title: 'Firmas ML-DSA y SLH-DSA' },
        { id: 'lab-hibrida', num: 'L4', path: 'guias/criptografia_hibrida.html', title: 'TLS híbrido con OpenSSL' },
        { id: 'lab-qkd', num: 'L5', path: 'guias/qkd.html', title: 'Simulación de QKD' },
      ],
    },
    {
      id: 'apoyo',
      title: 'Consulta',
      items: [
        { id: 'glosario', path: 'glosario.html', title: 'Glosario' },
        { id: 'recursos', path: 'recursos/index.html', title: 'Recursos y bibliografía' },
        { id: 'busqueda', path: 'busqueda.html', title: 'Buscar', hidden: true },
      ],
    },
  ],
};
