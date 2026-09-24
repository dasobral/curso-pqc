# curso-pqc

Curso de Criptografía Post-Cuántica: 16 horas, seis temas, cinco ejemplos interactivos y cinco
laboratorios. Contenido revisado en septiembre de 2026.

Sitio web: [dasobral.github.io/curso-pqc](https://dasobral.github.io/curso-pqc/)

Profesorado: Prof. Florina Almenares, Francisco Javier Blanco Romero y Daniel Sobral Blanco.

## Contenido

| Temas | Ejemplos (en el navegador) | Laboratorios |
| --- | --- | --- |
| 1 · Criptografía moderna y la amenaza cuántica | E1 · Algoritmo de Shor | L1 · Shor y el fin de RSA (Python, Qiskit) |
| 2 · PKI, TLS y la infraestructura de Internet | E2 · ML-KEM paso a paso | L2 · ML-KEM en la práctica (liboqs, OpenSSL, pyca) |
| 3 · Fundamentos matemáticos de la PQC | E3 · ML-DSA paso a paso | L3 · Firmas ML-DSA y SLH-DSA (OpenSSL, liboqs) |
| 4 · Estándares: ML-KEM, ML-DSA, SLH-DSA y más | E4 · Intercambio híbrido | L4 · TLS híbrido con OpenSSL 3.5+ |
| 5 · Migración, hibridación e implementación | E5 · Protocolo BB84 | L5 · Simulación de QKD (NumPy, Qiskit) |
| 6 · Distribución cuántica de claves (QKD) | | |

Además: programa y calendario, glosario, recursos comentados y búsqueda.

## Ejecutar en local

Sitio estático, sin dependencias ni paso de compilación:

```sh
python3 -m http.server 8000
```

y abre <http://localhost:8000>. La búsqueda necesita servir el sitio por HTTP; el resto funciona
también abriendo los ficheros directamente.

## Estructura

- `index.html`, `programa.html`, `glosario.html`, `busqueda.html`
- `temas/`, `ejemplos/`, `guias/`, `recursos/`: contenido
- `css/styles.css`: sistema visual (tipografía del sitio personal, fondo claro)
- `js/course-data.js`: estructura del curso (menú lateral, paginación, búsqueda)
- `js/course.js`: mejora progresiva común (índice de página, anclajes, copiar código, menú móvil, búsqueda)
- `js/*_interactive.js`: demos, en JavaScript sin dependencias
- `docs/AUTHORING.md` y `docs/componentes.html`: guía para editar o añadir páginas

Las demos son material didáctico: no son implementaciones seguras ni de tiempo constante.

## Licencia

GPL-3.0. Consulta [LICENSE](LICENSE).
