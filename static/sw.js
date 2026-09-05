/* Amnezia Web Panel — static-assets-only service worker.
 *
 * Cache version comes from the script URL (?v=...), which base.html sets to
 * static_v (newest mtime under static/). Asset changes → new SW URL → fresh
 * install → activate evicts every other awp-static-* cache.
 *
 * CSS/JS are network-first so a new ?v= is never served from an old cache
 * entry. Match is always the exact request URL, including the query string.
 *
 * Pages and /api/* are never intercepted: session auth has no CSRF and a
 * shared device must not serve one user's cached HTML to another.
 */
const VERSION = new URL(self.location).searchParams.get('v') || 'dev';
const CACHE = `awp-static-${VERSION}`;

const PRECACHE = [
  `/static/css/style.css?v=${VERSION}`,
  `/static/favicon.svg?v=${VERSION}`,
  `/static/js/qrcode.min.js?v=${VERSION}`,
  `/static/js/searchable-select.js?v=${VERSION}`,
  `/static/icons/icon-192.png`,
  `/static/icons/icon-512.png`,
  `/static/icons/maskable-192.png`,
  `/static/icons/maskable-512.png`,
  `/static/icons/apple-touch-icon-180.png`,
  `/static/offline.html`,
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE).then((cache) => cache.addAll(PRECACHE)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k.startsWith('awp-static-') && k !== CACHE).map((k) => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);

  // Never touch API or non-same-origin requests.
  if (url.origin !== self.location.origin) return;
  if (url.pathname.startsWith('/api/')) return;

  if (url.pathname.startsWith('/static/')) {
    const isCssOrJs = url.pathname.endsWith('.css') || url.pathname.endsWith('.js');

    if (isCssOrJs) {
      // Network-first, exact URL match (honor ?v=).
      event.respondWith(
        fetch(req).then((res) => {
          if (res.ok) {
            const clone = res.clone();
            caches.open(CACHE).then((cache) => cache.put(req, clone));
          }
          return res;
        }).catch(() => caches.match(req))
      );
      return;
    }

    // Icons / offline.html: cache-first, exact URL match.
    event.respondWith(
      caches.match(req).then((hit) => {
        if (hit) return hit;
        return fetch(req).then((res) => {
          if (res.ok) {
            const clone = res.clone();
            caches.open(CACHE).then((cache) => cache.put(req, clone));
          }
          return res;
        });
      })
    );
    return;
  }

  // Navigations: network first, offline.html on failure. Do not cache pages.
  if (req.mode === 'navigate') {
    event.respondWith(
      fetch(req).catch(() => caches.match('/static/offline.html'))
    );
  }
  // Everything else: no respondWith — browser default.
});
