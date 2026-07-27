// Service worker do ATLAS — permite instalar e abrir rápido.
// Estratégia: rede primeiro (pra sempre pegar a versão nova), com cache de reserva.
const CACHE = 'atlas-v5';
const ASSETS = ['/', '/manifest.webmanifest', '/icon-192.png', '/icon-512.png', '/icon-maskable.png'];

self.addEventListener('install', e => {
  self.skipWaiting();
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(ASSETS).catch(() => {})));
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  const req = e.request;
  // nunca cachear a API nem pedidos não-GET
  if (req.method !== 'GET' || req.url.includes('/api/')) return;
  e.respondWith(
    fetch(req).then(res => {
      // guarda uma cópia dos arquivos estáticos
      if (res.ok && (req.url.endsWith('.png') || req.url.endsWith('.webmanifest') || req.mode === 'navigate')) {
        const copy = res.clone();
        caches.open(CACHE).then(c => c.put(req, copy)).catch(() => {});
      }
      return res;
    }).catch(() => caches.match(req).then(r => r || caches.match('/')))
  );
});
