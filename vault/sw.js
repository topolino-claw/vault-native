const CACHE_NAME = 'vault-v3.2';
const ASSETS = [
  './',
  './index.html',
  './app.js',
  './bip39WordList.js',
  './crypto-js.min.js',
  './lib/nostr-tools.min.js',
  './manifest.json'
];

// Install: cache all core assets
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS))
  );
  self.skipWaiting();
});

// Activate: clean old caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

// Fetch: cache-first for assets, network-first for everything else
self.addEventListener('fetch', (event) => {
  // Skip non-GET and WebSocket requests
  if (event.request.method !== 'GET' || event.request.url.startsWith('wss://')) return;
  
  event.respondWith(
    caches.match(event.request).then((cached) => {
      if (cached) {
        // Return cached, but update in background
        const fetchPromise = fetch(event.request).then((response) => {
          if (response.ok) {
            caches.open(CACHE_NAME).then((cache) => cache.put(event.request, response));
          }
          return response.clone();
        }).catch(() => {});
        return cached;
      }
      return fetch(event.request);
    })
  );
});
