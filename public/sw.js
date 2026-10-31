const SHELL_CACHE = 'huntdeck-shell-v1'
const DATA_CACHE = 'huntdeck-data-v1'

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(SHELL_CACHE)
      .then(cache => cache.add(new URL('./', self.registration.scope)))
      .then(() => self.skipWaiting())
  )
})

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys
        .filter(key => ![SHELL_CACHE, DATA_CACHE].includes(key))
        .filter(key => key.startsWith('huntdeck-'))
        .map(key => caches.delete(key))))
      .then(() => self.clients.claim())
  )
})

self.addEventListener('fetch', event => {
  const request = event.request
  if (request.method !== 'GET') return

  const url = new URL(request.url)
  if (url.origin !== self.location.origin) return

  if (request.mode === 'navigate') {
    event.respondWith(fetch(request).then(response => {
      if (response.ok) {
        const copy = response.clone()
        void caches.open(SHELL_CACHE).then(cache => cache.put(new URL('./', self.registration.scope), copy))
      }
      return response
    }).catch(async () => {
      const cached = await caches.match(new URL('./', self.registration.scope))
      if (cached) return cached
      return Response.error()
    }))
    return
  }

  if (url.pathname.includes('/data/')) {
    event.respondWith(fetch(request).then(response => {
      if (response.ok) {
        const copy = response.clone()
        void caches.open(DATA_CACHE).then(cache => cache.put(request, copy))
      }
      return response
    }).catch(async () => {
      const cached = await caches.match(request)
      return cached ?? Response.error()
    }))
    return
  }

  if (url.pathname.includes('/assets/')) {
    event.respondWith(caches.match(request).then(cached => cached ?? fetch(request).then(response => {
      if (response.ok) {
        const copy = response.clone()
        void caches.open(SHELL_CACHE).then(cache => cache.put(request, copy))
      }
      return response
    })))
  }
})
