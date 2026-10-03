// Service Worker der verschlüsselten Pages-Fassung; tools/build_pages.mjs kopiert ihn nach _site/sw.js.
// Jede Datei außer HTML ist AES-256-GCM-Geheimtext (iv | Geheimtext | Tag). Die Login-Seite legt den
// abgeleiteten Schlüssel in IndexedDB ab; dieser Worker holt den Geheimtext, entschlüsselt ihn und
// gibt der Seite die Klartextdatei. HTML-Seiten sind selbst Login-Seiten und laufen unverändert durch.

const TYPES = {
  css: "text/css", js: "text/javascript", json: "application/json", txt: "text/plain",
  svg: "image/svg+xml", png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg",
  gif: "image/gif", webp: "image/webp", ico: "image/x-icon", pdf: "application/pdf",
  woff: "font/woff", woff2: "font/woff2",
};
const plain = new Map(); // Pfad → Promise<ArrayBuffer>, solange der Worker lebt

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));

self.addEventListener("fetch", (e) => {
  const req = e.request;
  const url = new URL(req.url);
  const scope = new URL(self.registration.scope).pathname;
  if (req.method !== "GET" || req.mode === "navigate" || url.origin !== location.origin) return;
  if (!url.pathname.startsWith(scope)) return;
  const rel = url.pathname.slice(scope.length);
  if (!rel || rel.endsWith("/") || rel.endsWith(".html") || rel === "sw.js" || rel === "robots.txt") return;
  e.respondWith(serve(url.pathname));
});

function loadKey() {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open("cosy-pages", 1);
    open.onupgradeneeded = () => open.result.createObjectStore("k");
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const get = open.result.transaction("k").objectStore("k").get("key");
      get.onsuccess = () => resolve(get.result);
      get.onerror = () => reject(get.error);
    };
  });
}

async function decrypt(pathname) {
  const key = await loadKey();
  if (!key) throw new Response("Locked", { status: 403 });
  const res = await fetch(pathname, { cache: "no-cache" });
  if (!res.ok) throw res;
  const buf = new Uint8Array(await res.arrayBuffer());
  try {
    return await crypto.subtle.decrypt({ name: "AES-GCM", iv: buf.subarray(0, 12) }, key, buf.subarray(12));
  } catch {
    throw new Response("Locked", { status: 403 });
  }
}

async function serve(pathname) {
  if (!plain.has(pathname)) {
    const p = decrypt(pathname);
    plain.set(pathname, p);
    p.catch(() => plain.delete(pathname));
  }
  try {
    const body = await plain.get(pathname);
    return new Response(body, {
      headers: { "Content-Type": TYPES[pathname.split(".").pop().toLowerCase()] || "application/octet-stream" },
    });
  } catch (err) {
    return err instanceof Response ? err : new Response("Error", { status: 500 });
  }
}
