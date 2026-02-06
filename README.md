## Cloudflare Tester Demo

This is a tiny, intentionally vulnerable **Node.js + Express** app designed to help QA testers and engineers
demonstrate **Cloudflare WAF**, **Rate Limiting**, **Bot Detection**, and **Zero Trust Access**.

The app has a switchable **“VULNERABLE DEMO MODE”** controlled by an environment variable so you can show
before/after behavior safely and predictably.

---

### Features

- **Node + Express (CommonJS)** – no database, minimal dependencies.
- **Reflected XSS demo** at `GET /search?q=...`.
- **Brute force / rate limiting demo** at `POST /login`.
- **Simple JSON API** at `GET /api/data`.
- **Admin dashboard** at `GET /admin`:
  - Open to everyone in vulnerable mode.
  - Token-protected in safe mode.
- **Echo endpoint** at `GET /echo` that just returns query params.
- **Helmet** is enabled but **CSP is disabled** so reflected XSS is easy to demonstrate.
 - **Version and HTML page caching** at `GET /version` and `GET /page` (ETag, cache-control).
 - **Cache-key/query-string behavior** at `GET /product`.
 - **Personalized profile** at `GET /profile` and `GET /set-user`.
 - **Latency + edge caching** at `GET /slow`.
 - **Geo/locale variations** at `GET /welcome`.
 - **Image optimization demo** at `GET /gallery` (with static `/assets/hero.jpg`).

---

### Getting Started (Local)

1. **Clone and enter the repo**

   ```bash
   git clone <your-fork-or-copy-url> cloudflare-tester-demo
   cd cloudflare-tester-demo
   ```

2. **Create your `.env`**

   ```bash
   cp .env.example .env
   ```

   The example values are:

   ```env
   PORT=3000
   DEMO_VULN=true
   ADMIN_TOKEN=letmein-demo-token
   APP_VERSION=1.0.0
   DEMO_USER=alice
   ```

3. **Install dependencies**

   ```bash
   npm install
   ```

4. **Run the app**

   ```bash
   npm start
   ```

   The app listens on `http://localhost:3000` by default.

---

### Toggling Vulnerable Demo Mode

The behavior is driven by the `DEMO_VULN` environment variable:

- **Vulnerable demo mode** (`DEMO_VULN=true`):
  - `/search` reflects the `q` parameter directly into HTML **without escaping** (reflected XSS).
  - `/admin` is accessible to everyone, with **no token required**.
- **Safe mode** (`DEMO_VULN=false`):
  - `/search` escapes HTML special characters in `q` using a helper that correctly handles `&`, `<`, `>`, `"` and `'`.
  - `/admin` requires a valid admin token.

To switch:

```bash
# Edit .env
DEMO_VULN=false

# Then restart the server
npm start
```

---

### Important Routes

- **Home**

  - `GET /`
  - Simple HTML page with links and a summary of how to use the demo.
  - Shows whether vulnerable mode is enabled.

- **Version + Caching**

  - `GET /version`
  - `GET /page`
  - Used to demonstrate stale content, ETag/304, and Cloudflare cache purging.

- **Reflected XSS**

  - `GET /search?q=...`
  - Use payload:
    ```text
    <script>alert('XSS from /search')</script>
    ```
  - In vulnerable mode it executes; in safe mode it is shown as text.

- **Brute Force / Rate Limiting Target**

  - `POST /login`
  - Always responds with:
    ```json
    { "ok": false, "message": "Invalid credentials" }
    ```
  - HTTP status code is always `401`.

- **JSON API**

  - `GET /api/data`
  - Returns:
    ```json
    {
      "ok": true,
      "time": "2025-01-01T12:34:56.789Z",
      "note": "Demo data endpoint for Cloudflare WAF / Rate Limiting / Bot demos."
    }
    ```

- **Admin Dashboard**

  - `GET /admin`
  - Vulnerable mode (`DEMO_VULN=true`):
    - No token required; everyone can see the "admin" page.
  - Safe mode (`DEMO_VULN=false`):
    - Requires token from either:
      - Query: `GET /admin?token=YOUR_ADMIN_TOKEN`
      - Header: `x-admin-token: YOUR_ADMIN_TOKEN`

- **Echo Endpoint**

  - `GET /echo?foo=bar&x=1`
  - Response:
    ```json
    {
      "ok": true,
      "query": {
        "foo": "bar",
        "x": "1"
      }
    }
    ```

- **Product / Cache Key**

  - `GET /product?currency=USD&amount=100`
  - Demonstrates why cache keys should include query string parameters like `currency` and `amount`.

- **Profile / Personalization**

  - `GET /profile`
  - `GET /set-user?u=bob`
  - Shows how user-specific content must not be cached.

- **Latency / Slow Origin**

  - `GET /slow?ms=1500`
  - Simulates slow origin responses that can be accelerated by edge caching.

- **Geo / Locale**

  - `GET /welcome?country=ZA`
  - Uses `Accept-Language` + `country` query param to vary content.

- **Image Gallery / Optimization**

  - `GET /gallery`
  - Renders multiple `<img>` tags pointing at `/assets/hero.jpg` with different query params as hints for Cloudflare image optimization.

---

### Brute Force Demo Script

A helper script is provided at `scripts/brute-login.sh`.

Make it executable:

```bash
chmod +x scripts/brute-login.sh
```

Run it:

```bash
./scripts/brute-login.sh
```

You should see 25 attempts, each returning HTTP `401`. This is ideal for:

- Showing **Cloudflare Rate Limiting** kicking in after `N` requests.
- Demonstrating **Bot Management** / challenges.
- Confirming that blocked requests never reach your Express logs.

You can also override the base URL:

```bash
BASE_URL="https://your-demo-domain.example" ./scripts/brute-login.sh
```

---

### Running with Docker

Build the image:

```bash
docker build -t cloudflare-tester-demo .
```

Run the container:

```bash
docker run --rm -p 3000:3000 \
  -e PORT=3000 \
  -e DEMO_VULN=true \
  -e ADMIN_TOKEN=letmein-demo-token \
  cloudflare-tester-demo
```

Then open `http://localhost:3000`.

---

### Hosting & Safety Warning

This repo is **for ethical testing and training only**.

- The app is intentionally vulnerable when `DEMO_VULN=true`.
- **Do not** expose it directly to the public internet as-is.
- If you must put it on a public URL:
  - Run in **safe mode** (`DEMO_VULN=false`) unless actively demonstrating a specific issue.
  - Put `/admin` (and any other sensitive paths) behind **Cloudflare Zero Trust Access**.
  - Use **Cloudflare WAF / Rate Limiting / Bot Detection** to control traffic.

Treat this as a lab environment, not production software.

---

### Cloudflare Scenarios for Testers

- **Caching / Stale Content – `/version` and `/page`**
  - **What to do**: Hit `/version` and `/page` repeatedly in the browser, then change `APP_VERSION` or redeploy. Optionally enable Cloudflare caching on these paths.
  - **Observe in DevTools**: `Cache-Control: public, max-age=60`, `ETag` on `/version`, and status codes `200` vs `304`. With Cloudflare, also watch any cache-related response headers and when content actually updates.
  - **Cloudflare levers**: Cache Rules (cache by URL or path), Purge (single-file or cache-tag), and edge cache TTL.

- **Cache Key / Query Strings – `/product`**
  - **What to do**: Call `/product?currency=USD&amount=100` and `/product?currency=EUR&amount=100` and `/product?currency=USD&amount=200`. Repeat requests to see when Cloudflare serves from cache.
  - **Observe in DevTools**: `Cache-Control: public, max-age=120`, response JSON differences (`currency`, `amount`, `convertedExample`), and whether Cloudflare treats different query combos as separate cache entries.
  - **Cloudflare levers**: Cache Rules (cache by full URL vs ignoring some query params), Cache Key customization (include/exclude/query normalization).

- **Personalization No-Cache – `/profile` + `/set-user`**
  - **What to do**: Visit `/profile` with no extra headers/cookies, then hit `/set-user?u=bob` and refresh `/profile`. Optionally send a custom `X-Demo-User` header.
  - **Observe in DevTools**: Headers `Cache-Control: private, no-store` and `Vary: Cookie, X-Demo-User`. Confirm that the HTML body includes the right username and that shared caches should not reuse responses across users.
  - **Cloudflare levers**: Disable caching of personalized routes, bypass cache on cookie/header, and Zero Trust Access for authenticated user paths.

- **Latency & Edge Caching – `/slow`**
  - **What to do**: Hit `/slow?ms=1500` a few times. First request should be slow; subsequent ones can be cached at the edge when Cloudflare is configured to cache it.
  - **Observe in DevTools**: Response time, `Cache-Control: public, max-age=60`, and `Server-Timing: app-wait;dur=...`. With Cloudflare caching, note that later responses become fast even though origin simulates latency.
  - **Cloudflare levers**: Cache Rules for dynamic-but-cacheable routes, edge TTL, and performance analytics for origin vs edge latency.

- **Geo / Locale Vary – `/welcome`**
  - **What to do**: Hit `/welcome?country=ZA` with different `Accept-Language` settings (e.g. `en`, `fr`, `es`). Use browser settings or tools like `curl -H "Accept-Language: fr"`.
  - **Observe in DevTools**: `Vary: Accept-Language`, `Cache-Control: public, max-age=120`, and body text changing (`Hello`, `Bonjour`, `Hola`). Verify that caches keep separate variants per language.
  - **Cloudflare levers**: Cache key customization (include headers like `Accept-Language`), and localization rules (geo-based routing, page rules).

- **Image Optimization – `/gallery` + `/assets/hero.jpg`**
  - **What to do**: Open `/gallery` with Cloudflare Image Optimization enabled. Reload several times and inspect each image request.
  - **Observe in DevTools**: Requests to `/assets/hero.jpg` with different query params, `Content-Type` possibly changing from `image/jpeg` to `image/webp`/`image/avif`, differences in response size, and `Cache-Control: public, max-age=86400, immutable` on the static asset.
  - **Cloudflare levers**: Polish / Image Optimization, image resizing, and cache rules for static assets.

---

### Quick Demo Flow

1. **XSS Demo (`/search`)**
   - Start the app with `DEMO_VULN=true`.
   - Visit:  
     `http://localhost:3000/search?q=<script>alert('XSS from /search')</script>`
   - Observe: the alert fires because CSP is disabled and the input is reflected unescaped.
   - Switch to `DEMO_VULN=false`, reload the same URL, and note that the payload is now shown as harmless text.

2. **Rate Limiting Demo (`/login`)**
   - With the app running, execute:
     ```bash
     ./scripts/brute-login.sh
     ```
   - Observe 25 consecutive `401` responses.
   - Configure Cloudflare Rate Limiting or Bot rules on `POST /login` and re-run the script to show requests being blocked, challenged, or delayed.

3. **Admin Protection Demo (`/admin`)**
   - In vulnerable mode (`DEMO_VULN=true`), show that anyone can access `http://your-demo-domain/admin` with no token.
   - Then configure Cloudflare Zero Trust Access so only authenticated users can reach `/admin`.
   - Optionally switch to safe mode (`DEMO_VULN=false`) and demonstrate the additional in-app token check via `?token=ADMIN_TOKEN` or `x-admin-token` header.

4. **Caching & Stale Content (`/version`, `/page`)**
   - With caching enabled, hit `/version` and `/page` repeatedly, then change `APP_VERSION` and redeploy.
   - Show that clients or Cloudflare may keep serving old content until TTL expires or you purge cache; highlight `Cache-Control`, `ETag`, and `200/304` responses.

5. **Personalization & No-Cache (`/profile`, `/set-user`)**
   - Visit `/profile`, then `/set-user?u=bob`, and reload `/profile` to see the name change.
   - Confirm no caching via `Cache-Control: private, no-store` and `Vary: Cookie, X-Demo-User`, and explain why shared caching here would be a vulnerability.

6. **Latency & Edge Caching (`/slow`)**
   - Hit `/slow?ms=1500` and note slow origin time, then configure Cloudflare to cache it and show subsequent fast responses with the same JSON.

7. **Geo/Locale & Image Optimization (`/welcome`, `/gallery`)**
   - Call `/welcome?country=ZA` with different `Accept-Language` headers to see localized greetings and `Vary: Accept-Language`.
   - Open `/gallery` and compare image responses (type, size, format) before and after enabling Cloudflare image optimization.

