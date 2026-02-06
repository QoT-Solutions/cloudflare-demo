/* eslint-disable no-console */
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const dotenv = require('dotenv');

// Load environment variables from .env if present
dotenv.config();

const PORT = process.env.PORT || 3000;
const APP_VERSION = process.env.APP_VERSION || '1.0.0';
const isVulnerableMode = String(process.env.DEMO_VULN).toLowerCase() === 'true';
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'letmein-demo-token';
const DEMO_USER = process.env.DEMO_USER || 'alice';

const app = express();

// Basic body parsers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Helmet with CSP disabled so reflected XSS is obvious
app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

// Very simple logger so testers can see requests flowing through
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const ms = Date.now() - start;
    console.log(`${req.method} ${req.originalUrl} -> ${res.statusCode} (${ms}ms)`);
  });
  next();
});

// Serve static assets (images, etc.) with long-lived caching
const assetsDir = path.join(__dirname, 'assets');
app.use(
  '/assets',
  express.static(assetsDir, {
    setHeaders(res) {
      // Simulate hashed asset filenames being safe to cache aggressively.
      res.setHeader('Cache-Control', 'public, max-age=86400, immutable');
    }
  })
);

// --- Helper utilities ---

/**
 * Safely escape a string for HTML contexts.
 * Escapes &, <, >, " and ' in that order.
 *
 * @param {string} str
 * @returns {string}
 */
function escapeHtml(str) {
  if (typeof str !== 'string') {
    return '';
  }
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Get admin token from query param `token` or header `x-admin-token`.
 *
 * @param {import('express').Request} req
 * @returns {string | undefined}
 */
function getAdminTokenFromRequest(req) {
  if (req.query && typeof req.query.token === 'string') {
    return req.query.token;
  }
  const hdr = req.headers['x-admin-token'];
  if (typeof hdr === 'string') {
    return hdr;
  }
  if (Array.isArray(hdr) && hdr.length > 0) {
    return hdr[0];
  }
  return undefined;
}

/**
 * Generate a simple strong ETag for a given body string.
 *
 * @param {string} body
 * @returns {string}
 */
function generateEtag(body) {
  const hash = crypto.createHash('sha1').update(body, 'utf8').digest('hex');
  return `"${hash}"`;
}

/**
 * Very small cookie parser for demo purposes.
 *
 * @param {import('express').Request} req
 * @returns {Record<string, string>}
 */
function parseCookies(req) {
  const header = req.headers.cookie;
  if (!header || typeof header !== 'string') {
    return {};
  }
  return header.split(';').reduce((acc, part) => {
    const [rawKey, ...rest] = part.split('=');
    if (!rawKey) {
      return acc;
    }
    const key = rawKey.trim();
    const value = rest.join('=').trim();
    if (key) {
      acc[key] = decodeURIComponent(value || '');
    }
    return acc;
  }, {});
}

/**
 * Read demo user identity from header, cookie, or env default.
 *
 * @param {import('express').Request} req
 * @returns {string}
 */
function getDemoUser(req) {
  const headerUser = req.headers['x-demo-user'];
  if (typeof headerUser === 'string' && headerUser.trim()) {
    return headerUser.trim();
  }

  const cookies = parseCookies(req);
  if (cookies.demo_user && cookies.demo_user.trim()) {
    return cookies.demo_user.trim();
  }

  return DEMO_USER;
}

// --- Routes ---

// Home page
app.get('/', (req, res) => {
  const modeLabel = isVulnerableMode ? 'VULNERABLE DEMO MODE (DEMO_VULN=true)' : 'SAFE MODE (DEMO_VULN=false)';

  const samplePayload = `<script>alert('XSS from /search')</script>`;
  const escapedSamplePayload = escapeHtml(samplePayload);

  const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Cloudflare Tester Demo</title>
  <style>
    body { font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 2rem; line-height: 1.5; }
    code { background: #f4f4f4; padding: 0.1rem 0.3rem; border-radius: 3px; }
    pre { background: #f4f4f4; padding: 0.75rem; border-radius: 4px; overflow-x: auto; }
    .mode { padding: 0.5rem 0.75rem; border-radius: 4px; display: inline-block; margin-bottom: 1rem; font-weight: bold; }
    .mode.vuln { background: #ffe5e5; color: #a10000; }
    .mode.safe { background: #e5ffe5; color: #004d00; }
    ul { margin-top: 0.25rem; }
    h1, h2, h3 { margin-top: 1.2rem; }
  </style>
</head>
<body>
  <h1>Cloudflare Tester Demo with suprise!</h1>
  <div class="mode ${isVulnerableMode ? 'vuln' : 'safe'}">${modeLabel}</div>

  <p>
    This tiny Express app is intentionally simple so you can demonstrate
    <strong>Cloudflare WAF</strong>, <strong>Rate Limiting</strong>,
    <strong>Bot Management</strong>, <strong>Zero Trust Access</strong>,
    and <strong>Edge Caching / Performance</strong>.
  </p>

  <h2>Key Routes</h2>
  <ul>
    <li><a href="/">GET /</a> (this page)</li>
    <li><a href="/search">GET /search?q=...</a> – reflected XSS demo</li>
    <li><code>POST /login</code> – always returns 401 for brute-force / rate limiting</li>
    <li><a href="/api/data">GET /api/data</a> – simple JSON endpoint</li>
    <li><a href="/admin">GET /admin</a> – fake admin dashboard (token protected in safe mode)</li>
    <li><a href="/echo?foo=bar&x=1">GET /echo</a> – echoes query params as JSON</li>
    <li><a href="/version">GET /version</a> – version + caching demo (ETag, 304)</li>
    <li><a href="/page">GET /page</a> – HTML page with cacheable version + time</li>
    <li><a href="/product?currency=USD&amount=100">GET /product</a> – cache-key / query-string demo</li>
    <li><a href="/profile">GET /profile</a> – personalized page (no-cache)</li>
    <li><a href="/set-user?u=bob">GET /set-user?u=bob</a> – set demo_user cookie then redirect</li>
    <li><a href="/slow?ms=1500">GET /slow?ms=1500</a> – latency + edge caching demo</li>
    <li><a href="/welcome?country=ZA">GET /welcome?country=ZA</a> – geo / locale vary demo</li>
    <li><a href="/gallery">GET /gallery</a> – image optimization + caching demo</li>
    <li><a href="/purge-hint">GET /purge-hint</a> – cache purge explanation</li>
  </ul>

  <h2>1. Reflected XSS Demo (/search)</h2>
  <p>
    Use this payload as the <code>q</code> parameter:
  </p>
  <pre>${escapedSamplePayload}</pre>
  <p>
    Example URL:
  </p>
  <pre>/search?q=${encodeURIComponent(samplePayload)}</pre>
  <ul>
    <li>In <strong>VULNERABLE DEMO MODE</strong> (<code>DEMO_VULN=true</code>): the payload is reflected <em>unescaped</em> and should execute in the browser.</li>
    <li>In <strong>SAFE MODE</strong> (<code>DEMO_VULN=false</code>): the payload is properly escaped and shows up as text.</li>
  </ul>

  <h2>2. Brute Force / Rate Limiting Demo (/login)</h2>
  <p>
    Use the helper script to send multiple login attempts:
  </p>
  <pre>./scripts/brute-login.sh</pre>
  <p>
    Every request returns <code>401</code>. You can configure Cloudflare Rate Limiting / Bot detection
    rules on <code>POST /login</code> and watch them block or challenge traffic.
  </p>

  <h2>3. Admin Protection Demo (/admin)</h2>
  <ul>
    <li>In <strong>VULNERABLE DEMO MODE</strong>: no token is required – anyone can access <code>/admin</code>.</li>
    <li>In <strong>SAFE MODE</strong>: requests must include a valid token:
      <ul>
        <li>Query param: <code>?token=YOUR_ADMIN_TOKEN</code></li>
        <li>or Header: <code>x-admin-token: YOUR_ADMIN_TOKEN</code></li>
      </ul>
    </li>
  </ul>
  <p>
    In production demos, put <code>/admin</code> behind <strong>Cloudflare Zero Trust Access</strong>
    so only authenticated users can reach it, even if the app is misconfigured.
  </p>

  <h2>Environment Flags</h2>
  <pre>
PORT=3000
DEMO_VULN=true
ADMIN_TOKEN=letmein-demo-token
APP_VERSION=${APP_VERSION}
DEMO_USER=${DEMO_USER}
  </pre>
  <p>
    Toggle <code>DEMO_VULN</code> to switch between intentionally vulnerable and safer behavior.
  </p>

</body>
</html>
`;

  res.status(200).send(html);
});

// --- Version + caching (stale content) ---

// Plain-text version endpoint with ETag + Cache-Control
app.get('/version', (req, res) => {
  const body = `version=${APP_VERSION} time=${new Date().toISOString()}`;
  const etag = generateEtag(body);

  const ifNoneMatch = req.headers['if-none-match'];
  if (ifNoneMatch && ifNoneMatch === etag) {
    res.status(304);
    res.setHeader('ETag', etag);
    res.setHeader('Cache-Control', 'public, max-age=60');
    return res.end();
  }

  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.setHeader('ETag', etag);
  res.setHeader('Cache-Control', 'public, max-age=60');
  res.status(200).send(body);
});

// HTML page that can go stale due to caching
app.get('/page', (req, res) => {
  const now = new Date().toISOString();
  const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Version Page – Caching Demo</title>
</head>
<body>
  <h1>Version Page – Caching Demo</h1>
  <p><strong>Current version:</strong> ${escapeHtml(APP_VERSION)}</p>
  <p><strong>Server time now:</strong> ${escapeHtml(now)}</p>
  <p>
    This page is deliberately cacheable (<code>Cache-Control: public, max-age=60</code>),
    so you may see <em>stale content</em> while Cloudflare or the browser serves cached responses.
  </p>
  <p>
    Change <code>APP_VERSION</code>, redeploy, and refresh quickly to see old content being served from cache.
  </p>
  <p>
    See <a href="/purge-hint">/purge-hint</a> for tips on purging the cache.
  </p>
  <p><a href="/">Back to home</a></p>
</body>
</html>
`;

  res.setHeader('Cache-Control', 'public, max-age=60');
  res.status(200).send(html);
});

// --- Cache key / query-string correctness ---

app.get('/product', (req, res) => {
  const currencyRaw = typeof req.query.currency === 'string' ? req.query.currency : 'ZAR';
  const amountRaw = typeof req.query.amount === 'string' ? req.query.amount : '100';

  const currency = currencyRaw.toUpperCase();
  const amount = Number.parseFloat(amountRaw) || 100;

  let rate = 1.0;
  if (currency === 'USD') {
    rate = 0.055;
  } else if (currency === 'EUR') {
    rate = 0.05;
  }

  const convertedExample = Number((amount * rate).toFixed(2));

  res.setHeader('Cache-Control', 'public, max-age=120');
  res.json({
    currency,
    amount,
    convertedExample,
    cacheKeyHint: 'cache key should include currency + amount'
  });
});

// --- Personalization (do NOT cache) ---

app.get('/profile', (req, res) => {
  const user = getDemoUser(req);
  const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Profile – Personalization Demo</title>
</head>
<body>
  <h1>Profile – Personalization Demo</h1>
  <p>Hello, ${escapeHtml(user)}</p>
  <p>
    This response is personalized per user and <strong>must not be cached</strong>.
    Caching personalized pages is a serious security and privacy bug.
  </p>
  <p>
    Identity is read from:
  </p>
  <ul>
    <li>Header <code>X-Demo-User</code></li>
    <li>or Cookie <code>demo_user</code></li>
    <li>or env default <code>DEMO_USER</code> (${escapeHtml(DEMO_USER)})</li>
  </ul>
  <p>
    Try <a href="/set-user?u=bob">/set-user?u=bob</a> and then reload this page.
  </p>
  <p><a href="/">Back to home</a></p>
</body>
</html>
`;

  res.setHeader('Cache-Control', 'private, no-store');
  res.setHeader('Vary', 'Cookie, X-Demo-User');
  res.status(200).send(html);
});

app.get('/set-user', (req, res) => {
  const u = typeof req.query.u === 'string' && req.query.u.trim() ? req.query.u.trim() : DEMO_USER;
  const encoded = encodeURIComponent(u);
  // HttpOnly intentionally omitted so testers can see the cookie in DevTools.
  res.setHeader('Set-Cookie', `demo_user=${encoded}; Path=/; Max-Age=3600`);
  res.redirect('/profile');
});

// --- Latency / edge performance ---

app.get('/slow', (req, res) => {
  const raw = typeof req.query.ms === 'string' ? req.query.ms : '';
  let ms = Number.parseInt(raw, 10);
  if (Number.isNaN(ms)) {
    ms = 1200;
  }
  if (ms < 0) ms = 0;
  if (ms > 5000) ms = 5000;

  const start = Date.now();

  setTimeout(() => {
    const waitedMs = Date.now() - start;
    res.setHeader('Cache-Control', 'public, max-age=60');
    res.setHeader('Server-Timing', `app-wait;dur=${waitedMs}`);
    res.json({
      ok: true,
      waitedMs,
      time: new Date().toISOString()
    });
  }, ms);
});

// --- Geo / locale variations ---

app.get('/welcome', (req, res) => {
  const acceptLangHeader = typeof req.headers['accept-language'] === 'string' ? req.headers['accept-language'] : '';
  const primaryLang = acceptLangHeader.split(',')[0].trim().toLowerCase();
  const country = typeof req.query.country === 'string' ? req.query.country : '';

  let greeting = 'Hello';
  if (primaryLang.startsWith('fr')) {
    greeting = 'Bonjour';
  } else if (primaryLang.startsWith('es')) {
    greeting = 'Hola';
  }

  const fromPart = country ? ` from ${escapeHtml(country)}` : '';

  const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Welcome – Geo / Locale Demo</title>
</head>
<body>
  <h1>Welcome – Geo / Locale Demo</h1>
  <p>${greeting}${fromPart}!</p>
  <p>
    This response varies by <code>Accept-Language</code> and optional <code>?country=...</code> query param.
  </p>
  <p>
    Check the <strong>Vary</strong> and <strong>Cache-Control</strong> headers to see how caches should treat
    localized content.
  </p>
  <p><a href="/">Back to home</a></p>
</body>
</html>
`;

  res.setHeader('Vary', 'Accept-Language');
  res.setHeader('Cache-Control', 'public, max-age=120');
  res.status(200).send(html);
});

// --- Image optimization demo ---

app.get('/gallery', (req, res) => {
  const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Image Gallery – Optimization Demo</title>
</head>
<body>
  <h1>Image Gallery – Optimization Demo</h1>
  <p>
    All images below reference the same origin file <code>/assets/hero.jpg</code>, but use different query
    parameters as <em>hints</em> for Cloudflare Image Resizing / Optimization.
  </p>
  <p>
    This app does <strong>not</strong> resize images itself – it always serves the original file.
    Enable Cloudflare Image Optimization to see changes in <code>Content-Type</code>, file size,
    and formats (WebP/AVIF) in your browser Network panel.
  </p>

  <h2>Original</h2>
  <img src="/assets/hero.jpg" alt="Hero original" style="max-width: 100%; border: 1px solid #ccc;" />

  <h2>Hints for different sizes (same origin file)</h2>
  <p>These URLs are identical on the origin, but Cloudflare can treat them differently based on query params:</p>
  <ul>
    <li><img src="/assets/hero.jpg?w=200" alt="Hero 200w hint" /></li>
    <li><img src="/assets/hero.jpg?w=600" alt="Hero 600w hint" /></li>
    <li><img src="/assets/hero.jpg?w=1200&format=webp" alt="Hero 1200w WebP hint" /></li>
  </ul>

  <p>
    In DevTools, compare:
  </p>
  <ul>
    <li><strong>Content-Type</strong> (e.g. image/jpeg vs image/webp)</li>
    <li>Response size</li>
    <li><strong>Cache-Control</strong> and any Cloudflare-specific headers</li>
  </ul>

  <p><a href="/">Back to home</a></p>
</body>
</html>
`;

  res.setHeader('Cache-Control', 'public, max-age=300');
  res.status(200).send(html);
});

// --- Purge hint page ---

app.get('/purge-hint', (req, res) => {
  const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Purge Hint – Cloudflare Cache</title>
</head>
<body>
  <h1>Purge Hint – Cloudflare Cache</h1>
  <p>
    The <code>/version</code> and <code>/page</code> endpoints are deliberately cacheable with
    <code>Cache-Control: public, max-age=60</code> and (for <code>/version</code>) an <code>ETag</code>.
  </p>
  <p>
    When Cloudflare caching is enabled, you should expect to see <strong>stale content</strong> for up to 60 seconds
    after deployment or version changes, unless you purge the cache.
  </p>
  <h2>Things to Try</h2>
  <ol>
    <li>Open <code>/version</code> and <code>/page</code> in a browser while watching the Network panel.</li>
    <li>Change <code>APP_VERSION</code> or redeploy the app.</li>
    <li>Refresh several times and note when responses are served from cache vs origin.</li>
    <li>Use Cloudflare's <strong>Purge Cache</strong> (URL or cache-tag rules) and observe how quickly new content appears.</li>
  </ol>
  <p>
    Check HTTP status codes (<code>200</code> vs <code>304</code>), <code>Cache-Control</code>, and any Cloudflare
    cache headers to understand what is happening at the edge.
  </p>
  <p><a href="/">Back to home</a></p>
</body>
</html>
`;

  res.status(200).send(html);
});

// Reflected XSS demo
app.get('/search', (req, res) => {
  const q = typeof req.query.q === 'string' ? req.query.q : '';

  const modeNote = isVulnerableMode
    ? 'VULNERABLE DEMO MODE: user input is reflected without escaping. This is intentionally unsafe.'
    : 'SAFE MODE: user input is escaped before rendering.';

  let reflected;
  if (!q) {
    reflected = '<em>No query provided. Try adding ?q=... to the URL.</em>';
  } else if (isVulnerableMode) {
    // Intentionally unsafe: raw reflection
    reflected = q;
  } else {
    // Safe mode: escape before embedding
    reflected = escapeHtml(q);
  }

  const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>/search – Cloudflare Tester Demo</title>
</head>
<body>
  <h1>/search – Reflected XSS Demo</h1>
  <p>${modeNote}</p>

  <form method="GET" action="/search">
    <label for="q">Search term (will be echoed back):</label>
    <input id="q" type="text" name="q" value="${escapeHtml(q)}" style="min-width: 300px;" />
    <button type="submit">Search</button>
  </form>

  <h2>Reflected output</h2>
  <div style="padding: 0.5rem; border: 1px solid #ccc; margin-top: 0.5rem;">
    ${reflected}
  </div>

  <p><a href="/">Back to home</a></p>
</body>
</html>
`;

  res.status(200).send(html);
});

// Login endpoint for brute force / rate limiting demo
app.post('/login', (req, res) => {
  // Credentials are deliberately ignored.
  res.status(401).json({
    ok: false,
    message: 'Invalid credentials'
  });
});

// Simple data API
app.get('/api/data', (req, res) => {
  res.json({
    ok: true,
    time: new Date().toISOString(),
    note: 'Demo data endpoint for Cloudflare WAF / Rate Limiting / Bot demos.'
  });
});

// Admin dashboard
app.get('/admin', (req, res) => {
  if (!isVulnerableMode) {
    const token = getAdminTokenFromRequest(req);
    if (!token || token !== ADMIN_TOKEN) {
      return res.status(401).send(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Unauthorized</title>
</head>
<body>
  <h1>401 – Unauthorized</h1>
  <p>Valid admin token required.</p>
  <ul>
    <li>Query param: <code>?token=YOUR_ADMIN_TOKEN</code></li>
    <li>or Header: <code>x-admin-token: YOUR_ADMIN_TOKEN</code></li>
  </ul>
  <p><a href="/">Back to home</a></p>
</body>
</html>
      `);
    }
  }

  const modeText = isVulnerableMode
    ? 'VULNERABLE DEMO MODE – no app-level auth is enforced here. Protect this with Cloudflare Access.'
    : 'SAFE MODE – request passed token check.';

  const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Admin Dashboard</title>
</head>
<body>
  <h1>Admin Dashboard</h1>
  <p>${modeText}</p>
  <p>This is a fake admin page used to demonstrate how Cloudflare Access can protect sensitive routes.</p>
  <p><a href="/">Back to home</a></p>
</body>
</html>
`;

  res.status(200).send(html);
});

// Echo endpoint – shows what query params reached the app
app.get('/echo', (req, res) => {
  res.json({
    ok: true,
    query: req.query
  });
});

// Fallback 404 to keep behavior explicit in demos
app.use((req, res) => {
  res.status(404).json({
    ok: false,
    message: 'Not found'
  });
});

app.listen(PORT, () => {
  console.log(`Cloudflare Tester Demo listening on http://localhost:${PORT}`);
  console.log(`Vulnerable demo mode: ${isVulnerableMode ? 'ENABLED (DEMO_VULN=true)' : 'DISABLED (DEMO_VULN=false)'}`);
});

