const http = require("http");
const fs = require("fs");
const path = require("path");
const { URL } = require("url");

const PORT = process.env.PORT || 3000;
const ROOT_DIR = __dirname;

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".mp3": "audio/mpeg",
  ".wav": "audio/wav",
  ".webp": "image/webp",
  ".gif": "image/gif",
  ".txt": "text/plain; charset=utf-8"
};

function getCookies(header = "") {
  return Object.fromEntries(
    header
      .split(";")
      .map((cookie) => cookie.trim())
      .filter(Boolean)
      .map((cookie) => {
        const index = cookie.indexOf("=");
        const key = index >= 0 ? cookie.slice(0, index) : cookie;
        const value = index >= 0 ? cookie.slice(index + 1) : "";
        return [key, value];
      })
  );
}

function isAuthenticated(req) {
  const cookies = getCookies(req.headers.cookie || "");
  const expiresAt = sessions.get(cookies[AUTH_COOKIE]);
  if (!expiresAt) return false;
  if (expiresAt <= Date.now()) {
    sessions.delete(cookies[AUTH_COOKIE]);
    return false;
  }
  return true;
}

function setAuthCookie(res) {
  const token = crypto.randomBytes(32).toString("base64url");
  sessions.set(token, Date.now() + SESSION_TTL_MS);
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  res.setHeader("Set-Cookie", `${AUTH_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${SESSION_TTL_MS / 1000}${secure}`);
}

function clearAuthCookie(req, res) {
  const cookies = getCookies(req.headers.cookie || "");
  sessions.delete(cookies[AUTH_COOKIE]);
  res.setHeader("Set-Cookie", `${AUTH_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`);
}

function getClientAddress(req) {
  return req.headers["x-forwarded-for"]?.split(",")[0].trim() || req.socket.remoteAddress || "unknown";
}

function isRateLimited(address) {
  const now = Date.now();
  const record = loginAttempts.get(address);
  if (!record || record.resetAt <= now) {
    loginAttempts.set(address, { count: 0, resetAt: now + LOGIN_WINDOW_MS });
    return false;
  }
  return record.count >= MAX_LOGIN_ATTEMPTS;
}

function recordFailedLogin(address) {
  const record = loginAttempts.get(address) || { count: 0, resetAt: Date.now() + LOGIN_WINDOW_MS };
  record.count += 1;
  loginAttempts.set(address, record);
}

function buildLoginPage(errorMessage = "") {
  const message = errorMessage ? `<p class="error">${errorMessage}</p>` : "<p class=\"helper\">Enter the password to unlock the site.</p>";
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>BlueNote Access</title>
  <style>
    :root {
      --bg: #0f172a;
      --panel: #111827;
      --panel-border: #2d3748;
      --text: #e5e7eb;
      --muted: #94a3b8;
      --accent: #22c55e;
      --danger: #ef4444;
      --shadow: rgba(0,0,0,.25);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      background: linear-gradient(135deg, #0f172a, #111827 45%, #0b1120);
      color: var(--text);
      font-family: Arial, sans-serif;
    }
    .card {
      width: min(92vw, 420px);
      background: rgba(17,24,39,.92);
      border: 1px solid var(--panel-border);
      border-radius: 18px;
      padding: 32px 28px;
      box-shadow: 0 24px 80px var(--shadow);
    }
    h1 {
      margin: 0 0 10px;
      font-size: 2rem;
      letter-spacing: -0.04em;
    }
    .helper, .error {
      margin: 0 0 18px;
      color: var(--muted);
      font-size: 0.95rem;
    }
    .error {
      color: #fecaca;
      background: rgba(239,68,68,.12);
      border: 1px solid rgba(239,68,68,.32);
      border-radius: 8px;
      padding: 10px 12px;
    }
    form {
      display: grid;
      gap: 14px;
    }
    label {
      font-size: 0.85rem;
      color: var(--muted);
    }
    input {
      width: 100%;
      padding: 12px 14px;
      border: 1px solid var(--panel-border);
      border-radius: 10px;
      background: #0b1220;
      color: var(--text);
      font-size: 1rem;
    }
    button {
      border: 0;
      border-radius: 10px;
      padding: 12px 16px;
      background: linear-gradient(135deg, #16a34a, #22c55e);
      color: white;
      font-weight: 700;
      cursor: pointer;
      font-size: 1rem;
    }
    button:hover { filter: brightness(1.06); }
  </style>
</head>
<body>
  <div class="card">
    <h1>BlueNote</h1>
    ${message}
    <form method="POST" action="/login">
      <label for="password">Password</label>
      <input id="password" name="password" type="password" placeholder="Enter password" autocomplete="current-password" required>
      <button type="submit">Unlock site</button>
    </form>
  </div>
</body>
</html>`;
}

function serveFile(res, filePath) {
  fs.readFile(filePath, (error, content) => {
    if (error) {
      res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("Not found");
      return;
    }

    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, { "Content-Type": MIME_TYPES[ext] || "application/octet-stream" });
    res.end(content);
  });
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";

    req.on("data", (chunk) => {
      data += chunk;
      if (data.length > 1_000_000) {
        reject(new Error("Payload too large"));
        req.destroy();
      }
    });

    req.on("end", () => {
      if (!data) {
        resolve({});
        return;
      }

      try {
        const params = new URLSearchParams(data);
        const result = {};
        for (const [key, value] of params.entries()) {
          result[key] = value;
        }
        resolve(result);
      } catch (error) {
        reject(error);
      }
    });

    req.on("error", reject);
  });
}

const server = http.createServer((req, res) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  const url = new URL(req.url, `http://${req.headers.host}`);
  const pathname = decodeURIComponent(url.pathname === "/login" ? "/" : url.pathname);

  const safePath = pathname === "/" ? path.join(ROOT_DIR, "index.html") : path.join(ROOT_DIR, pathname);
  const normalizedRoot = path.resolve(ROOT_DIR);
  const normalizedTarget = path.resolve(safePath);

  if (!normalizedTarget.startsWith(normalizedRoot)) {
    res.writeHead(403, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("Forbidden");
    return;
  }

  serveFile(res, normalizedTarget);
});

server.listen(PORT, () => {
  console.log(`BlueNote protected app running at http://localhost:${PORT}`);
});
