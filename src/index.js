
const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization"
};

function response(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...corsHeaders,
      "Content-Type": "application/json"
    }
  });
}

async function hashPassword(password, salt) {
  const encoder = new TextEncoder();

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: encoder.encode(salt),
      iterations: 100000,
      hash: "SHA-256"
    },
    key,
    256
  );

  return [...new Uint8Array(bits)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

async function ensureLoginTable(DB) {
  await DB.prepare(`
    CREATE TABLE IF NOT EXISTS login_logs (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      username TEXT,
      identity TEXT,
      ip_address TEXT,
      user_agent TEXT,
      login_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();
}

function isAdmin(request, env) {
  const auth = request.headers.get("Authorization") || "";
  const token = auth.startsWith("Bearer ")
    ? auth.slice(7)
    : "";

  return Boolean(
    env.ADMIN_SECRET &&
    token &&
    token === env.ADMIN_SECRET
  );
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders
      });
    }

    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "");

    try {
      if (path === "/api/health" || path === "/health") {
        return response({
          success: true,
          message: "FBD44 API is running"
        });
      }

      if (!env.DB) {
        return response({
          success: false,
          message: "Database binding DB missing"
        }, 500);
      }

      // REGISTER
      if (path === "/api/register" && request.method === "POST") {
        const body = await request.json();

        const name = String(
          body.name || body.username || ""
        ).trim();

        const password = String(body.password || "");

        const email = String(body.email || "")
          .trim()
          .toLowerCase();

        const phone = String(
          body.phone || body.mobile || ""
        ).trim();

        if (!name || password.length < 6 || (!email && !phone)) {
          return response({
            success: false,
            message: "Username, phone or email, and password (minimum 6 characters) are required"
          }, 400);
        }

        const finalEmail = email || `${phone}@fbd44.local`;

        const existing = await env.DB.prepare(
          `SELECT id FROM users
           WHERE lower(email) = lower(?)
           OR (? != '' AND phone = ?)
           OR lower(name) = lower(?)
           LIMIT 1`
        ).bind(
          finalEmail,
          phone,
          phone,
          name
        ).first();

        if (existing) {
          return response({
            success: false,
            message: "Account already exists"
          }, 409);
        }

        const id = crypto.randomUUID();
        const salt = crypto.randomUUID();

        const passwordHash = await hashPassword(
          password,
          salt
        );

        await env.DB.prepare(
          `INSERT INTO users
          (id, name, email, password_hash, password_salt, role, phone)
          VALUES (?, ?, ?, ?, ?, 'user', ?)`
        ).bind(
          id,
          name,
          finalEmail,
          passwordHash,
          salt,
          phone || null
        ).run();

        return response({
          success: true,
          message: "Registration successful",
          user: {
            id,
            name,
            email: finalEmail,
            phone,
            role: "user"
          }
        }, 201);
      }

      // LOGIN
      if (path === "/api/login" && request.method === "POST") {
        const body = await request.json();

        const identity = String(
          body.email ||
          body.phone ||
          body.mobile ||
          body.username ||
          ""
        ).trim().toLowerCase();

        const password = String(body.password || "");

        if (!identity || !password) {
          return response({
            success: false,
            message: "Enter username, email or phone and password"
          }, 400);
        }

        const user = await env.DB.prepare(
          `SELECT id, name, email, phone,
          password_hash, password_salt, role
          FROM users
          WHERE lower(email) = ?
          OR phone = ?
          OR lower(name) = ?
          LIMIT 1`
        ).bind(
          identity,
          identity,
          identity
        ).first();

        if (!user) {
          return response({
            success: false,
            message: "Invalid login details"
          }, 401);
        }

        const check = await hashPassword(
          password,
          user.password_salt
        );

        if (check !== user.password_hash) {
          return response({
            success: false,
            message: "Invalid login details"
          }, 401);
        }

        // Save successful login history
        await ensureLoginTable(env.DB);

        await env.DB.prepare(
          `INSERT INTO login_logs
          (id, user_id, username, identity, ip_address, user_agent)
          VALUES (?, ?, ?, ?, ?, ?)`
        ).bind(
          crypto.randomUUID(),
          user.id,
          user.name,
          identity,
          request.headers.get("CF-Connecting-IP") || "Unknown",
          request.headers.get("User-Agent") || "Unknown"
        ).run();

        return response({
          success: true,
          message: "Login successful",
          user: {
            id: user.id,
            name: user.name,
            email: user.email,
            phone: user.phone,
            role: user.role
          }
        });
      }

      // ADMIN: REGISTERED USERS
      if (path === "/api/admin/users" && request.method === "GET") {
        if (!isAdmin(request, env)) {
          return response({
            success: false,
            message: "Unauthorized admin access"
          }, 401);
        }

        const result = await env.DB.prepare(
          `SELECT id, name, email, phone, role
           FROM users
           ORDER BY rowid DESC`
        ).all();

        return response({
          success: true,
          total: result.results.length,
          users: result.results
        });
      }

      // ADMIN: LOGIN HISTORY
      if (path === "/api/admin/logins" && request.method === "GET") {
        if (!isAdmin(request, env)) {
          return response({
            success: false,
            message: "Unauthorized admin access"
          }, 401);
        }

        await ensureLoginTable(env.DB);

        const result = await env.DB.prepare(
          `SELECT id, user_id, username, identity,
          ip_address, user_agent, login_at
          FROM login_logs
          ORDER BY login_at DESC
          LIMIT 500`
        ).all();

        return response({
          success: true,
          total: result.results.length,
          logins: result.results
        });
      }

      return response({
        success: false,
        message: "API route not found"
      }, 404);

    } catch (error) {
      return response({
        success: false,
        message: "Server error"
      }, 500);
    }
  }
};
