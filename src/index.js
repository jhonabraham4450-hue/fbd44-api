
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

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
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
        return response({ success: false, message: "Database binding DB missing" }, 500);
      }

      if (path === "/api/register" && request.method === "POST") {
        const body = await request.json();
        const name = String(body.name || "").trim();
        const password = String(body.password || "");
        const email = String(body.email || "").trim().toLowerCase();
        const phone = String(body.phone || body.mobile || "").trim();

        if (!name || password.length < 6 || (!email && !phone)) {
          return response({
            success: false,
            message: "Name, phone or email, and password (minimum 6 characters) are required"
          }, 400);
        }

        const finalEmail = email || `${phone}@fbd44.local`;
        const existing = await env.DB.prepare(
          "SELECT id FROM users WHERE email = ? OR (? != '' AND phone = ?) LIMIT 1"
        ).bind(finalEmail, phone, phone).first();

        if (existing) {
          return response({ success: false, message: "Account already exists" }, 409);
        }

        const id = crypto.randomUUID();
        const salt = crypto.randomUUID();
        const passwordHash = await hashPassword(password, salt);

        await env.DB.prepare(
          "INSERT INTO users (id, name, email, password_hash, password_salt, role, phone) VALUES (?, ?, ?, ?, ?, 'user', ?)"
        ).bind(id, name, finalEmail, passwordHash, salt, phone || null).run();

        return response({
          success: true,
          message: "Registration successful",
          user: { id, name, email: finalEmail, phone }
        }, 201);
      }

      if (path === "/api/login" && request.method === "POST") {
        const body = await request.json();
        const identity = String(body.email || body.phone || body.mobile || body.username || "").trim().toLowerCase();
        const password = String(body.password || "");

        if (!identity || !password) {
          return response({ success: false, message: "Enter email or phone and password" }, 400);
        }

        const user = await env.DB.prepare(
          "SELECT id, name, email, phone, password_hash, password_salt, role FROM users WHERE lower(email) = ? OR phone = ? LIMIT 1"
        ).bind(identity, identity).first();

        if (!user) {
          return response({ success: false, message: "Invalid login details" }, 401);
        }

        const check = await hashPassword(password, user.password_salt);

        if (check !== user.password_hash) {
          return response({ success: false, message: "Invalid login details" }, 401);
        }

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

      return response({ success: false, message: "API route not found" }, 404);

    } catch (error) {
      return response({
        success: false,
        message: "Server error",
        detail: error.message
      }, 500);
    }
  }
};


