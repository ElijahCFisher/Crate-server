const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';

const SESSION_TTL_SECONDS = 60 * 60 * 24 * 30; // 30 days
const ACCESS_TOKEN_REFRESH_BUFFER_MS = 60 * 1000; // 1 minute

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return handleOptions(request, env);
    }

    try {
      let response;

      if (url.pathname === '/oauth/google/code' && request.method === 'POST') {
        response = await handleGoogleCode(request, env);
      } else if (url.pathname === '/api/session' && request.method === 'GET') {
        response = await handleSession(request, env);
      } else if (url.pathname === '/api/google/access-token' && request.method === 'POST') {
        response = await handleAccessToken(request, env);
      } else if (url.pathname === '/logout' && request.method === 'POST') {
        response = await handleLogout(env);
      } else {
        response = json({ error: 'Not found' }, 404);
      }

      return withCors(response, request, env);
    } catch (err) {
      console.error(err);
      return withCors(
        json({ error: err?.message || 'Internal server error' }, err?.status || 500),
        request,
        env
      );
    }
  },
};

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...extraHeaders,
    },
  });
}

function corsHeaders(request, env) {
  const origin = request.headers.get('Origin');
  const allowedOrigins = getAllowedOrigins(env);
  const headers = { Vary: 'Origin' };

  if (origin && allowedOrigins.includes(origin)) {
    headers['Access-Control-Allow-Origin'] = origin;
    headers['Access-Control-Allow-Credentials'] = 'true';
  }

  return headers;
}

function withCors(response, request, env) {
  const headers = new Headers(response.headers);

  for (const [k, v] of Object.entries(corsHeaders(request, env))) {
    headers.set(k, v);
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function handleOptions(request, env) {
  return new Response(null, {
    status: 204,
    headers: {
      ...corsHeaders(request, env),
      'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-Requested-With',
      'Access-Control-Max-Age': '86400',
    },
  });
}

async function handleGoogleCode(request, env) {
  verifyFrontendOrigin(request, env);
  verifyPopupCsrfHeader(request);

  const { code } = await request.json();

  if (!code) {
    throw httpError(400, 'Missing authorization code');
  }

  const tokenRes = await fetch(GOOGLE_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code,
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      redirect_uri: env.FRONTEND_ORIGIN,
      grant_type: 'authorization_code',
    }),
  });

  const tokenData = await tokenRes.json();

  if (!tokenRes.ok) {
    throw httpError(
      401,
      `Google token exchange failed: ${tokenData.error || 'unknown_error'}`
    );
  }

  const idClaims = parseJwt(tokenData.id_token);
  if (!idClaims?.sub) {
    throw httpError(401, 'Google token response missing id_token/sub');
  }

  const now = Date.now();

  const existing = await env.DB
    .prepare('SELECT id, refresh_token FROM users WHERE google_sub = ? LIMIT 1')
    .bind(idClaims.sub)
    .first();

  const userId = existing?.id || crypto.randomUUID();
  const refreshToken = tokenData.refresh_token || existing?.refresh_token || null;

  if (!refreshToken) {
    throw httpError(
      401,
      'No refresh token returned. Remove the app from Google account permissions and sign in again.'
    );
  }

  await env.DB
    .prepare(`
      INSERT INTO users (
        id,
        google_sub,
        email,
        refresh_token,
        access_token,
        access_token_expires_at,
        created_at,
        updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(google_sub) DO UPDATE SET
        email = excluded.email,
        refresh_token = excluded.refresh_token,
        access_token = excluded.access_token,
        access_token_expires_at = excluded.access_token_expires_at,
        updated_at = excluded.updated_at
    `)
    .bind(
      userId,
      idClaims.sub,
      idClaims.email || null,
      refreshToken,
      tokenData.access_token || null,
      tokenData.expires_in ? now + tokenData.expires_in * 1000 : null,
      now,
      now
    )
    .run();

  const cookie = await buildSessionCookie(userId, env, false);

  return json(
    {
      ok: true,
      email: idClaims.email || null,
    },
    200,
    {
      'Set-Cookie': cookie,
      'Cache-Control': 'no-store',
    }
  );
}

async function handleSession(request, env) {
  verifyFrontendOrigin(request, env);

  const user = await requireUser(request, env);
  if (!user) {
    return json(
      { authenticated: false },
      401,
      { 'Cache-Control': 'no-store' }
    );
  }

  return json(
    {
      authenticated: true,
      email: user.email || null,
    },
    200,
    { 'Cache-Control': 'no-store' }
  );
}

async function handleAccessToken(request, env) {
  verifyFrontendOrigin(request, env);

  const user = await requireUser(request, env);
  if (!user) {
    throw httpError(401, 'Not authenticated');
  }

  const tokenInfo = await getOrRefreshAccessToken(user, env);

  return json(
    {
      accessToken: tokenInfo.accessToken,
      expiresAt: tokenInfo.expiresAt,
    },
    200,
    { 'Cache-Control': 'no-store' }
  );
}

async function handleLogout(env) {
  return json(
    { ok: true },
    200,
    {
      'Set-Cookie': await buildSessionCookie('', env, true),
      'Cache-Control': 'no-store',
    }
  );
}

function getAllowedOrigins(env) {
  return (env.FRONTEND_ORIGINS || '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);
}

function verifyFrontendOrigin(request, env) {
  const origin = request.headers.get('Origin');
  const allowedOrigins = getAllowedOrigins(env);

  if (!origin || !allowedOrigins.includes(origin)) {
    throw httpError(403, 'Invalid Origin');
  }
}

function verifyPopupCsrfHeader(request) {
  const xrw = request.headers.get('X-Requested-With');
  if (xrw !== 'XmlHttpRequest') {
    throw httpError(403, 'Missing X-Requested-With header');
  }
}

async function requireUser(request, env) {
  const session = await parseSessionCookie(request, env);
  if (!session?.uid) return null;

  const user = await env.DB
    .prepare(`
      SELECT id, email, refresh_token, access_token, access_token_expires_at
      FROM users
      WHERE id = ?
      LIMIT 1
    `)
    .bind(session.uid)
    .first();

  return user || null;
}

async function getOrRefreshAccessToken(user, env) {
  const now = Date.now();

  if (
    user.access_token &&
    user.access_token_expires_at &&
    now < user.access_token_expires_at - ACCESS_TOKEN_REFRESH_BUFFER_MS
  ) {
    return {
      accessToken: user.access_token,
      expiresAt: user.access_token_expires_at,
    };
  }

  const refreshRes = await fetch(GOOGLE_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      refresh_token: user.refresh_token,
      grant_type: 'refresh_token',
    }),
  });

  const refreshData = await refreshRes.json();

  if (!refreshRes.ok) {
    throw httpError(
      401,
      `Google refresh failed: ${refreshData.error || 'unknown_error'}`
    );
  }

  const expiresAt = now + refreshData.expires_in * 1000;

  await env.DB
    .prepare(`
      UPDATE users
      SET access_token = ?, access_token_expires_at = ?, updated_at = ?
      WHERE id = ?
    `)
    .bind(
      refreshData.access_token,
      expiresAt,
      now,
      user.id
    )
    .run();

  return {
    accessToken: refreshData.access_token,
    expiresAt,
  };
}

async function buildSessionCookie(userId, env, clear = false) {
  const cookieName = env.COOKIE_NAME || '__Host-crate_session';

  if (clear) {
    return `${cookieName}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=None`;
  }

  const payload = {
    uid: userId,
    exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS,
  };

  const encodedPayload = base64urlEncode(JSON.stringify(payload));
  const signature = await sign(encodedPayload, env.COOKIE_SIGNING_SECRET);

  return `${cookieName}=${encodedPayload}.${signature}; Max-Age=${SESSION_TTL_SECONDS}; Path=/; HttpOnly; Secure; SameSite=None`;
}

async function parseSessionCookie(request, env) {
  const cookieName = env.COOKIE_NAME || '__Host-crate_session';
  const cookieHeader = request.headers.get('Cookie') || '';

  const cookies = Object.fromEntries(
    cookieHeader
      .split(';')
      .map(part => part.trim())
      .filter(Boolean)
      .map(part => {
        const idx = part.indexOf('=');
        return idx === -1
          ? [part, '']
          : [part.slice(0, idx), part.slice(idx + 1)];
      })
  );

  const raw = cookies[cookieName];
  if (!raw) return null;

  const [encodedPayload, signature] = raw.split('.');
  if (!encodedPayload || !signature) return null;

  const valid = await verify(encodedPayload, signature, env.COOKIE_SIGNING_SECRET);
  if (!valid) return null;

  const payload = JSON.parse(base64urlDecode(encodedPayload));
  if (!payload?.uid || !payload?.exp) return null;
  if (payload.exp < Math.floor(Date.now() / 1000)) return null;

  return payload;
}

function parseJwt(jwt) {
  if (!jwt) return null;
  const parts = jwt.split('.');
  if (parts.length < 2) return null;
  return JSON.parse(base64urlDecode(parts[1]));
}

async function sign(value, secret) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const sig = await crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(value)
  );

  return uint8ToBase64url(new Uint8Array(sig));
}

async function verify(value, signature, secret) {
  const expected = await sign(value, secret);
  return timingSafeEqual(expected, signature);
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

function base64urlEncode(input) {
  return uint8ToBase64url(new TextEncoder().encode(input));
}

function base64urlDecode(input) {
  const base64 = input.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

function uint8ToBase64url(bytes) {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function httpError(status, message) {
  const err = new Error(message);
  err.status = status;
  return err;
}