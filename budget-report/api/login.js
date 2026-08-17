export const config = { runtime: "edge" };

const COOKIE = "budget_auth";
const COOKIE_PAYLOAD = "budget-report-ok";

async function hmacHex(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return [...new Uint8Array(sig)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function json(status, body, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

export default async function handler(request) {
  if (request.method !== "POST") {
    return json(405, { error: "Method not allowed" });
  }

  const password = process.env.SITE_PASSWORD || "";
  if (!password) {
    return json(500, { error: "Login is not configured yet" });
  }

  let given = "";
  try {
    const body = await request.json();
    given = String(body.password || "");
  } catch {
    given = "";
  }

  const expected = await hmacHex(password, COOKIE_PAYLOAD);
  const received = await hmacHex(given, COOKIE_PAYLOAD);
  if (!given || received !== expected) {
    return json(401, { error: "Wrong password" });
  }

  const isHttps = new URL(request.url).protocol === "https:";
  const cookie = [
    `${COOKIE}=${expected}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    "Max-Age=2592000",
    isHttps ? "Secure" : "",
  ]
    .filter(Boolean)
    .join("; ");

  return json(200, { ok: true }, { "set-cookie": cookie });
}
