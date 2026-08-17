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

function readCookie(request, name) {
  const header = request.headers.get("cookie") || "";
  for (const part of header.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return rest.join("=");
  }
  return "";
}

export const config = {
  matcher: ["/((?!login.html|api/login|api/logout).*)"],
};

export default async function middleware(request) {
  const password = process.env.SITE_PASSWORD || "";
  if (!password) {
    return Response.redirect(new URL("/login.html", request.url));
  }

  const token = readCookie(request, COOKIE);
  const expected = await hmacHex(password, COOKIE_PAYLOAD);
  if (token && token === expected) {
    return;
  }

  return Response.redirect(new URL("/login.html", request.url));
}
