export const config = { runtime: "edge" };

export default async function handler(request) {
  const isHttps = new URL(request.url).protocol === "https:";
  const cookie = [
    "budget_auth=",
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    "Max-Age=0",
    isHttps ? "Secure" : "",
  ]
    .filter(Boolean)
    .join("; ");

  return new Response(null, {
    status: 302,
    headers: {
      "set-cookie": cookie,
      location: "/login.html",
    },
  });
}
