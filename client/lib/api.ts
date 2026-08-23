// Thin wrapper over the Go API. Everything goes through here so the base URL
// and the credentials flag live in exactly one place.

export const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE ?? "http://localhost:8000";

/**
 * The Go handlers read fields with r.FormValue, which parses
 * application/x-www-form-urlencoded -- not JSON. So we post a URLSearchParams
 * body rather than JSON.stringify.
 *
 * credentials: "include" is required: the API is on a different port, so the
 * browser treats it as cross-origin and will not store the session_token
 * cookie (or send it back) without it.
 */
async function post(path: string, body: Record<string, string>, csrf?: string) {
  const headers: Record<string, string> = {
    "Content-Type": "application/x-www-form-urlencoded",
  };
  if (csrf) headers["X-CSRF-Token"] = csrf;

  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers,
    credentials: "include",
    body: new URLSearchParams(body).toString(),
  });

  const text = (await res.text()).trim();
  if (!res.ok) throw new Error(text || `Request failed (${res.status})`);
  return text;
}

export function register(username: string, password: string) {
  return post("/register", { username, password });
}

export function login(username: string, password: string) {
  return post("/login", { username, password });
}

export function logout(username: string) {
  return post("/logout", { username }, readCsrfToken() ?? undefined);
}

export function getProtected(username: string) {
  return post("/protected", { username }, readCsrfToken() ?? undefined);
}

/**
 * The session cookie is HttpOnly so JS cannot see it -- that is the point.
 * The CSRF cookie deliberately is not, because we have to echo it back in the
 * X-CSRF-Token header for the double-submit check in Authorize(). Its presence
 * doubles as our client-side "probably logged in" hint; the server is still the
 * only thing that actually decides.
 */
export function readCsrfToken(): string | null {
  if (typeof document === "undefined") return null;
  const match = document.cookie.match(/(?:^|;\s*)csrf_token=([^;]*)/);
  return match ? decodeURIComponent(match[1]) : null;
}
