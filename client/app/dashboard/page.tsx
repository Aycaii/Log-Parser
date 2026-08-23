"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { logout, readCsrfToken } from "@/lib/api";

/**
 * Intentionally blank -- this is the shell the log upload and analysis views
 * will be built into. It only proves the auth round trip worked.
 */
export default function DashboardPage() {
  const router = useRouter();
  const [username, setUsername] = useState<string | null>(null);

  useEffect(() => {
    // Cheap client-side guard so a direct visit to /dashboard does not render
    // an empty shell for someone who never logged in. Not a security control:
    // the API re-checks the session on every protected request.
    const name = sessionStorage.getItem("username");
    if (!name || !readCsrfToken()) {
      router.replace("/login");
      return;
    }
    setUsername(name);
  }, [router]);

  async function onLogout() {
    if (username) {
      // A failed logout should not strand the user on a page they can't leave.
      await logout(username).catch(() => {});
    }
    sessionStorage.removeItem("username");
    router.replace("/login");
  }

  if (!username) return null;

  return (
    <>
      <header className="topbar">
        <span className="who">Signed in as {username}</span>
        <button className="btn ghost" onClick={onLogout}>
          Log out
        </button>
      </header>
      <main />
    </>
  );
}
