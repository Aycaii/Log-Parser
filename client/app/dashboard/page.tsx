"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import {
  logout,
  listUploads,
  readCsrfToken,
  uploadFile,
  type UploadMeta,
} from "@/lib/api";

function formatSize(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  const kb = bytes / 1024;
  if (kb < 1024) return `${kb.toFixed(1)} KB`;
  return `${(kb / 1024).toFixed(1)} MB`;
}

export default function DashboardPage() {
  const router = useRouter();
  const [username, setUsername] = useState<string | null>(null);
  const [uploads, setUploads] = useState<UploadMeta[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const refreshUploads = useCallback(async (name: string) => {
    try {
      setUploads(await listUploads(name));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load uploads");
    }
  }, []);

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
    refreshUploads(name);
  }, [router, refreshUploads]);

  async function onLogout() {
    if (username) {
      // A failed logout should not strand the user on a page they can't leave.
      await logout(username).catch(() => {});
    }
    sessionStorage.removeItem("username");
    router.replace("/login");
  }

  async function onFileChosen(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file || !username) return;

    setError(null);
    setBusy(true);
    try {
      await uploadFile(username, file);
      await refreshUploads(username);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Upload failed");
    } finally {
      setBusy(false);
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
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
      <main className="uploads">
        <div className="uploads-toolbar">
          <label className="btn upload-btn">
            {busy ? "Uploading..." : "Upload log file"}
            <input
              ref={fileInputRef}
              type="file"
              accept=".txt,.log,.json"
              onChange={onFileChosen}
              disabled={busy}
              hidden
            />
          </label>
        </div>

        {error && <p className="msg">{error}</p>}

        {uploads.length === 0 ? (
          <p className="sub">No files uploaded yet.</p>
        ) : (
          <table className="uploads-table">
            <thead>
              <tr>
                <th>Filename</th>
                <th>Size</th>
                <th>Uploaded</th>
              </tr>
            </thead>
            <tbody>
              {uploads.map((u) => (
                <tr key={u.id}>
                  <td>{u.filename}</td>
                  <td>{formatSize(u.size_bytes)}</td>
                  <td>{new Date(u.uploaded_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </main>
    </>
  );
}
