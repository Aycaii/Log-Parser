"use client";

import { useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { login, register } from "@/lib/api";

export default function LoginPage() {
  const router = useRouter();
  const [mode, setMode] = useState<"login" | "register">("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setNotice(null);
    setBusy(true);

    try {
      if (mode === "register") {
        await register(username, password);
        // Registering does not log you in -- the Go handler only stores the
        // hash. Drop back to the login form with the username prefilled.
        setMode("login");
        setPassword("");
        setNotice("Account created. Sign in to continue.");
        return;
      }

      await login(username, password);
      // The username is needed on later requests because the Go handlers look
      // the user up by form value rather than deriving it from the session.
      sessionStorage.setItem("username", username);
      router.push("/dashboard");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="center">
      <form className="card" onSubmit={onSubmit}>
        <h1>{mode === "login" ? "Sign in" : "Create an account"}</h1>
        <p className="sub">Log analysis console</p>

        {error && <p className="msg">{error}</p>}
        {notice && <p className="msg ok">{notice}</p>}

        <label className="field">
          <span>Username</span>
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            required
          />
        </label>

        <label className="field">
          <span>Password</span>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete={
              mode === "login" ? "current-password" : "new-password"
            }
            required
          />
        </label>

        <button className="btn" type="submit" disabled={busy}>
          {busy ? "Working..." : mode === "login" ? "Sign in" : "Register"}
        </button>

        <p className="toggle">
          {mode === "login" ? "No account yet? " : "Already registered? "}
          <button
            type="button"
            onClick={() => {
              setMode(mode === "login" ? "register" : "login");
              setError(null);
              setNotice(null);
            }}
          >
            {mode === "login" ? "Register" : "Sign in"}
          </button>
        </p>
      </form>
    </main>
  );
}
