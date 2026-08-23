package main

import "net/http"

// The Next.js dev server runs on a different port than this API, so the browser
// treats every request as cross-origin. Without these headers the login POST is
// blocked and, more subtly, the Set-Cookie on the response is dropped.
//
// Allow-Credentials is what lets the session_token cookie ride along, and it
// requires an explicit origin -- the "*" wildcard is rejected by the browser
// when credentials are involved. Prototype-only: a real deployment would read
// the allowed origin from config rather than hardcoding localhost.
const frontendOrigin = "http://localhost:3000"

func withCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", frontendOrigin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token")

		// Preflight: the browser sends OPTIONS before any POST carrying a
		// custom header (X-CSRF-Token). Answer it and stop.
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next(w, r)
	}
}
