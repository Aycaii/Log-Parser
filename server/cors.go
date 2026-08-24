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
        // 1. Explicitly tell the browser that http://localhost:3000 is allowed to read responses.
        w.Header().Set("Access-Control-Allow-Origin", frontendOrigin)
        
        // 2. Allow credentials (cookies/session headers) to be sent across origins.
        w.Header().Set("Access-Control-Allow-Credentials", "true")
        
        // 3. Declare allowed HTTP methods and custom headers.
        w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
        w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token")

        // 4. Handle Preflight: Browsers send an automatic OPTIONS request before POSTs 
        // that carry custom headers (like X-CSRF-Token). This answers "Yes, I allow this" 
        // with HTTP 204 (No Content) so the browser can immediately send the real POST.
        if r.Method == http.MethodOptions {
            w.WriteHeader(http.StatusNoContent)
            return
        }

        next(w, r)
    }
}
