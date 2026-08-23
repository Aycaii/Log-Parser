package auth

import (
	"database/sql"
	"errors"
	"net/http"

	"logparseapp/db"
)

var AuthError = errors.New("Unauthorized")

// Returns the authorized user's id so handlers (uploads) can scope queries
// to it without a second lookup.
func Authorize(r *http.Request) (int64, error) {
	username := r.FormValue("username")

	var id int64
	var sessionToken, csrfToken sql.NullString
	err := db.DB.QueryRow(
		`SELECT id, session_token, csrf_token FROM users WHERE username = $1`,
		username,
	).Scan(&id, &sessionToken, &csrfToken)
	if err != nil {
		return 0, AuthError
	}

	// Get the Session Token from the cookie
	st, err := r.Cookie("session_token")
	if err != nil || st.Value == "" || st.Value != sessionToken.String {
		return 0, AuthError
	}

	// Get the CSRF token from the headers
	csrf := r.Header.Get("X-CSRF-Token")
	if csrf == "" || csrf != csrfToken.String {
		return 0, AuthError
	}

	return id, nil
}
