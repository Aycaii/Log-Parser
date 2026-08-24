package auth

import (
	"fmt"
	"net/http"
	"time"

	"logparseapp/db"
)

func Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		er := http.StatusMethodNotAllowed
		http.Error(w, "Invalid method", er)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")


	//Validation checks for user input
	if containsSpace(username) || containsSpace(password) {
		http.Error(w, "Username and password cannot contain spaces", http.StatusNotAcceptable)
		return
	}
	
	if len(username) < 5 || len(password) < 5 {
		er := http.StatusNotAcceptable
		http.Error(w, "Invalid username/password", er)
		return
	}

	var exists bool
	if err := db.DB.QueryRow(`SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)`, username).Scan(&exists); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if exists {
		er := http.StatusConflict
		http.Error(w, "User already exists", er)
		return
	}

	hashedPassword, _ := hashPassword(password)
	if _, err := db.DB.Exec(`INSERT INTO users (username, hashed_password) VALUES ($1, $2)`, username, hashedPassword); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	fmt.Fprintln(w, "User registered")

}

func Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		er := http.StatusMethodNotAllowed
		http.Error(w, "Invalid request method", er)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	var id int64
	var hashedPassword string
	err := db.DB.QueryRow(`SELECT id, hashed_password FROM users WHERE username = $1`, username).Scan(&id, &hashedPassword)
	if err != nil || !checkPasswordHash(password, hashedPassword) {
		er := http.StatusUnauthorized
		http.Error(w, "Invalid username or password", er)
		return
	}

	sessionToken := generateToken(32)
	csrfToken := generateToken(32)

	//Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true, //can't be accessed by front end javascript
	})


	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: false, //needs to be accessible from client side
	})


	if _, err := db.DB.Exec(`UPDATE users SET session_token = $1, csrf_token = $2 WHERE id = $3`, sessionToken, csrfToken, id); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	fmt.Fprintln(w, "login successful")

}

func Logout(w http.ResponseWriter, r *http.Request) {
	id, err := Authorize(r)
	if err != nil {
		er := http.StatusUnauthorized
		http.Error(w, "Unauthorized", er)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: true,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: false,
	})

	if _, err := db.DB.Exec(`UPDATE users SET session_token = NULL, csrf_token = NULL WHERE id = $1`, id); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	fmt.Fprintln(w, "Logged out")
}

func Protected(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		er := http.StatusMethodNotAllowed
		http.Error(w, "Invalid request method", er)
		return
	}

	if _, err := Authorize(r); err != nil {
		er := http.StatusUnauthorized
		http.Error(w, "Unauthorized", er)
		return
	}

	username := r.FormValue("username")
	fmt.Fprintf(w, "CSRF validation successful! Welcome, %s", username)
}
