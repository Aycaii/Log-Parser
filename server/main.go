package main

import (
	"fmt"
	"net/http"
	"time"
)

type Login struct {
	HashedPassword string
	SessionToken string
	CSRFToken string
}

// In-memory stand-in for a SQL database.
//
// For a real app this would be swapped for Postgres: a `users` table
// (id, username, password_hash, created_at) with a unique index on username,
// and sessions in their own table (token hash, user_id, expires_at) or in Redis
// so they can expire and be revoked server-side. The handlers below would go
// through a small store interface (GetUser/CreateUser/SaveSession) instead of
// touching the map directly. 
var users = map[string]Login{}

func main() {
	http.HandleFunc("/register", withCORS(register))
	http.HandleFunc("/login", withCORS(login))
	http.HandleFunc("/logout", withCORS(logout))
	http.HandleFunc("/protected", withCORS(protected))

	fmt.Println("API listening on http://localhost:8000")
	http.ListenAndServe(":8000", nil)
}

func register(w http.ResponseWriter, r *http.Request){
	if r.Method != http.MethodPost {
		er := http.StatusMethodNotAllowed
		http.Error(w, "Invalid method", er)
		return
	}

	//grab password and username
	username := r.FormValue("username")
	password := r.FormValue("password")

	//validation checks
	if len(username) < 5 || len(password) < 5 {
		er := http.StatusNotAcceptable
		http.Error(w, "Invalid username/password", er)
		return
	}

	if _, ok := users[username]; ok {
		er := http.StatusConflict
		http.Error(w, "User already exists", er)
		return
	}

	hashedPassword, _ := hashPassword(password)
	users[username] = Login {
		HashedPassword: hashedPassword,
	}

	fmt.Fprintln(w, "User registered")

}

func login(w http.ResponseWriter, r *http.Request){
	if r.Method!= http.MethodPost {
		er := http.StatusMethodNotAllowed
		http.Error(w, "Invalid request method", er)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	user, ok := users[username]
	if !ok || !checkPasswordHash(password, user.HashedPassword) {
		er:= http.StatusUnauthorized
		http.Error(w, "Invalid username or password", er)
		return
	}

	sessionToken := generateToken(32)
	csrfToken := generateToken(32)

	//Set session cookie
	http.SetCookie(w, &http.Cookie {
		Name: "session_token",
		Value: sessionToken,
		Expires: time.Now().Add(24 * time.Hour),
		HttpOnly: true,  //can't be accessed by front end javascript
	})

	// Set CSRF token in a cookie

	http.SetCookie(w, &http.Cookie {
		Name: "csrf_token",
		Value: csrfToken,
		Expires: time.Now().Add(24 * time.Hour),
		HttpOnly: false, //needs to be accessible from client side
	})

	// Store tokens in the database

	user.SessionToken = sessionToken
	user.CSRFToken = csrfToken
	users[username] = user

	fmt.Fprintln(w, "login successful")


}

// delete the sessionToken and the csrfToken? from the Login struct 
func logout(w http.ResponseWriter, r *http.Request) {
	if err := Authorize(r); err != nil {
		er := http.StatusUnauthorized
		http.Error(w, "Unauthorized", er)
		return 
	}

	http.SetCookie(w, &http.Cookie{
		Name:	"session_token", 
		Value: 	"", 
		Expires: 	time.Now().Add(-time.Hour), 
		HttpOnly:	true,
	}) 

	http.SetCookie(w, &http.Cookie{
		Name: "csrf_token", 
		Value: "", 
		Expires: time.Now().Add(-time.Hour),
		HttpOnly:	false, 
	})

	// Clear the tokens from the database
	username := r.FormValue("username")
	user, _ :=users[username]
	user.SessionToken = "" 
	user.CSRFToken = "" 
	users[username] = user
	fmt.Fprintln(w, "Logged out")
}

func protected(w http.ResponseWriter, r *http.Request){
	// Same Origin Policy
	if r.Method != http.MethodPost {
		er := http.StatusMethodNotAllowed 
		http.Error(w, "Invalid request method", er)
		return
	}

	if err := Authorize(r); err != nil {
		er := http.StatusUnauthorized
		http.Error(w, "Unauthorized", er)
		return
	}

	username := r.FormValue("username")
	fmt.Fprintf(w, "CSRF validation successful! Welcome, %s", username)
}
