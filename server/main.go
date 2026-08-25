package main

import (
	"fmt"
	"log"
	"net/http"

	"logparseapp/auth"
	"logparseapp/db"
	"logparseapp/upload"
)

func main() {
	if err := db.Connect(); err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	defer db.DB.Close()

	if err := db.ApplySchema(); err != nil {
		log.Fatalf("failed to apply schema: %v", err)
	}

	http.HandleFunc("/register", withCORS(auth.Register))
	http.HandleFunc("/login", withCORS(auth.Login))
	http.HandleFunc("/logout", withCORS(auth.Logout))
	http.HandleFunc("/protected", withCORS(auth.Protected))
	http.HandleFunc("/upload", withCORS(upload.UploadFile))
	http.HandleFunc("/uploads", withCORS(upload.ListUploads))
	http.HandleFunc("/uploads/events", withCORS(upload.GetUploadEvents))
	http.HandleFunc("/uploads/retry", withCORS(upload.RetryThreatDetection))

	fmt.Println("API listening on http://localhost:8000")
	http.ListenAndServe(":8000", nil)
}
