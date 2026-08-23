package upload

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"logparseapp/auth"
	"logparseapp/db"
)

type UploadMeta struct {
	ID          int64     `json:"id"`
	Filename    string    `json:"filename"`
	ContentType string    `json:"content_type"`
	SizeBytes   int64     `json:"size_bytes"`
	UploadedAt  time.Time `json:"uploaded_at"`
}

// r.FormValue (used inside auth.Authorize) parses the multipart form itself
// if it hasn't been parsed yet, but with the default in-memory cap -- calling
// ParseMultipartForm first with our own limit avoids relying on that default.
func UploadFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseMultipartForm(32 << 20); err != nil {
		http.Error(w, "File too large", http.StatusBadRequest)
		return
	}

	userID, err := auth.Authorize(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Missing file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "Failed to read file", http.StatusInternalServerError)
		return
	}

	contentType := header.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	var meta UploadMeta
	err = db.DB.QueryRow(
		`INSERT INTO uploads (user_id, filename, content_type, size_bytes, content)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, filename, content_type, size_bytes, uploaded_at`,
		userID, header.Filename, contentType, len(content), content,
	).Scan(&meta.ID, &meta.Filename, &meta.ContentType, &meta.SizeBytes, &meta.UploadedAt)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(meta)
}

func ListUploads(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	userID, err := auth.Authorize(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	rows, err := db.DB.Query(
		`SELECT id, filename, content_type, size_bytes, uploaded_at
		 FROM uploads WHERE user_id = $1 ORDER BY uploaded_at DESC`,
		userID,
	)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	uploads := []UploadMeta{}
	for rows.Next() {
		var u UploadMeta
		if err := rows.Scan(&u.ID, &u.Filename, &u.ContentType, &u.SizeBytes, &u.UploadedAt); err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		uploads = append(uploads, u)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(uploads)
}
