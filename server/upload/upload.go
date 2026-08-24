package upload

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"logparseapp/auth"
	"logparseapp/db"
	"logparseapp/parser"
)

type UploadMeta struct {
	ID           int64     `json:"id"`
	Filename     string    `json:"filename"`
	ContentType  string    `json:"content_type"`
	SizeBytes    int64     `json:"size_bytes"`
	UploadedAt   time.Time `json:"uploaded_at"`
	ParsedCount  int       `json:"parsed_count"`
	SkippedCount int       `json:"skipped_count"`
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

	entries, skippedLines, err := parser.ParseLogFile(content)
	if err != nil {
		http.Error(w, "Failed to parse file", http.StatusInternalServerError)
		return
	}

	tx, err := db.DB.Begin()
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	var meta UploadMeta
	err = tx.QueryRow(
		`INSERT INTO uploads (user_id, filename, content_type, size_bytes, content, parsed_count, skipped_count, skipped_lines)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 RETURNING id, filename, content_type, size_bytes, uploaded_at, parsed_count, skipped_count`,
		userID, header.Filename, contentType, len(content), content, len(entries), len(skippedLines), strings.Join(skippedLines, "\n"),
	).Scan(&meta.ID, &meta.Filename, &meta.ContentType, &meta.SizeBytes, &meta.UploadedAt, &meta.ParsedCount, &meta.SkippedCount)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	stmt, err := tx.Prepare(
		`INSERT INTO events (upload_id, source_ip, event_time, method, url, status_code, bytes_sent)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
	)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	for _, e := range entries {
		if _, err := stmt.Exec(meta.ID, e.SourceIP, e.Timestamp, e.Method, e.URL, e.StatusCode, e.BytesSent); err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	}

	if err := tx.Commit(); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(meta)
}

func ListUploads(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	userID, err := auth.Authorize(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	rows, err := db.DB.Query(
		`SELECT id, filename, content_type, size_bytes, uploaded_at, parsed_count, skipped_count
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
		if err := rows.Scan(&u.ID, &u.Filename, &u.ContentType, &u.SizeBytes, &u.UploadedAt, &u.ParsedCount, &u.SkippedCount); err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		uploads = append(uploads, u)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(uploads)
}
