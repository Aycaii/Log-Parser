package upload

import (
	"net/http"
	"strconv"

	"logparseapp/auth"
	"logparseapp/db"
)

// RetryThreatDetection re-runs AI threat detection for an upload whose
// previous attempt didn't produce a report (e.g. the AI API returned a 429
// or otherwise errored out), discarding any partial report from that run.
func RetryThreatDetection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	userID, err := auth.Authorize(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	uploadID, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid upload id", http.StatusBadRequest)
		return
	}

	var exists bool
	if err := db.DB.QueryRow(
		`SELECT EXISTS(SELECT 1 FROM uploads WHERE id = $1 AND user_id = $2)`,
		uploadID, userID,
	).Scan(&exists); err != nil || !exists {
		http.Error(w, "Upload not found", http.StatusNotFound)
		return
	}

	entries, err := loadUploadEvents(uploadID, userID)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if err := setThreatStatus(uploadID, "pending", ""); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	go analyzeAndStore(uploadID, entries)

	w.WriteHeader(http.StatusOK)
}
