package upload

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"logparseapp/auth"
	"logparseapp/db"
	"logparseapp/parser"
)

type CountEntry struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

type TimelineBucket struct {
	BucketStart time.Time `json:"bucket_start"`
	Count       int       `json:"count"`
}

type Summary struct {
	TotalEvents     int              `json:"total_events"`
	SkippedLines    int              `json:"skipped_lines"`
	Timeline        []TimelineBucket `json:"timeline"`
	StatusBreakdown []CountEntry     `json:"status_breakdown"`
}

type EventsResponse struct {
	Events       []parser.LogEntry `json:"events"`
	SkippedLines []string          `json:"skipped_lines"`
	Summary      Summary           `json:"summary"`
}

const timelineBuckets = 20

// GetUploadEvents returns the events parsed from one upload (at upload time,
// see UploadFile) plus a summary built from them -- top source IPs/URLs, a
// status-code breakdown, and a fixed-bucket timeline, which is the
// "summarized timeline of events" the SOC-analyst view is built around.
func GetUploadEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	userID, err := auth.Authorize(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	uploadID, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid upload id", http.StatusBadRequest)
		return
	}

	var skippedCount int
	var skippedLinesRaw string
	err = db.DB.QueryRow(
		`SELECT skipped_count, skipped_lines FROM uploads WHERE id = $1 AND user_id = $2`,
		uploadID, userID,
	).Scan(&skippedCount, &skippedLinesRaw)
	if err != nil {
		http.Error(w, "Upload not found", http.StatusNotFound)
		return
	}

	skippedLines := []string{}
	if skippedLinesRaw != "" {
		skippedLines = strings.Split(skippedLinesRaw, "\n")
	}

	// The join against u.user_id, not just e.upload_id, is what stops one
	// user from pulling another's events by guessing an id.
	rows, err := db.DB.Query(
		`SELECT e.source_ip, e.event_time, e.method, e.url, e.status_code, e.bytes_sent
		 FROM events e
		 JOIN uploads u ON u.id = e.upload_id
		 WHERE e.upload_id = $1 AND u.user_id = $2
		 ORDER BY e.event_time`,
		uploadID, userID,
	)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	events := []parser.LogEntry{}
	for rows.Next() {
		var e parser.LogEntry
		if err := rows.Scan(&e.SourceIP, &e.Timestamp, &e.Method, &e.URL, &e.StatusCode, &e.BytesSent); err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		events = append(events, e)
	}

	resp := EventsResponse{
		Events:       events,
		SkippedLines: skippedLines,
		Summary:      buildSummary(events, skippedCount),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func buildSummary(events []parser.LogEntry, skippedLines int) Summary {
	summary := Summary{
		TotalEvents:  len(events),
		SkippedLines: skippedLines,
		Timeline:     []TimelineBucket{},
	}
	if len(events) == 0 {
		return summary
	}

	statusClassCounts := map[string]int{}

	minTime, maxTime := events[0].Timestamp, events[0].Timestamp
	for _, e := range events {
		statusClassCounts[statusClass(e.StatusCode)]++

		if e.Timestamp.Before(minTime) {
			minTime = e.Timestamp
		}
		if e.Timestamp.After(maxTime) {
			maxTime = e.Timestamp
		}
	}
	summary.StatusBreakdown = topN(statusClassCounts, len(statusClassCounts))
	summary.Timeline = buildTimeline(events, minTime, maxTime)

	return summary
}

func statusClass(status int) string {
	switch {
	case status >= 200 && status < 300:
		return "2xx"
	case status >= 300 && status < 400:
		return "3xx"
	case status >= 400 && status < 500:
		return "4xx"
	case status >= 500:
		return "5xx"
	default:
		return "other"
	}
}

func topN(counts map[string]int, n int) []CountEntry {
	entries := make([]CountEntry, 0, len(counts))
	for k, c := range counts {
		entries = append(entries, CountEntry{Key: k, Count: c})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Count > entries[j].Count })
	if len(entries) > n {
		entries = entries[:n]
	}
	return entries
}

func buildTimeline(events []parser.LogEntry, minTime, maxTime time.Time) []TimelineBucket {
	span := maxTime.Sub(minTime)
	bucketWidth := span / timelineBuckets
	if bucketWidth <= 0 {
		// All events landed in the same instant (or span too small to
		// divide) -- a single bucket covers everything.
		return []TimelineBucket{{BucketStart: minTime, Count: len(events)}}
	}

	buckets := make([]TimelineBucket, timelineBuckets)
	for i := range buckets {
		buckets[i].BucketStart = minTime.Add(time.Duration(i) * bucketWidth)
	}

	for _, e := range events {
		idx := int(e.Timestamp.Sub(minTime) / bucketWidth)
		if idx >= timelineBuckets {
			idx = timelineBuckets - 1
		}
		buckets[idx].Count++
	}

	return buckets
}
