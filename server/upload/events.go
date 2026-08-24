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

type Anomaly struct {
	SourceIP        string  `json:"source_ip"`
	EventTime       string  `json:"event_time"`
	IsAnomaly       bool    `json:"is_anomaly"`
	Reason          string  `json:"reason"`
	ConfidenceScore float64 `json:"confidence_score"`
	Severity string `json:"severity"`
}

type EventsResponse struct {
	Events        []parser.LogEntry `json:"events"`
	SkippedLines  []string          `json:"skipped_lines"`
	Summary       Summary           `json:"summary"`
	ThreatSummary string            `json:"threat_summary"`
	ThreatStatus string    `json:"threat_status"`
	ThreatError  string    `json:"threat_error"`
	Anomalies    []Anomaly `json:"anomalies"`
}

const timelineBuckets = 20

// GetUploadEvents returns the events parsed from one upload (at upload time,
// see UploadFile) plus a summary built from them
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
	var threatSummary, threatStatus, threatError string
	err = db.DB.QueryRow(
		`SELECT skipped_count, skipped_lines, threat_summary, threat_status, threat_error
		 FROM uploads WHERE id = $1 AND user_id = $2`,
		uploadID, userID,
	).Scan(&skippedCount, &skippedLinesRaw, &threatSummary, &threatStatus, &threatError)
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

	// Same ownership guard as the events query above: join against
	// uploads.user_id rather than trusting upload_id alone.
	anomalyRows, err := db.DB.Query(
		`SELECT a.source_ip, a.event_time, a.is_anomaly, a.reason, a.confidence_score, a.severity
		 FROM anomalies a
		 JOIN uploads u ON u.id = a.upload_id
		 WHERE a.upload_id = $1 AND u.user_id = $2
		 ORDER BY a.confidence_score DESC`,
		uploadID, userID,
	)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer anomalyRows.Close()

	anomalies := []Anomaly{}
	for anomalyRows.Next() {
		var a Anomaly
		if err := anomalyRows.Scan(&a.SourceIP, &a.EventTime, &a.IsAnomaly, &a.Reason, &a.ConfidenceScore, &a.Severity); err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		anomalies = append(anomalies, a)
	}

	resp := EventsResponse{
		Events:        events,
		SkippedLines:  skippedLines,
		Summary:       buildSummary(events, skippedCount),
		ThreatSummary: threatSummary,
		ThreatStatus:  threatStatus,
		ThreatError:   threatError,
		Anomalies:     anomalies,
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
