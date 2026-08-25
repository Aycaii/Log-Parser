package upload

import (
	"log"

	"logparseapp/db"
	"logparseapp/parser"
	"logparseapp/threatdetect"
)

// storeAnomalies persists a completed AI threat report against an upload and
// marks it 'ok', regardless of whether any anomalies were actually flagged.
func storeAnomalies(uploadID int64, report *threatdetect.AIThreatResponse) error {
	if _, err := db.DB.Exec(
		`UPDATE uploads SET threat_status = 'ok', threat_error = '' WHERE id = $1`,
		uploadID,
	); err != nil {
		return err
	}

	// A retry re-analyzes the same upload, so clear out its previous report
	// first -- otherwise old and new anomaly rows would pile up together.
	if _, err := db.DB.Exec(`DELETE FROM anomalies WHERE upload_id = $1`, uploadID); err != nil {
		return err
	}

	for _, a := range report.Anomalies {
		if _, err := db.DB.Exec(
			`INSERT INTO anomalies (upload_id, source_ip, event_time, is_anomaly, reason, confidence_score, severity)
			 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			uploadID, a.SourceIP, a.Timestamp, a.IsAnomaly, a.AnomalyReason, a.ConfidenceScore, a.Severity,
		); err != nil {
			return err
		}
	}

	return nil
}

// setThreatStatus records that detection did not produce a report: either it
// was skipped or it errored out
func setThreatStatus(uploadID int64, status, errMsg string) error {
	_, err := db.DB.Exec(
		`UPDATE uploads SET threat_status = $1, threat_error = $2 WHERE id = $3`,
		status, errMsg, uploadID,
	)
	return err
}

// analyzeAndStore runs AI threat detection over entries and persists the
// result. Called in the background, both right after a fresh upload and
// when a previously failed analysis (e.g. a 429 from the AI API) is retried.
func analyzeAndStore(uploadID int64, entries []parser.LogEntry) {
	if len(entries) == 0 {
		if err := setThreatStatus(uploadID, "skipped", ""); err != nil {
			log.Printf("failed to set threat status for upload %d: %v", uploadID, err)
		}
		return
	}

	report, err := threatdetect.AnalyzeLogsWithAI(entries)
	if err != nil {
		log.Printf("anomaly detection failed for upload %d: %v", uploadID, err)
		if err := setThreatStatus(uploadID, "error", err.Error()); err != nil {
			log.Printf("failed to set threat status for upload %d: %v", uploadID, err)
		}
		return
	}
	if err := storeAnomalies(uploadID, report); err != nil {
		log.Printf("failed to store anomaly report for upload %d: %v", uploadID, err)
		if err := setThreatStatus(uploadID, "error", err.Error()); err != nil {
			log.Printf("failed to set threat status for upload %d: %v", uploadID, err)
		}
	}
}
