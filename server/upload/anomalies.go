package upload

import (
	"logparseapp/db"
	"logparseapp/threatdetect"
)

// storeAnomalies persists a completed AI threat report against an upload
func storeAnomalies(uploadID int64, report *threatdetect.AIThreatResponse) error {
	if _, err := db.DB.Exec(
		`UPDATE uploads SET threat_summary = $1 WHERE id = $2`,
		report.Summary, uploadID,
	); err != nil {
		return err
	}

	for _, a := range report.Anomalies {
		if _, err := db.DB.Exec(
			`INSERT INTO anomalies (upload_id, source_ip, event_time, is_anomaly, reason, confidence_score)
			 VALUES ($1, $2, $3, $4, $5, $6)`,
			uploadID, a.SourceIP, a.Timestamp, a.IsAnomaly, a.AnomalyReason, a.ConfidenceScore,
		); err != nil {
			return err
		}
	}

	return nil
}
