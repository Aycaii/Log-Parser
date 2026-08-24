package upload

import (
	"logparseapp/db"
	"logparseapp/threatdetect"
)

// storeAnomalies persists a completed AI threat report against an upload and
// marks it 'ok', regardless of whether any anomalies were actually flagged.
func storeAnomalies(uploadID int64, report *threatdetect.AIThreatResponse) error {
	if _, err := db.DB.Exec(
		`UPDATE uploads SET threat_summary = $1, threat_status = 'ok', threat_error = '' WHERE id = $2`,
		report.Summary, uploadID,
	); err != nil {
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
// was skipped (nothing to analyze) or it errored out (missing API key,
// timed-out/failed request, unparseable AI response).
func setThreatStatus(uploadID int64, status, errMsg string) error {
	_, err := db.DB.Exec(
		`UPDATE uploads SET threat_status = $1, threat_error = $2 WHERE id = $3`,
		status, errMsg, uploadID,
	)
	return err
}
