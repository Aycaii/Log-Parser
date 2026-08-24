package parser

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"time"
)

type LogEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	SourceIP   string    `json:"source_ip"`
	Method     string    `json:"method"`
	URL        string    `json:"url"`
	StatusCode int       `json:"status_code"`
	BytesSent  int64     `json:"bytes_sent"`
}

// Regex matching: IP, Timestamp, HTTP Method, Requested Path, Status Code, Bytes
//
// Targets NCSA common log format, e.g.:
// 192.168.1.105 - - [23/Aug/2026:14:32:10 +0000] "GET /api/v1/auth HTTP/1.1" 200 1024
var logPattern = regexp.MustCompile(
	`^(\S+) \S+ \S+ \[([^\]]+)\] "(\w+) (\S+) \S+" (\d{3}) (\d+|-)$`,
)

// ParseLogFile scans rawContent line by line and regex-matches each line
// against the common log format. Lines that don't match, or whose timestamp
// fails to parse, are returned in skippedLines.
func ParseLogFile(rawContent []byte) (entries []LogEntry, skippedLines []string, err error) {
	scanner := bufio.NewScanner(bytes.NewReader(rawContent))

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		matches := logPattern.FindStringSubmatch(line)
		if len(matches) < 7 {
			skippedLines = append(skippedLines, line)
			continue
		}

		parsedTime, err := time.Parse("02/Jan/2006:15:04:05 -0700", matches[2])
		if err != nil {
			skippedLines = append(skippedLines, line)
			continue
		}

		statusCode, err := strconv.Atoi(matches[5])
		if err != nil {
			skippedLines = append(skippedLines, line)
			continue
		}

		var bytesSent int64
		if matches[6] != "-" {
			bytesSent, err = strconv.ParseInt(matches[6], 10, 64)
			if err != nil {
				skippedLines = append(skippedLines, line)
				continue
			}
		}

		entries = append(entries, LogEntry{
			Timestamp:  parsedTime,
			SourceIP:   matches[1],
			Method:     matches[3],
			URL:        matches[4],
			StatusCode: statusCode,
			BytesSent:  bytesSent,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("error reading log scanner: %w", err)
	}

	return entries, skippedLines, nil
}
