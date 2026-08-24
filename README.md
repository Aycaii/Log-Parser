# Full-Stack Log Analyzer Application

A full-stack log analysis tool for SOC analysts: upload an access log, get it parsed into structured events, and have an LLM flag anomalous entries with a reason, a confidence score, and a severity rating.

- **Client**: Next.js 16 + React 19 + TypeScript (`client/`)
- **Server**: Go, `net/http` (`server/`)
- **Database**: PostgreSQL
- **AI**: Google Gemini, used for anomaly detection

## Features

- Basic Username/password auth 
- Upload `.log`/`.txt`/`.json` access log files
- Server-side parsing into structured events (source IP, timestamp, method, URL, status code, bytes sent)
- Per-upload dashboard: events table (filterable/sortable), request timeline chart, upload history
- AI-based anomaly detection per upload: each flagged entry gets a plain-English reason, a confidence score, and a severity (`critical`/`high`/`medium`/`low`/`informational`), shown as badges in the UI and filterable by severity

## Running locally

### Prerequisites

- [Go](https://go.dev/) 1.27+
- [Node.js](https://nodejs.org/) 20+
- PostgreSQL running locally
- A free [Gemini API key](https://aistudio.google.com/apikey)

### Quick start

To run the application: 
```bash
export GEMINI_API_KEY=your-key-here   # optional, enables AI anomaly detection
./run.sh
```

If not configured run the following: 
```bash
export GEMINI_API_KEY=your-key-here   # optional, enables AI anomaly detection
```

This creates the `logparseapp` database if it doesn't exist yet, installs client dependencies on first run, and starts the Go API (`http://localhost:8000`) and the Next.js client (`http://localhost:3000`) together. Ctrl-C stops both.

Environment variables (all optional, exported before running `run.sh`):

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | `postgres://$USER@localhost:5432/logparseapp?sslmode=disable` | Postgres connection string |
| `GEMINI_API_KEY` | — | Enables AI anomaly detection; without it, uploads still parse but skip analysis |
| `GEMINI_MODEL` | `gemini-3.6-flash` | Override the Gemini model used |
| `NEXT_PUBLIC_API_BASE` | `http://localhost:8000` | Where the client looks for the API |

<details>
<summary>Running each piece manually</summary>

**Database** — the server applies the schema automatically on boot, so no migration step is needed:

```bash
createdb logparseapp
```

**Server:**

```bash
cd server
export GEMINI_API_KEY=your-key-here   # optionally enables anomaly detection
go run .
```

**Client:**

```bash
cd client
npm install
npm run dev
```

</details>

### Try it out

1. Open `http://localhost:3000`, register an account, and log in.
2. Upload one of the sample logs in [`examples/`](examples/) (`sample-access.log`/`.txt`/`.json` or `big-sample-access.log`).
3. Watch the dashboard! Parsing is synchronus and AI analysis runs in the background and the status badge updates from "pending" to "ok" within a few seconds.

## AI approach (anomaly detection)

Anomaly detection is implemented in [`server/threatdetect/threatdetect.go`](server/threatdetect/threatdetect.go) and runs automatically after each upload finishes parsing (kicked off from [`server/upload/upload.go`](server/upload/upload.go)), storing results in the `anomalies` table.

- **Model**: Google Gemini (`gemini-3.6-flash` by default), called through its OpenAI-compatible chat completions endpoint.
- **Why batching**: the free tier's context window and rate limits are too tight to send an entire uploaded file in one request, so parsed log entries are split into batches of 50 and sent concurrently (up to 5 batches in flight at a time). Results from all batches are concatenated into one report.
- **Prompt**: each batch is sent as JSON with instructions to act as a SOC analyst and flag anomalies such as brute-force attempts, path traversal, unexpected status code bursts, suspicious IPs, and unauthorized DELETE requests. The model is asked to return strict JSON containing, per anomaly, a `source_ip`, `timestamp`, `anomaly_reason`, `confidence_score` (0–1), and `severity` (`critical`/`high`/`medium`/`low`/`informational`, judged independently of confidence — a low-confidence guess can still describe a critical threat).
- **Prompt-injection guard**: the prompt explicitly instructs the model to treat the log content as untrusted data, not instructions, since uploaded files are user-controlled and could contain text designed to hijack the prompt.
- **Failure handling**: a missing `GEMINI_API_KEY` or a failed request doesn't fail the upload — parsing and display still work, and the upload's `threat_status` is left as `error`/`skipped` so the UI can distinguish "detection hasn't run" from "detection ran and found nothing."

## Known limitations (prototype scope)

- Sessions: the session and CSRF tokens are stored directly on the `users` row (see `server/db/schema.sql`), capping each user at one active session with no server-side expiry. A production version would use a dedicated `sessions` table storing hashed tokens.
- Uploaded file bytes are stored directly in Postgres (`BYTEA`) rather than in object storage.
- AI Approach: Because each batch (up to 50 events) is analyzed independently, a pattern spread thinly across many batches (e.g. a slow, low-and-slow brute force) won't be caught, only patterns visible within a single batch of 50 entries. A paid tier or a larger-context model would let this run in fewer, bigger batches.
