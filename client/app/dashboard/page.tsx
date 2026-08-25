"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import {
  logout,
  listUploads,
  readCsrfToken,
  uploadFile,
  getUploadEvents,
  retryThreatDetection,
  type UploadMeta,
  type EventsResponse,
  type LogEntry,
  type CountEntry,
  type TimelineBucket,
  type Anomaly,
  type ThreatStatus,
  type Severity,
} from "@/lib/api";

function formatSize(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  const kb = bytes / 1024;
  if (kb < 1024) return `${kb.toFixed(1)} KB`;
  return `${(kb / 1024).toFixed(1)} MB`;
}

function formatTime(iso: string) {
  return new Date(iso).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
  });
}

const STATUS_META: Record<string, { cls: string; label: string }> = {
  "2xx": { cls: "good", label: "2xx OK" },
  "3xx": { cls: "neutral", label: "3xx Redirect" },
  "4xx": { cls: "warning", label: "4xx Client error" },
  "5xx": { cls: "critical", label: "5xx Server error" },
};

type FilterField = "timestamp" | "source_ip" | "method" | "url" | "status_code" | "bytes_sent" | "date";

const FILTER_FIELDS: { key: FilterField; label: string }[] = [
  { key: "timestamp", label: "Time" },
  { key: "source_ip", label: "Source IP" },
  { key: "method", label: "Method" },
  { key: "url", label: "URL" },
  { key: "status_code", label: "Status" },
  { key: "bytes_sent", label: "Bytes" },
  { key: "date", label: "Date" },
];

type FilterRow = { field: FilterField; value: string };

// "Time" and "Date" both get the native calendar date picker and match by
// day, rather than a text substring.
function filterInputType(field: FilterField) {
  if (field === "date" || field === "timestamp") return "date";
  return "text";
}

function matchesFilter(e: LogEntry, field: FilterField, rawValue: string): boolean {
  const value = rawValue.trim();
  if (!value) return true;
  switch (field) {
    case "date":
    case "timestamp":
      return e.timestamp.slice(0, 10) === value;
    case "status_code":
      return String(e.status_code).includes(value);
    case "bytes_sent":
      return String(e.bytes_sent).includes(value);
    default:
      return e[field].toLowerCase().includes(value.toLowerCase());
  }
}

function sortValue(e: LogEntry, field: FilterField): string | number {
  switch (field) {
    case "date":
      return e.timestamp.slice(0, 10);
    case "timestamp":
      return e.timestamp;
    case "status_code":
      return e.status_code;
    case "bytes_sent":
      return e.bytes_sent;
    default:
      return e[field];
  }
}

const TIMELINE_BUCKETS = 20;

function statusClass(status: number): string {
  if (status >= 200 && status < 300) return "2xx";
  if (status >= 300 && status < 400) return "3xx";
  if (status >= 400 && status < 500) return "4xx";
  if (status >= 500) return "5xx";
  return "other";
}

type LiveSummary = { totalEvents: number; timeline: TimelineBucket[]; statusBreakdown: CountEntry[] };

// Mirrors the server's buildSummary (server/upload/events.go), but over
// whatever subset of events is currently filtered in, so the timeline and
// status chips track the filters instead of showing the whole file's stats.
function buildLiveSummary(events: LogEntry[]): LiveSummary {
  if (events.length === 0) {
    return { totalEvents: 0, timeline: [], statusBreakdown: [] };
  }

  const statusCounts: Record<string, number> = {};
  let minMs = new Date(events[0].timestamp).getTime();
  let maxMs = minMs;
  for (const e of events) {
    const cls = statusClass(e.status_code);
    statusCounts[cls] = (statusCounts[cls] ?? 0) + 1;
    const ms = new Date(e.timestamp).getTime();
    if (ms < minMs) minMs = ms;
    if (ms > maxMs) maxMs = ms;
  }

  const statusBreakdown = Object.entries(statusCounts)
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count);

  const span = maxMs - minMs;
  let timeline: TimelineBucket[];
  if (span <= 0) {
    timeline = [{ bucket_start: new Date(minMs).toISOString(), count: events.length }];
  } else {
    const bucketWidth = span / TIMELINE_BUCKETS;
    const buckets: TimelineBucket[] = Array.from({ length: TIMELINE_BUCKETS }, (_, i) => ({
      bucket_start: new Date(minMs + i * bucketWidth).toISOString(),
      count: 0,
    }));
    for (const e of events) {
      const idx = Math.min(
        TIMELINE_BUCKETS - 1,
        Math.floor((new Date(e.timestamp).getTime() - minMs) / bucketWidth),
      );
      buckets[idx].count++;
    }
    timeline = buckets;
  }

  return { totalEvents: events.length, timeline, statusBreakdown };
}

// Renders the parsed view for one upload: a timeline of event counts, a
// status-code breakdown, top talkers/paths, a filterable event table, and a
// tab to see the raw lines the parser skipped.
function AnomalyBadge({ score }: { score: number }) {
  const cls = score >= 0.75 ? "critical" : score >= 0.4 ? "warning" : "neutral";
  return (
    <span className={`status-chip`}>
      <span className={`status-dot ${cls}`} />
      {(score * 100).toFixed(0)}% confidence
    </span>
  );
}


const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "informational"];
const SEVERITY_RANK: Record<Severity, number> = Object.fromEntries(
  SEVERITIES.map((s, i) => [s, i]),
) as Record<Severity, number>;

type FindingsSortField = "severity" | "event_time" | "source_ip" | "reason" | "confidence_score";

function findingSortValue(a: Anomaly, field: FindingsSortField): string | number {
  if (field === "severity") return SEVERITY_RANK[a.severity];
  return a[field];
}

const FINDINGS_FILTER_FIELDS: { key: FindingsSortField; label: string }[] = [
  { key: "severity", label: "Severity" },
  { key: "confidence_score", label: "Confidence" },
  { key: "event_time", label: "Time" },
  { key: "source_ip", label: "Source IP" },
  { key: "reason", label: "Reason" },
];

type FindingsFilterRow = { field: FindingsSortField; value: string };

function matchesFindingFilter(a: Anomaly, field: FindingsSortField, rawValue: string): boolean {
  const value = rawValue.trim();
  if (!value) return true;
  switch (field) {
    case "severity":
      return a.severity === value;
    case "event_time":
      return a.event_time.slice(0, 10) === value;
    case "confidence_score":
      return String(a.confidence_score).includes(value);
    default:
      return a[field].toLowerCase().includes(value.toLowerCase());
  }
}

function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className="status-chip">{severity}</span>;
}

// AI detection runs in the background after /upload responds (see upload.go)
function findingsStatusDot(status: ThreatStatus): string {
  switch (status) {
    case "error":
      return "critical";
    case "pending":
      return "warning";
    default:
      return "good";
  }
}

const PAGE_SIZE = 50;

function Pagination({
  page,
  totalPages,
  onPageChange,
}: {
  page: number;
  totalPages: number;
  onPageChange: (page: number) => void;
}) {
  if (totalPages <= 1) return null;
  return (
    <div className="pagination">
      <button
        className="btn ghost small"
        disabled={page <= 1}
        onClick={() => onPageChange(page - 1)}
      >
        Prev
      </button>
      <span className="sub">
        Page {page} of {totalPages}
      </span>
      <button
        className="btn ghost small"
        disabled={page >= totalPages}
        onClick={() => onPageChange(page + 1)}
      >
        Next
      </button>
    </div>
  );
}

function FindingsPanel({
  status,
  error,
  anomalies,
  onRetry,
}: {
  status: ThreatStatus;
  error: string;
  anomalies: Anomaly[];
  onRetry: () => Promise<void>;
}) {
  const [sortField, setSortField] = useState<FindingsSortField>("severity");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [filters, setFilters] = useState<FindingsFilterRow[]>([]);
  const [retrying, setRetrying] = useState(false);

  async function handleRetry() {
    setRetrying(true);
    try {
      await onRetry();
    } finally {
      setRetrying(false);
    }
  }

  function updateFilter(index: number, patch: Partial<FindingsFilterRow>) {
    setFilters((prev) => prev.map((f, i) => (i === index ? { ...f, ...patch } : f)));
  }
  function addFilter() {
    setFilters((prev) => [...prev, { field: "source_ip", value: "" }]);
  }
  function removeFilter(index: number) {
    setFilters((prev) => prev.filter((_, i) => i !== index));
  }

  function toggleSort(field: FindingsSortField) {
    if (sortField === field) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortField(field);
      setSortDir("asc");
    }
  }

  function sortableHeader(field: FindingsSortField, label: string) {
    return (
      <th className="sortable" onClick={() => toggleSort(field)}>
        {label}
        {sortField === field && (
          <span className="sort-indicator">{sortDir === "asc" ? " ▲" : " ▼"}</span>
        )}
      </th>
    );
  }

  const [page, setPage] = useState(1);

  const flagged = anomalies.filter((a) => a.is_anomaly);
  const filteredFlagged = useMemo(
    () => flagged.filter((a) => filters.every((f) => matchesFindingFilter(a, f.field, f.value))),
    [flagged, filters],
  );
  const sortedFlagged = useMemo(
    () =>
      [...filteredFlagged].sort((a, b) => {
        const va = findingSortValue(a, sortField);
        const vb = findingSortValue(b, sortField);
        const cmp = va < vb ? -1 : va > vb ? 1 : 0;
        return sortDir === "asc" ? cmp : -cmp;
      }),
    [filteredFlagged, sortField, sortDir],
  );
  const totalPages = Math.max(1, Math.ceil(sortedFlagged.length / PAGE_SIZE));
  const pageClamped = Math.min(page, totalPages);
  const pagedFlagged = sortedFlagged.slice(
    (pageClamped - 1) * PAGE_SIZE,
    pageClamped * PAGE_SIZE,
  );

  if (status === "pending") {
    return <p className="sub">Pending AI analysis</p>;
  }

  if (status === "skipped") {
    return (
      <p className="sub">
        No log lines were parsed from this file, so threat detection did not
        run.
      </p>
    );
  }

  if (status === "error") {
    return (
      <div className="retry-block">
        <p className="msg">
          Threat detection failed and produced no report: {error || "unknown error"}
        </p>
        <button className="btn ghost small" disabled={retrying} onClick={handleRetry}>
          {retrying ? "Retrying..." : "Retry"}
        </button>
      </div>
    );
  }

  return (
    <>
      {flagged.length === 0 ? (
        <p className="sub">Detection ran and found no anomalies.</p>
      ) : (
        <>
          <div className="filter-toolbar">
            {filters.map((f, i) => (
              <div className="filter-box" key={i}>
                <select
                  value={f.field}
                  onChange={(e) =>
                    updateFilter(i, { field: e.target.value as FindingsSortField, value: "" })
                  }
                >
                  {FINDINGS_FILTER_FIELDS.map((ff) => (
                    <option key={ff.key} value={ff.key}>
                      {ff.label}
                    </option>
                  ))}
                </select>
                {f.field === "severity" ? (
                  <select
                    value={f.value}
                    onChange={(e) => updateFilter(i, { value: e.target.value })}
                  >
                    <option value="">Any</option>
                    {SEVERITIES.map((sev) => (
                      <option key={sev} value={sev}>
                        {sev}
                      </option>
                    ))}
                  </select>
                ) : (
                  <input
                    type={f.field === "event_time" ? "date" : "text"}
                    placeholder="Value"
                    value={f.value}
                    onChange={(e) => updateFilter(i, { value: e.target.value })}
                  />
                )}
                <button className="btn ghost small" onClick={() => removeFilter(i)}>
                  Remove
                </button>
              </div>
            ))}
            <button className="btn ghost small" onClick={addFilter}>
              + Add filter
            </button>
          </div>

          {filteredFlagged.length === 0 ? (
            <p className="sub">No anomalies match the current filter(s).</p>
          ) : (
            <table className="uploads-table">
              <thead>
                <tr>
                  {sortableHeader("severity", "Severity")}
                  {sortableHeader("confidence_score", "Confidence")}
                  {sortableHeader("event_time", "Time")}
                  {sortableHeader("source_ip", "Source IP")}
                  {sortableHeader("reason", "Reason")}
                </tr>
              </thead>
              <tbody>
                {pagedFlagged.map((a, i) => (
                  <tr key={i}>
                    <td>
                      <SeverityBadge severity={a.severity} />
                    </td>
                    <td>
                      <AnomalyBadge score={a.confidence_score} />
                    </td>
                    <td>{a.event_time}</td>
                    <td>{a.source_ip}</td>
                    <td>{a.reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
      <Pagination page={pageClamped} totalPages={totalPages} onPageChange={setPage} />
    </>
  );
}

function EventsPanel({
  data,
  onRetryThreatDetection,
}: {
  data: EventsResponse;
  onRetryThreatDetection: () => Promise<void>;
}) {
  const {
    summary,
    events,
    skipped_lines,
    threat_status,
    threat_error,
    anomalies,
  } = data;
  const [tab, setTab] = useState<"findings" | "events" | "skipped">("findings");
  const [filters, setFilters] = useState<FilterRow[]>([]);
  const [sortField, setSortField] = useState<FilterField>("timestamp");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [eventsPage, setEventsPage] = useState(1);

  function updateFilter(index: number, patch: Partial<FilterRow>) {
    setFilters((prev) => prev.map((f, i) => (i === index ? { ...f, ...patch } : f)));
  }
  function addFilter() {
    setFilters((prev) => [...prev, { field: "source_ip", value: "" }]);
  }
  function removeFilter(index: number) {
    setFilters((prev) => prev.filter((_, i) => i !== index));
  }

  function toggleSort(field: FilterField) {
    if (sortField === field) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortField(field);
      setSortDir("asc");
    }
  }

  function sortableHeader(field: FilterField, label: string) {
    return (
      <th className="sortable" onClick={() => toggleSort(field)}>
        {label}
        {sortField === field && (
          <span className="sort-indicator">{sortDir === "asc" ? " ▲" : " ▼"}</span>
        )}
      </th>
    );
  }

  const filteredEvents = useMemo(
    () =>
      events
        .filter((e) => filters.every((f) => matchesFilter(e, f.field, f.value)))
        .sort((a, b) => {
          const va = sortValue(a, sortField);
          const vb = sortValue(b, sortField);
          const cmp = va < vb ? -1 : va > vb ? 1 : 0;
          return sortDir === "asc" ? cmp : -cmp;
        }),
    [events, filters, sortField, sortDir],
  );
  const totalEventsPages = Math.max(1, Math.ceil(filteredEvents.length / PAGE_SIZE));
  const eventsPageClamped = Math.min(eventsPage, totalEventsPages);
  const pagedEvents = filteredEvents.slice(
    (eventsPageClamped - 1) * PAGE_SIZE,
    eventsPageClamped * PAGE_SIZE,
  );

  const liveSummary = useMemo(() => buildLiveSummary(filteredEvents), [filteredEvents]);

  if (summary.total_events === 0 && skipped_lines.length === 0) {
    return (
      <div className="events-panel">
        <p className="sub">No lines found in this file.</p>
      </div>
    );
  }

  const maxCount = Math.max(...liveSummary.timeline.map((b) => b.count), 1);

  return (
    <div className="events-panel">
      <div className="stat-line">
        <div className="stat-tile">
          <div className="value">{liveSummary.totalEvents}</div>
          <div className="label">Events parsed</div>
        </div>
        <div className="stat-tile">
          <div className="value">{summary.skipped_lines}</div>
          <div className="label">Lines skipped</div>
        </div>
      </div>

      {liveSummary.totalEvents === 0 ? (
        <p className="sub">No events match the current filter(s).</p>
      ) : (
        <>
          <div className="timeline">
            {liveSummary.timeline.map((b, i) => (
              <div
                key={i}
                className="timeline-bar"
                style={{
                  height: `${Math.max(2, Math.round((b.count / maxCount) * 84))}px`,
                }}
                title={`${new Date(b.bucket_start).toLocaleString()}: ${b.count} event(s)`}
              />
            ))}
          </div>
          <div className="timeline-labels">
            <span>{formatTime(liveSummary.timeline[0].bucket_start)}</span>
            <span>
              {formatTime(
                liveSummary.timeline[liveSummary.timeline.length - 1].bucket_start,
              )}
            </span>
          </div>

          <div className="status-chips">
            {liveSummary.statusBreakdown.map((s) => {
              const meta = STATUS_META[s.key] ?? {
                cls: "neutral",
                label: s.key,
              };
              return (
                <span className="status-chip" key={s.key}>
                  <span className={`status-dot ${meta.cls}`} />
                  {meta.label}: {s.count}
                </span>
              );
            })}
          </div>
        </>
      )}

      <div className="table-card">
        <div className="tab-strip">
          <button
            className={tab === "findings" ? "active" : ""}
            onClick={() => setTab("findings")}
          >
            <span className={`status-dot ${findingsStatusDot(threat_status)}`} />
            Findings ({anomalies.filter((a) => a.is_anomaly).length})
          </button>
          <button
            className={tab === "events" ? "active" : ""}
            onClick={() => setTab("events")}
          >
            Events ({filteredEvents.length})
          </button>
          <button
            className={tab === "skipped" ? "active" : ""}
            onClick={() => setTab("skipped")}
          >
            Skipped lines ({skipped_lines.length})
          </button>
        </div>

        {tab === "events" && (
          <div className="filter-toolbar">
            {filters.map((f, i) => (
              <div className="filter-box" key={i}>
                <select
                  value={f.field}
                  onChange={(e) =>
                    updateFilter(i, { field: e.target.value as FilterField, value: "" })
                  }
                >
                  {FILTER_FIELDS.map((ff) => (
                    <option key={ff.key} value={ff.key}>
                      {ff.label}
                    </option>
                  ))}
                </select>
                <input
                  type={filterInputType(f.field)}
                  placeholder="Value"
                  value={f.value}
                  onChange={(e) => updateFilter(i, { value: e.target.value })}
                />
                <button className="btn ghost small" onClick={() => removeFilter(i)}>
                  Remove
                </button>
              </div>
            ))}
            <button className="btn ghost small" onClick={addFilter}>
              + Add filter
            </button>
          </div>
        )}

        <div className="table-card-body">
          {tab === "findings" && (
            <FindingsPanel
              status={threat_status}
              error={threat_error}
              anomalies={anomalies}
              onRetry={onRetryThreatDetection}
            />
          )}

          {tab === "events" && (
            <>
              <table className="uploads-table">
                <thead>
                  <tr>
                    {sortableHeader("timestamp", "Time")}
                    {sortableHeader("source_ip", "Source IP")}
                    {sortableHeader("method", "Method")}
                    {sortableHeader("url", "URL")}
                    {sortableHeader("status_code", "Status")}
                    {sortableHeader("bytes_sent", "Bytes")}
                  </tr>
                </thead>
                <tbody>
                  {pagedEvents.map((e, i) => (
                    <tr key={i}>
                      <td>{new Date(e.timestamp).toLocaleString()}</td>
                      <td>{e.source_ip}</td>
                      <td>{e.method}</td>
                      <td>{e.url}</td>
                      <td>{e.status_code}</td>
                      <td>{e.bytes_sent}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {filteredEvents.length === 0 && (
                <p className="sub">No events match this filter.</p>
              )}
              <Pagination
                page={eventsPageClamped}
                totalPages={totalEventsPages}
                onPageChange={setEventsPage}
              />
            </>
          )}

          {tab === "skipped" &&
            (skipped_lines.length === 0 ? (
              <p className="sub">No lines were skipped.</p>
            ) : (
              <pre className="skipped-lines">{skipped_lines.join("\n")}</pre>
            ))}
        </div>
      </div>
    </div>
  );
}

export default function DashboardPage() {
  const router = useRouter();
  const [username, setUsername] = useState<string | null>(null);
  const [uploads, setUploads] = useState<UploadMeta[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [pickerOpen, setPickerOpen] = useState(false);
  const fileHeaderRef = useRef<HTMLDivElement>(null);
  const [eventsById, setEventsById] = useState<Record<number, EventsResponse>>(
    {},
  );
  const [eventsLoadingId, setEventsLoadingId] = useState<number | null>(null);
  const [eventsError, setEventsError] = useState<string | null>(null);

  const refreshUploads = useCallback(async (name: string) => {
    try {
      const list = await listUploads(name);
      setUploads(list);
      return list;
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load uploads");
      return [];
    }
  }, []);

  const loadEvents = useCallback(async (id: number, name: string) => {
    setEventsError(null);
    setEventsLoadingId(id);
    try {
      const data = await getUploadEvents(id, name);
      setEventsById((prev) => ({ ...prev, [id]: data }));
    } catch (err) {
      setEventsError(
        err instanceof Error ? err.message : "Failed to load parsed events",
      );
    } finally {
      setEventsLoadingId(null);
    }
  }, []);

  useEffect(() => {
    const name = sessionStorage.getItem("username");
    if (!name || !readCsrfToken()) {
      router.replace("/login");
      return;
    }
    setUsername(name);
    refreshUploads(name).then((list) => {
      if (list.length === 0) return;
      const mostRecent = list.reduce((a, b) =>
        new Date(a.uploaded_at) > new Date(b.uploaded_at) ? a : b,
      );
      setSelectedId(mostRecent.id);
      loadEvents(mostRecent.id, name);
    });
  }, [router, refreshUploads, loadEvents]);

  async function onLogout() {
    if (username) {
      await logout(username).catch(() => {});
    }
    sessionStorage.removeItem("username");
    router.replace("/login");
  }

  async function onFileChosen(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file || !username) return;

    setError(null);
    setBusy(true);
    try {
      const meta = await uploadFile(username, file);
      await refreshUploads(username);
      setSelectedId(meta.id);
      setPickerOpen(false);
      loadEvents(meta.id, username);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Upload failed");
    } finally {
      setBusy(false);
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  }

  function selectUpload(id: number) {
    setSelectedId(id);
    setPickerOpen(false);
    if (eventsById[id] || !username) return;
    loadEvents(id, username);
  }

  async function onRetryThreatDetection(id: number) {
    if (!username) return;
    await retryThreatDetection(id, username);
    await loadEvents(id, username);
  }

  // Close the file picker dropdown on outside clicks.
  useEffect(() => {
    if (!pickerOpen) return;
    function onDocClick(e: MouseEvent) {
      if (fileHeaderRef.current && !fileHeaderRef.current.contains(e.target as Node)) {
        setPickerOpen(false);
      }
    }
    document.addEventListener("mousedown", onDocClick);
    return () => document.removeEventListener("mousedown", onDocClick);
  }, [pickerOpen]);

  const eventsByIdRef = useRef(eventsById);
  useEffect(() => {
    eventsByIdRef.current = eventsById;
  }, [eventsById]);

  // AI-based anomaly detection runs in the background after upload
  useEffect(() => {
    if (selectedId == null || !username) return;

    const interval = setInterval(async () => {
      if (eventsByIdRef.current[selectedId]?.threat_status !== "pending") return;
      try {
        const fresh = await getUploadEvents(selectedId, username);
        setEventsById((prev) => ({ ...prev, [selectedId]: fresh }));
      } catch {
      }
    }, 3000);

    return () => clearInterval(interval);
  }, [selectedId, username]);

  if (!username) return null;

  const selected = uploads.find((u) => u.id === selectedId) ?? null;

  return (
    <>
      <header className="topbar">
        <span className="who">Signed in as {username}</span>
        <button className="btn ghost" onClick={onLogout}>
          Log out
        </button>
      </header>
      <main className="uploads">
        <div className="page-header">
          {selected ? (
            <div className="file-header" ref={fileHeaderRef}>
              <button
                type="button"
                className={`file-header-title ${uploads.length > 1 ? "selectable" : ""}`}
                onClick={() => uploads.length > 1 && setPickerOpen((v) => !v)}
              >
                <h1>{selected.filename}</h1>
                {uploads.length > 1 && (
                  <span className={`file-chevron ${pickerOpen ? "open" : ""}`}>
                    ⌄
                  </span>
                )}
              </button>
              <p className="file-header-meta">
                {formatSize(selected.size_bytes)} &middot;{" "}
                {selected.parsed_count}/
                {selected.parsed_count + selected.skipped_count} lines parsed
                &middot; {new Date(selected.uploaded_at).toLocaleString()}
              </p>

              {pickerOpen && uploads.length > 1 && (
                <div className="file-dropdown">
                  {uploads
                    .filter((u) => u.id !== selected.id)
                    .map((u) => (
                      <button
                        key={u.id}
                        type="button"
                        className="file-dropdown-item"
                        onClick={() => selectUpload(u.id)}
                      >
                        <span className="file-dropdown-name">{u.filename}</span>
                        <span className="file-dropdown-sub">
                          {formatSize(u.size_bytes)} &middot; {u.parsed_count}/
                          {u.parsed_count + u.skipped_count} lines parsed
                          &middot; {new Date(u.uploaded_at).toLocaleString()}
                        </span>
                      </button>
                    ))}
                </div>
              )}
            </div>
          ) : (
            <h1 className="file-header-title placeholder">No files uploaded yet</h1>
          )}

          <label className="btn ghost upload-btn">
            {busy ? "Uploading..." : "Upload log file"}
            <input
              ref={fileInputRef}
              type="file"
              accept=".txt,.log,.json"
              onChange={onFileChosen}
              disabled={busy}
              hidden
            />
          </label>
        </div>

        {error && <p className="msg">{error}</p>}

        {selected && (
          <>
            {eventsLoadingId === selected.id && <p className="sub">Loading...</p>}
            {eventsError && <p className="msg">{eventsError}</p>}
            {eventsById[selected.id] && (
              <EventsPanel
                key={selected.id}
                data={eventsById[selected.id]}
                onRetryThreatDetection={() => onRetryThreatDetection(selected.id)}
              />
            )}
          </>
        )}
      </main>
    </>
  );
}
