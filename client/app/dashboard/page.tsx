"use client";

import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import {
  logout,
  listUploads,
  readCsrfToken,
  uploadFile,
  getUploadEvents,
  type UploadMeta,
  type EventsResponse,
  type LogEntry,
  type CountEntry,
  type TimelineBucket,
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
function EventsPanel({ data }: { data: EventsResponse }) {
  const { summary, events, skipped_lines } = data;
  const [tab, setTab] = useState<"events" | "skipped">("events");
  const [filters, setFilters] = useState<FilterRow[]>([]);
  const [sortField, setSortField] = useState<FilterField>("timestamp");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");

  function updateFilter(index: number, patch: Partial<FilterRow>) {
    setFilters((prev) => prev.map((f, i) => (i === index ? { ...f, ...patch } : f)));
  }
  function addFilter() {
    setFilters((prev) => [...prev, { field: "source_ip", value: "" }]);
  }
  function removeFilter(index: number) {
    setFilters((prev) => prev.filter((_, i) => i !== index));
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

  // Timeline + status chips track whatever is currently filtered in, not
  // the whole file -- recomputed client-side since filtering happens here.
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
          <>
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

            <div className="sort-toolbar">
              <span className="sub">Sort by</span>
              <select
                value={sortField}
                onChange={(e) => setSortField(e.target.value as FilterField)}
              >
                {FILTER_FIELDS.map((ff) => (
                  <option key={ff.key} value={ff.key}>
                    {ff.label}
                  </option>
                ))}
              </select>
              <button
                className="btn ghost small"
                onClick={() => setSortDir((d) => (d === "asc" ? "desc" : "asc"))}
              >
                {sortDir === "asc" ? "Ascending ▲" : "Descending ▼"}
              </button>
            </div>
          </>
        )}

        <div className="table-card-body">
          {tab === "events" ? (
            <>
              <table className="uploads-table">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Source IP</th>
                    <th>Method</th>
                    <th>URL</th>
                    <th>Status</th>
                    <th>Bytes</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredEvents.map((e, i) => (
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
            </>
          ) : skipped_lines.length === 0 ? (
            <p className="sub">No lines were skipped.</p>
          ) : (
            <pre className="skipped-lines">{skipped_lines.join("\n")}</pre>
          )}
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

  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [eventsById, setEventsById] = useState<Record<number, EventsResponse>>(
    {},
  );
  const [eventsLoadingId, setEventsLoadingId] = useState<number | null>(null);
  const [eventsError, setEventsError] = useState<string | null>(null);

  const refreshUploads = useCallback(async (name: string) => {
    try {
      setUploads(await listUploads(name));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load uploads");
    }
  }, []);

  useEffect(() => {
    // Cheap client-side guard so a direct visit to /dashboard does not render
    // an empty shell for someone who never logged in. Not a security control:
    // the API re-checks the session on every protected request.
    const name = sessionStorage.getItem("username");
    if (!name || !readCsrfToken()) {
      router.replace("/login");
      return;
    }
    setUsername(name);
    refreshUploads(name);
  }, [router, refreshUploads]);

  async function onLogout() {
    if (username) {
      // A failed logout should not strand the user on a page they can't leave.
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
      await uploadFile(username, file);
      await refreshUploads(username);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Upload failed");
    } finally {
      setBusy(false);
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  }

  async function onRowClick(u: UploadMeta) {
    if (expandedId === u.id) {
      setExpandedId(null);
      return;
    }
    setExpandedId(u.id);
    if (eventsById[u.id] || !username) return;

    setEventsError(null);
    setEventsLoadingId(u.id);
    try {
      const data = await getUploadEvents(u.id, username);
      setEventsById((prev) => ({ ...prev, [u.id]: data }));
    } catch (err) {
      setEventsError(
        err instanceof Error ? err.message : "Failed to load parsed events",
      );
    } finally {
      setEventsLoadingId(null);
    }
  }

  if (!username) return null;

  return (
    <>
      <header className="topbar">
        <span className="who">Signed in as {username}</span>
        <button className="btn ghost" onClick={onLogout}>
          Log out
        </button>
      </header>
      <main className="uploads">
        <div className="uploads-toolbar">
          <label className="btn upload-btn">
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

        {uploads.length === 0 ? (
          <p className="sub">No files uploaded yet.</p>
        ) : (
          <>
            <p className="sub">
              Click a row to view its parsed events, timeline, and stats.
            </p>
            <table className="uploads-table">
              <thead>
                <tr>
                  <th>Filename</th>
                  <th>Size</th>
                  <th>Parsed</th>
                  <th>Uploaded</th>
                </tr>
              </thead>
              <tbody>
                {uploads.map((u) => (
                  <Fragment key={u.id}>
                    <tr className="upload-row" onClick={() => onRowClick(u)}>
                      <td>
                        <span className="expand-arrow">
                          {expandedId === u.id ? "▾" : "▸"}
                        </span>
                        {u.filename}
                      </td>
                      <td>{formatSize(u.size_bytes)}</td>
                      <td>
                        {u.parsed_count}/{u.parsed_count + u.skipped_count}{" "}
                        lines
                      </td>
                      <td>{new Date(u.uploaded_at).toLocaleString()}</td>
                    </tr>
                    {expandedId === u.id && (
                      <tr key={`${u.id}-panel`}>
                        <td colSpan={4}>
                          {eventsLoadingId === u.id && (
                            <p className="sub">Loading...</p>
                          )}
                          {eventsError && <p className="msg">{eventsError}</p>}
                          {eventsById[u.id] && (
                            <EventsPanel data={eventsById[u.id]} />
                          )}
                        </td>
                      </tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </>
        )}
      </main>
    </>
  );
}
