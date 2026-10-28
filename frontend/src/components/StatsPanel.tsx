import { pct } from "../format";
import type { StatsResponse } from "../types";

interface Props {
  stats: StatsResponse | null;
  error: string | null;
}

export function StatsPanel({ stats, error }: Props) {
  return (
    <div className="card">
      <h2>Live gateway stats</h2>
      <p className="sub">Since the gateway started. Refreshes every 5 seconds.</p>
      {error && !stats && <p className="empty">Couldn't load stats: {error}</p>}
      {stats && (
        <div className="tiles">
          <Tile label="Prompts screened" value={String(stats.total_checked)} note={`${stats.safe} safe`} />
          <Tile
            label="Block rate"
            value={stats.total_checked ? pct(stats.block_rate) : "–"}
            note={`${stats.blocked} blocked`}
          />
          <Tile
            label="Redacted / flagged"
            value={`${stats.redacted} / ${stats.flagged}`}
            note="masked or logged"
          />
          <Tile
            label="Injection attempts"
            value={String(stats.injection_detections)}
            note="detected"
          />
          <Tile
            label="LLM answers scanned"
            value={String(stats.responses_scanned)}
            note={`${stats.response_leaks} contained a leak`}
          />
          <Tile label="Verdict cache hits" value={String(stats.cache_hits)} note="repeat prompts" />
        </div>
      )}
    </div>
  );
}

function Tile({ label, value, note }: { label: string; value: string; note: string }) {
  return (
    <div className="tile">
      <div className="label">{label}</div>
      <div className="value">{value}</div>
      <div className="note">{note}</div>
    </div>
  );
}
