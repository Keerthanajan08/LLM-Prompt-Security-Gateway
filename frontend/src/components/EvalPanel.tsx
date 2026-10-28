import { useState } from "react";

import { categoryLabel, ms, pct } from "../format";
import type { EvalResults, SplitResult } from "../types";

// Categories the gateway should catch vs. let through, in display order.
const SHOULD_BLOCK = [
  "secret",
  "pii",
  "financial",
  "confidential_paraphrase",
  "confidential_buried",
  "injection",
];
const SHOULD_PASS = ["clean", "hard_negative", "injection_hard_negative"];

type Split = "test" | "dev";

export function EvalPanel({ data }: { data: EvalResults }) {
  const [split, setSplit] = useState<Split>("test");
  const result: SplitResult = data[split];
  const total = data.dev.n + data.test.n;

  return (
    <div className="card">
      <h2>How well does it work?</h2>
      <p className="sub">
        {total} hand-written prompts. Thresholds were tuned on the dev split only; the test split
        is unseen, so its numbers are the honest ones.
      </p>

      <fieldset className="segmented" aria-label="Evaluation split">
        {(["test", "dev"] as const).map((s) => (
          <label key={s} className={split === s ? "active" : ""}>
            <input
              type="radio"
              name="split"
              value={s}
              checked={split === s}
              onChange={() => setSplit(s)}
            />
            {s === "test" ? `Test (unseen, ${data.test.n})` : `Dev (tuning, ${data.dev.n})`}
          </label>
        ))}
      </fieldset>

      <div className="tiles" style={{ marginTop: 12 }}>
        <Tile label="Recall" value={pct(result.recall)} note="risky prompts caught" />
        <Tile label="Precision" value={pct(result.precision)} note="of flags were right" />
        <Tile label="F1" value={result.f1.toFixed(2)} note="balance of both" />
        <Tile
          label="False alarms"
          value={pct(result.false_positive_rate)}
          note="of safe prompts flagged"
        />
        <Tile
          label="Latency (p50)"
          value={ms(result.latency_ms_p50)}
          note={`p95 ${ms(result.latency_ms_p95)}`}
        />
      </div>

      <BarGroup title="Should be blocked" series="series-1" keys={SHOULD_BLOCK} result={result} />
      <BarGroup title="Should pass through" series="series-2" keys={SHOULD_PASS} result={result} />

      <p className="callout">
        Embeddings: {data.config.embedding_model}. Leak threshold{" "}
        {data.config.semantic_leak_threshold}, injection threshold{" "}
        {data.config.injection_similarity_threshold}.
      </p>
    </div>
  );
}

interface BarGroupProps {
  title: string;
  series: "series-1" | "series-2";
  keys: string[];
  result: SplitResult;
}

function BarGroup({ title, series, keys, result }: BarGroupProps) {
  const rows = keys.filter((k) => result.per_category[k]);
  return (
    <div className="bars" role="table" aria-label={`${title}: share handled correctly`}>
      <div className="bars-title" role="row">
        <span role="columnheader">
          <i className="swatch" style={{ background: `var(--${series})` }} aria-hidden="true" />
          {title}
        </span>
        <span role="columnheader" className="sr-only">
          Handled correctly
        </span>
      </div>
      {rows.map((k) => {
        const c = result.per_category[k]!;
        return (
          <div
            className="bar-row"
            role="row"
            key={k}
            title={`${categoryLabel(k)}: ${c.correct} of ${c.n} handled correctly (${pct(c.rate, 0)})`}
          >
            <span className="bar-label" role="cell">
              {categoryLabel(k)}
            </span>
            <span className="bar-track" role="cell" aria-label={`${pct(c.rate, 0)}`}>
              <span
                className="bar-fill"
                style={{ width: `${c.rate * 100}%`, background: `var(--${series})` }}
              />
            </span>
            <span className="bar-value" role="cell">
              {c.correct}/{c.n}
            </span>
          </div>
        );
      })}
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
