import type { HealthResponse } from "../types";

interface Props {
  health: HealthResponse | null;
  error: string | null;
}

export function HealthBar({ health, error }: Props) {
  if (error) {
    return (
      <div className="health" role="status">
        <span className="pill">
          <span className="dot bad" aria-hidden="true" />
          <strong>Gateway unreachable</strong>
        </span>
      </div>
    );
  }
  if (!health) {
    return (
      <div className="health" role="status">
        <span className="pill">Connecting…</span>
      </div>
    );
  }
  return (
    <div className="health" role="status" aria-label="Gateway status">
      <span className="pill">
        <span className={`dot ${health.status === "ok" ? "ok" : "warn"}`} aria-hidden="true" />
        <strong>{health.status === "ok" ? "Healthy" : health.status}</strong>
      </span>
      <span className="pill">
        On leak <strong>{health.on_leak_action}</strong>
      </span>
      <span className="pill">
        LLM <strong>{health.llm_provider}</strong>
      </span>
      <span className="pill">
        Rule packs <strong>{health.rule_packs.join(", ")}</strong>
      </span>
      <span className="pill">
        Corpus <strong>{health.corpus_chunks} chunks</strong>
      </span>
      <span className="pill">
        Injection check <strong>{health.injection_detection ? "on" : "off"}</strong>
      </span>
      <span className="pill">v{health.version}</span>
    </div>
  );
}
