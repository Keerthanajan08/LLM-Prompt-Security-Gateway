import { categoryLabel, ms, ruleLabel } from "../format";
import { type Span, segment } from "../highlight";
import type { CheckResponse, Verdict } from "../types";

export const VERDICT_TEXT: Record<Verdict, { icon: string; label: string; note: string }> = {
  safe: { icon: "✓", label: "SAFE", note: "Nothing sensitive found" },
  blocked: { icon: "⛔", label: "BLOCKED", note: "Never reaches the LLM" },
  redacted: { icon: "✎", label: "REDACTED", note: "Sensitive parts masked before sending" },
  flagged: { icon: "⚑", label: "FLAGGED", note: "Logged only (log_only mode)" },
};

export function VerdictBadge({ verdict }: { verdict: Verdict }) {
  const v = VERDICT_TEXT[verdict];
  return (
    <span className={`badge verdict-${verdict}`}>
      <span aria-hidden="true">{v.icon}</span>
      {v.label}
    </span>
  );
}

/** Every flagged span, in one shape, for highlighting and the findings list. */
export function spansOf(result: CheckResponse): Span[] {
  return [
    ...result.pattern_matches.map<Span>((m) => ({
      start: m.start,
      end: m.end,
      kind: "pattern",
      label: `${ruleLabel(m.rule_name)} (${categoryLabel(m.category)}, ${m.pack} pack)`,
    })),
    ...result.semantic_matches.map<Span>((m) => ({
      start: m.start,
      end: m.end,
      kind: "leak",
      label: `Close to confidential doc "${m.doc_id}" (similarity ${m.similarity.toFixed(2)})`,
    })),
    ...result.injection_matches.map<Span>((m) => ({
      start: m.start,
      end: m.end,
      kind: "injection",
      label: `Prompt injection: ${ruleLabel(m.rule_name)} (${m.kind}${
        m.similarity !== null ? `, similarity ${m.similarity.toFixed(2)}` : ""
      })`,
    })),
  ];
}

const KIND_LABEL = { pattern: "Pattern", leak: "Leak", injection: "Injection" } as const;

interface Props {
  result: CheckResponse;
  /** The exact text that was screened, so flagged spans can be shown in place. */
  text: string;
  title?: string;
}

export function VerdictView({ result, text, title }: Props) {
  const spans = spansOf(result);
  const v = VERDICT_TEXT[result.verdict];

  return (
    <section className="result" aria-label={title ?? "Screening result"} aria-live="polite">
      {title && <h3 className="result-title">{title}</h3>}
      <div className="result-head">
        <VerdictBadge verdict={result.verdict} />
        <span className="kv">{v.note}</span>
        <span className="kv">
          Latency <strong>{ms(result.latency_ms)}</strong>
          {result.from_cache && " (cached verdict)"}
        </span>
      </div>

      {result.categories.length > 0 && (
        <div className="tags" aria-label="Categories">
          {result.categories.map((c) => (
            <span className="tag" key={c}>
              {categoryLabel(c)}
            </span>
          ))}
        </div>
      )}

      {spans.length > 0 && (
        <>
          <p className="prompt-view" aria-label="Screened text with findings highlighted">
            {segment(text, spans).map((seg, i) =>
              seg.spans.length === 0 ? (
                <span key={i}>{seg.text}</span>
              ) : (
                <mark
                  key={i}
                  className={`hl hl-${seg.spans[0]!.kind}`}
                  title={seg.spans.map((s) => s.label).join("\n")}
                >
                  {seg.text}
                </mark>
              ),
            )}
          </p>
          <ul className="findings" aria-label="Findings">
            {spans.map((s, i) => (
              <li key={i}>
                <span className={`kind kind-${s.kind}`}>{KIND_LABEL[s.kind]}</span>
                <span>{s.label}</span>
              </li>
            ))}
          </ul>
        </>
      )}

      {result.reasons.length > 0 && spans.length === 0 && (
        <ul className="findings">
          {result.reasons.map((r) => (
            <li key={r}>{r}</li>
          ))}
        </ul>
      )}

      {result.sanitized_prompt && (
        <div>
          <p className="matched">What the LLM receives instead:</p>
          <p className="answer">{result.sanitized_prompt}</p>
        </div>
      )}
    </section>
  );
}
