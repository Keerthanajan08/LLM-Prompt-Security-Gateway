// Mirrors app/schemas.py and GET /health. Keep the two in sync.

export type Verdict = "safe" | "blocked" | "redacted" | "flagged";
export type Category = "secret" | "financial" | "pii" | "confidential" | "injection";

export interface PatternMatch {
  rule_name: string;
  pack: string;
  category: string;
  matched_text: string;
  start: number;
  end: number;
}

export interface SemanticMatch {
  doc_id: string;
  similarity: number;
  start: number;
  end: number;
  snippet: string | null;
}

export interface InjectionMatch {
  rule_name: string;
  kind: "heuristic" | "semantic";
  start: number;
  end: number;
  similarity: number | null;
}

export interface CheckResponse {
  verdict: Verdict;
  action_taken: "none" | "block" | "redact" | "log_only";
  categories: Category[];
  reasons: string[];
  pattern_matches: PatternMatch[];
  semantic_matches: SemanticMatch[];
  injection_matches: InjectionMatch[];
  sanitized_prompt: string | null;
  from_cache: boolean;
  latency_ms: number;
}

export interface QueryResponse {
  check: CheckResponse;
  forwarded_to_llm: boolean;
  provider: string | null;
  model: string | null;
  answer: string | null;
  response_check: CheckResponse | null;
}

export interface StatsResponse {
  total_checked: number;
  safe: number;
  blocked: number;
  redacted: number;
  flagged: number;
  block_rate: number;
  cache_hits: number;
  injection_detections: number;
  responses_scanned: number;
  response_leaks: number;
}

export interface HealthResponse {
  status: string;
  version: string;
  llm_provider: string;
  on_leak_action: string;
  on_response_leak_action: string;
  rule_packs: string[];
  embedding_backend: string;
  corpus_chunks: number;
  injection_detection: boolean;
}

// evals/results.json, written by `python -m evals.run_eval`.
export interface CategoryResult {
  n: number;
  correct: number;
  rate: number;
}

export interface SplitResult {
  n: number;
  precision: number;
  recall: number;
  f1: number;
  false_positive_rate: number;
  per_category: Record<string, CategoryResult>;
  latency_ms_p50: number;
  latency_ms_p95: number;
  misses: { id: string; got: string[]; text: string }[];
}

export interface EvalResults {
  config: {
    embedding_model: string;
    rule_packs: string;
    semantic_leak_threshold: number;
    injection_similarity_threshold: number;
  };
  dev: SplitResult;
  test: SplitResult;
}
