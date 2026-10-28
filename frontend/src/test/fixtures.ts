import type { CheckResponse, EvalResults, QueryResponse, StatsResponse } from "../types";

export const CARD_PROMPT = "Charge card 4111 1111 1111 1111 exp 12/28.";

export const blocked: CheckResponse = {
  verdict: "blocked",
  action_taken: "block",
  categories: ["financial"],
  reasons: ["credit_card (global)"],
  pattern_matches: [
    {
      rule_name: "credit_card",
      pack: "global",
      category: "financial",
      matched_text: "4111********1111",
      start: 12,
      end: 31,
    },
  ],
  semantic_matches: [],
  injection_matches: [],
  sanitized_prompt: null,
  from_cache: false,
  latency_ms: 3.2,
};

export const safe: CheckResponse = {
  verdict: "safe",
  action_taken: "none",
  categories: [],
  reasons: [],
  pattern_matches: [],
  semantic_matches: [],
  injection_matches: [],
  sanitized_prompt: null,
  from_cache: false,
  latency_ms: 31.9,
};

export const answered: QueryResponse = {
  check: safe,
  forwarded_to_llm: true,
  provider: "mock",
  model: "mock-1",
  answer: "Use a layered layout with routers per feature.",
  response_check: safe,
};

export const notSent: QueryResponse = {
  check: blocked,
  forwarded_to_llm: false,
  provider: null,
  model: null,
  answer: null,
  response_check: null,
};

export const stats: StatsResponse = {
  total_checked: 8,
  safe: 3,
  blocked: 5,
  redacted: 0,
  flagged: 0,
  block_rate: 0.625,
  cache_hits: 1,
  injection_detections: 1,
  responses_scanned: 2,
  response_leaks: 0,
};

const split = (recall: number, fpr: number) => ({
  n: 69,
  precision: 0.889,
  recall,
  f1: 0.93,
  false_positive_rate: fpr,
  per_category: {
    secret: { n: 7, correct: 7, rate: 1 },
    injection: { n: 11, correct: 10, rate: 0.909 },
    hard_negative: { n: 10, correct: 6, rate: 0.6 },
  },
  latency_ms_p50: 32.4,
  latency_ms_p95: 41,
  misses: [
    { id: "t-1", got: ["confidential"], text: "How should a startup price an IoT device subscription?" },
  ],
});

export const evalResults: EvalResults = {
  config: {
    embedding_model: "BAAI/bge-small-en-v1.5",
    rule_packs: "global,us,uk,eu,in",
    semantic_leak_threshold: 0.66,
    injection_similarity_threshold: 0.67,
  },
  test: split(0.976, 0.179),
  dev: { ...split(1, 0), n: 66, misses: [] },
};

/** Replace fetch with a function returning the given JSON bodies in order. */
export function mockFetch(...bodies: Array<{ status?: number; body: unknown }>) {
  const fn = vi.fn();
  for (const { status = 200, body } of bodies) {
    fn.mockResolvedValueOnce(
      new Response(JSON.stringify(body), {
        status,
        headers: { "Content-Type": "application/json" },
      }),
    );
  }
  vi.stubGlobal("fetch", fn);
  return fn;
}
