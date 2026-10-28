/** 0.976 -> "97.6%" */
export function pct(value: number, digits = 1): string {
  return `${(value * 100).toFixed(digits)}%`;
}

/** 32.41 -> "32.4 ms" */
export function ms(value: number): string {
  if (value >= 1000) return `${(value / 1000).toFixed(2)} s`;
  return `${value.toFixed(1)} ms`;
}

const CATEGORY_LABELS: Record<string, string> = {
  secret: "Secrets & API keys",
  pii: "Personal data (PII)",
  financial: "Payment & financial",
  confidential: "Confidential documents",
  confidential_paraphrase: "Paraphrased confidential docs",
  confidential_buried: "Confidential, buried in long text",
  injection: "Prompt injection",
  clean: "Ordinary prompts",
  hard_negative: "Tricky but safe prompts",
  injection_hard_negative: "Safe questions about injection",
};

export function categoryLabel(category: string): string {
  return CATEGORY_LABELS[category] ?? category.replace(/_/g, " ");
}

/** "aws_access_key_id" -> "aws access key id" */
export function ruleLabel(rule: string): string {
  return rule.replace(/_/g, " ");
}
