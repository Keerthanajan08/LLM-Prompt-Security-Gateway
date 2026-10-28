/** A span of the prompt that a detector flagged. */
export interface Span {
  start: number;
  end: number;
  kind: "pattern" | "leak" | "injection";
  label: string;
}

export interface Segment {
  text: string;
  spans: Span[]; // empty = unflagged text
}

/**
 * Split `text` into consecutive segments so that every flagged span can be
 * highlighted, including overlapping ones (a segment lists every span covering it).
 * Spans are clamped to the text, and empty or inverted spans are ignored.
 */
export function segment(text: string, spans: Span[]): Segment[] {
  const valid = spans
    .map((s) => ({ ...s, start: Math.max(0, s.start), end: Math.min(text.length, s.end) }))
    .filter((s) => s.end > s.start);
  const cuts = new Set<number>([0, text.length]);
  for (const s of valid) {
    cuts.add(s.start);
    cuts.add(s.end);
  }
  const points = [...cuts].sort((a, b) => a - b);
  const out: Segment[] = [];
  for (let i = 0; i < points.length - 1; i++) {
    const a = points[i]!;
    const b = points[i + 1]!;
    if (b <= a) continue;
    out.push({ text: text.slice(a, b), spans: valid.filter((s) => s.start <= a && s.end >= b) });
  }
  return out;
}
