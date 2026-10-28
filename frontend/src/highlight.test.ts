import { type Span, segment } from "./highlight";

const span = (start: number, end: number, kind: Span["kind"] = "pattern"): Span => ({
  start,
  end,
  kind,
  label: kind,
});

describe("segment", () => {
  it("returns the whole text when nothing is flagged", () => {
    expect(segment("hello", [])).toEqual([{ text: "hello", spans: [] }]);
  });

  it("isolates a flagged span", () => {
    const parts = segment("card 4111 here", [span(5, 9)]);
    expect(parts.map((p) => [p.text, p.spans.length])).toEqual([
      ["card ", 0],
      ["4111", 1],
      [" here", 0],
    ]);
  });

  it("splits overlapping spans so each piece lists every span covering it", () => {
    const parts = segment("abcdef", [span(0, 4, "pattern"), span(2, 6, "leak")]);
    expect(parts.map((p) => [p.text, p.spans.map((s) => s.kind)])).toEqual([
      ["ab", ["pattern"]],
      ["cd", ["pattern", "leak"]],
      ["ef", ["leak"]],
    ]);
  });

  it("clamps out-of-range spans and ignores empty ones", () => {
    const parts = segment("abc", [span(-5, 1), span(2, 99), span(1, 1)]);
    expect(parts.map((p) => [p.text, p.spans.length])).toEqual([
      ["a", 1],
      ["b", 0],
      ["c", 1],
    ]);
  });
});
