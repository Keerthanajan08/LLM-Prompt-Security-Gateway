"""
Chunking, redaction and masking helpers shared by the detectors.

Why chunk at all: embedding models truncate input (all-MiniLM-L6-v2 stops
at 256 word pieces, bge-small-en-v1.5 at 512) and average meaning over
everything they do see. Embedding a whole prompt means one confidential sentence buried in a
long, otherwise harmless prompt gets diluted below the threshold, and
anything past the truncation point is never seen at all. Embedding each
sentence (plus adjacent pairs, for facts split across two sentences) fixes
both.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_BOUNDARY_RE = re.compile(r"(?<=[.!?])\s+|\n+")
_WORD_RE = re.compile(r"\S+")

MAX_WORDS_PER_UNIT = 120
MAX_WORDS_PER_GROUP = 150


@dataclass(frozen=True)
class Chunk:
    text: str
    start: int
    end: int


def _sentence_spans(text: str) -> list[tuple[int, int]]:
    spans, pos = [], 0
    for m in _BOUNDARY_RE.finditer(text):
        if m.start() > pos:
            spans.append((pos, m.start()))
        pos = m.end()
    if pos < len(text):
        spans.append((pos, len(text)))
    return [(s, e) for s, e in spans if text[s:e].strip()]


def _split_long(text: str, start: int, end: int) -> list[tuple[int, int]]:
    words = list(_WORD_RE.finditer(text, start, end))
    if len(words) <= MAX_WORDS_PER_UNIT:
        return [(start, end)]
    out = []
    for i in range(0, len(words), MAX_WORDS_PER_UNIT):
        window = words[i : i + MAX_WORDS_PER_UNIT]
        out.append((window[0].start(), window[-1].end()))
    return out


def _word_count(text: str, span: tuple[int, int]) -> int:
    return len(_WORD_RE.findall(text, span[0], span[1]))


def chunk_text(text: str, max_chunks: int = 128) -> list[Chunk]:
    """Split text into embeddable chunks that together cover all of it.

    Coverage is never sacrificed for the chunk budget: when there are too
    many sentences, consecutive ones are grouped (up to ~150 words, which
    still fits the model's window) rather than dropped. Dropping chunks
    would let an attacker pad a prompt until the sensitive part falls off
    the end.
    """
    units: list[tuple[int, int]] = []
    for s, e in _sentence_spans(text):
        units.extend(_split_long(text, s, e))
    if not units:
        return []

    if 2 * len(units) - 1 > max_chunks:
        grouped: list[tuple[int, int]] = []
        current, words = units[0], _word_count(text, units[0])
        for unit in units[1:]:
            n = _word_count(text, unit)
            if words + n <= MAX_WORDS_PER_GROUP:
                current, words = (current[0], unit[1]), words + n
            else:
                grouped.append(current)
                current, words = unit, n
        grouped.append(current)
        units = grouped

    spans = list(units)
    if 2 * len(units) - 1 <= max_chunks:
        spans += [(a[0], b[1]) for a, b in zip(units, units[1:], strict=False)]
    return [Chunk(text[s:e], s, e) for s, e in spans]


def redact_spans(text: str, spans: list[tuple[int, int, str]]) -> str:
    """Replace each (start, end, label) span with [REDACTED:LABEL].

    Overlapping spans are merged; the label of the earliest span is kept.
    """
    if not spans:
        return text
    ordered = sorted(spans, key=lambda s: (s[0], -s[1]))
    merged: list[list] = []
    for start, end, label in ordered:
        if merged and start < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end, label])
    out, pos = [], 0
    for start, end, label in merged:
        out.append(text[pos:start])
        out.append(f"[REDACTED:{label.upper()}]")
        pos = end
    out.append(text[pos:])
    return "".join(out)


def mask_value(value: str) -> str:
    """Show just enough of a secret to identify it, never enough to use it."""
    compact = value.strip()
    if len(compact) <= 8:
        return "*" * len(compact)
    keep = 2 if len(compact) <= 16 else 4
    hidden = min(len(compact) - 2 * keep, 12)
    return f"{compact[:keep]}{'*' * hidden}{compact[-keep:]}"
