"""
Prompt-injection / jailbreak detection (OWASP Top 10 for LLM Apps: LLM01).

Two complementary signals, mirroring the leak detectors:

- Heuristics: regexes for the well-known attack shapes ("ignore previous
  instructions", "reveal your system prompt", fake system tags, persona
  jailbreaks). Exact, explainable, near-zero cost.
- Semantic similarity against a set of known attack exemplars
  (app/data/injection_exemplars.txt), which catches rewordings the regexes
  don't anticipate.

This is a screening layer, not a guarantee: injection is an open problem
and determined attackers will get past any filter. The value is cheaply
stopping the common attacks and producing an audit signal for the rest.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import numpy as np

from app.config import settings
from app.embeddings import get_embedder
from app.text_utils import Chunk


@dataclass(frozen=True)
class InjectionMatch:
    rule_name: str
    kind: str  # "heuristic" | "semantic"
    start: int
    end: int
    similarity: float | None = None


_FLAGS = re.I | re.S

HEURISTICS: list[tuple[str, re.Pattern]] = [
    (
        "ignore_previous_instructions",
        re.compile(
            r"\b(?:ignore|disregard|forget|override|bypass)\b.{0,40}?"
            r"\b(?:previous|prior|above|earlier|preceding|all|any|your|the|these|those)\b.{0,25}?"
            r"\b(?:instructions?|rules|prompts?|directions|guidelines|directives|context|constraints)\b",
            _FLAGS,
        ),
    ),
    (
        "system_prompt_extraction",
        re.compile(
            r"\b(?:reveal|show|print|repeat|output|display|leak|dump|tell me|what (?:is|are|was|were))\b.{0,40}?"
            r"\b(?:system prompt|initial (?:prompt|instructions)|hidden (?:prompt|instructions)|"
            r"your (?:instructions|rules|guidelines)|developer (?:message|prompt)|the text above)\b",
            _FLAGS,
        ),
    ),
    (
        "persona_jailbreak",
        re.compile(
            r"\b(?:you are now|from now on,? you(?: are|'re| will be)|act as|pretend (?:to be|you are)|roleplay as|"
            r"you will play)\b.{0,60}?"
            r"\b(?:DAN|do anything now|unfiltered|uncensored|jailbroken|unrestricted|"
            r"without (?:any )?(?:restrictions|limits|limitations|filters|rules|guidelines)|"
            r"no (?:rules|restrictions|limits))\b",
            _FLAGS,
        ),
    ),
    (
        "developer_mode",
        re.compile(
            r"\b(?:enable|activate|enter|switch to)\b.{0,15}?\b(?:developer|god|debug|sudo|admin|jailbreak) mode\b|"
            r"\b(?:developer|god|jailbreak) mode\b.{0,15}?\b(?:enabled|on|activated)\b",
            _FLAGS,
        ),
    ),
    (
        "disable_safety",
        re.compile(
            r"\b(?:bypass|disable|turn off|deactivate|remove|ignore)\b.{0,30}?"
            r"\b(?:safety|content (?:policy|filter)|moderation|guardrails?|safeguards|filters|restrictions|"
            r"ethical guidelines)\b",
            _FLAGS,
        ),
    ),
    (
        "fake_system_message",
        re.compile(
            r"(?:^|\n)\s*(?:\[\s*system\s*\]|<\|?\s*system\s*\|?>|<\|im_start\|>\s*system|#{2,}\s*system\b|system\s*(?:override|message)\s*:)",
            re.I,
        ),
    ),
    (
        "encoded_instruction",
        re.compile(
            r"\b(?:decode|base64|rot13|reverse)\b.{0,40}?\b(?:follow|execute|run|obey|do what it says)\b", _FLAGS
        ),
    ),
]


def detect_injection_heuristics(text: str) -> list[InjectionMatch]:
    matches = []
    for name, pattern in HEURISTICS:
        m = pattern.search(text)
        if m:
            matches.append(InjectionMatch(name, "heuristic", m.start(), m.end()))
    return matches


class InjectionExemplars:
    def __init__(self, path: Path):
        self.texts: list[str] = []
        self.matrix = np.zeros((0, 1), dtype=np.float32)
        if path.is_file():
            self.texts = [
                line.strip()
                for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            ]
        if self.texts:
            self.matrix = get_embedder().encode_batch(self.texts)

    def __len__(self) -> int:
        return len(self.texts)


@lru_cache(maxsize=1)
def get_exemplars() -> InjectionExemplars:
    return InjectionExemplars(Path(settings.injection_exemplars_path))


# Very short chunks ("How do I present this?") carry too little meaning to
# compare: short generic questions all land near the "what are your
# instructions?" exemplars. The heuristics still see the full text.
MIN_WORDS_FOR_SEMANTIC_CHECK = 6


def detect_injection_semantic(chunks: list[Chunk], vectors: np.ndarray) -> list[InjectionMatch]:
    exemplars = get_exemplars()
    if not len(exemplars) or not chunks:
        return []
    scores = vectors @ exemplars.matrix.T
    best_per_chunk = scores.max(axis=1)
    for idx, chunk in enumerate(chunks):
        if len(chunk.text.split()) < MIN_WORDS_FOR_SEMANTIC_CHECK:
            best_per_chunk[idx] = -1.0
    i = int(best_per_chunk.argmax())
    score = float(best_per_chunk[i])
    if score < settings.injection_similarity_threshold:
        return []
    chunk = chunks[i]
    return [InjectionMatch("similar_to_known_attack", "semantic", chunk.start, chunk.end, round(score, 4))]
