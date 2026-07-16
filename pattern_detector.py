"""
Fast, cheap first line of defense: regex rules for structurally
recognizable sensitive data (API keys, SSNs, credit cards, private keys).

Deliberately NOT trying to catch paraphrased/contextual leaks here — that's
the semantic detector's job. Keeping these two concerns separate is what
makes each one easy to reason about and test independently.
"""
import re
from dataclasses import dataclass


@dataclass
class PatternRule:
    name: str
    pattern: re.Pattern


RULES: list[PatternRule] = [
    PatternRule("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    PatternRule("generic_api_key", re.compile(r"\b(sk|api|key)[-_][A-Za-z0-9]{20,}\b", re.IGNORECASE)),
    PatternRule("private_key_block", re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----")),
    PatternRule("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    PatternRule("credit_card", re.compile(r"\b(?:\d[ -]*?){13,16}\b")),
    PatternRule("email_internal", re.compile(r"\b[A-Za-z0-9._%+-]+@(internal|corp)\.[A-Za-z]{2,}\b", re.IGNORECASE)),
]


@dataclass
class PatternDetectionResult:
    matches: list[tuple[str, str]]  # (rule_name, matched_text)

    @property
    def has_matches(self) -> bool:
        return len(self.matches) > 0


def detect_patterns(text: str) -> PatternDetectionResult:
    matches = []
    for rule in RULES:
        for m in rule.pattern.finditer(text):
            matches.append((rule.name, m.group(0)))
    return PatternDetectionResult(matches=matches)


def redact_patterns(text: str) -> str:
    redacted = text
    for rule in RULES:
        redacted = rule.pattern.sub(f"[REDACTED:{rule.name.upper()}]", redacted)
    return redacted
