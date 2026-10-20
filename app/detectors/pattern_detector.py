"""
Fast, cheap first line of defence: regex rules for structurally
recognisable sensitive data, organised into rule packs.

- "global" covers what leaks everywhere: cloud/API credentials, private
  keys, connection strings, payment data (card numbers, IBANs) and contact
  details (emails, international phone numbers).
- Regional packs (us, uk, eu, in) add national identifiers. A deployment
  enables the jurisdictions it operates in via RULE_PACKS.

Rules can carry a checksum validator (Luhn, mod-97, Verhoeff, ...) so a
number that merely has the right shape is not flagged.

Deliberately NOT trying to catch paraphrased/contextual leaks here — that's
the semantic detector's job.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from functools import lru_cache

from app.detectors import validators as v

Validator = Callable[[str], bool]


@dataclass(frozen=True)
class PatternRule:
    name: str
    pack: str
    category: str  # "secret" | "financial" | "pii"
    pattern: re.Pattern
    validator: Validator | None = None
    group: int = 0  # which capture group holds the sensitive value


@dataclass(frozen=True)
class PatternMatch:
    rule_name: str
    pack: str
    category: str
    text: str
    start: int
    end: int


_PLACEHOLDER_RE = re.compile(r"^(?:\*+|x+|\.+|<.*>|\{\{.*\}\}|\$\{.*\}|your[_-]?\w*|changeme|redacted)$", re.I)


def _not_placeholder(value: str) -> bool:
    return not _PLACEHOLDER_RE.match(value) and len(set(value)) > 3


def _phone_digits_ok(value: str) -> bool:
    return 8 <= len(v.digits_only(value)) <= 15


def _rule(name, pack, category, regex, validator=None, group=0, flags=0) -> PatternRule:
    return PatternRule(name, pack, category, re.compile(regex, flags), validator, group)


# Order matters: when two rules match the same span, the earlier (more
# specific) rule wins. Generic rules go last.
RULES: list[PatternRule] = [
    # ---- global: secrets ----------------------------------------------------
    _rule(
        "private_key_block",
        "global",
        "secret",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----"
        r"[\s\S]*?(?:-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----|\Z)",
    ),
    _rule("aws_access_key_id", "global", "secret", r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
    _rule(
        "aws_secret_access_key",
        "global",
        "secret",
        r"aws.{0,20}?(?:secret|sk).{0,20}?[:=]\s*[\"']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])",
        group=1,
        flags=re.I,
    ),
    _rule("anthropic_api_key", "global", "secret", r"\bsk-ant-[A-Za-z0-9_\-]{20,}"),
    _rule("openai_api_key", "global", "secret", r"\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}"),
    _rule("github_token", "global", "secret", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b"),
    _rule("gitlab_token", "global", "secret", r"\bglpat-[A-Za-z0-9_\-]{20,}"),
    _rule("slack_token", "global", "secret", r"\bxox[abposr]-[A-Za-z0-9-]{10,}"),
    _rule("stripe_secret_key", "global", "secret", r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    _rule("google_api_key", "global", "secret", r"\bAIza[0-9A-Za-z_\-]{35}(?![0-9A-Za-z_\-])"),
    _rule("huggingface_token", "global", "secret", r"\bhf_[A-Za-z0-9]{30,}\b"),
    _rule("azure_storage_key", "global", "secret", r"AccountKey=[A-Za-z0-9+/=]{40,}"),
    _rule("jwt", "global", "secret", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    _rule(
        "connection_string_with_password",
        "global",
        "secret",
        r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver)"
        r"://[^\s:/@]+:[^\s@/]+@[^\s'\"<>]+",
    ),
    _rule(
        "secret_assignment",
        "global",
        "secret",
        r"\b(?:password|passwd|pwd|secret|client_secret|api[_-]?key|access[_-]?token|auth[_-]?token)\b"
        r"[\"']?\s*[:=]\s*[\"']?([^\s\"',;]{8,})",
        validator=_not_placeholder,
        group=1,
        flags=re.I,
    ),
    # ---- global: financial -------------------------------------------------
    _rule("credit_card", "global", "financial", r"\b(?:\d[ -]?){12,18}\d\b", validator=v.credit_card_valid),
    _rule("iban", "global", "financial", r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b", validator=v.iban_valid),
    # ---- global: contact details ------------------------------------------
    _rule("email_address", "global", "pii", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    _rule(
        "phone_number_e164",
        "global",
        "pii",
        r"(?<![\w+])\+[1-9](?:[ .()-]{0,2}\d){7,14}\b",
        validator=_phone_digits_ok,
    ),
    # ---- us ----------------------------------------------------------------
    _rule("us_ssn", "us", "pii", r"\b\d{3}-\d{2}-\d{4}\b", validator=v.us_ssn_valid),
    # ---- uk ----------------------------------------------------------------
    _rule(
        "uk_national_insurance_number",
        "uk",
        "pii",
        r"\b(?!BG|GB|NK|KN|TN|NT|ZZ)[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z] ?\d{2} ?\d{2} ?\d{2} ?[A-D]\b",
    ),
    _rule("uk_nhs_number", "uk", "pii", r"\b\d{3}[ -]?\d{3}[ -]?\d{4}\b", validator=v.uk_nhs_valid),
    # ---- eu ----------------------------------------------------------------
    _rule(
        "eu_vat_number",
        "eu",
        "pii",
        r"\b(?:ATU\d{8}|BE[01]\d{9}|DE\d{9}|DK\d{8}|ES[A-Z0-9]\d{7}[A-Z0-9]|FI\d{8}"
        r"|FR[A-HJ-NP-Z0-9]{2}\d{9}|IE\d{7}[A-W][A-I]?|IT\d{11}|NL\d{9}B\d{2}|PL\d{10}|PT\d{9}|SE\d{12})\b",
    ),
    # ---- in ----------------------------------------------------------------
    _rule("in_aadhaar", "in", "pii", r"\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b", validator=v.aadhaar_valid),
    _rule("in_pan", "in", "pii", r"\b[A-Z]{3}[PCHFATBLJG][A-Z]\d{4}[A-Z]\b"),
    _rule(
        "in_upi_id",
        "in",
        "financial",
        r"\b[A-Za-z0-9._-]{2,64}@(?:ok(?:axis|sbi|hdfcbank|icici)|ybl|ibl|axl|paytm|upi|apl|yapl)\b",
    ),
]

AVAILABLE_PACKS: frozenset[str] = frozenset(rule.pack for rule in RULES)


@lru_cache(maxsize=16)
def rules_for_packs(packs: tuple[str, ...]) -> tuple[PatternRule, ...]:
    unknown = set(packs) - AVAILABLE_PACKS
    if unknown:
        raise ValueError(f"Unknown rule pack(s): {sorted(unknown)}. Available: {sorted(AVAILABLE_PACKS)}")
    return tuple(rule for rule in RULES if rule.pack in packs)


def detect_patterns(text: str, packs: list[str] | None = None) -> list[PatternMatch]:
    """Return non-overlapping matches, earliest first."""
    if packs is None:
        from app.config import settings

        packs = settings.rule_pack_list
    rules = rules_for_packs(tuple(packs))

    candidates: list[tuple[int, int, int, PatternMatch]] = []
    for priority, rule in enumerate(rules):
        for m in rule.pattern.finditer(text):
            value = m.group(rule.group)
            if not value or (rule.validator and not rule.validator(value)):
                continue
            start, end = m.span(rule.group)
            candidates.append(
                (start, -(end - start), priority, PatternMatch(rule.name, rule.pack, rule.category, value, start, end))
            )

    # Resolve overlaps: earliest start wins, then the longest span, then rule order.
    candidates.sort(key=lambda c: c[:3])
    accepted: list[PatternMatch] = []
    last_end = -1
    for _, _, _, match in candidates:
        if match.start >= last_end:
            accepted.append(match)
            last_end = match.end
    return accepted
