import pytest

from app.detectors.pattern_detector import AVAILABLE_PACKS, detect_patterns, rules_for_packs

ALL_PACKS = sorted(AVAILABLE_PACKS)


def rule_names(text, packs=ALL_PACKS):
    return [m.rule_name for m in detect_patterns(text, packs)]


@pytest.mark.parametrize(
    "text, expected_rule",
    [
        ("Here's my key: AKIAABCDEFGHIJKLMNOP for the config", "aws_access_key_id"),
        ("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "aws_secret_access_key"),
        ("key: sk-proj-Xr4T9qLm2vBn8KpZ3wYe6HdF1sGa", "openai_api_key"),
        ("sk-abcdefghijklmnopqrstuvwxyz123456", "openai_api_key"),
        ("ANTHROPIC_API_KEY=sk-ant-api03-q8Wm3Zt7Lp2Xc9Vb4Nn6Rr1Kk5Hh0Jj", "anthropic_api_key"),
        ("token ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8", "github_token"),
        ("github_pat_11ABCDEFG0123456789_abcdefghijklmnop", "github_token"),
        ("glpat-abcdefghij1234567890", "gitlab_token"),
        ("xoxb-123456789012-1234567890123-AbCdEfGhIjKl", "slack_token"),
        ("stripe sk_live_51Hx9zQ2eZvKYlo2C8a7bNmP", "stripe_secret_key"),
        ("AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY", "google_api_key"),
        ("hf_AbCdEfGhIjKlMnOpQrStUvWxYz12345678", "huggingface_token"),
        ("DefaultEndpointsProtocol=https;AccountKey=" + "A" * 86 + "==", "azure_storage_key"),
        (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
            "jwt",
        ),
        ("postgres://admin:S3cr3tPass!@db.internal:5432/prod", "connection_string_with_password"),
        ("mongodb+srv://appuser:hunter2hunter2@cluster0.mongodb.net/prod", "connection_string_with_password"),
        ("client_secret: 9f8e7d6c5b4a39281706f5e4d3c2b1a0", "secret_assignment"),
        ('"password": "Tr0ub4dor&3xyz"', "secret_assignment"),
        ("Charge card 4111 1111 1111 1111 exp 12/28", "credit_card"),
        ("Wire to GB82 WEST 1234 5698 7654 32 today", "iban"),
        ("mail priya.sharma@gmail.com", "email_address"),
        ("call +44 20 7946 0958", "phone_number_e164"),
        ("call +1 (415) 555-0132", "phone_number_e164"),
        ("My SSN is 123-45-6789", "us_ssn"),
        ("NI number AB 12 34 56 C", "uk_national_insurance_number"),
        ("NHS 943 476 5919", "uk_nhs_number"),
        ("VAT DE123456789", "eu_vat_number"),
        ("PAN ABCPE1234F", "in_pan"),
        ("pay priya.s@okaxis", "in_upi_id"),
    ],
)
def test_detects(text, expected_rule):
    assert expected_rule in rule_names(text)


@pytest.mark.parametrize(
    "text",
    [
        "What's a good way to structure a FastAPI project?",
        "How do I rotate AWS access keys safely?",
        "api_key = YOUR_API_KEY_HERE",
        "password: ********",
        "password = ${DB_PASSWORD}",
        "Order number 4111111111111112 hasn't shipped",  # fails Luhn
        "Call me at 9876543210123",  # v0.1 flagged this as a credit card
        "order id 1234567890123456",  # v0.1 flagged this as a credit card
        "timestamp 1729468800000",  # v0.1 flagged this as a credit card
        "The SSN format is XXX-XX-XXXX",
        "000-12-3456 is not a real SSN",
        "postgres://localhost:5432/dev has no password",
        "sk-short",
    ],
)
def test_no_false_positive(text):
    assert rule_names(text) == []


def test_spans_point_at_the_matched_text():
    text = "My SSN is 123-45-6789 and my key is AKIAABCDEFGHIJKLMNOP."
    for m in detect_patterns(text, ALL_PACKS):
        assert text[m.start : m.end] == m.text


def test_secret_assignment_reports_only_the_value():
    text = "client_secret: 9f8e7d6c5b4a39281706f5e4d3c2b1a0"
    (match,) = detect_patterns(text, ALL_PACKS)
    assert match.text == "9f8e7d6c5b4a39281706f5e4d3c2b1a0"


def test_specific_rule_wins_over_generic_rule_on_same_span():
    text = "api_key = sk-proj-Xr4T9qLm2vBn8KpZ3wYe6HdF1sGa"
    assert rule_names(text) == ["openai_api_key"]


def test_anthropic_key_is_not_reported_as_openai():
    assert rule_names("sk-ant-api03-q8Wm3Zt7Lp2Xc9Vb4Nn6Rr1Kk5Hh0Jj") == ["anthropic_api_key"]


def test_overlapping_matches_are_reported_once():
    # The digits inside an IBAN must not also come back as a card number.
    assert rule_names("IBAN DE89 3704 0044 0532 0130 00") == ["iban"]


def test_private_key_block_covers_the_whole_key():
    text = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk=\n-----END OPENSSH PRIVATE KEY-----\nthanks"
    (match,) = detect_patterns(text, ALL_PACKS)
    assert match.rule_name == "private_key_block"
    assert "b3BlbnNzaC1rZXk=" in match.text


@pytest.mark.parametrize("kind", ["RSA ", "EC ", "DSA ", "OPENSSH ", "ENCRYPTED ", ""])
def test_private_key_variants(kind):
    assert rule_names(f"-----BEGIN {kind}PRIVATE KEY-----\nabc") == ["private_key_block"]


def test_pgp_private_key_block():
    assert rule_names("-----BEGIN PGP PRIVATE KEY BLOCK-----\nabc") == ["private_key_block"]


def test_regional_packs_are_opt_in():
    text = "PAN ABCPE1234F and NHS 943 476 5919"
    assert rule_names(text, ["global", "us"]) == []
    assert set(rule_names(text, ["global", "in", "uk"])) == {"in_pan", "uk_nhs_number"}


def test_unknown_pack_is_rejected():
    with pytest.raises(ValueError, match="Unknown rule pack"):
        rules_for_packs(("global", "atlantis"))


def test_categories_are_set():
    cats = {m.category for m in detect_patterns("AKIAABCDEFGHIJKLMNOP 4111111111111111 a@b.io", ALL_PACKS)}
    assert cats == {"secret", "financial", "pii"}


def test_uses_configured_packs_by_default(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "rule_packs", "global")
    assert detect_patterns("My SSN is 123-45-6789") == []
    monkeypatch.setattr(settings, "rule_packs", "global,us")
    assert [m.rule_name for m in detect_patterns("My SSN is 123-45-6789")] == ["us_ssn"]
