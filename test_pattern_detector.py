from app.detectors.pattern_detector import detect_patterns, redact_patterns


def test_no_match_on_clean_text():
    result = detect_patterns("What's a good way to structure a FastAPI project?")
    assert result.has_matches is False


def test_detects_aws_key():
    result = detect_patterns("Here's my key: AKIAABCDEFGHIJKLMNOP for the config")
    assert result.has_matches is True
    assert result.matches[0][0] == "aws_access_key"


def test_detects_ssn():
    result = detect_patterns("My SSN is 123-45-6789")
    assert any(name == "ssn" for name, _ in result.matches)


def test_detects_private_key_block():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIExample...\n-----END RSA PRIVATE KEY-----"
    result = detect_patterns(text)
    assert any(name == "private_key_block" for name, _ in result.matches)


def test_redact_replaces_matched_text():
    text = "My SSN is 123-45-6789, please help"
    redacted = redact_patterns(text)
    assert "123-45-6789" not in redacted
    assert "REDACTED" in redacted
