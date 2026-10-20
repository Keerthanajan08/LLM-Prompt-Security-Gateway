import re

from app.text_utils import chunk_text, mask_value, redact_spans


def covered(text, chunks):
    mask = [False] * len(text)
    for c in chunks:
        assert text[c.start : c.end] == c.text
        for i in range(c.start, c.end):
            mask[i] = True
    return all(mask[i] for i, ch in enumerate(text) if not ch.isspace())


def test_splits_sentences_and_adds_adjacent_pairs():
    chunks = chunk_text("First one. Second one! Third one?")
    texts = [c.text for c in chunks]
    assert "First one." in texts and "Second one!" in texts and "Third one?" in texts
    assert "First one. Second one!" in texts


def test_does_not_split_on_decimal_points():
    chunks = chunk_text("Revenue fell 12.5% to $4.2M this quarter.")
    assert [c.text for c in chunks] == ["Revenue fell 12.5% to $4.2M this quarter."]


def test_every_character_is_covered():
    text = "Line one\nLine two. Sentence three is here!\n\nAnd a final paragraph without punctuation"
    assert covered(text, chunk_text(text))


def test_long_sentence_is_split_into_windows():
    text = " ".join(f"w{i}" for i in range(500))
    chunks = chunk_text(text)
    assert covered(text, chunks)
    assert max(len(c.text.split()) for c in chunks) <= 240  # unit or pair of units


def test_huge_prompt_is_grouped_not_truncated():
    """Regression: dropping chunks to fit a budget would let an attacker pad a
    prompt until the sensitive sentence falls off the end."""
    filler = " ".join(f"Harmless sentence number {i}." for i in range(400))
    text = filler + " The secret merger closes on Friday."
    chunks = chunk_text(text, max_chunks=16)
    assert covered(text, chunks)
    assert any("secret merger" in c.text for c in chunks)


def test_empty_text_has_no_chunks():
    assert chunk_text("") == [] and chunk_text("   \n  ") == []


def test_redact_spans_replaces_and_merges_overlaps():
    text = "aaa SECRET bbb"
    assert redact_spans(text, [(4, 10, "key")]) == "aaa [REDACTED:KEY] bbb"
    merged = redact_spans("0123456789", [(2, 6, "a"), (4, 8, "b")])
    assert merged == "01[REDACTED:A]89"
    assert redact_spans(text, []) == text


def test_mask_value_hides_the_middle():
    masked = mask_value("AKIAABCDEFGHIJKLMNOP")
    assert masked.startswith("AKIA") and masked.endswith("MNOP") and "*" in masked
    assert "EFGHIJ" not in masked
    assert mask_value("short") == "*****"
    assert len(mask_value("x" * 5000)) < 30
    assert re.fullmatch(r"12\*+90", mask_value("1234567890"))
