from app.config import settings
from app.detectors.semantic_detector import detect_semantic_leak, get_corpus
from app.embeddings import get_embedder
from app.text_utils import chunk_text


def detect(text):
    chunks = chunk_text(text)
    return detect_semantic_leak(chunks, get_embedder().encode_batch([c.text for c in chunks]))


def test_corpus_loads_sentences_and_skips_headings(corpus_dir):
    corpus = get_corpus()
    assert len(corpus) == 2
    assert all(not t.startswith("#") for t in corpus.texts)
    assert corpus.fingerprint != "empty"


def test_flags_text_close_to_a_confidential_passage(corpus_dir):
    matches = detect("Project Bluefin will acquire Orchard Systems for forty million dollars")
    assert matches and matches[0].doc_id.startswith("plans.md#")
    assert matches[0].similarity >= settings.semantic_leak_threshold


def test_ignores_unrelated_text(corpus_dir):
    assert detect("How do I bake sourdough bread at home?") == []


def test_buried_sentence_is_found_despite_long_prompt(corpus_dir):
    """Regression: v0.1 embedded the whole prompt, so one confidential sentence
    inside a long harmless prompt was averaged away."""
    filler = " ".join(f"Our team shipped feature {i} and customers liked it a lot." for i in range(15))
    prompt = filler + " Project Bluefin will acquire Orchard Systems for forty million dollars in March."

    whole = get_embedder().encode(prompt) @ get_corpus().matrix.T
    assert whole.max() < settings.semantic_leak_threshold  # the old approach misses it

    matches = detect(prompt)
    assert matches
    assert "Bluefin" in prompt[matches[0].start : matches[0].end]


def test_missing_corpus_directory_means_no_matches(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "corpus_dir", tmp_path / "does-not-exist")
    get_corpus.cache_clear()
    assert len(get_corpus()) == 0
    assert detect("anything at all") == []


def test_threshold_is_respected(corpus_dir, monkeypatch):
    monkeypatch.setattr(settings, "semantic_leak_threshold", 0.999)
    assert detect("Project Bluefin will acquire Orchard Systems for millions") == []
