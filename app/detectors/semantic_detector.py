"""
Catches leaks a regex can't: paraphrased or contextual references to
confidential information, e.g. "our unreleased Q3 numbers are down 12%"
has no regex-matchable pattern but is clearly sensitive if it closely
matches something in the confidential corpus.

Mechanically this is the retrieval half of RAG (embed the query, compare
against embedded corpus chunks, take the closest matches), used for
*detection* instead of *generation*.

The prompt is compared chunk by chunk (see app/text_utils.py), so a single
confidential sentence can't hide inside a long prompt, and the corpus is
held as one normalised matrix so a comparison is a single matrix multiply
rather than a Python loop.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import numpy as np

from app.config import settings
from app.embeddings import get_embedder
from app.text_utils import Chunk, chunk_text

MIN_WORDS_PER_CORPUS_CHUNK = 5


@dataclass(frozen=True)
class SemanticMatch:
    doc_id: str
    snippet: str
    similarity: float
    start: int  # span in the checked text that matched
    end: int


class ConfidentialCorpus:
    def __init__(self, directory: Path):
        self.doc_ids: list[str] = []
        self.texts: list[str] = []
        self.matrix = np.zeros((0, 1), dtype=np.float32)
        self.fingerprint = "empty"
        self._load(directory)

    def _load(self, directory: Path) -> None:
        if not directory.is_dir():
            return
        digest = hashlib.sha256()
        for path in sorted(directory.iterdir()):
            if path.suffix not in (".md", ".txt"):
                continue
            content = path.read_text(encoding="utf-8")
            digest.update(path.name.encode() + b"\0" + content.encode())
            for i, para in enumerate(p.strip() for p in content.split("\n\n")):
                # Headings and one-liners ("# Q3 Financials") describe a topic,
                # not a secret; matching them would flag anyone asking about Q3.
                if para.startswith("#") or len(para.split()) < MIN_WORDS_PER_CORPUS_CHUNK:
                    continue
                # Sentence-level chunks: a paragraph packed with several facts
                # embeds as an average of all of them, so a prompt leaking just
                # one of those facts scores low against the whole paragraph.
                for j, chunk in enumerate(chunk_text(para)):
                    if len(chunk.text.split()) >= MIN_WORDS_PER_CORPUS_CHUNK:
                        self.texts.append(chunk.text)
                        self.doc_ids.append(f"{path.name}#{i}.{j}")
        self.fingerprint = digest.hexdigest()[:16]
        if self.texts:
            self.matrix = get_embedder().encode_batch(self.texts)

    def __len__(self) -> int:
        return len(self.texts)

    def text_for(self, doc_id: str) -> str:
        if not hasattr(self, "_by_id"):
            self._by_id = dict(zip(self.doc_ids, self.texts, strict=True))
        return self._by_id.get(doc_id, "")


@lru_cache(maxsize=1)
def get_corpus() -> ConfidentialCorpus:
    return ConfidentialCorpus(Path(settings.corpus_dir))


def detect_semantic_leak(chunks: list[Chunk], vectors: np.ndarray) -> list[SemanticMatch]:
    """Flag every chunk whose closest corpus paragraph clears the threshold.

    Returns one match per flagged chunk, so callers get every span they may
    need to redact.
    """
    corpus = get_corpus()
    if not len(corpus) or not chunks:
        return []
    scores = vectors @ corpus.matrix.T  # (n_chunks, n_corpus) cosine similarities
    best = scores.argmax(axis=1)
    matches = []
    for i, chunk in enumerate(chunks):
        j = int(best[i])
        score = float(scores[i, j])
        if score >= settings.semantic_leak_threshold:
            matches.append(SemanticMatch(corpus.doc_ids[j], corpus.texts[j], round(score, 4), chunk.start, chunk.end))
    return matches
