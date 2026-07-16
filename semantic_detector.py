"""
Catches leaks a regex can't: paraphrased or contextual references to
confidential information, e.g. "our unreleased Q3 numbers are down 12%"
has no regex-matchable pattern but is clearly sensitive if it closely
matches something in the confidential corpus.

Mechanically this is the same retrieval step used in RAG (embed the
query, compare against embedded corpus chunks, take the closest matches)
— just used for *detection* instead of *generation*. Worth being able to
say precisely that in an interview: it's RAG's retrieval half, repurposed.
"""
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import numpy as np

from app.config import settings
from app.embeddings import cosine_similarity, get_embedder

CORPUS_DIR = Path(__file__).parent.parent / "confidential_docs"


@dataclass
class CorpusChunk:
    doc_id: str
    text: str
    vector: np.ndarray


class ConfidentialCorpus:
    def __init__(self, directory: Path):
        self.chunks: list[CorpusChunk] = []
        self._load(directory)

    def _load(self, directory: Path) -> None:
        embedder = get_embedder()
        texts, doc_ids = [], []

        for filename in sorted(os.listdir(directory)):
            if not filename.endswith(".md"):
                continue
            content = (directory / filename).read_text(encoding="utf-8").strip()
            for i, para in enumerate(p.strip() for p in content.split("\n\n")):
                if para:
                    texts.append(para)
                    doc_ids.append(f"{filename}#{i}")

        if not texts:
            return

        vectors = embedder.encode_batch(texts)
        self.chunks = [
            CorpusChunk(doc_id=doc_ids[i], text=texts[i], vector=vectors[i])
            for i in range(len(texts))
        ]

    def top_matches(self, query_vector: np.ndarray, top_k: int = 3):
        scored = [(c, cosine_similarity(query_vector, c.vector)) for c in self.chunks]
        scored.sort(key=lambda pair: pair[1], reverse=True)
        return scored[:top_k]


@lru_cache(maxsize=1)
def get_corpus() -> ConfidentialCorpus:
    return ConfidentialCorpus(CORPUS_DIR)


@dataclass
class SemanticDetectionResult:
    matches: list[tuple[str, str, float]]  # (doc_id, snippet, similarity)

    @property
    def has_matches(self) -> bool:
        return len(self.matches) > 0


def detect_semantic_leak(query_vector: np.ndarray) -> SemanticDetectionResult:
    corpus = get_corpus()
    top = corpus.top_matches(query_vector, top_k=3)
    flagged = [
        (chunk.doc_id, chunk.text, round(score, 4))
        for chunk, score in top
        if score >= settings.semantic_leak_threshold
    ]
    return SemanticDetectionResult(matches=flagged)
