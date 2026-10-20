"""
Evaluate the gateway's detectors on a labeled dataset.

    python -m evals.run_eval                  # calibrate on dev, report on test
    python -m evals.run_eval --no-calibrate   # use thresholds from config/.env
    python -m evals.run_eval --no-calibrate --fail-under-f1 0.9   # CI regression gate

Calibration picks the semantic-leak and injection-similarity thresholds that
maximise F1 on the *dev* split only; the *test* split is never used for
tuning, so its numbers estimate how the thresholds generalise.

Writes evals/results.md and evals/results.json.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
# Every regional pack on, so regional PII examples are in scope.
os.environ.setdefault("RULE_PACKS", "global,us,uk,eu,in")
os.environ.setdefault("ON_LEAK_ACTION", "block")

import numpy as np  # noqa: E402

from app.cache import reset_result_cache  # noqa: E402
from app.config import settings  # noqa: E402
from app.detectors.injection_detector import MIN_WORDS_FOR_SEMANTIC_CHECK, get_exemplars  # noqa: E402
from app.detectors.semantic_detector import get_corpus  # noqa: E402
from app.embeddings import get_embedder  # noqa: E402
from app.langchain_pipeline import run_security_check  # noqa: E402
from app.text_utils import chunk_text  # noqa: E402

DATASET = ROOT / "evals" / "dataset.jsonl"
CONFIDENTIAL = {"confidential_paraphrase", "confidential_buried"}
PATTERN_CATS = {"secret": "secret", "pii": "pii", "financial": "financial"}


def load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def max_scores(text: str) -> tuple[float, float]:
    """Highest corpus similarity and highest attack-exemplar similarity over all chunks."""
    chunks = chunk_text(text, settings.max_chunks_per_prompt)
    vectors = get_embedder().encode_batch([c.text for c in chunks])
    sem = float((vectors @ get_corpus().matrix.T).max())
    inj_scores = (vectors @ get_exemplars().matrix.T).max(axis=1)
    long_enough = [len(c.text.split()) >= MIN_WORDS_FOR_SEMANTIC_CHECK for c in chunks]
    inj = float(max((s for s, ok in zip(inj_scores, long_enough, strict=True) if ok), default=-1.0))
    return sem, inj


def best_threshold(pos: list[float], neg: list[float]) -> tuple[float, float]:
    """Threshold maximising F1; among ties, the middle of the best range."""
    candidates = np.round(np.arange(0.30, 0.96, 0.01), 2)
    scored = []
    for t in candidates:
        tp = sum(s >= t for s in pos)
        fp = sum(s >= t for s in neg)
        fn = len(pos) - tp
        f1 = 2 * tp / (2 * tp + fp + fn) if tp else 0.0
        scored.append((f1, t))
    best_f1 = max(f for f, _ in scored)
    ties = [t for f, t in scored if f == best_f1]
    return float(ties[len(ties) // 2]), best_f1


def calibrate(items: list[dict]) -> dict:
    dev = [i for i in items if i["split"] == "dev"]
    safe = [i for i in dev if i["expected"] == "safe"]
    sem_pos = [max_scores(i["text"])[0] for i in dev if i["category"] in CONFIDENTIAL]
    sem_neg = [max_scores(i["text"])[0] for i in safe]
    inj_pos = [max_scores(i["text"])[1] for i in dev if i["category"] == "injection"]
    inj_neg = [max_scores(i["text"])[1] for i in safe]
    sem_t, sem_f1 = best_threshold(sem_pos, sem_neg)
    inj_t, inj_f1 = best_threshold(inj_pos, inj_neg)
    return {
        "semantic_leak_threshold": sem_t,
        "semantic_dev_f1": round(sem_f1, 3),
        "injection_similarity_threshold": inj_t,
        "injection_dev_f1": round(inj_f1, 3),
    }


def right_detector(item: dict, categories: list[str]) -> bool:
    cat = item["category"]
    if cat in CONFIDENTIAL:
        return "confidential" in categories
    if cat == "injection":
        return "injection" in categories
    if cat in PATTERN_CATS:
        return PATTERN_CATS[cat] in categories
    return not categories


def evaluate(items: list[dict], split: str) -> dict:
    rows = [i for i in items if i["split"] == split]
    tp = fp = fn = tn = 0
    per_cat: dict[str, list[bool]] = {}
    latencies, misses = [], []
    for item in rows:
        reset_result_cache()  # measure detection, not cache hits
        t0 = time.perf_counter()
        result = run_security_check(item["text"])
        latencies.append((time.perf_counter() - t0) * 1000)
        flagged = result.verdict != "safe"
        should = item["expected"] != "safe"
        tp += flagged and should
        fp += flagged and not should
        fn += should and not flagged
        tn += not flagged and not should
        ok = right_detector(item, result.categories)
        per_cat.setdefault(item["category"], []).append(ok)
        if not ok:
            misses.append({"id": item["id"], "got": result.categories, "text": item["text"][:90]})
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "n": len(rows),
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(2 * precision * recall / (precision + recall), 3) if precision + recall else 0.0,
        "false_positive_rate": round(fp / (fp + tn), 3) if fp + tn else 0.0,
        "per_category": {
            c: {"n": len(v), "correct": sum(v), "rate": round(sum(v) / len(v), 3)} for c, v in per_cat.items()
        },
        "latency_ms_p50": round(statistics.median(latencies), 1),
        "latency_ms_p95": round(sorted(latencies)[int(0.95 * (len(latencies) - 1))], 1),
        "misses": misses,
    }


def to_markdown(report: dict) -> str:
    cfg = report["config"]
    lines = [
        "# Evaluation results",
        "",
        f"Generated by `python -m evals.run_eval`. Embedding model: `{cfg['embedding_model']}` "
        f"(backend `{cfg['embedding_backend']}`). Rule packs: `{cfg['rule_packs']}`.",
        "",
        f"Thresholds ({'calibrated on dev' if cfg['calibration'] else 'from config'}): "
        f"semantic leak **{cfg['semantic_leak_threshold']}**, "
        f"injection similarity **{cfg['injection_similarity_threshold']}**.",
        "",
        "| Split | n | Precision | Recall | F1 | False-positive rate | p50 latency | p95 latency |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for split in ("dev", "test"):
        r = report[split]
        lines.append(
            f"| {split} | {r['n']} | {r['precision']} | {r['recall']} | {r['f1']} | "
            f"{r['false_positive_rate']} | {r['latency_ms_p50']} ms | {r['latency_ms_p95']} ms |"
        )
    lines += [
        "",
        "Per category on **test** (correct = the right detector fired; for safe categories, nothing fired):",
        "",
        "| Category | n | Correct | Rate |",
        "|---|---|---|---|",
    ]
    for cat, r in report["test"]["per_category"].items():
        lines.append(f"| {cat} | {r['n']} | {r['correct']} | {r['rate']} |")
    if report["test"]["misses"]:
        lines += ["", "Misses on test:", ""]
        lines += [f"- `{m['id']}` got {m['got'] or 'nothing'}: {m['text']}" for m in report["test"]["misses"]]
    lines += [
        "",
        f"Caveat: {report['dev']['n'] + report['test']['n']} hand-written examples against a small fabricated "
        "corpus. Treat these as a "
        "regression baseline and a sanity check on threshold choice, not a benchmark.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-calibrate", action="store_true")
    parser.add_argument(
        "--fail-under-f1", type=float, default=None, help="Exit non-zero if test-split F1 is below this (CI gate)."
    )
    args = parser.parse_args()

    items = load(DATASET)
    calibration = {}
    if not args.no_calibrate:
        calibration = calibrate(items)
        settings.semantic_leak_threshold = calibration["semantic_leak_threshold"]
        settings.injection_similarity_threshold = calibration["injection_similarity_threshold"]

    report = {
        "config": {
            "embedding_backend": settings.embedding_backend,
            "embedding_model": settings.embedding_model,
            "rule_packs": settings.rule_packs,
            "semantic_leak_threshold": settings.semantic_leak_threshold,
            "injection_similarity_threshold": settings.injection_similarity_threshold,
            "calibration": calibration,
        },
        "dev": evaluate(items, "dev"),
        "test": evaluate(items, "test"),
    }
    out = ROOT / "evals"
    (out / "results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (out / "results.md").write_text(to_markdown(report), encoding="utf-8")
    print(to_markdown(report))
    if args.fail_under_f1 is not None and report["test"]["f1"] < args.fail_under_f1:
        sys.exit(f"Test F1 {report['test']['f1']} is below the required {args.fail_under_f1}")


if __name__ == "__main__":
    main()
