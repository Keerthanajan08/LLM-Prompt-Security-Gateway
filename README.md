# LLM Prompt-Security Gateway

A gateway that sits in front of LLM API calls and flags sensitive
information in outbound prompts — **including paraphrased or contextual
leaks that a regex can't catch** — before the prompt ever reaches a model.

## The problem

Companies are increasingly worried about employees pasting sensitive
data into ChatGPT/Copilot/internal AI tools. Most existing mitigations
are regex filters: catch an SSN pattern, catch something that looks like
an API key. Those work for structurally obvious leaks, but they miss
this kind of thing entirely:

> "Our revenue dropped about 12% versus last quarter because we lost some
> big enterprise customers — help me frame this positively for a board
> slide."

No regex matches that. But if a company's actual (confidential) Q3
report says almost exactly that, this prompt is a real leak. Catching it
requires understanding *meaning*, not pattern-matching *structure*.

## How it works

```
prompt
  │
  ▼
verdict cache lookup (has a near-identical prompt already been checked?)
  │
  ├── hit → reuse cached verdict, skip re-checking
  │
  └── miss
        │
        ▼
      pattern detection (regex: API keys, SSNs, credit cards, private keys)
        │
        ▼
      semantic detection (embed the prompt, compare against an embedded
      confidential-document corpus — same retrieval mechanism RAG uses,
      applied to detection instead of generation)
        │
        ▼
      verdict: safe / blocked / redacted
        │
        ▼
      cache the verdict
        │
        ▼
      (if /query) forward to LLM only if not blocked
```

LangChain composes steps 2 onward as a runnable chain (`app/langchain_pipeline.py`) — a deliberately linear pipeline, not an agent, because the problem doesn't need branching logic, just composition.

## Design decisions worth knowing (and being asked about)

- **Two separate detectors, not one.** Pattern matching is cheap and
  exact but blind to paraphrase. Semantic matching catches paraphrase but
  is probabilistic and needs a real confidential-document corpus to
  compare against. Running both and combining their verdicts covers more
  ground than either alone — and it's easy to explain *why* each exists.
- **The verdict cache uses a stricter similarity threshold (0.97) than
  the leak detector (0.62 by default).** Reusing a semantic-leak-detection
  verdict should require a near-identical prompt, not just a "similar
  topic" — a false negative here (reusing a "safe" verdict for something
  that isn't) is worse than a cache miss, so the bar for reuse is set high on purpose.
- **`ON_LEAK_ACTION` is configurable (`block` / `redact` / `log_only`).**
  A real deployment might want to start in `log_only` mode to see what
  would have been flagged before enforcing blocks — this is a realistic
  rollout pattern, not just a toggle for the demo.
- **Semantic detection is RAG's retrieval half, repurposed.** Worth
  saying exactly that in an interview rather than overclaiming a full RAG
  pipeline: there's no generation step in the detector itself — retrieval
  is used to answer "does this resemble something confidential," not to
  answer the user's question.

## Setup

```bash
git clone <your-repo-url>
cd llm-prompt-security-gateway
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp env.example.txt .env         # defaults to mock LLM + in-memory cache — works immediately
```

Run it:

```bash
uvicorn app.main:app --reload
```

In another terminal:

```bash
python scripts/run_demo.py
```

Run tests:

```bash
pytest
```

### Try it manually

```bash
curl -X POST http://127.0.0.1:8000/check \
  -H "Content-Type: application/json" \
  -d '{"prompt": "My SSN is 123-45-6789, help me fill this form"}'

curl -X POST http://127.0.0.1:8000/check \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Our revenue dropped 12% this quarter because we lost some big enterprise customers"}'
```

## Using a real LLM

Same as before — pick one, both have usable free tiers:
- **Groq** — https://console.groq.com
- **Gemini** — https://aistudio.google.com/apikey

```
LLM_PROVIDER=groq
GROQ_API_KEY=your_key_here
```

## Deploying

| Piece | Where |
|---|---|
| FastAPI backend | Render or Railway free tier |
| Redis (verdict cache) | Upstash free tier |
| Embedding model | Runs in the same backend process |
| LLM | Groq or Gemini free tier |

## Project structure

```
app/
  main.py                        FastAPI app — /check, /query, /stats
  langchain_pipeline.py          LangChain-composed check pipeline
  cache.py                       Verdict cache (in-memory / Redis)
  embeddings.py                  sentence-transformers wrapper
  llm_providers.py               Mock / Groq / Gemini
  schemas.py                     request/response models
  config.py                      env-driven settings
  detectors/
    pattern_detector.py          regex rules for structural leaks
    semantic_detector.py         embedding-similarity retrieval for paraphrased leaks
  confidential_docs/             fabricated demo corpus (financials, roadmap)
scripts/
  run_demo.py                    fires test prompts, prints verdicts
tests/
  test_pattern_detector.py       unit tests for regex detection
```

## Honest scope

The confidential corpus here is fabricated demo data — in a real
deployment this would be indexed from a company's actual confidential
document store, kept fresh, and access-controlled. Things a production
version would add: audit logging with retention policy, per-team
corpus scoping, human review queue for `redact` verdicts, and an ANN
index once the corpus is large enough that a linear scan stops being
fast. The core mechanism — two independent detectors, a config-driven
enforcement action, and a verdict cache — is real and complete end to end.
