# SentinelAI — Autonomous API Security Scanner

An AI agent that retrieves OWASP Top 10 guidance via RAG, generates test cases,
executes them against a real target API, and uses a trained ML classifier
(plus targeted logic probes) to decide what's actually a vulnerability.

**This is a real, working pipeline** — not a mockup. Every piece below actually
runs: real FAISS retrieval, a real trained scikit-learn model, real HTTP
requests via `httpx`, and a real dashboard consuming a real streaming API.

## What's real here (matches your resume stack)

| Piece | Tech | What it actually does |
|---|---|---|
| **RAG retrieval** | TF-IDF → TruncatedSVD embeddings → **FAISS** (`IndexFlatIP`) | Given an endpoint description, retrieves the OWASP categories most relevant to it, instead of testing every category against every endpoint |
| **Test generation** | Template engine, pluggable **LLM API** hook | Turns retrieved OWASP context into concrete test cases. Uses Anthropic/OpenAI if you set an API key; falls back to grounded templates otherwise, so it runs with zero external dependency out of the box |
| **ML classification** | **scikit-learn RandomForestClassifier**, trained and saved as a real `.joblib` model | Scores real HTTP responses (size deltas, error keywords, payload reflection, timing) for vulnerability likelihood — this is genuine trained ML, not an if/else chain |
| **Direct logic probes** | `httpx` | BOLA, rate-limiting, and header-misconfiguration checks that content-diffing genuinely can't catch (see "Known limitations" below for *why* these needed a separate approach) |
| **Backend** | **FastAPI** + Server-Sent Events | Real `/scans` POST + streaming progress endpoint |
| **Frontend** | Vanilla JS dashboard | Calls the real API — no more scripted fake logs |
| **Local test target** | **Flask** app with real, intentional SQLi/BOLA/rate-limit/header bugs | Something safe and legal to actually scan |

## ⚠️ Safety design — read this before you touch `executor.py`

`executor.py` will **only** send requests to hosts in `ALLOWED_HOSTS`
(`127.0.0.1` / `localhost` by default). This is enforced in code, not just
documented. **Do not** widen that allowlist to point at a host you don't own
or don't have explicit written permission to test — that crosses from "student
security project" into unauthorized access, which is a real legal line, not
a formality.

If you want to test something beyond the bundled `vulnerable_target`, spin up
your own local instance of a deliberately-vulnerable app (e.g. OWASP Juice
Shop via Docker) and add `127.0.0.1` with the right port — you're still only
ever hitting `localhost`.

## Project structure

```
sentinelai-backend/
├── app/
│   ├── main.py              FastAPI app (POST /scans, GET /scans/{id}, SSE stream)
│   ├── engine.py             Orchestrates one full scan (the "agent loop")
│   ├── rag.py                 OWASP knowledge base + FAISS retrieval
│   ├── generator.py          Turns retrieved context into test cases (template or LLM)
│   ├── executor.py            Fires real HTTP requests; BOLA/rate-limit/header probes
│   ├── feature_extractor.py   Turns raw responses into ML feature vectors
│   ├── train_classifier.py    Trains the RandomForest model (run once, or to retrain)
│   ├── vuln_classifier.joblib  The trained model (already included, ready to use)
│   └── data/owasp_top10.json   The RAG knowledge base
├── vulnerable_target/
│   └── app.py                A small Flask app with real, intentional vulnerabilities
├── frontend/
│   └── index.html             The dashboard UI (talks to the real backend)
├── requirements.txt
└── README.md
```

## Running it (3 terminals)

**1. Install dependencies once:**
```bash
cd sentinelai-backend
pip install -r requirements.txt
```

**2. Terminal 1 — start the vulnerable test target:**
```bash
cd vulnerable_target
python3 app.py
# -> running on http://127.0.0.1:5001
```

**3. Terminal 2 — start the backend API:**
```bash
cd app
uvicorn main:app --reload --port 8000
# -> running on http://127.0.0.1:8000
```

**4. Terminal 3 (or just your browser) — open the dashboard:**
```bash
cd frontend
python3 -m http.server 3000
```
Open `http://localhost:3000`, leave the target URL as `http://127.0.0.1:5001`,
and click **Run Scan**. You'll see a real, live-updating log as the agent
retrieves OWASP context, generates test cases, fires real requests, and
classifies the responses — then a real results table with real findings.

**In VS Code:** open the `sentinelai-backend` folder, use three integrated
terminal tabs for the three commands above (Terminal → Split Terminal), or
use the Live Server extension for the frontend instead of the Python
http.server.

## What it actually finds (against the bundled vulnerable target)

Running a scan against `vulnerable_target` should surface:
- **Critical** — SQL Injection on `/api/v1/users/search` (real SQLi, real vulnerable app)
- **Critical** — Broken Object Level Authorization on `/api/v1/orders/{id}/refund`
- **High** — Missing rate limiting on `/api/v1/auth/login` (15 real requests fired, no 429 ever seen)
- **Low** — Version disclosure + missing hardening headers

These are genuinely detected from real HTTP responses, not hardcoded.

## Retraining the classifier

```bash
cd app
python3 train_classifier.py
```
This regenerates a synthetic labeled dataset, trains a fresh RandomForest,
prints a classification report, and overwrites `vuln_classifier.joblib`.

## Enabling real LLM-based test generation

By default, `generator.py` uses grounded templates (no API key needed). To
use a real LLM call instead:
```bash
export ANTHROPIC_API_KEY=sk-...   # or OPENAI_API_KEY
```
`generator.py` will automatically detect the key and use it, falling back
to templates if the call fails for any reason.

## Known limitations — read this before presenting it as finished

Being upfront about these matters more than pretending they don't exist,
especially if you're asked about this in an interview:

1. **RAG retrieval isn't perfect.** With only 10 knowledge-base entries and
   TF-IDF+SVD embeddings (chosen so the project runs with zero downloaded
   model weights), semantic retrieval sometimes ranks a less-relevant OWASP
   category above the right one for short endpoint descriptions. The fix
   (already partially applied) is enriching endpoint descriptions with real
   parameter/schema info — which you'd get for free from parsing an actual
   OpenAPI spec instead of hand-describing endpoints.
2. **The RandomForest classifier is trained on synthetic data**, because
   there's no public labeled dataset of "API responses to security probes."
   It generalizes reasonably to the bundled vulnerable target because the
   synthetic features were designed to mirror it, but it will need real
   labeled examples (confirmed findings / false positives fed back in) to
   generalize further — this is genuinely the next real step, not a small
   detail.
3. **Some test-case/category labels don't perfectly match the real root
   cause.** You may see a finding logically caused by a malformed-string
   side effect labeled under the wrong OWASP category. This is a precision
   problem worth mentioning if asked, and a good "what I'd improve next"
   answer in an interview.
4. **BOLA, rate-limiting, and header checks are direct logic probes, not ML.**
   This is intentional, not a shortcut: content-diffing genuinely can't see
   *who* a response was served to, or *how many* requests were sent over
   time, or response *headers* — those need dedicated checks. A real
   production tool combines both approaches, which is exactly what this does.
5. **Scan history has no persistence** — `main.py` keeps scans in an
   in-memory dict, so history resets when you restart the API. Add a
   database (SQLite is plenty to start) and a `/scans` list endpoint to fix
   this — the frontend's History view is clearly labeled as sample data
   until then.

## Natural next steps, roughly in order of impact

1. Parse a real OpenAPI/Swagger spec instead of hand-describing endpoints
2. Persist scans to SQLite, add a real `/scans` list endpoint, wire up History
3. Feed confirmed findings back into the classifier as labeled training data
4. Add more vulnerability classes to `vulnerable_target` and the OWASP KB (XXE, SSRF with a real internal service to hit, deserialization)
5. Swap TF-IDF+SVD for real sentence embeddings once you're comfortable
   pulling model weights (`sentence-transformers`), and compare retrieval
   quality against the current approach — a genuinely good thing to measure
   and write up
