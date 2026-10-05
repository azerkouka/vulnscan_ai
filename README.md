# VulnScan AI

A full-stack platform that analyzes source code and detects security
vulnerabilities using a local LLM (Ollama) grounded by a RAG pipeline over
OWASP Top 10, CWE and MITRE ATT&CK knowledge, stored in ChromaDB.

> Static analysis only — the platform never executes submitted code.

## Architecture

Backend follows Clean/Hexagonal architecture: dependencies point inward
(`api → application → domain`); infrastructure implements domain ports; the
domain layer has zero framework imports (no FastAPI, SQLAlchemy, LangChain,
Chroma).

```mermaid
flowchart LR
    subgraph Client
        FE[Angular SPA]
    end

    subgraph Backend [FastAPI backend]
        API[api/v1 routers + schemas]
        APP[application/use_cases]
        DOM[domain: entities, value objects, ports]
        INFRA[infrastructure: persistence, llm, vectorstore,\ningestion, code_analysis, security]
        API --> APP --> DOM
        INFRA -. implements ports .-> DOM
    end

    PG[(PostgreSQL)]
    CHROMA[(ChromaDB)]
    OLLAMA[[Ollama / Llama 3]]

    FE -- REST/JWT --> API
    INFRA --> PG
    INFRA --> CHROMA
    INFRA --> OLLAMA
```

How one scan flows through it:

```mermaid
sequenceDiagram
    actor User
    participant FE as Angular SPA
    participant API as FastAPI
    participant Job as Scan job (in-process)
    participant KB as ChromaDB
    participant LLM as Ollama
    participant DB as PostgreSQL

    User->>FE: paste code / upload file or zip
    FE->>API: POST /scans (multipart)
    API->>DB: scan = PENDING
    API-->>FE: 202 Accepted
    API-)Job: enqueue
    loop every chunk of every file
        Job->>KB: retrieve OWASP / CWE / ATT&CK excerpts
        Job->>LLM: code chunk + excerpts
        LLM-->>Job: findings (JSON)
        Job->>DB: validated findings, progress
    end
    Job->>DB: scan = COMPLETED
    loop until finished
        FE->>API: GET /scans/{id}/report
    end
    FE-->>User: report (also as JSON / PDF)
```

Data model: `users` own `scans`; a scan has `scan_files` (metadata - the
source text itself is kept on disk, under generated names) and `findings`;
a finding has `finding_references` to the knowledge base entries it cites.
`knowledge_documents` mirrors what is indexed in ChromaDB.

## Repository layout

```
backend/    FastAPI + SQLAlchemy 2.0 (async) + Alembic + LangChain/Ollama + Chroma
frontend/   Angular (standalone components, signals, strict TS)
docker-compose.yml   frontend, backend, postgres, chromadb, ollama
```

## Prerequisites

- Docker + Docker Compose
- (for local, non-Docker dev) Python 3.12, Node.js 22, an Angular-CLI-compatible
  npm version

## Quick start (Docker)

```bash
cp .env.example .env
# edit .env - at minimum set JWT_SECRET_KEY and POSTGRES_PASSWORD

docker compose up --build
```

- Backend: http://localhost:8000 (docs at `/docs`, health at `/api/v1/health`)
- Frontend: http://localhost:4200
- ChromaDB: http://localhost:8001
- Ollama: http://localhost:11434

On the first run, three one-off steps are needed once the services are up:

```bash
# 1. Create the database tables
docker compose exec backend alembic upgrade head
# 2. Load the OWASP / CWE / ATT&CK knowledge base (downloads an ~80 MB embedding model)
docker compose exec backend python -m scripts.ingest_knowledge
# 3. Pull the model Ollama will use (~5 GB)
docker compose exec ollama ollama pull llama3
```

Then open http://localhost:4200, create an account and start a scan. Run
step 1 again after pulling a version that adds a migration.

If PostgreSQL is already installed on your machine, its port 5432 collides
with the container's: set `POSTGRES_HOST_PORT=5433` in `.env`.

## Trying it without a model

A real scan needs Ollama and the `llama3` model (about 5 GB; without a GPU a
scan can take several minutes). To see the app with data before that, record
a finished demo scan of the bundled sample project:

```bash
docker compose exec backend alembic upgrade head            # once
docker compose exec backend python -m scripts.ingest_knowledge   # once
docker compose exec backend python -m scripts.seed_demo
```

It creates the account `demo@example.com`, prints its generated password
once, and adds a completed scan with hand-written findings (each is labelled
as demo data). Sign in at http://localhost:4200 to browse the dashboard, the
report and its JSON / PDF exports.

The sample it uses lives in `backend/data/samples/vulnerable-app` - a few
files written to be insecure. Zip that folder and upload it on the *New
scan* page to run a real scan of the same code. Never run or deploy it.

## Local development (without Docker)

**Backend**

```bash
cd backend
python -m venv .venv && .venv/Scripts/activate   # .venv/bin/activate on Linux/macOS
pip install -e ".[dev]"
cp ../.env.example ../.env   # or export the vars another way
uvicorn app.main:app --reload
```

`.[dev]` is enough to run the unit tests. Knowledge ingestion and real scans
need the `rag` extra (`.[dev,rag]`), function-level code chunking needs
`chunking` (without it files are cut into plain line windows), and PDF
export needs `export`. On
Windows, `rag` and `chunking` pull in packages with native extensions
(`chroma-hnswlib`, `tree-sitter-language-pack`) that need the
[Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
if no prebuilt wheel exists for your Python version — Docker always works
without that, since the Linux image has prebuilt wheels.

**Backend checks**

```bash
ruff check .
black --check .
mypy app
pytest
```

`pytest` never fails for a missing service: tests that need one are skipped,
and the summary says why. What each group needs:

| Tests | Need | How to get it |
| --- | --- | --- |
| Unit | nothing | `pytest` |
| Integration / e2e (database) | PostgreSQL with a `vulnscan_test` database | see below |
| ChromaDB store | the `rag` extra + a ChromaDB server | Docker run below |
| tree-sitter chunker | the `chunking` extra | Docker run below |

To run the database tests from your machine:

```bash
docker compose up -d postgres
docker compose exec postgres createdb -U vulnscan vulnscan_test   # once
export DATABASE_URL=postgresql+asyncpg://vulnscan:<POSTGRES_PASSWORD>@localhost:5432/vulnscan_test
pytest
```

(PowerShell: `$env:DATABASE_URL = "..."`.) If they are still skipped with
`connection was closed in the middle of operation`, port 5432 is already used
by a PostgreSQL installed on your machine: set `POSTGRES_HOST_PORT=5433` in
`.env`, run `docker compose up -d postgres` again, and use port 5433 in
`DATABASE_URL`.

To run **everything**, with nothing skipped, use the dedicated test container.
It runs on Linux, where the `rag` and `chunking` extras install without a
compiler, and it is hard-wired to the `vulnscan_test` database:

```bash
docker compose exec postgres createdb -U vulnscan vulnscan_test   # once
docker compose run --rm backend-tests
```

The first run downloads Chroma's embedding model (about 80 MB) into a Docker
volume; if that download times out, just run the command again.

**Frontend**

```bash
cd frontend
npm ci
npm start          # ng serve
npm run lint
npm run format:check
npm test
```

## Knowledge base

Curated OWASP Top 10 / CWE / MITRE ATT&CK data lives in `backend/data/knowledge/`
and is ingested into ChromaDB (+ a Postgres mirror table for admin listing
and idempotency) via:

```bash
cd backend
pip install -e ".[dev,rag]"
python -m scripts.ingest_knowledge              # all sources
python -m scripts.ingest_knowledge --source cwe # just one
```

Safe to re-run any time — documents are diffed by content hash, so
unchanged entries are skipped rather than re-embedded. The same flow is
available to admins (`is_superuser=true` users) via `POST
/api/v1/knowledge/ingest`, alongside `GET /api/v1/knowledge/documents`,
`GET /api/v1/knowledge/documents/{external_id}` and `GET
/api/v1/knowledge/health`.

## Scanning code

Any authenticated user can submit code and read back their own scans:

| Endpoint | Purpose |
| --- | --- |
| `POST /api/v1/scans` | Submit code (multipart form): either `file` (one source file, or a `.zip` of a project) or `code` (a pasted snippet, with an optional `language`). Returns `202` with the scan in `PENDING`. |
| `GET /api/v1/scans` | Your scans, most recent first (`limit`, `offset`). |
| `GET /api/v1/scans/{id}` | Status and progress - poll this until `COMPLETED` or `FAILED`. |
| `GET /api/v1/scans/{id}/report` | Findings (most severe first), per-severity counts and the scanned files. |
| `DELETE /api/v1/scans/{id}` | Delete a finished scan, its findings and its stored source. |
| `GET /api/v1/scans/{id}/export?format=json\|pdf` | Download a finished scan's report as a file. |
| `GET /api/v1/dashboard/summary` | Your totals: scans by status, findings by severity, most frequent CWEs, latest scans. |

```bash
curl -X POST http://localhost:8000/api/v1/scans   -H "Authorization: Bearer $TOKEN" -F "file=@project.zip"
```

What happens to a submission:

1. **Intake.** The upload is size-checked and decoded as text. Archives are
   extracted in memory with zip-slip and zip-bomb protection (entry count,
   uncompressed size and compression ratio are capped, and enforced on the
   bytes actually decompressed rather than on what the headers claim).
   Stored files are named after generated ids - no client-supplied name or
   archive path is ever used as a filesystem path.
2. **Chunking.** Each file is cut at function/class boundaries with
   tree-sitter (Python, JavaScript, TypeScript/TSX, Java, Go, PHP, C#, Ruby),
   keeping module-level code too; other files are cut into line windows.
3. **Retrieval + analysis.** For each chunk, the most relevant OWASP / CWE /
   ATT&CK entries are retrieved from ChromaDB and given to the LLM together
   with the line-numbered code. The reply must be a JSON object matching a
   strict schema; an invalid reply is sent back with the reason and retried.
4. **Validation.** Nothing the LLM says is stored unchecked: a CWE / OWASP /
   ATT&CK id is kept only if it exists in the ingested knowledge base (its
   title and URL then come from there, not from the LLM), line numbers are
   forced inside the chunk that was reviewed, and the vulnerable snippet is
   cut from the stored source rather than echoed by the model.

Scans run as background jobs inside the backend process, one at a time by
default (`SCAN_MAX_CONCURRENT_JOBS`), since they all share one local model.
A scan interrupted by a restart is marked `FAILED` at the next startup -
this assumes a single backend process, as in `docker-compose.yml`.

Ingest the knowledge base before scanning: without it scans still run, but
findings carry no CWE / OWASP / ATT&CK classification.

## Report export

A finished scan's report can be downloaded from its page, or from the API:

- **JSON** - the whole report as structured data (`schema_version: 1`), for
  scripts and other tools.
- **PDF** - a printable report, laid out by WeasyPrint.

Report content is text a language model wrote about code a user submitted,
so the PDF generator treats it as hostile: every value is HTML-escaped, and
the renderer is given a fetcher that refuses every URL, so nothing in a
report can make the server request a resource. PDF export needs the Pango
system library (included in the Docker image); where it is missing the
endpoint answers 503 and JSON export keeps working.

## Security

What the platform does to protect itself and its users:

| Area | Measures |
| --- | --- |
| Submitted code | Analyzed as text only - never imported or executed. Stored under generated ids; no client-supplied name is ever a filesystem path. |
| Archives | Zip slip and zip bombs rejected: path traversal entries, entry count, uncompressed size and compression ratio are checked on the bytes actually decompressed. |
| LLM output | Schema-validated; CWE / OWASP / ATT&CK ids kept only if they exist in the knowledge base; line numbers forced inside the reviewed code; rendered as plain text in the UI and escaped in PDFs. |
| Prompt injection | Code is fenced with a per-call random boundary and declared as data; the real defense is the validation above, which holds whatever the model was talked into. |
| Authentication | Argon2 password hashes; short-lived JWT access tokens; rotating single-use refresh tokens, with reuse treated as theft (all sessions revoked). Login does the same hashing work whether or not the account exists. |
| Authorization | Every scan, report, export and statistic is scoped to its owner; another user's scan answers 404, like a missing one. |
| Abuse | Rate limits on login, registration and scan submission; a cap on unfinished scans per user; request bodies over the upload limit refused before they are read. |
| HTTP | Security headers on every response (`nosniff`, no framing, no caching of API data, a deny-all content policy for the API and a strict one for the SPA); CORS limited to the configured origins, methods and headers. |
| Errors | One error envelope everywhere; validation errors never echo the rejected input; unexpected errors are logged, not returned. Secrets are redacted from logs. |

Known limits, by design of this version:

- Scan jobs run inside the backend process: run a single backend instance,
  and expect scans in progress to be marked failed if it restarts.
- Rate limits are counted per backend process, in memory.
- The refresh token is kept in the browser's `sessionStorage`, readable by
  any script running in the page; the strict content policy is what keeps
  such a script from running.
- Findings come from a language model: it misses vulnerabilities and it
  reports some that are not real. A report is a starting point for review,
  not a verdict.

### Production checklist

- Set `ENVIRONMENT=production`. The backend then refuses to start with
  `DEBUG=true`, a weak or placeholder `JWT_SECRET_KEY`, or a wildcard CORS
  origin; it turns the interactive API docs off and sends HSTS.
- Generate the secret: `python -c "import secrets; print(secrets.token_urlsafe(64))"`.
- Choose a real `POSTGRES_PASSWORD`, and do not publish the database,
  ChromaDB or Ollama ports outside the Docker network.
- Serve everything over HTTPS, behind a TLS-terminating proxy. Build the
  frontend with the `production` target of `frontend/Dockerfile`; it serves
  the bundle with nginx and proxies `/api/` to the backend.
- Set `CORS_ORIGINS` to the frontend's real origin (not needed when the API
  is only reached through that same-origin proxy).

## Frontend

Angular (standalone components, signals, zoneless), in `frontend/src/app`:

```
core/      API base URL, error messages, and everything auth: service,
           HTTP interceptor, route guards, token storage
features/  one folder per page (login, register, dashboard, ...)
layout/    the shell around signed-in pages (header, navigation)
shared/    small presentational components
```

How a session works:

- **Tokens.** The access token is kept in memory only. The refresh token is
  kept in `sessionStorage`, so a reload restores the session but closing the
  tab ends it, and each tab has its own token - the backend revokes every
  session of a user when a refresh token is reused, which two tabs sharing
  one token would trigger.
- **Requests.** An interceptor adds the access token to calls to our API
  (and to nothing else). On a 401 it refreshes the token once - a single
  refresh shared by all requests failing at that moment - and replays the
  request; if the refresh is refused, the user is returned to the login page.
- **Routes.** Guards send visitors to `/login` (remembering where they were
  going) and keep signed-in users off the login and register pages. They are
  a navigation aid: the backend authorizes every request itself.

Pages, all behind sign-in:

| Page | Address | What it does |
| --- | --- | --- |
| Dashboard | `/dashboard` | Totals, findings by severity, most frequent weaknesses, latest scans. |
| New scan | `/scans/new` | Paste a snippet, or upload a source file or a `.zip` of a project. |
| Scans | `/scans` | Every scan you submitted, paginated, with delete. |
| Scan report | `/scans/{id}` | Progress while the scan runs, then its findings, filterable by severity. |

A page showing a scan that is still running re-reads it every 3 seconds, and
stops once it has finished. Reports are text the model wrote about code a
user submitted, so everything in them is rendered as plain text, never as
HTML, and a reference is only turned into a link when its URL is http(s).

In development (`npm start`) the browser calls the backend directly at
`http://localhost:8000/api/v1` (`src/environments/environment.ts`). The
production bundle calls `/api/v1` on its own origin and nginx proxies it to
the backend (`frontend/nginx.conf`).

## Project status

Built phase by phase; each phase is reviewed before the next starts.

- [x] Phase 0 — Architecture proposal (folder tree, ERD, API list, `Finding` schema)
- [x] Phase 1 — Project setup (docker-compose, config, logging, linting, pre-commit, CI)
- [x] Phase 2 — Backend auth (domain → use cases → infra → API) + tests
- [x] Phase 3 — Knowledge ingestion (OWASP, CWE, ATT&CK) into ChromaDB + retrieval tests
- [x] Phase 4 — Code chunking + LLM analysis pipeline + scan use cases + async jobs + tests
- [x] Phase 5 — Angular core (auth, interceptors, guards, layout)
- [x] Phase 6 — Angular features (new scan, scan list, report view, dashboard)
- [x] Phase 7 — Report export, error handling polish, security hardening, README, demo data
