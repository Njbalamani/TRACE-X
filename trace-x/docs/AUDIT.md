# TRACE-X repository audit (Phase 1)

Method: every tracked source file was read; the Django test-suite was run before
and after changes (baseline **77 passing**, now **116 passing**).

## Architecture as found (differs from the project brief)

| Layer | What it actually is | Talks to |
|---|---|---|
| `investigations/` + `templates/` | Django 6.1 app, server-rendered UI, **real auth**, integrity chain, 77 tests | itself |
| `backend/` | **Separate FastAPI + SQLAlchemy service**, no authentication, own DB (`data/tracex.db`), own parsers, own PDF/OpenAI code, 4 test files | React |
| `frontend/` | React 18/TS/Vite SPA (~1,900 lines) calling `/api` -> proxied to **FastAPI :8020**, never Django | FastAPI |

Consequences: the React app has no login/CSRF; Django and FastAPI hold two
different copies of the data model; "Sentinel AI" exists only as marketing text
on the login page (the only AI code is an OpenAI provider in `backend/app/ai`).
Resolution (consistent with "keep Django, keep React"): Django is the system of
record; React will be re-pointed at a new authenticated Django API; useful
FastAPI pieces (parsers, provider abstraction) are ported, then the FastAPI tree
retired. Nothing in `backend/` has been deleted yet.

## Findings

| # | Area | Finding | Status |
|---|---|---|---|
| 1 | Security | `protected_media` served any case's file to **any** logged-in user | **Fixed** (case-scoped, audited) |
| 2 | Security | Evidence served inline from app origin -> stored XSS via uploaded .html/.svg | **Fixed** (attachment + nosniff + no-store) |
| 3 | Security | Insecure `SECRET_KEY` fallback committed in source; `DEBUG` default on | **Fixed** (per-install key, debug off by default) |
| 4 | Security | No upload allow-list / content sniffing; client filename used as title | **Fixed** (`services/uploads.py`) |
| 5 | Security | No login throttling | **Fixed** (per addr+username, audited) |
| 6 | Security | Authorization = staff or creator only; no roles | **Fixed** (4 roles, 404 vs 403 semantics) |
| 7 | Security | No audit log | **Fixed** (append-only `AuditEvent`) |
| 8 | Bug | Case-number generator race -> duplicate key 500 | **Fixed** (retry in transaction) |
| 9 | Bug | Login template hard-codes "Invalid username or password" (hid lockout message) | **Fixed** |
| 10 | Bug | Migration drift: `Finding.Meta.ordering` had no migration | **Fixed** |
| 11 | Perf | `api_investigations` = 3 COUNT queries per case (N+1) | **Fixed** (annotate) |
| 12 | Perf | No indexes on `occurred_at`, `source_ip`, `severity`, `status`, IOC value | **Fixed** (named indexes) |
| 13 | Perf | `investigation_detail` re-hashes every evidence file on each page view | Open |
| 14 | Detection | Analysis is regex flags with **no time windows**: 1 failed login on day 1 + 1 success on day 30 => "compromise" | Open (next increment) |
| 15 | Detection | Detection is case-global, not per-actor; `ATTACK_PATTERNS` matches `root`, `c2`, `upload` anywhere (false positives) | Open |
| 16 | Integrity | Ledger anchor lives in the same DB row as the chain: an attacker with DB write can rewrite both | Open (needs exported/signed anchor) |
| 17 | Integrity | Re-analysis deletes AI events/findings; ledger keeps blocks for deleted objects | Open |
| 18 | Frontend | React app unauthenticated, bound to FastAPI, plain `fetch` (no CSRF/session) | Open |
| 19 | Hygiene | No `.gitignore`; committed: `db.sqlite3`, `data/tracex.db`, logs, `_shots/`, `.pytest_cache`, `frontend/dist`, `storage/*`, **a personal PDF in `media/`** | **Fixed** in the clean export |
| 20 | Docs | README claims 54 tests (actual 77 at baseline) | Open |

## Dead / duplicated code
* `backend/` (FastAPI) duplicates Django's models, parsers, analysis, ledger and reports.
* `scripts/seed_demo.py` duplicates `manage.py seed_demo`.
* `static/vendor/{gsap,lottie,motion,aos}` loaded for the template UI only.
