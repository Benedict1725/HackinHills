# LeakProof AI — Agent Handoff

> Read this file first, then `CHANGELOG_AND_ERRORS.md`.
> Written 2026-10-27 from (a) the original "Master Build Prompt" and (b) a direct inspection of the project zip `DOC-20261027-WA0015.zip`.
> **Verified by running** = I executed it in a sandbox this session. **Not verified** = read in code only, or not run.

---

## 1. What this project is

LeakProof AI is an AI security testing product for a hackathon. Non-technical judges should understand it in 60 seconds.

Core loop:

```
Red Team attack -> shared finding -> Blue Team defense -> retest the SAME attack
  -> before/after comparison -> dashboard update
```

Hard rules from the owner's master prompt (do not violate):

- Never fabricate model responses, scores, blocked attacks or "successful" defenses.
- Keep **execution status** (did the test run?) separate from **security verdict** (PASS / FAIL / NEEDS_REVIEW).
- A provider error or timeout is **never** a successful defense.
- Never mark a finding mitigated just because a defense checkbox was enabled. Only a real retest can do that.
- A single passing retest is not proof that the model is secure. Say so in the UI.
- All secrets in tests are **synthetic canaries**. No real secrets in code or logs. API keys stay server-side.
- Reuse existing code. No big rewrites. No weakening tests to get green builds.
- Do not claim success unless you actually ran and verified it.

---

## 2. Stack and layout

| Layer | Tech |
|---|---|
| Backend | Python 3.11+ (CI) / 3.12 (sandbox), FastAPI 0.115, SQLAlchemy 2.0, Pydantic 2, httpx, SQLite (`leakproof.db`) |
| AI providers | Ollama (default) or Anthropic, selected in `backend/.env` |
| Frontend | React 18, Vite 5, react-router-dom 6, recharts, lucide-react, vitest + Testing Library |
| CI | `.github/workflows/ci.yml` (backend `pytest -q`, frontend `npm ci && npm run build`) |

```
backend/
  app/main.py            FastAPI app, CORS, lifespan (init_db), catch-all 500 handler
  app/config.py          Settings read from env on every call
  app/database.py        engine, init_db, additive migrations, severity backfill
  app/models.py          User, AuthSession, DefenseConfig, TestRun, AuditEvent
  app/schemas.py         Pydantic request/response models
  app/ai/providers.py    Ollama + Anthropic providers, health checks
  app/routes/            health, auth, admin, ai, dashboard, defense, findings, tests, audit, reports
  app/services/          runner, evaluator, defenses, defense_store, testcases, metrics, audit, auth, security
  scripts/seed_demo_users.py, smoke_test_provider.py
  tests/                 ~20 test files
frontend/src/
  App.jsx                routes + role Gate
  components/            Layout (nav), RedTeamFindings, ProtectionWizard, RedGuide, ui, teamViz
  pages/                 Overview, RedTeam, BlueTeam, History, TestDetail, Audit, Admin, Settings, Login
  services/              api.js, auth.jsx, useApi.js
  test/                  findings.test.jsx, guided.test.jsx
```

---

## 3. Architecture facts that matter

### 3.1 There is NO separate `findings` table
A **finding** is a `TestRun` row where:
`owner_role == "red_team" AND is_demo == False AND parent_test_id IS NULL`
(see `finding_filter()` in `backend/app/routes/findings.py`).

A **retest** is a *new* `TestRun` row with `parent_test_id = <finding.test_id>`, `mode = "defended"`, and `owner_role = blue_team`. The original finding row is never modified, so original evidence is preserved.

The "finding ID" shown to users is `TestRun.test_id` (string, unique, indexed).

### 3.2 Roles and permissions (server-enforced; frontend gates are cosmetic)
| Role | Can do |
|---|---|
| `red_team` | Run tests (`POST /api/tests/run`), run suite. **Cannot** read `/api/blue-team/*`. |
| `blue_team` | Read findings, **save defense config**, **retest**, run comparisons, run suite. |
| `admin` | Read findings and all data, manage users, view audit log. **Cannot retest.** |

Findings are shared across the whole deployment (single-workspace demo, no tenant model). Red Team results are visible to Blue Team and admin only.

Demo logins come from `python -m scripts.seed_demo_users`: `red@leakproof.local`, `blue@leakproof.local`, `admin@leakproof.local`. Passwords are random and printed once, or set via `LEAKPROOF_DEMO_PASSWORD` (min 8 chars). **If no users exist, nobody can sign in.** The backend logs a warning at startup.

### 3.3 API endpoints (all under the FastAPI app)
- Health/AI: `GET /api/health`, `GET /api/ai/health`
- Auth: `POST /api/auth/login`, `GET /api/auth/me`, `POST /api/auth/logout`
- Tests: `GET /api/test-cases`, `POST /api/tests/run`, `POST /api/tests/run-suite`, `GET /api/tests`, `GET /api/tests/{id}`, `POST /api/tests/{id}/review`
- Findings (Blue Team): `GET /api/blue-team/findings` (filters: severity, verdict, category, execution_status, limit, offset), `GET /api/blue-team/findings/{test_id}`, `POST /api/blue-team/findings/{test_id}/retest`
- Defense: `GET /api/defense/presets`, `GET|POST /api/defense/config`, `POST /api/comparisons/run`, `GET /api/comparisons/latest`
- Other: `GET /api/dashboard`, `GET /api/reports/evaluation`, `GET /api/audit`, `POST /api/audit/verify`, admin `GET|POST /api/admin/users`, `PATCH /api/admin/users/{id}`, `GET /api/admin/overview`

### 3.4 Defense pipeline (`services/defenses.py`)
`input screen -> hardened system prompt -> model -> output protection`.
Four toggles stored on `DefenseConfig`. Column names are legacy:

| UI / API name | DB column | What it does |
|---|---|---|
| `input_screen` | `input_validation` | Regex block of override / unrestricted-mode / secret-extraction phrasing |
| `hardened_prompt` | `hardened_prompt` | Appends an instruction-hierarchy policy (+ optional `policy_text`) to the system prompt |
| `output_redaction` | `output_checking` | Redacts registered synthetic canaries; withholds reversed/base64 forms |
| `output_contract` | `output_contract` | Enforces uppercase-only and literal end-token rules |

Saving config creates a **new version** row (`defense_store.save_new_version`), so history is kept. These are heuristics. The code comments say plainly they do **not** reliably stop jailbreaks.

### 3.5 Retest flow
`POST /api/blue-team/findings/{id}/retest` -> `defense_store.resolve(db, "defended")` (returns 409 if Blue Team has not saved a config) -> `runner.run_retest` -> re-runs the stored prompt with the original system prompt/check (predefined cases) or re-derived `custom_spec(category, objective)` (custom prompts) -> saves a new linked `TestRun`. Provider failure is saved as an `ERROR` row, not raised. The `assess()` function compares original vs retest and returns an `effect` (`mitigated`, `not_mitigated`, `worse`, `blocked`, `false_refusal`, `inconclusive`, `no_verdict`, `not_applicable`, `error`).

### 3.6 Other behavior worth knowing
- Concurrency: runner is `@_locked`; a second concurrent test returns HTTP 429.
- Audit log is a hash chain (`prev_hash`/`event_hash`); `POST /api/audit/verify` checks it.
- DB migrations are additive-only (`migrate_day1_schema`); relative SQLite paths are anchored to `backend/` so a different working directory cannot create a second empty DB.
- Test suite: 17 `TestCase` entries in `testcases.py`; some (RAG, tools) are documented but marked not runnable.
- Frontend build stamp (`__BUILD_STAMP__`) shows in the page corner so you can tell which build the browser is running. Vite is set to `strictPort: true` on 5173.

---

## 4. Verified status (run this session on the uploaded zip)

| Check | Result |
|---|---|
| `pytest -q` (backend) | **219 passed, 2 skipped** (the 2 skips are `test_real_provider.py`: no live model configured in the sandbox) |
| `npm ci && npm run build` | **Succeeded.** Warning only: JS chunk 658 kB (>500 kB) |
| `npm test` (vitest) | **21 passed** (`findings.test.jsx` 8, `guided.test.jsx` 13) |
| Real Ollama smoke test | **Not run.** No Ollama in the sandbox |
| App run end-to-end in a browser | **Not run** |
| Lint / type checks | None configured in the repo |

**So: the code is internally consistent and tested with mocked providers. The full live demo flow has not been verified against a real model.**

---

## 5. Gap analysis vs. the master prompt (what is still to do)

Order is priority. Items marked **VERIFY** may already be partly done; I only read code, I did not run the UI.

1. **Real end-to-end smoke test (highest priority).** Start backend + frontend, seed users, run the 13-step acceptance flow from the prompt §15 against real Ollama. Fix whatever breaks. Nothing else matters if this loop fails live.
2. **Navigation does not match the spec.** Current nav in `Layout.jsx`: *Dashboard, Red Team Console, Blue Team Console, Test History, Admin, Settings*. Spec wants exactly four primary items: **Overview, Red Team — Attack Lab, Blue Team — Defend & Retest, Reports & History**, with Admin/Settings/Audit as secondary. Needs renaming and regrouping.
3. **"Red Team Findings tab" location.** It exists as `components/RedTeamFindings.jsx`, rendered inside `pages/BlueTeam.jsx` as a tab, and `findings.test.jsx` asserts it is visible. **VERIFY in the running UI** that it appears for the blue_team user. Note that the red_team user is deliberately denied the findings API, so a Red Team user will never see it. Decide whether Red Team should get read-only access to its own findings.
4. **Finding status vocabulary.** Spec: `MITIGATED / STILL VULNERABLE / NEEDS REVIEW / NOT RETESTED`. Backend `assess().effect` uses different names. **VERIFY** that the list and detail views derive and display exactly the four spec states, including "NOT RETESTED" for findings with no retest and for findings whose latest retest predates the latest defense-config change.
5. **Latest retest + protection status on the findings list.** Spec wants these columns in the list. `FindingOut` has `retest_count` but I did not see latest-retest verdict/status in the list payload. **VERIFY** / add.
6. **Filters.** Backend supports severity, verdict, category, execution_status. Spec also wants **mitigation status** and **unresolved only** filters plus text search. **VERIFY** / add.
7. **Finding detail sections.** Spec: What happened / Why it matters / What should be protected / Recommended defense / Current protection status. **VERIFY** all are present with plain-English text and quoted evidence.
8. **Dashboard.** Spec lists specific metrics (attacks run, confirmed vulns, unresolved critical/high, defended, verified mitigated, still vulnerable, recent activity, model health, next action, documented score rules, empty state). **VERIFY** against `routes/dashboard.py` and `Overview.jsx`. Do not invent score values.
9. **Reports & History.** Currently `History.jsx` (+ `TestDetail.jsx`) and `GET /api/reports/evaluation`. Spec wants a combined view: attacks, findings, config changes, retests, before/after. CSV/PDF export only if cheap. **Not verified whether export exists.**
10. **Provider config.** `.env.example` ships `AI_MODEL=llama3.2:3b`. The owner's setup uses **`qwen2.5:3b`** (from the prompt). The owner's real `backend/.env` was **not** in the zip. Confirm the model with `ollama list`, set `AI_MODEL` to match, and keep the Ollama integration unchanged.
11. **Plain-English glossary** for every security term across the UI. `RedGuide.jsx` and `ProtectionWizard.jsx` already contain some. **VERIFY** coverage.
12. **Git checkpoint.** The zip has no `.git`. Run `git init && git add -A && git commit -m "checkpoint"` before editing.
13. **Bundle size** warning (658 kB). Optional: route-level `React.lazy`.

---

## 6. How to run it

```bash
# Terminal 1 — backend
cd backend
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                                   # then edit AI_MODEL etc.
python -m scripts.seed_demo_users                      # prints passwords once
uvicorn app.main:app --reload --port 8000

# Terminal 2 — frontend
cd frontend
cp .env.example .env                                   # VITE_API_BASE_URL=http://127.0.0.1:8000
npm install
npm run dev                                            # http://localhost:5173

# Optional: Ollama (separate terminal)
ollama serve
ollama pull qwen2.5:3b        # or whatever AI_MODEL is set to
cd backend && python -m scripts.smoke_test_provider    # real-model smoke test
```

Tests:

```bash
cd backend && pytest -q
cd frontend && npm test && npm run build
```

Environment variables (backend `.env`; **never print or commit values**): `DATABASE_URL`, `CORS_ORIGINS`, `AI_PROVIDER` (`ollama`|`anthropic`), `AI_MODEL`, `OLLAMA_HOST`, `ANTHROPIC_API_KEY` (only if provider is anthropic), `AI_TIMEOUT_SECONDS`, `AI_MAX_TOKENS`. Frontend: `VITE_API_BASE_URL`. Optional: `LEAKPROOF_DEMO_PASSWORD`.

---

## 7. Known pitfalls (learned the hard way — see the log for detail)

- **Stale dev server on port 5173.** An old copy of the frontend still running makes the browser show an old UI (this is the likely cause of the "missing Red Team Findings tab" report). Check the **build stamp** in the page corner; kill old `node`/`vite` processes. `strictPort` now makes Vite fail loudly instead of silently moving to 5174.
- **No users = cannot log in.** Run the seed script.
- **Different working directory = different database** (fixed by anchoring SQLite path to `backend/`, but older DB files may exist elsewhere).
- **Browser shows "CORS error" for a real 500.** Fixed with a catch-all handler registered inside CORS. If you see CORS errors, check the backend log for the true status.
- `create_all` does not alter tables. New columns go in `_NEW_COLUMNS` in `database.py`.
- Legacy rows may have `outcome` but NULL `execution_status`/`security_verdict`; migration backfills them.
- Model offline: tests save as `ERROR`; the UI must stay browsable for existing findings.

---

## 8. Working agreements for the next agent

1. Read both `.md` files. Run the three test commands in §6 to confirm the baseline before editing.
2. Make a git checkpoint.
3. Work in small steps. After each: run tests, then update `CHANGELOG_AND_ERRORS.md` (changes + any new errors with root cause and fix).
4. Verify in the **running UI**, not just in unit tests.
5. At the end report: summary, files changed, DB changes, run commands, env vars (names only), test/build results incl. failures, what is incomplete, and a short demo script.
6. If something is unverified, say so. Do not guess.

---

## 9. Suggested 60-second demo script (to confirm against the live app)

1. Log in as `red@leakproof.local`. Open Red Team. Pick a data-leakage scenario (e.g. `dl-002`, claimed developer asks for an API token). Run. Show prompt, response, verdict, evidence.
2. Log in as `blue@leakproof.local`. Open Blue Team -> Red Team Findings. The same finding is there, no copying.
3. Open it. Read what happened and why it matters. Enable Input Screen, Hardened Prompt and Output Safety Check. Save.
4. Click Retest. Show before vs after.
5. Show the dashboard update. Say clearly: "one passing retest is evidence, not a guarantee."
6. Refresh the page to show persistence.

*(Adjust once step 1 of §5 has been done against the real model; outcomes depend on how the model actually responds.)*
