# LeakProof AI — Changelog and Error Log

> Companion to `HANDOFF.md`. **Append new entries at the top of each section. Never delete old ones.**

## How this file was built (read this caveat)

The previous work sessions were not available to me. This file was **reconstructed from the project zip** (`DOC-20261027-WA0015.zip`): file timestamps, code comments that describe past bugs, test names, and my own test run on 2026-10-27.

- Entries marked **[Evidence: code]** are inferred from comments/structure in the source. The cause and fix are real in the code, but I did not witness them happening.
- Entries marked **[Verified]** I ran myself this session.
- If the project owner remembers other errors, add them under section 3 using the template.

---

## 1. Project timeline (from file timestamps)

| Date (2026) | What the files show |
|---|---|
| Oct 24 | Initial base: backend skeleton, providers, auth routes, defenses, audit log, migration code, CI workflow, most backend tests, login page, API client |
| Oct 25 | Findings router + serializers, evaluator and test-case library, severity/metrics, dashboard route, `RedTeamFindings.jsx`, `Overview`/`History`/`TestDetail` pages, `vite.config.js` (strictPort + build stamp), frontend `package-lock.json` |
| Oct 27 (08:10–08:15) | Latest edits: `main.py`, `database.py`, `models.py`, `defenses.py`, `defense.py`, `auth.py` (routes + service), `admin.py`, `Admin.jsx`, `Audit.jsx`, `Settings.jsx`, `Layout.jsx`, `App.jsx`, `BlueTeam.jsx`, `RedTeam.jsx`, `ProtectionWizard.jsx`, `RedGuide.jsx`, `index.css`, `api.js`, both frontend test files, `test_admin.py` |
| Oct 27 (09:40) | Zip uploaded to this session; baseline verified (section 4) |

Reading: Oct 27 work was mainly admin/user management, guided Red/Blue UIs (`RedGuide`, `ProtectionWizard`), and the `output_contract` defense.

---

## 2. Changes made (what exists in the code now)

Grouped by feature. All **[Evidence: code]** unless noted.

### 2.1 Shared findings (Red Team -> Blue Team)
- New router `backend/app/routes/findings.py` under `/api/blue-team`: list, detail, retest.
- Findings are `TestRun` rows (`owner_role=red_team`, non-demo, `parent_test_id IS NULL`). No new table, so no migration risk and existing history stays valid.
- Access limited to `blue_team` and `admin`; only `blue_team` can retest. `visible_filter()` for `/api/tests` and dashboards left untouched so existing isolation is unchanged.
- Filters on list: severity, verdict, category, execution_status; pagination (limit/offset).
- Frontend: `RedTeamFindings.jsx` mounted as a tab in `BlueTeam.jsx`, polling every 10 s (`POLL_MS`), with a retest button and before/after panels.

### 2.2 Retest
- `runner.run_retest` re-runs the stored prompt with the saved defense config and links the result via `parent_test_id`. The original finding is never modified.
- Predefined cases reuse the original system prompt and check; custom prompts re-derive the same category-aware check from category + objective.
- `assess()` judges the result from the real evaluated verdicts, not from which toggles are enabled. Handles: mitigated, not_mitigated, worse, blocked-by-input-screen, false_refusal, inconclusive, no_verdict, error.
- Returns 409 if Blue Team has not yet saved a defense config. Provider failure is saved as an ERROR retest, not hidden.

### 2.3 Execution status vs security verdict
- `TestRun` now has `execution_status` (PENDING/RUNNING/COMPLETED/ERROR), `security_verdict` (PASS/FAIL/NEEDS_REVIEW/NOT_APPLICABLE), `severity` (CRITICAL..NONE), `error_message`, `test_objective`.
- Legacy `outcome` column kept for backward compatibility. A migration backfills old rows (`migrate_day1_schema`) and `backfill_severity()` fills severity. Both are idempotent and never overwrite.

### 2.4 Defenses
- Four toggles (input screen, hardened prompt, output redaction, output contract). `output_contract` was the newest addition; migration defaults it to ON (`BOOLEAN DEFAULT 1`) for older saved configs.
- Saving creates a new version (history preserved); config changes are audit-logged without copying policy text.

### 2.5 Evaluator and test library
- `services/evaluator.py`: evidence-based checks (exact synthetic-canary match, normalized comparison, objective parser), severity mapping.
- `services/testcases.py`: 17 test cases across prompt injection, jailbreak, data leakage, instruction conflict, normal-request controls, system-prompt leakage, improper output handling, misinformation, resource consumption; RAG/tool cases documented but not runnable (HTTP 409 with explanation).

### 2.6 Auth, admin, audit
- Session tokens stored as SHA-256 hashes; passwords salted-hashed; `is_active` flag lets admins deactivate accounts.
- Admin routes (`/api/admin/users`, `/overview`), Admin page, hash-chained audit log with `/api/audit/verify`.
- `scripts/seed_demo_users.py` creates one demo account per role; refuses shared passwords under 8 chars.

### 2.7 Reliability / DX hardening
- `main.py`: startup logs DB location and warns when no users exist; catch-all 500 handler placed so errors still carry CORS headers.
- CORS: configured origins plus regex allowing any `localhost`/`127.0.0.1` port.
- `database.py`: SQLite relative path anchored to `backend/`.
- `vite.config.js`: `strictPort: true` and a build stamp shown in the UI corner.
- Runner is locked; concurrent test returns 429 with a clear message.
- `providers.py`: actionable messages ("Start it with `ollama serve`", "Run `ollama pull <model>`").

### 2.8 Frontend
- Role-gated routes, shared `ui.jsx` badges (verdict, severity, execution), `teamViz.jsx` charts, guided Red Team page (`RedGuide`) and Blue Team 'protection wizard'.
- Tests: `findings.test.jsx` (8) and `guided.test.jsx` (13).

### 2.9 Not changed / not done yet
See `HANDOFF.md` section 5. Main items: four-item navigation per spec, spec status vocabulary, list columns/filters, report export, and live-model end-to-end verification.

---

## 3. Errors encountered and how they were resolved

Template for new entries:

```
### E-NN  Short title                         (Status: open | fixed | workaround)
Symptom:      what the user saw
Root cause:   what was actually wrong (confirm, don't guess)
Fix:          what was changed, with file names
Verified by:  command / manual step that proved it
Prevention:   test or guard added
```

### E-01  "Red Team Findings" tab missing in the browser      (Status: fixed in code; **confirm in running UI**)
Symptom: Owner reported Red Team findings not appearing in Blue Team and the Findings tab not visible. **[Evidence: code]**
Root cause (per comments in `vite.config.js` and `Layout.jsx`): an **old copy of the project still running on port 5173**. Vite silently moved the new build to 5174 while the browser kept showing the stale app. The component and route were not the problem. A second contributing factor is role design: the `red_team` role is intentionally denied `/api/blue-team/*`, so it can never see the tab.
Fix: `strictPort: true` so Vite refuses to start if 5173 is busy; build stamp rendered on every page (`data-testid="build-stamp"`); `findings.test.jsx` asserts the tab renders next to the other tabs and is keyboard accessible.
Verified by: vitest passes **[Verified]**. The tab in a live browser has **not** been verified.
Prevention: check the build stamp against dev-server start time; kill old node/vite processes.

### E-02  Browser reports "CORS error" for a server failure     (Status: fixed) [Evidence: code]
Symptom: Misleading CORS message in the console when the API actually returned HTTP 500.
Root cause: unhandled exception escaped the CORS middleware, so no CORS headers on the error response.
Fix: `catch_unhandled` middleware in `main.py`, registered before CORS so it sits inside it; returns JSON `{"detail": "Internal server error."}` and logs only the exception type and path (no secrets). Covered by `tests/test_cors.py`.

### E-03  Second, empty database created from a different directory  (Status: fixed) [Evidence: code]
Symptom: Data "disappeared" depending on where uvicorn was started.
Root cause: relative `sqlite:///./leakproof.db` resolves against the current working directory.
Fix: `resolve_database_url()` anchors relative SQLite paths to `backend/`. Covered by `tests/test_database.py`.
Watch for: stray older `leakproof.db` files left in other folders.

### E-04  Cannot sign in on a fresh install                      (Status: fixed/guarded) [Evidence: code]
Root cause: no users exist until the seed script is run.
Fix: startup warning from `warn_if_no_users`; `scripts/seed_demo_users.py`.

### E-05  New DB columns missing on existing databases           (Status: fixed) [Evidence: code]
Root cause: SQLAlchemy `create_all` never alters existing tables, so rows from older schemas lacked `execution_status`, `severity`, `parent_test_id`, `output_contract`, etc.
Fix: additive `migrate_day1_schema()` with `_NEW_COLUMNS`, plus idempotent backfills. Never drops or rewrites data.
Rule: new columns must be added to `_NEW_COLUMNS` as well as to `models.py`.

### E-06  Provider failure looked like a defended/blocked attack  (Status: fixed) [Evidence: code]
Root cause: the old single `outcome` field mixed "did it run" with "was it safe".
Fix: split `execution_status` from `security_verdict`; ERROR rows have no verdict and no severity and are excluded from attack-success rates; retest of a failed run reports `effect="error"`.

### E-07  Ollama model name mismatch (potential)                  (Status: open, owner to confirm)
`backend/.env.example` says `AI_MODEL=llama3.2:3b`; the owner's prompt says `qwen2.5:3b`. The real `.env` was not in the zip. If the configured model is not installed, health check reports "Model '<name>' is not installed. Run `ollama pull <name>`." Run `ollama list` and align `AI_MODEL`.

### Errors seen by the previous sessions but NOT recoverable from the zip
Any build errors, stack traces, or UI bugs from earlier chats that left no trace in code comments are unknown to me. **Add them here** if you have them.

---

## 4. Baseline verification — 2026-10-27 **[Verified]**

Environment: Linux sandbox, Python 3.12, Node (npm ci succeeded). No Ollama, no browser.

| Command | Result |
|---|---|
| `cd backend && pip install -r requirements.txt && pytest -q` | **219 passed, 2 skipped, 1 warning** (starlette DeprecationWarning; skips = real-provider tests with no live model) |
| `cd frontend && npm ci && npm run build` | **Success**, built in ~9 s. Warning: `index-*.js` 658.77 kB (>500 kB) |
| `cd frontend && npm test` | **21 passed** (2 files). Only React Router v7 future-flag warnings |

No code was modified during this verification. Files were extracted to a scratch folder only.

### Not tested
Live Ollama smoke test; Anthropic provider; browser/UI behavior; the 13-step acceptance flow; PDF/CSV export; load/concurrency beyond unit tests.

---

## 5. Changes log for future sessions (append here)

```
### 2026-MM-DD  <agent/session>
Changed:   files + one-line reason
DB:        schema/migration changes, or "none"
Tested:    command -> result (exact numbers)
Errors:    link to E-NN entries in section 3
Open:      anything left unfinished
```

*(No entries yet after the baseline above.)*
