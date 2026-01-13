# GitHub Copilot / AI Agent Instructions

## Quick context
- Repository: minimal project scaffold for "CS395_Capstone". Current root contains only `README.md` (contents: "registered app governance").
- No source directories (`src/`, `app/`), no tests, and no CI workflows were detected.

## Purpose for AI agents
- Be conservative: make small, well-scoped changes and include tests and docs where applicable.
- When in doubt, open a draft PR or an issue instead of making large design changes without maintainer sign-off.

## What to do first (discovery steps)
1. Look at `README.md` to capture the stated purpose before adding new features.
2. Check open **issues** and **milestones** to prioritize work, then review branch protection and recent commits for any unwritten conventions (use `gh issue list`, `gh milestone list`, `git log`, and PR history).
3. If adding code, create a clear project layout (examples below) and update `README.md` with setup/run instructions.

## Project conventions and minimal expectations
- Project currently has no explicit language or framework. When adding code:
  - Use `src/` (or language specific convention) for implementation and `tests/` for unit tests.
  - Add a top-level `Makefile` or `README` commands that document: install, test, lint, run.
  - Add a small test suite and make PRs that pass tests locally before opening the PR.
- Keep changes small (one concept per PR) and include a short PR description referencing any related issue.

## Build / test / debug guidance (repository-specific notes)
- No build/test scripts were detected. If you add Python code, prefer `pytest` and document `python -m venv .venv` setup in `README.md`.
- If you add Node.js code, include `package.json` scripts for `test` and `start`.
- Add a GitHub Actions workflow at `.github/workflows/ci.yml` that runs tests on push/PR.

## Integration points & external dependencies
- None discovered. If integrating external services, document required env vars in `README.md` and add a `.env.example` with placeholder keys.

## Examples & concrete patterns (use these as templates)
- Adding a Python microservice:
  - `src/my_service/` — implementation
  - `tests/test_my_service.py` — unit tests
  - Update `README.md` with `pip install -r requirements.txt` and `pytest` commands
  - Add `.github/workflows/ci.yml` to run `pytest` on PRs

- Adding a web app:
  - `frontend/` and `backend/` directories; each with their own `README.md` and tests
  - Document cross-service env vars and versioning in the root `README.md`

## PR checklist (what an agent should include in a PR)
- Small, focused commit(s) with descriptive messages
- Tests that cover new behavior (or a clear TODO if test scaffolding is added first)
- Updated `README.md` for any new developer-facing commands
- A short PR description and, if needed, a request for design feedback via a draft PR

## Safety and policy constraints
- Do not commit secrets (API keys, private keys) or credentials. If found, stop and open an issue or redact the secret and rotate it with the maintainers.

---

If any part of these instructions is unclear or missing (for example, preferred language, CI, or style rules), please tell me what details to add and I will iterate on this document.