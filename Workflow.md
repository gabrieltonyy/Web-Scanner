# Web-Scanner — Working Process

How the three of us operate on this project: Claude (planning/review), Socrates (driver + real-world tester), coding agent (implementer). This doc is the source of truth for process — `job-plan.md` is the source of truth for scope/priority.

---

## Roles

**Claude (this chat) — the brain**
- Breaks each `job-plan.md` phase into a detailed, file-scoped prompt for the coding agent (like `agent-prompt.md`).
- Reviews the agent's work at the end of each phase: reads `handover.md`, pulls the actual GitHub diff/commits (public repo, so I can `web_fetch` commit URLs directly — don't just trust the handover doc), checks it against acceptance criteria.
- Reviews Socrates's live-testing feedback and decides: pass phase / send fixes back to the agent / adjust the plan.
- Updates `job-plan.md` status after each phase is signed off.
- Does not touch code directly — no filesystem access to the real repo (confirmed in our last session), so everything routes through you and the agent.

**Socrates — the driver / man-in-the-middle**
- Hands the phase prompt to the coding agent, monitors it while it works.
- Runs the clean-room test (see below) after each phase.
- Brings back to this chat: the `handover.md` content, the GitHub link to the phase branch/commits, and your own notes on how the tool actually behaves/feels to use.
- Makes the call on git operations (push, merge to main) — I'll tell you when I think a phase is ready, you pull the trigger.

**Coding agent — the implementer**
- Works task-by-task within a phase, per the prompt.
- Commits per task (not one giant phase commit — see below).
- Writes `handover.md` at the end of the phase.
- Does not start the next phase unprompted.

---

## Git workflow

**Branching**
- `main` — always stable, always what a stranger cloning the repo would run.
- One branch per phase: `phase0-safety-integrity`, `phase1-auth-proxy`, etc. (matches `job-plan.md` phase names).
- Agent works on the phase branch, never directly on `main`.

**Commit schedule**
- **One commit per task**, not per phase. E.g. for Phase 0: separate commits for 0.1 (SSRF crawler wiring), 0.2 (SSRF in checks), 0.3 (safe_mode), 0.4 (redaction), 0.5 (misconfig gating). This makes review and rollback sane — if 0.4 has a problem, we don't have to reject 0.1–0.3 with it.
- Commit message format: `phase<N>(<task-id>): <short description>` — e.g. `phase0(0.1): wire SSRF blocklist checks into crawler.fetch()`.
- **Push after every task-level commit**, not just at the end of the phase. This means I can review incrementally on GitHub as you go, instead of only at the very end — catch problems earlier.
- `handover.md` and `agent-prompt.md` are gitignored — they're working documents between the agent, you, and me, not part of the published repo. The agent should still write/update `handover.md` at the end of a phase, just don't expect (or need) it to show up in `git status` as trackable — it's local-only.

**Merging to main**
- Only after: (a) I've reviewed the diffs + `handover.md`, (b) you've clean-room tested it, (c) I've given an explicit go-ahead.
- Merge (not squash) so the task-level commit history survives on `main` — useful later if we need to bisect a regression.
- After merge, update `job-plan.md`: check off the phase, note the merge commit SHA.

---

## Testing — two-repo setup

This is the part that matters most for catching "works on the agent's machine" problems, especially since this is a security tool people may actually run against real targets.

**Repo A — working copy** (`~/Downloads/Maverick/code/Web-Scanner`)
- This is what the coding agent edits directly. Has uncommitted work-in-progress at times. Not what gets tested for "does this actually work for a fresh user."

**Repo B — clean-room test clone** (new, e.g. `~/projects/web-scanner-verify`)
- A **separate `git clone`** of the GitHub repo, pulling the phase branch after it's pushed.
- Every phase, after the agent pushes: `cd ~/projects/web-scanner-verify && git fetch && git checkout phase0-safety-integrity && git pull`.
- Fresh virtualenv each time (`python -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt`) — this is what catches "the agent used a package that isn't in requirements.txt" or "it only works because of leftover state in the working copy."
- Run the CLI here, not in Repo A, for anything you're reporting back to me as "I tested X and it works/doesn't."

**What to actually test against**
- For general crawl/passive checks: `http://testphp.vulnweb.com` — a site explicitly put up for security testing practice, safe to point active scanners at.
- For SSRF-specific verification (Phase 0's main point): you don't need a real internal target — spin up a trivial local Flask/HTTP server on `127.0.0.1` that returns a redirect, or just point a config directly at `http://127.0.0.1:PORT` / `http://169.254.169.254/` and confirm the scanner refuses to fetch it and logs why, rather than actually reaching anything sensitive.
- For anything needing a genuinely vulnerable app (later phases — SQLi/XSS depth, access control checks): a local **DVWA** or **OWASP Juice Shop** Docker container, never a live third-party target.
- Never point active checks at anything you don't own/have written permission for — same rule as always.

---

## Review cadence (the phase gate)

1. Agent finishes a phase → pushes final task-level commits (code only — `handover.md` stays local, it's gitignored) → tells you it's done.
2. You bring me: the `handover.md` content (paste or upload), and the GitHub branch/commit link.
3. I `web_fetch` the actual commits/diffs on GitHub and cross-check against the phase's acceptance criteria in `job-plan.md` — I'm reading real code, not just taking the handover doc's word for it.
4. In parallel, you run the clean-room test (Repo B) and tell me what you saw — both "did the acceptance checks pass" and any UX/behavior observations (weird output, confusing CLI messages, something that felt off even if technically "correct").
5. I give one of: **pass** (merge to main, update job-plan.md, move to next phase prompt) / **needs fixes** (I write a targeted follow-up prompt for just the broken task(s), same phase branch, new commits) / **plan needs adjusting** (something in job-plan.md itself turns out wrong once we see real code — we update the plan together before continuing).
6. We don't start the next phase's agent prompt until step 5 lands on "pass."

---

## Your feedback loop specifically

Two different kinds of feedback are useful from you, and it helps if you label which one you're giving:
- **Correctness feedback** — "the acceptance check for 0.1 doesn't actually hold, here's what I saw" → I treat this as a phase-gate blocker.
- **Product/UX feedback** — "this works but the CLI output is confusing" or "I wish it also did X" → I log this into `job-plan.md` as a new backlog item in the right phase (or a new Phase 6 if it doesn't fit anywhere) rather than silently expanding the current phase's scope.

---

## House-keeping

- `handover.md` and `agent-prompt.md` are gitignored (not committed) — decided instead of archiving per phase. `agent-prompt.md` gets its content replaced each phase with the new phase's prompt; `handover.md` gets overwritten with each new phase's notes. Neither has permanent history in git — if you personally want to keep a local record of past phases, that's on you to save copies outside the repo, but it's not part of the project's tracked history (reasonable, since `job-plan.md` and these working docs also shouldn't be visible on a public security-tool repo — no reason to publish a roadmap of what wasn't hardened yet).
- Keep `job-plan.md`'s status checklist as the single place phase progress is tracked — don't let progress notes drift into other files.
- If the coding agent hits something ambiguous mid-task, better it stops and flags it in `handover.md`'s "Open questions" section than guesses silently — we resolve it at the phase gate rather than downstream.

---

## Status

- [ ] Phase 0 in progress — awaiting `handover.md` + clean-room test results