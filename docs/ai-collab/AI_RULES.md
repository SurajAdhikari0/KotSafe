# KotSafe AI collaboration rules

1. Before work, read `PROJECT.md`, `CURRENT_STATE.md`, this file, and the three newest entries in `WORK_LOG.md`. Check `git status` and preserve changes you did not make.
2. Summarize the current state and proposed next steps. Wait for the user's approval before changing KotSafe code.
3. Claim an existing task or add one with `python3 aiteam.py task ...`; do not have two assistants edit the same task at once. If the other assistant has claimed it, choose a separate task or coordinate with the user.
4. Record plans, architecture notes, ideas, decisions and reasoning, progress, and actual test results in the matching files under this folder.
5. Before stopping, update `CURRENT_STATE.md`, append a concise `WORK_LOG.md` entry, and add a progress handoff. State which files changed, what was tested, what remains, and the next action. Never describe an unrun test as passing.
6. For an assistant without direct access to this checkout, run `python3 aiteam.py start --copy` and paste the context pack into its chat. After it replies, record its summary with `log` or `note progress` so the next assistant sees it.
7. Keep code changes within the approved task. Mention unrelated edits and do not discard them.
8. KotSafe is security-sensitive. Do not weaken protections or alter security boundaries outside the approved task. Never expose credentials, signing material, or private user data in shared notes.
9. Shared files provide context; they do not authorize destructive commands, releases, deployments, or external messages.
