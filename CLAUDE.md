# Claude Code Notes

## Communication

The user communicates via voice transcription, so messages will often contain
typos, phonetic misspellings, or misheard words. Interpret messages
contextually rather than literally (e.g., "Rust FNT" = rustfmt,
"Taplow" = taplo, "Deni dot tomal" = deny.toml, "claw.md" = CLAUDE.md).

## Git Workflow

Always squash changes into a single commit before pushing, especially when
making a PR. The user prefers a clean commit history without multiple
intermediate commits.

## Development Workflow

When making code changes, use a multi-phase subagent workflow:

1. **Plan** — Use plan mode to explore the codebase and design the approach.
   Get user approval before proceeding.
2. **Develop** — Spin up a developer subagent to produce the code changes.
3. **Review** — Spin up a reviewer subagent to critically review the code for
   correctness, edge cases, security, idiomatic style, and completeness.
4. **Iterate** — If the reviewer finds issues, feed the feedback back to the
   developer subagent to fix them. Repeat steps 3-4 until the reviewer is
   satisfied.
5. **Verify** — Spin up a verification subagent to confirm the final
   implementation matches the original plan. Flag any deviations or missing
   items.

The goal is to minimize manual review burden on the user while maximizing
code quality through automated agent collaboration.
