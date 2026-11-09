# Post-release triage

How bug reports are handled after a release. The goal is to answer quickly and never ask a user
to send their vault, passphrase, recovery code, note text, or file names.

## Intake

- Reports come in through the GitHub issue tracker. Use the **bug** label for defects and
  **security** for anything that could expose data.
- A security report is not discussed in a public issue. Ask the reporter to contact the
  maintainer privately and mark the issue as a security report without details.

## What to ask for

Ask only for this, and say what it is for:

- The app version, the operating system and its version.
- For a mount problem: whether WinFsp (Windows) or FUSE 3 (Linux) is installed.
- The steps taken, and what was expected and what happened.
- The message text shown in the app, copied as written. Leave out any folder or file names in it.

Do not ask for the vault folder, the `vault.conf` file, a passphrase, or a recovery code.

## Labels and priority

| Priority | Meaning | Target |
|----------|---------|--------|
| P0 | Data loss, data exposure, or a vault that cannot be unlocked | Patch release as soon as possible |
| P1 | Mount failure or crash on a supported platform | Next patch release |
| P2 | Wrong behaviour with a workaround | Next minor release |
| P3 | Polish, wording, requests | Backlog |

Reproduce each P0 and P1 report before fixing it. Add a regression test in `core/tests/` or
`tests/frontend/` where the bug can be reached without a real drive or desktop.

## Closing

- Close with the release in which the fix ships, and link the changelog entry.
- If a report is not reproducible after two requests for more detail, close it with a note that
  it can be reopened.
