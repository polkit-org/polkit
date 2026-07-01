# AGENTS.md

This file provides context for AI agents working with the polkit codebase.

## Authorship

When AI tools, LLMs, or other automated tooling contribute to submitted content (code, commits, issues, or pull request descriptions), their involvement **must be disclosed**. Include a brief note in the commit message or PR description stating which tool was used and the extent of its contribution.

All AI-generated content **must be reviewed by a human** before submission. The human submitter bears full responsibility for the correctness, quality, and licensing compliance of any such content.

See also: the [AI-Assisted Contributions](README.md#ai-assisted-contributions) section in `README.md`.

## Documentation

Read these files before making changes:

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — Project architecture: daemon, client library, agent library, D-Bus integration, GLib/GObject patterns, systemd integration, meson build system, and directory layout.
- [docs/CODING_STYLE.md](docs/CODING_STYLE.md) — Formatting rules, naming conventions, header guards, error handling patterns, brace style, and gtk-doc documentation format.
- [docs/TESTING.md](docs/TESTING.md) — Unit test pipeline: GLib testing framework, wrapper.py harness (namespace isolation + dbusmock), test data fixtures, and how to run tests.

## Key Rules

- C99, 2-space indentation, no tabs, max 109 characters per line
- GNU/GLib brace style: function braces on next line, control-flow braces on next line indented under the statement
- All public API uses GObject conventions with `polkit_` prefix
- Every public function must have gtk-doc documentation
- Error handling uses `GError**` with `goto out` cleanup pattern
- Build with Meson; test with `meson test -C builddir` (requires `-Dtests=true`)

## Existing Guidelines

- [docs/HACKING.md](docs/HACKING.md) — SCM workflow, commit message format, contribution process.
