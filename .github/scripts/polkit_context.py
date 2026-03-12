"""Curated polkit project context and Gemini prompt templates."""

POLKIT_SUMMARY = """\
polkit (formerly PolicyKit) is an application-level toolkit for defining and \
handling authorization policies in Linux. It allows unprivileged processes to \
communicate with privileged ones via a structured authorization framework. \
polkit is used across most major Linux desktop and server distributions. \
The main repository is https://github.com/polkit-org/polkit.

Architecture overview:
- polkitd (src/polkitbackend/polkitd.c): the system-wide authorization daemon. \
  Runs as D-Bus system service org.freedesktop.PolicyKit1. Loads JavaScript \
  authorization rules from /usr/share/polkit-1/rules.d/ and /etc/polkit-1/rules.d/ \
  via an embedded Duktape JS engine. Communicates with session monitors \
  (systemd-logind, elogind, or ConsoleKit) to track active user sessions.
- libpolkit-gobject-1 (src/polkit/): core GObject library defining data types \
  for authorities, subjects (PolkitUnixProcess, PolkitUnixSession, \
  PolkitSystemBusName), identities, actions, and authorization results.
- libpolkit-agent-1 (src/polkitagent/): authentication agent library. \
  PolkitAgentSession manages the authentication dialogue by communicating with \
  polkit-agent-helper-1, either by forking it (legacy SETUID mode) or via a \
  systemd socket-activated AF_UNIX service.
- polkit-agent-helper-1 (src/polkitagent/polkitagenthelper-pam.c, -shadow.c, \
  -bsdauth.c): a privileged helper that performs PAM/shadow/BSD authentication \
  on behalf of the agent session.
- pkexec (src/programs/pkexec.c): run a command as another user, governed by \
  polkit policy.
- pkcheck (src/programs/pkcheck.c): check whether a process is authorized for \
  an action.
- pkttyagent (src/programs/pkttyagent.c): textual authentication agent for \
  terminal sessions.

Build system: Meson (>=1.4.0). Key build options include session_tracking \
(logind/elogind/ConsoleKit), authfw (pam/shadow/bsdauth), and tests/examples toggles.

Source layout:
  src/polkit/         - core library (subjects, identity, authority, permissions)
  src/polkitagent/    - agent library + PAM/shadow/BSD helpers
  src/polkitbackend/  - polkitd daemon, Duktape JS engine, session monitors
  src/programs/       - pkexec, pkcheck, pkaction, pkttyagent
  actions/            - default .policy XML action definitions
  data/               - systemd units, D-Bus configs, tmpfiles
  test/               - unit tests (wrapper.py) and integration tests (systemd-nspawn)

Common issue categories:
  - Authentication failures (PAM misconfiguration, agent not registering)
  - Authorization policy bugs (wrong allow/deny, implicit vs. explicit auth)
  - pkexec behavior (PATH handling, SETUID, environment sanitization)
  - Session tracking issues (logind seat/session detection, race conditions)
  - Memory leaks and crashes (GObject reference counting, D-Bus lifecycle)
  - Build/packaging issues (Meson options, cross-compilation, distro integration)
  - CI/CD infrastructure (GitHub Actions, Coverity, CodeQL)
"""

PROMPT_ASSESS = """\
You are a senior software engineer triaging issues for the polkit project.

PROJECT CONTEXT:
{polkit_summary}

ISSUE TITLE: {issue_title}

ISSUE BODY:
{issue_body}

Analyze this issue and classify it. Respond with ONLY a JSON object (no markdown \
fencing, no extra text) with these fields:
- "type": one of "bug", "feature_request", "ci_cd", "question", "invalid"
- "confidence": a float between 0.0 and 1.0
- "summary": a one-sentence summary of the issue in your own words
- "missing_info": a list of strings describing critical information that the \
  reporter did not provide but that is needed to act on this issue. For bugs, \
  check for: OS/distro version, polkit version, desktop environment, \
  reproduction steps, log output (journalctl -u polkit.service). For feature \
  requests, check for: use case, desired behavior, alternatives considered. \
  Return an empty list if nothing critical is missing.
- "affected_components": a list of polkit components likely involved, chosen \
  from: "polkitd", "pkexec", "pkcheck", "pkttyagent", "polkit-agent-helper", \
  "libpolkit-gobject", "libpolkit-agent", "pam", "duktape", "rules", \
  "session-monitor", "build-system", "ci-cd", "documentation"
"""

PROMPT_LABEL = """\
You are assigning GitHub labels to a polkit issue based on a prior assessment.

AVAILABLE LABELS IN THIS REPOSITORY:
{available_labels}

ASSESSMENT:
{assessment_json}

Select the most appropriate labels from the available list above. If the \
assessment type is "bug", include "bug". If "feature_request", include \
"enhancement". If "ci_cd", include "ci/cd". If "question", include "question". \
Also add component labels if relevant (e.g. "pkexec", "polkitd", "pam").

If labels you want to apply do not exist in the available list, do NOT invent \
them -- pick the closest available match or omit.

Respond with ONLY a JSON object (no markdown fencing):
- "labels": a list of label strings to apply
- "reasoning": a one-sentence explanation
"""

PROMPT_ELICIT = """\
You are a polite, knowledgeable polkit maintainer responding to a GitHub issue \
where critical information is missing.

ISSUE TITLE: {issue_title}

ISSUE BODY:
{issue_body}

THE FOLLOWING INFORMATION IS MISSING:
{missing_info}

Write a brief, friendly GitHub comment that:
1. Thanks the reporter for filing the issue
2. Explains why each piece of missing information is needed
3. Provides specific instructions on how to obtain it (e.g., exact commands \
   like `journalctl -u polkit.service`, `pkaction --version`, `cat /etc/os-release`)
4. Ends with encouragement

Respond with ONLY the comment text in Markdown format (no JSON wrapping).
"""

PROMPT_DESIGN_REPRODUCER = """\
You are a senior C/systems engineer designing a minimal reproducer for a polkit bug.

PROJECT CONTEXT:
{polkit_summary}

ISSUE TITLE: {issue_title}

ISSUE BODY:
{issue_body}

ASSESSMENT:
{assessment_json}

Design the SIMPLEST possible reproducer script. Prefer a shell script using \
existing polkit CLI tools (pkexec, pkcheck, pkaction, pkttyagent, \
busctl/gdbus/dbus-send). Only write C code if the bug cannot be triggered via \
CLI tools. The reproducer must be fully self-contained and exit with code 0 \
if the bug is reproduced, or non-zero if not.

Respond with ONLY a JSON object (no markdown fencing):
- "reproducer_script": the full reproducer script as a string (use \\n for newlines)
- "script_filename": filename, e.g. "reproducer.sh" or "reproducer.c"
- "base_image": Docker base image appropriate for the reporter's environment. \
  Use "fedora:latest" if unknown. Examples: "ubuntu:22.04", "debian:bookworm", \
  "fedora:39", "alpine:latest".
- "extra_packages": list of additional distro packages needed beyond polkit \
  build deps (e.g. ["expect", "python3"])
- "explanation": brief explanation of what the reproducer does and why it \
  triggers the bug
"""

PROMPT_DESIGN_SOLUTION = """\
You are a senior C/systems engineer proposing a solution for a polkit feature request.

PROJECT CONTEXT:
{polkit_summary}

ISSUE TITLE: {issue_title}

ISSUE BODY:
{issue_body}

ASSESSMENT:
{assessment_json}

Propose a practical, minimal implementation approach. Identify which source \
files would need changes, describe the approach, and provide a rough sketch \
(pseudocode or partial diff) of the key changes. Consider backward compatibility, \
security implications, and the existing polkit architecture.

Respond with ONLY a JSON object (no markdown fencing):
- "approach": multi-paragraph description of the proposed solution
- "affected_files": list of file paths relative to repo root
- "complexity": one of "trivial", "moderate", "significant", "major"
- "security_considerations": list of security concerns to review
- "sketch": a rough diff or pseudocode of the core change
"""

PROMPT_VALIDATE_DOCKERFILE = """\
Generate a Dockerfile that:
1. Starts FROM {base_image}
2. Installs packages needed to build polkit from source for this distro. \
   polkit build-requires: meson (>=1.4.0), ninja, gcc, glib2-devel, \
   gobject-introspection-devel, expat-devel, pam-devel, duktape-devel, \
   systemd-devel, dbus-devel, gettext. Adjust package names for the distro.
3. Installs these additional packages: {extra_packages}
4. Copies the polkit source tree into /polkit
5. Builds polkit: cd /polkit && meson setup builddir && ninja -C builddir
6. Copies the reproducer script to /reproducer/{script_filename}
7. Makes the reproducer executable
8. Sets the CMD to run the reproducer

Respond with ONLY the Dockerfile contents as plain text (no markdown fencing, \
no JSON wrapping). Use a single RUN command where possible to minimize layers.
"""
