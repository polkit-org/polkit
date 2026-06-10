#!/usr/bin/env python3
"""AI-powered issue triage for the polkit project using Gemini."""

import argparse
import base64
import json
import logging
import os
import subprocess
import sys
import tempfile
import textwrap
import time
from dataclasses import dataclass, field
import re
import requests

from polkit_context import (
    POLKIT_SUMMARY,
    PROMPT_ASSESS,
    PROMPT_DESIGN_REPRODUCER,
    PROMPT_DESIGN_SOLUTION,
    PROMPT_ELICIT,
    PROMPT_LABEL,
    PROMPT_SELECT_ENVIRONMENT,
    PROMPT_VALIDATE_DOCKERFILE,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("ai_issue_triage")

GEMINI_API_BASE = "https://generativelanguage.googleapis.com/v1beta/models"
DOCKER_TIMEOUT_SECONDS = 300
DOCKER_MEMORY_LIMIT = "512m"
MAX_COMMENT_LENGTH = 65536

# Agentic reproducer constants
AGENT_CONTAINER_IMAGE = {
    "fedora": "ghcr.io/polkit-org/polkit-ai-reproducer-tools:fedora",
    "ubuntu": "ghcr.io/polkit-org/polkit-ai-reproducer-tools:ubuntu",
}
SKILLS_REPO = "https://github.com/polkit-org/polkit-ai-reproducer-tools.git"
POLKIT_SOURCE_REPO = "https://github.com/vmihalko/polkit.git"
AGENT_TIMEOUT_SECONDS = 900

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
SKILLS_REPO_TOKEN = os.environ.get("SKILLS_REPO_TOKEN")

_TRIAGE_MARKER = "Issue triaged by AI assistant"
_TRIAGE_MARKER_BOT = "github-actions[bot]"


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


_FENCE_RE = re.compile(r"```[^\n]*\n(.*?)```", re.DOTALL)

def _stripc_fences(text: str) -> str:
    m = _FENCE_RE.search(text.strip())
    return m.group(1).strip() if m else text.strip()


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class AssessmentResult:
    type: str = "unknown"
    confidence: float = 0.0
    summary: str = ""
    missing_info: list[str] = field(default_factory=list)
    affected_components: list[str] = field(default_factory=list)


@dataclass
class ReproducerDesign:
    reproducer_script: str = ""
    script_filename: str = "reproducer.sh"
    base_image: str = "fedora:latest"
    extra_packages: list[str] = field(default_factory=list)
    explanation: str = ""


@dataclass
class SolutionDesign:
    approach: str = ""
    affected_files: list[str] = field(default_factory=list)
    complexity: str = "unknown"
    security_considerations: list[str] = field(default_factory=list)
    sketch: str = ""


@dataclass
class DesignResult:
    kind: str = ""  # "reproducer" or "solution"
    reproducer: ReproducerDesign | None = None
    solution: SolutionDesign | None = None


@dataclass
class ValidationResult:
    exit_code: int = -1
    stdout: str = ""
    stderr: str = ""
    success: bool = False
    dockerfile: str = ""


@dataclass
class AgentResult:
    success: bool = False
    reproducer_script: str = ""
    prepare_env_script: str = ""
    reproducer_human: str = ""
    result_json: dict = field(default_factory=dict)
    agent_output: str = ""
    distro: str = "fedora"


# ---------------------------------------------------------------------------
# Gemini REST API client
# ---------------------------------------------------------------------------

class GeminiClient:
    """Thin wrapper around the Gemini REST API with retry logic."""

    def __init__(self, api_key: str, model: str = "gemini-2.5-pro"):
        self.api_key = api_key
        self.model = model
        self._session = requests.Session()

    def generate(self, prompt: str, system_instruction: str | None = None) -> str:
        url = f"{GEMINI_API_BASE}/{self.model}:generateContent"
        body: dict = {
            "contents": [{"parts": [{"text": prompt}]}],
        }
        if system_instruction:
            body["system_instruction"] = {
                "parts": [{"text": system_instruction}]
            }
        body["generationConfig"] = {
            "temperature": 0.2,
            "maxOutputTokens": 16384,
        }

        last_err: Exception | None = None
        for attempt in range(3):
            try:
                resp = self._session.post(
                    url,
                    headers={"x-goog-api-key": self.api_key},
                    json=body,
                    timeout=120,
                )
                if resp.status_code in (429, 503):
                    wait = 2 ** (attempt + 1)
                    log.warning("Gemini %d, retrying in %ds", resp.status_code, wait)
                    time.sleep(wait)
                    continue
                resp.raise_for_status()
                data = resp.json()
                text = data["candidates"][0]["content"]["parts"][0]["text"]
                log.debug("Gemini response (%d chars):\n%s", len(text), text)
                return text
            except Exception as exc:
                last_err = exc
                if attempt < 2:
                    time.sleep(2 ** attempt)

        raise RuntimeError(
            f"Gemini API failed after 3 attempts: {last_err}"
        ) from last_err


# ---------------------------------------------------------------------------
# GitHub API client
# ---------------------------------------------------------------------------

class GitHubClient:
    """Thin wrapper around the GitHub REST API for issue operations."""

    def __init__(self, token: str, repo: str):
        self.repo = repo
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        })
        self._base = f"https://api.github.com/repos/{repo}"

    def get_issue(self, number: int) -> dict:
        resp = self._session.get(f"{self._base}/issues/{number}", timeout=30)
        resp.raise_for_status()
        return resp.json()

    def get_issue_comments(self, number: int) -> list[dict]:
        resp = self._session.get(f"{self._base}/issues/{number}/comments", timeout=30)
        resp.raise_for_status()
        return resp.json()

    def add_labels(self, number: int, labels: list[str]) -> None:
        if not labels:
            return
        resp = self._session.post(
            f"{self._base}/issues/{number}/labels",
            json={"labels": labels},
            timeout=30,
        )
        resp.raise_for_status()
        log.info("Applied labels %s to issue #%d", labels, number)

    def post_comment(self, number: int, body: str) -> None:
        body = body[:MAX_COMMENT_LENGTH]
        # Strip @ mentions to avoid notifying users (especially on fork mirrors)
        body = re.sub(r'@([a-zA-Z0-9_-]+)', r'`\1`', body)
        resp = self._session.post(
            f"{self._base}/issues/{number}/comments",
            json={"body": body},
            timeout=30,
        )
        resp.raise_for_status()
        log.info("Posted comment on issue #%d", number)

    def get_labels(self) -> list[str]:
        labels: list[str] = []
        page = 1
        while True:
            resp = self._session.get(
                f"{self._base}/labels",
                params={"per_page": 100, "page": page},
                timeout=30,
            )
            resp.raise_for_status()
            batch = resp.json()
            if not batch:
                break
            labels.extend(item["name"] for item in batch)
            page += 1
        return labels


# ---------------------------------------------------------------------------
# JSON parsing helpers
# ---------------------------------------------------------------------------

def _fix_json_escapes(text: str) -> str:
    """Fix invalid JSON escape sequences without breaking already-valid ones.

    Walks the string character-by-character so that already-escaped
    backslashes (``\\\\``) are consumed as pairs and left intact, while
    truly invalid escapes like ``\\$`` or ``\\x`` get an extra backslash.
    """
    _VALID_AFTER_BS = set('"\\/bfnrtu')
    out: list[str] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == '\\' and i + 1 < len(text):
            nxt = text[i + 1]
            if nxt in _VALID_AFTER_BS:
                out.append(text[i:i + 2])
                i += 2
                if nxt == 'u' and i + 4 <= len(text):
                    out.append(text[i:i + 4])
                    i += 4
            else:
                # Invalid escape — double the backslash, leave next char
                out.append('\\\\')
                i += 1
        else:
            out.append(ch)
            i += 1
    return ''.join(out)

def _parse_json_response(text: str) -> dict:
    """Extract a JSON object from Gemini's response, tolerating markdown fences."""
    text = _stripc_fences(text)
    # Fallback: if text doesn't look like JSON, extract the first JSON object
    if text and not text.startswith(('{', '[')):
        start = text.find('{')
        end = text.rfind('}')
        if start != -1 and end != -1:
            text = text[start:end + 1]
    # Gemini sometimes emits invalid JSON escapes (e.g. \$, \x03) inside strings.
    text = _fix_json_escapes(text)
    return json.loads(text)


def _safe_parse_json(text: str, context: str) -> dict | None:
    try:
        return _parse_json_response(text)
    except (json.JSONDecodeError, ValueError, IndexError) as exc:
        log.error("Failed to parse Gemini JSON for %s: %s\nRaw: %s", context, exc, text[:500])
        return None


# ---------------------------------------------------------------------------
# Feature 1: Assess
# ---------------------------------------------------------------------------

def assess(gemini: GeminiClient, issue: dict) -> AssessmentResult | None:
    log.info("Assessing issue #%s: %s", issue["number"], issue["title"])
    prompt = PROMPT_ASSESS.format(
        issue_title=issue["title"],
        issue_body=issue.get("body", "") or "",
    )
    raw = gemini.generate(prompt, system_instruction=POLKIT_SUMMARY)
    data = _safe_parse_json(raw, "assess")
    if data is None:
        return None

    valid_types = {"bug", "feature_request", "ci_cd", "question", "invalid"}
    issue_type = data.get("type", "unknown")
    if issue_type not in valid_types:
        log.warning("Gemini returned unknown type '%s', defaulting to 'unknown'", issue_type)
        issue_type = "unknown"

    return AssessmentResult(
        type=issue_type,
        confidence=float(data.get("confidence", 0.0)),
        summary=data.get("summary", ""),
        missing_info=data.get("missing_info", []),
        affected_components=data.get("affected_components", []),
    )


# ---------------------------------------------------------------------------
# Feature 2: Label
# ---------------------------------------------------------------------------

def label(
    gemini: GeminiClient,
    github: GitHubClient,
    issue: dict,
    assessment: AssessmentResult,
) -> list[str]:
    log.info("Labeling issue #%s", issue["number"])
    available = github.get_labels()
    if not available:
        log.warning("No labels found in repo, skipping labeling")
        return []

    prompt = PROMPT_LABEL.format(
        available_labels=json.dumps(available),
        assessment_json=json.dumps({
            "type": assessment.type,
            "confidence": assessment.confidence,
            "summary": assessment.summary,
            "affected_components": assessment.affected_components,
        }, indent=2),
    )
    raw = gemini.generate(prompt, system_instruction=POLKIT_SUMMARY)
    data = _safe_parse_json(raw, "label")
    if data is None:
        return []

    suggested = data.get("labels", [])
    available_set = set(available)
    validated = [lbl for lbl in suggested if lbl in available_set]
    rejected = [lbl for lbl in suggested if lbl not in available_set]
    if rejected:
        log.warning("Rejected non-existent labels: %s", rejected)

    github.add_labels(issue["number"], validated)
    return validated


# ---------------------------------------------------------------------------
# Feature 3: Elicit
# ---------------------------------------------------------------------------

def elicit(
    gemini: GeminiClient,
    github: GitHubClient,
    issue: dict,
    assessment: AssessmentResult,
) -> str | None:
    if not assessment.missing_info:
        log.info("No missing info for issue #%s, skipping elicitation", issue["number"])
        return None

    log.info("Requesting missing info for issue #%s: %s", issue["number"], assessment.missing_info)
    prompt = PROMPT_ELICIT.format(
        issue_title=issue["title"],
        issue_body=issue.get("body", "") or "",
        missing_info="\n".join(f"- {item}" for item in assessment.missing_info),
    )
    comment_text = gemini.generate(prompt, system_instruction=POLKIT_SUMMARY)
    github.post_comment(issue["number"], comment_text)
    return comment_text


# ---------------------------------------------------------------------------
# Feature 4: Design
# ---------------------------------------------------------------------------

def design_reproducer(
    gemini: GeminiClient,
    issue: dict,
    assessment: AssessmentResult,
) -> ReproducerDesign | None:
    log.info("Designing reproducer for issue #%s", issue["number"])
    prompt = PROMPT_DESIGN_REPRODUCER.format(
        issue_title=issue["title"],
        issue_body=issue.get("body", "") or "",
        assessment_json=json.dumps({
            "type": assessment.type,
            "summary": assessment.summary,
            "affected_components": assessment.affected_components,
        }, indent=2),
    )
    raw = gemini.generate(prompt, system_instruction=POLKIT_SUMMARY)
    data = _safe_parse_json(raw, "design_reproducer")
    if data is None:
        return None

    return ReproducerDesign(
        reproducer_script=data.get("reproducer_script", ""),
        script_filename=data.get("script_filename", "reproducer.sh"),
        base_image=data.get("base_image", "fedora:latest"),
        extra_packages=data.get("extra_packages", []),
        explanation=data.get("explanation", ""),
    )


def design_solution(
    gemini: GeminiClient,
    issue: dict,
    assessment: AssessmentResult,
) -> SolutionDesign | None:
    log.info("Designing solution for issue #%s", issue["number"])
    prompt = PROMPT_DESIGN_SOLUTION.format(
        issue_title=issue["title"],
        issue_body=issue.get("body", "") or "",
        assessment_json=json.dumps({
            "type": assessment.type,
            "summary": assessment.summary,
            "affected_components": assessment.affected_components,
        }, indent=2),
    )
    raw = gemini.generate(prompt, system_instruction=POLKIT_SUMMARY)
    data = _safe_parse_json(raw, "design_solution")
    if data is None:
        return None

    return SolutionDesign(
        approach=data.get("approach", ""),
        affected_files=data.get("affected_files", []),
        complexity=data.get("complexity", "unknown"),
        security_considerations=data.get("security_considerations", []),
        sketch=data.get("sketch", ""),
    )


def design(
    gemini: GeminiClient,
    issue: dict,
    assessment: AssessmentResult,
) -> DesignResult | None:
    if assessment.type == "bug":
        repro = design_reproducer(gemini, issue, assessment)
        if repro:
            return DesignResult(kind="reproducer", reproducer=repro)
    elif assessment.type == "feature_request":
        sol = design_solution(gemini, issue, assessment)
        if sol:
            return DesignResult(kind="solution", solution=sol)
    else:
        log.info(
            "Issue type '%s' is not a bug or feature request, skipping design",
            assessment.type,
        )
    return None


# ---------------------------------------------------------------------------
# Feature 5: Validate
# ---------------------------------------------------------------------------

def validate(
    gemini: GeminiClient,
    github: GitHubClient,
    issue: dict,
    design_result: DesignResult,
) -> ValidationResult | None:
    if design_result.kind != "reproducer" or design_result.reproducer is None:
        log.info("No reproducer to validate for issue #%s", issue["number"])
        return None

    repro = design_result.reproducer
    log.info("Validating reproducer for issue #%s in Docker", issue["number"])

    dockerfile_prompt = PROMPT_VALIDATE_DOCKERFILE.format(
        base_image=repro.base_image,
        script_filename=repro.script_filename,
        reproducer_script=repro.reproducer_script,
    )
    dockerfile_content = gemini.generate(
        dockerfile_prompt, system_instruction=POLKIT_SUMMARY
    )
    dockerfile_content = _stripc_fences(dockerfile_content)

    result = ValidationResult(dockerfile=dockerfile_content)

    with tempfile.TemporaryDirectory(prefix="polkit-validate-") as tmpdir:
        dockerfile_path = os.path.join(tmpdir, "Dockerfile")
        reproducer_path = os.path.join(tmpdir, repro.script_filename)

        with open(dockerfile_path, "w") as f:
            f.write(dockerfile_content)

        with open(reproducer_path, "w") as f:
            f.write(repro.reproducer_script)
        os.chmod(reproducer_path, 0o755)

        tag = f"polkit-validate-{issue['number']}"
        container_name = f"polkit-test-{issue['number']}"

        try:
            build_proc = subprocess.run(
                [
                    "docker", "build",
                    "-t", tag,
                    "-f", dockerfile_path,
                    tmpdir,
                ],
                capture_output=True,
                text=True,
                timeout=DOCKER_TIMEOUT_SECONDS,
            )
            if build_proc.returncode != 0:
                log.error("Docker build failed:\n%s", build_proc.stderr[-2000:])
                result.stderr = build_proc.stderr[-2000:]
                result.exit_code = build_proc.returncode
                return result

            # Start container with systemd as PID 1
            start_proc = subprocess.run(
                [
                    "docker", "run", "-d",
                    "--privileged",
                    "--cgroupns=host",
                    "-v", "/sys/fs/cgroup:/sys/fs/cgroup:rw",
                    f"--name={container_name}",
                    f"--memory={DOCKER_MEMORY_LIMIT}",
                    "--entrypoint", "/sbin/init",
                    tag,
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if start_proc.returncode != 0:
                log.error("Docker start failed:\n%s", start_proc.stderr[-2000:])
                result.stderr = start_proc.stderr[-2000:]
                result.exit_code = start_proc.returncode
                return result

            # Wait for systemd to finish booting
            log.info("Waiting for systemd to boot in container...")
            for _ in range(15):
                boot_check = subprocess.run(
                    ["docker", "exec", container_name,
                     "systemctl", "is-system-running"],
                    capture_output=True, text=True, timeout=10,
                )
                state = boot_check.stdout.strip()
                log.info("systemd state: %s", state)
                if state in ("running", "degraded"):
                    break
                time.sleep(2)
            else:
                log.warning("systemd did not reach running state")

            # Run the reproducer as testuser (-t for TTY, needed by pkttyagent)
            run_proc = subprocess.run(
                [
                    "docker", "exec", "-t", container_name,
                    "runuser", "-u", "testuser", "--",
                    f"/reproducer/{repro.script_filename}",
                ],
                capture_output=True,
                text=True,
                timeout=DOCKER_TIMEOUT_SECONDS,
            )
            result.exit_code = run_proc.returncode
            result.stdout = run_proc.stdout[-4000:]
            result.stderr = run_proc.stderr[-4000:]
            result.success = run_proc.returncode == 0

        except subprocess.TimeoutExpired:
            log.error("Docker operation timed out after %ds", DOCKER_TIMEOUT_SECONDS)
            result.stderr = f"Timed out after {DOCKER_TIMEOUT_SECONDS}s"
        except FileNotFoundError:
            log.error("Docker not found -- is it installed on this runner?")
            result.stderr = "Docker not found on runner"
        finally:
            subprocess.run(
                ["docker", "rm", "-f", container_name],
                capture_output=True,
                timeout=30,
            )
            subprocess.run(
                ["docker", "rmi", "-f", tag],
                capture_output=True,
                timeout=30,
            )

    return result


# ---------------------------------------------------------------------------
# Feature 5b: Agentic reproducer (replaces Design+Validate for bugs)
# ---------------------------------------------------------------------------

def select_environment(
    gemini: GeminiClient,
    issue: dict,
    assessment: AssessmentResult,
) -> tuple[str, list[str]]:
    """Use Gemini REST to pick the right container distro and extra packages."""
    log.info("Selecting environment for issue #%s", issue["number"])
    prompt = PROMPT_SELECT_ENVIRONMENT.format(
        assessment_json=json.dumps({
            "type": assessment.type,
            "summary": assessment.summary,
            "affected_components": assessment.affected_components,
        }, indent=2),
        issue_title=issue["title"],
        issue_body=issue.get("body", "") or "",
    )
    raw = gemini.generate(prompt, system_instruction=POLKIT_SUMMARY)
    data = _safe_parse_json(raw, "select_environment")
    if data is None:
        return "fedora", []

    distro = data.get("distro", "fedora")
    if distro not in AGENT_CONTAINER_IMAGE:
        log.warning("Unknown distro '%s', falling back to fedora", distro)
        distro = "fedora"

    extra = data.get("extra_packages", [])
    log.info("Selected environment: %s, extra packages: %s", distro, extra)
    return distro, extra


def _wait_for_systemd(container_name: str, retries: int = 15) -> None:
    """Poll systemctl is-system-running until ready."""
    for i in range(retries):
        try:
            check = subprocess.run(
                ["docker", "exec", container_name,
                 "systemctl", "is-system-running"],
                capture_output=True, text=True, timeout=10,
            )
            state = check.stdout.strip()
            log.info("systemd state: %s (attempt %d/%d)", state, i + 1, retries)
            if state in ("running", "degraded"):
                return
        except subprocess.TimeoutExpired:
            pass
        time.sleep(2)
    log.warning("systemd did not reach running state after %d attempts", retries)


def _create_skill_pr(skills_dir: str, issue_number: int) -> str | None:
    """Open a PR to polkit-ai-reproducer-tools with new skill files the agent discovered."""
    if not SKILLS_REPO_TOKEN:
        log.info("No SKILLS_REPO_TOKEN, skipping skill PR")
        return None

    # Collect skill files
    new_files = []
    for root, _dirs, files in os.walk(skills_dir):
        for fname in files:
            full = os.path.join(root, fname)
            rel = os.path.relpath(full, skills_dir)
            new_files.append((rel, full))

    if not new_files:
        return None

    log.info("Agent produced %d new skill file(s): %s",
             len(new_files), [f[0] for f in new_files])

    with tempfile.TemporaryDirectory(prefix="polkit-skills-pr-") as tmpdir:
        # Clone skills repo (public, no token needed)
        clone_proc = subprocess.run(
            ["git", "clone", "--depth=1", SKILLS_REPO, tmpdir],
            capture_output=True, text=True, timeout=60,
        )
        if clone_proc.returncode != 0:
            log.error("Failed to clone skills repo: %s", clone_proc.stderr[-500:])
            return None

        # Copy new skill files into the clone
        branch = f"agent/issue-{issue_number}-skills"
        subprocess.run(
            ["git", "-C", tmpdir, "checkout", "-b", branch],
            capture_output=True, text=True,
        )
        for rel_path, src_path in new_files:
            dest = os.path.join(tmpdir, "skills", rel_path)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(src_path, "r") as sf, open(dest, "w") as df:
                df.write(sf.read())

        # Commit and push
        subprocess.run(
            ["git", "-C", tmpdir, "add", "skills/"],
            capture_output=True, text=True,
        )
        commit_msg = f"Add skill files discovered while reproducing issue #{issue_number}"
        subprocess.run(
            ["git", "-C", tmpdir,
             "-c", "user.name=polkit-ai-bot",
             "-c", "user.email=noreply@github.com",
             "commit", "-m", commit_msg],
            capture_output=True, text=True,
        )
        auth_header = f"Authorization: Basic {base64.b64encode(f'x-access-token:{SKILLS_REPO_TOKEN}'.encode()).decode()}"
        push_env = {
            **os.environ,
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "http.extraHeader",
            "GIT_CONFIG_VALUE_0": auth_header,
        }
        push_proc = subprocess.run(
            ["git", "-C", tmpdir, "push", "origin", branch],
            capture_output=True, text=True, timeout=30,
            env=push_env,
        )
        if push_proc.returncode != 0:
            log.error("Failed to push skill branch: %s", push_proc.stderr[-500:])
            return None

        # Open PR via GitHub API
        pr_body = (
            f"New skill files discovered by the AI agent while "
            f"reproducing polkit issue #{issue_number}.\n\n"
            f"Files:\n" +
            "\n".join(f"- `skills/{rel}`" for rel, _ in new_files)
        )
        pr_resp = requests.post(
            "https://api.github.com/repos/polkit-org/polkit-ai-reproducer-tools/pulls",
            headers={
                "Authorization": f"Bearer {SKILLS_REPO_TOKEN}",
                "Accept": "application/vnd.github+json",
            },
            json={
                "title": f"Skills from issue #{issue_number}",
                "head": branch,
                "base": "main",
                "body": pr_body,
            },
            timeout=30,
        )
        if pr_resp.status_code in (200, 201):
            pr_url = pr_resp.json().get("html_url", "")
            log.info("Opened skill PR: %s", pr_url)
            return pr_url
        else:
            log.error("Failed to create skill PR: %d %s",
                      pr_resp.status_code, pr_resp.text[:500])
            return None


def run_agent(
    gemini: GeminiClient,
    github: GitHubClient,
    issue: dict,
    assessment: AssessmentResult,
) -> AgentResult:
    """Run Gemini CLI inside a Docker container to iteratively build a reproducer."""
    # Stage 4: Select environment
    distro, extra_packages = select_environment(gemini, issue, assessment)

    image = AGENT_CONTAINER_IMAGE[distro]
    container_name = f"polkit-agent-{issue['number']}"
    result = AgentResult(distro=distro)

    try:
        # Pull pre-built image
        log.info("Pulling container image %s", image)
        subprocess.run(
            ["docker", "pull", image],
            capture_output=True, text=True, timeout=120,
        )

        # Stage 5: Start container with systemd as PID 1
        # API keys passed at `docker run` time so they are never on a
        # `docker exec` command line (avoids leaking to process listings).
        log.info("Starting container %s", container_name)
        start_proc = subprocess.run(
            [
                "docker", "run", "-d",
                "--privileged",
                "--cgroupns=host",
                "-v", "/sys/fs/cgroup:/sys/fs/cgroup:rw",
                f"--name={container_name}",
                "--memory=1g",
                "-e", "GEMINI_API_KEY",
                "-e", "GITHUB_TOKEN",
                "-e", "GEMINI_CLI_TRUST_WORKSPACE=true",
                image,
            ],
            capture_output=True, text=True, timeout=60,
        )
        if start_proc.returncode != 0:
            log.error("Container start failed:\n%s", start_proc.stderr[-2000:])
            result.agent_output = start_proc.stderr[-2000:]
            return result

        # Wait for systemd
        _wait_for_systemd(container_name)

        # Install extra packages
        if extra_packages:
            pkgs = " ".join(extra_packages)
            if distro == "fedora":
                pkg_cmd = f"dnf install -y {pkgs}"
            else:
                pkg_cmd = f"apt-get update && apt-get install -y {pkgs}"
            log.info("Installing extra packages: %s", pkgs)
            subprocess.run(
                ["docker", "exec", container_name, "bash", "-c", pkg_cmd],
                capture_output=True, text=True, timeout=120,
            )

        # Stage 6: Prepare workspace — clone skills repo and polkit source
        log.info("Preparing workspace (skills, source)")
        subprocess.run(
            ["docker", "exec", container_name,
             "git", "clone", "--depth=1", SKILLS_REPO,
             "/workspace/polkit-ai-reproducer-tools"],
            capture_output=True, text=True, timeout=60,
        )
        # GEMINI.md at workspace root; .gemini/ to both workspace and home
        subprocess.run(
            ["docker", "exec", container_name, "bash", "-c",
             "cp /workspace/polkit-ai-reproducer-tools/GEMINI.md /workspace/GEMINI.md && "
             "cp -r /workspace/polkit-ai-reproducer-tools/.gemini /workspace/.gemini && "
             "cp -r /workspace/polkit-ai-reproducer-tools/.gemini /root/.gemini"],
            capture_output=True, text=True, timeout=10,
        )
        subprocess.run(
            ["docker", "exec", container_name,
             "git", "clone", "--depth=1", POLKIT_SOURCE_REPO,
             "/workspace/polkit-src"],
            capture_output=True, text=True, timeout=60,
        )

        # Verify settings are in place
        settings_check = subprocess.run(
            ["docker", "exec", container_name, "bash", "-c",
             "cat /root/.gemini/settings.json 2>&1; "
             "echo '---'; "
             "cat /workspace/.gemini/settings.json 2>&1"],
            capture_output=True, text=True, timeout=10,
        )
        log.info("Settings check:\n%s", settings_check.stdout)

        # Quick sanity check — does gemini CLI start at all?
        ver_proc = subprocess.run(
            ["docker", "exec", container_name, "gemini", "--version"],
            capture_output=True, text=True, timeout=30,
        )
        log.info("Gemini CLI version: %s (exit %d)",
                 ver_proc.stdout.strip(), ver_proc.returncode)
        if ver_proc.returncode != 0:
            log.error("Gemini CLI not working: %s", ver_proc.stderr.strip())
            result.agent_output = f"Gemini CLI failed: {ver_proc.stderr.strip()}"
            return result

        # Check available gemini flags
        help_proc = subprocess.run(
            ["docker", "exec", container_name, "gemini", "--help"],
            capture_output=True, text=True, timeout=10,
        )
        log.info("Gemini CLI help:\n%s", help_proc.stdout)

        # Stage 7: Run Gemini CLI agent
        # Redirect output to files inside container so we can always read
        # them, even if the process times out or gets killed.
        repo = github.repo
        agent_prompt = (
            f"Reproduce the bug reported at "
            f"https://github.com/{repo}/issues/{issue['number']}. "
            f"Follow the instructions in /workspace/GEMINI.md. "
            f"Read the skill files in /workspace/polkit-ai-reproducer-tools/skills/ "
            f"for domain knowledge about polkit."
        )
        log.info("Launching Gemini CLI agent for issue #%s", issue["number"])
        agent_cmd = (
            f"gemini -y --skip-trust --sandbox false -p {repr(agent_prompt)} "
            f">/workspace/output/agent_stdout.log "
            f"2>/workspace/output/agent_stderr.log"
        )
        try:
            subprocess.run(
                ["docker", "exec", "-w", "/workspace",
                 container_name, "bash", "-c", agent_cmd],
                capture_output=True, text=True,
                timeout=AGENT_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            log.error("Agent timed out after %ds", AGENT_TIMEOUT_SECONDS)
            # Kill the gemini process inside the container
            subprocess.run(
                ["docker", "exec", container_name, "pkill", "-f", "gemini"],
                capture_output=True, timeout=10,
            )

        # Read agent logs from inside container (always available)
        for logname in ("agent_stdout.log", "agent_stderr.log"):
            log_proc = subprocess.run(
                ["docker", "exec", container_name,
                 "cat", f"/workspace/output/{logname}"],
                capture_output=True, text=True, timeout=10,
            )
            log.info("Agent %s:\n%s", logname, log_proc.stdout)
            if logname == "agent_stdout.log":
                result.agent_output = log_proc.stdout

        # Stage 8: Collect results
        log.info("Collecting results from container")
        with tempfile.TemporaryDirectory(prefix="polkit-agent-") as tmpdir:
            subprocess.run(
                ["docker", "cp",
                 f"{container_name}:/workspace/output/.", tmpdir],
                capture_output=True, text=True, timeout=30,
            )

            # Read reproducer script
            reproducer_path = os.path.join(tmpdir, "reproducer.sh")
            if os.path.exists(reproducer_path):
                with open(reproducer_path) as f:
                    result.reproducer_script = f.read()
                log.info("Found reproducer script (%d bytes)",
                         len(result.reproducer_script))

            # Read prepare_env script
            prepare_path = os.path.join(tmpdir, "prepare_env.sh")
            if os.path.exists(prepare_path):
                with open(prepare_path) as f:
                    result.prepare_env_script = f.read()
                log.info("Found prepare_env script (%d bytes)",
                         len(result.prepare_env_script))

            # Read human-readable reproducer
            human_path = os.path.join(tmpdir, "reproducer_human.txt")
            if os.path.exists(human_path):
                with open(human_path) as f:
                    result.reproducer_human = f.read()
                log.info("Found human-readable reproducer (%d bytes)",
                         len(result.reproducer_human))

            # Read result.json
            result_json_path = os.path.join(tmpdir, "result.json")
            if os.path.exists(result_json_path):
                with open(result_json_path) as f:
                    result.result_json = json.load(f)
                result.success = result.result_json.get("success", False)
                log.info("Agent result: success=%s", result.success)
            else:
                log.warning("No result.json found in agent output")

            # Open PR for any new skill files the agent wrote
            skills_output = os.path.join(tmpdir, "skills")
            if os.path.isdir(skills_output):
                try:
                    _create_skill_pr(skills_output, issue["number"])
                except Exception:
                    log.exception("Skill PR creation failed")

    except subprocess.TimeoutExpired:
        log.error("Agent timed out after %ds", AGENT_TIMEOUT_SECONDS)
        result.agent_output = f"Agent timed out after {AGENT_TIMEOUT_SECONDS}s"
    except FileNotFoundError:
        log.error("Docker not found — is it installed on this runner?")
        result.agent_output = "Docker not found on runner"
    except Exception:
        log.exception("Agent failed unexpectedly")
    finally:
        subprocess.run(
            ["docker", "rm", "-f", container_name],
            capture_output=True, timeout=30,
        )

    return result


# ---------------------------------------------------------------------------
# Feature 6: Communicate
# ---------------------------------------------------------------------------

def _issue_already_has_reproducer(github: GitHubClient, issue: dict) -> bool:
    """Check if a bot already posted a reproducer on this issue."""
    comments = github.get_issue_comments(issue["number"])
    for comment in comments:
        if comment["user"]["login"] != _TRIAGE_MARKER_BOT:
            continue
        body = (comment.get("body") or "").lower()
        if "verified reproducer" in body or "automated reproducer" in body:
            return True
    return False


def communicate(
    github: GitHubClient,
    issue: dict,
    design_result: DesignResult,
    validation_result: ValidationResult | None = None,
) -> str | None:
    if design_result.kind != "reproducer" or design_result.reproducer is None:
        return None

    if _issue_already_has_reproducer(github, issue):
        log.info("Issue #%s already contains a reproducer, skipping", issue["number"])
        return None

    repro = design_result.reproducer

    # Validation failed or was not run — post a short notice instead
    if validation_result is None or not validation_result.success:
        log.info("Reproducer for issue #%s did not pass validation, posting failure notice", issue["number"])
        parts = ["### Automated Reproducer\n"]
        parts.append(
            "An automated reproducer was generated but **could not be verified** "
            "in an isolated Docker container.\n"
        )
        output = "\n".join(filter(None, [
            validation_result.stdout.strip() if validation_result else "",
            validation_result.stderr.strip() if validation_result else "",
        ]))
        if validation_result and output:
            parts.append(
                f"<details><summary>Validation error details</summary>\n\n"
                f"**Exit code:** {validation_result.exit_code}\n\n"
                f"```\n{output}\n```\n"
                f"</details>\n"
            )
        parts.append(
            "\n---\n"
            "*The AI assistant was unable to produce a working reproducer "
            "within the current constraints. "
            "A maintainer may attempt to reproduce this manually.*"
        )
        comment = "\n".join(parts)
        github.post_comment(issue["number"], comment)
        return comment

    # Validation succeeded — post the verified reproducer
    log.info("Posting verified reproducer for issue #%s", issue["number"])
    extra_pkgs = ""
    if repro.extra_packages:
        extra_pkgs = ", additional packages: " + ", ".join(f"`{p}`" for p in repro.extra_packages)

    comment = (
        "### Verified Reproducer\n\n"
        "The following reproducer was automatically generated and "
        "**successfully validated** in an isolated Docker container.\n\n"
        f"**What it does:** {repro.explanation}\n\n"
        f"**Reproducer** (`{repro.script_filename}`):\n"
        f"```bash\n{repro.reproducer_script}\n```\n\n"
        f"**Environment:** `{repro.base_image}`{extra_pkgs}\n\n"
    )
    if validation_result.stdout.strip():
        comment += (
            "<details><summary>Validation output</summary>\n\n"
            f"```\n{validation_result.stdout.strip()}\n```\n"
            "</details>\n\n"
        )
    if validation_result.dockerfile.strip():
        comment += (
            "<details><summary>Run it locally with Docker/Podman</summary>\n\n"
            f"Save the reproducer script as `{repro.script_filename}` and "
            "the following as `Dockerfile` in the same directory, then run:\n\n"
            "```bash\n"
            f"docker build -t polkit-repro . && docker run --rm polkit-repro\n"
            "```\n\n"
            "Or with Podman:\n\n"
            "```bash\n"
            f"podman build -t polkit-repro . && podman run --rm polkit-repro\n"
            "```\n\n"
            f"**Dockerfile:**\n"
            f"```dockerfile\n{validation_result.dockerfile.strip()}\n```\n"
            "</details>\n\n"
        )
    comment += (
        "---\n"
        "*This reproducer was generated and verified by an AI assistant. "
        "Please confirm it matches the problem you reported.*"
    )

    github.post_comment(issue["number"], comment)
    return comment


def communicate_agent(
    github: GitHubClient,
    issue: dict,
    agent_result: AgentResult,
) -> str | None:
    """Post the agentic reproducer result to the issue."""
    if _issue_already_has_reproducer(github, issue):
        log.info("Issue #%s already contains a reproducer, skipping", issue["number"])
        return None

    if not agent_result.success or not agent_result.reproducer_script:
        log.info("Agent did not produce a working reproducer for issue #%s",
                 issue["number"])
        parts = ["### Automated Reproducer (Agentic)\n"]
        parts.append(
            "An AI agent attempted to reproduce this bug but "
            "**could not produce a verified reproducer**.\n"
        )
        explanation = agent_result.result_json.get("explanation", "")
        if explanation:
            parts.append(f"**Agent notes:** {explanation}\n")
        if agent_result.agent_output.strip():
            # Truncate to keep comment reasonable
            output = agent_result.agent_output.strip()[-4000:]
            parts.append(
                "<details><summary>Agent output (last 4000 chars)</summary>\n\n"
                f"```\n{output}\n```\n"
                "</details>\n"
            )
        parts.append(
            "\n---\n"
            "*The AI agent was unable to produce a working reproducer. "
            "A maintainer may attempt to reproduce this manually.*"
        )
        comment = "\n".join(parts)
        github.post_comment(issue["number"], comment)
        return comment

    # Success — post the verified reproducer
    log.info("Posting agent-verified reproducer for issue #%s", issue["number"])
    explanation = agent_result.result_json.get("explanation", "")
    comment = (
        "### Verified Reproducer\n\n"
        "An AI agent automatically reproduced this bug inside "
        f"a `{agent_result.distro}` container.\n\n"
    )
    if explanation:
        comment += f"**What it does:** {explanation}\n\n"

    # Human-readable version first (the prominent part)
    if agent_result.reproducer_human:
        comment += (
            f"**How to reproduce:**\n"
            f"```\n{agent_result.reproducer_human}\n```\n\n"
        )

    # Collapsible sections for the agentic scripts
    if agent_result.prepare_env_script:
        comment += (
            "<details><summary>Environment setup "
            "(<code>prepare_env.sh</code>)</summary>\n\n"
            f"```bash\n{agent_result.prepare_env_script}\n```\n"
            "</details>\n\n"
        )

    comment += (
        "<details><summary>Full agentic reproducer "
        "(<code>reproducer.sh</code>)</summary>\n\n"
        f"```bash\n{agent_result.reproducer_script}\n```\n"
        "</details>\n\n"
    )

    comment += (
        f"**Environment:** `{AGENT_CONTAINER_IMAGE[agent_result.distro]}`\n\n"
        "---\n"
        "*This reproducer was generated and verified by an AI agent. "
        "Please confirm it matches the problem you reported.*"
    )

    github.post_comment(issue["number"], comment)
    return comment


# ---------------------------------------------------------------------------
# CLI and pipeline
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="AI-powered issue triage for the polkit project",
    )
    parser.add_argument("--issue-number", type=int, required=True, help="GitHub issue number")
    parser.add_argument("--repo", required=True, help="owner/repo (e.g. polkit-org/polkit)")
    parser.add_argument(
        "--model", default="gemini-2.5-pro",
        help="Gemini model name (default: gemini-2.5-pro)",
    )

    parser.add_argument(
        "--debug", action="store_true", default=False,
        help="Enable debug logging (shows raw Gemini responses)",
    )

    for feat in ("assess", "label", "elicit", "design", "communicate", "validate"):
        parser.add_argument(
            f"--{feat}", action=argparse.BooleanOptionalAction, default=True,
            help=f"Enable/disable the {feat} stage",
        )

    return parser


def run_pipeline(args: argparse.Namespace) -> None:
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    gemini = GeminiClient(api_key=GEMINI_API_KEY, model=args.model)
    github = GitHubClient(token=GITHUB_TOKEN, repo=args.repo)
    ret_val = 0

    issue = github.get_issue(args.issue_number)
    log.info("Fetched issue #%d: %s", args.issue_number, issue["title"])

    assessment: AssessmentResult | None = None
    applied_labels: list[str] = []
    design_result: DesignResult | None = None

    # Stage 0: Check if issue is already triaged
    comments = github.get_issue_comments(args.issue_number)
    
    if any(
        comment["user"]["login"] == _TRIAGE_MARKER_BOT
        and _TRIAGE_MARKER in comment["body"]
        for comment in comments
    ):
        log.info("Issue #%d already triaged", args.issue_number)
        ret_val = 1
        return ret_val

    # Stage 1: Assess
    if args.assess:
        try:
            assessment = assess(gemini, issue)
            if assessment:
                log.info(
                    "Assessment: type=%s confidence=%.2f summary=%s",
                    assessment.type, assessment.confidence, assessment.summary,
                )
            else:
                log.warning("Assessment returned no result")
        except Exception:
            log.exception("Assessment failed")
            ret_val = 2
    # Stage 2: Label
    if args.label and assessment:
        try:
            applied_labels = label(gemini, github, issue, assessment)
            log.info("Applied labels: %s", applied_labels)
        except Exception:
            log.exception("Labeling failed")
            ret_val = 2
    else:
        log.info("Skipping labeling: no assessment result")

    # Stage 3: Elicit
    if args.elicit and assessment:
        try:
            elicit(gemini, github, issue, assessment)
        except Exception:
            log.exception("Elicitation failed")
            ret_val = 2
    else:
        log.info("Skipping elicitation: no assessment result")

    # Stage 4+5+6: Bug path → agentic reproducer; feature path → design+validate
    agent_result: AgentResult | None = None

    if assessment and assessment.type == "bug" and args.design:
        # Agentic reproducer pipeline for bugs
        log.info("Bug detected — running agentic reproducer pipeline")
        try:
            agent_result = run_agent(gemini, github, issue, assessment)
            log.info("Agent complete: success=%s", agent_result.success)
        except Exception:
            log.exception("Agent failed")
            ret_val = 2

        if args.communicate and agent_result:
            try:
                communicate_agent(github, issue, agent_result)
            except Exception:
                log.exception("Agent communication failed")
                ret_val = 2

    elif assessment and assessment.type == "feature_request" and args.design:
        # Single-shot design for feature requests (unchanged)
        try:
            design_result = design(gemini, issue, assessment)
            if design_result:
                log.info("Design complete: kind=%s", design_result.kind)
        except Exception:
            log.exception("Design failed")
            ret_val = 2

        validation_result: ValidationResult | None = None
        if args.validate and design_result:
            try:
                validation_result = validate(gemini, github, issue, design_result)
                if validation_result:
                    log.info("Validation: success=%s exit_code=%d",
                             validation_result.success, validation_result.exit_code)
            except Exception:
                log.exception("Validation failed")
                ret_val = 2

        if args.communicate and design_result:
            try:
                communicate(github, issue, design_result, validation_result)
            except Exception:
                log.exception("Communication failed")
                ret_val = 2
    else:
        log.info("Skipping design/agent: type=%s or no assessment",
                 assessment.type if assessment else "none")

    log.info("Pipeline complete for issue #%d", args.issue_number)

    if ret_val == 0 and assessment is not None:
        github.post_comment(args.issue_number, _TRIAGE_MARKER)

    return ret_val


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    ret_val = run_pipeline(args)
    sys.exit(ret_val)

if __name__ == "__main__":
    main()
