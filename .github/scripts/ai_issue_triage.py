#!/usr/bin/env python3
"""AI-powered issue triage for the polkit project using Gemini."""

import argparse
import json
import logging
import os
import subprocess
import sys
import tempfile
import textwrap
import time
from dataclasses import dataclass, field

import requests

from polkit_context import (
    POLKIT_SUMMARY,
    PROMPT_ASSESS,
    PROMPT_DESIGN_REPRODUCER,
    PROMPT_DESIGN_SOLUTION,
    PROMPT_ELICIT,
    PROMPT_LABEL,
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


# ---------------------------------------------------------------------------
# Gemini REST API client
# ---------------------------------------------------------------------------

class GeminiClient:
    """Thin wrapper around the Gemini REST API with retry logic."""

    def __init__(self, api_key: str, model: str = "gemini-2.0-flash"):
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
            "maxOutputTokens": 8192,
        }

        last_err: Exception | None = None
        for attempt in range(3):
            try:
                resp = self._session.post(
                    url,
                    params={"key": self.api_key},
                    json=body,
                    timeout=120,
                )
                if resp.status_code == 429:
                    wait = 2 ** (attempt + 1)
                    log.warning("Gemini rate-limited (429), retrying in %ds", wait)
                    time.sleep(wait)
                    continue
                resp.raise_for_status()
                data = resp.json()
                return data["candidates"][0]["content"]["parts"][0]["text"]
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

def _parse_json_response(text: str) -> dict:
    """Extract a JSON object from Gemini's response, tolerating markdown fences."""
    text = text.strip()
    if text.startswith("```"):
        first_nl = text.index("\n")
        text = text[first_nl + 1:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()
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
        polkit_summary=POLKIT_SUMMARY,
        issue_title=issue["title"],
        issue_body=issue.get("body", "") or "",
    )
    raw = gemini.generate(prompt)
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
    raw = gemini.generate(prompt)
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
    comment_text = gemini.generate(prompt)
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
        polkit_summary=POLKIT_SUMMARY,
        issue_title=issue["title"],
        issue_body=issue.get("body", "") or "",
        assessment_json=json.dumps({
            "type": assessment.type,
            "summary": assessment.summary,
            "affected_components": assessment.affected_components,
        }, indent=2),
    )
    raw = gemini.generate(prompt)
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
        polkit_summary=POLKIT_SUMMARY,
        issue_title=issue["title"],
        issue_body=issue.get("body", "") or "",
        assessment_json=json.dumps({
            "type": assessment.type,
            "summary": assessment.summary,
            "affected_components": assessment.affected_components,
        }, indent=2),
    )
    raw = gemini.generate(prompt)
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
# Feature 5: Communicate
# ---------------------------------------------------------------------------

def _issue_already_has_reproducer(issue: dict) -> bool:
    """Heuristic: check if the issue body contains code blocks that look like a reproducer."""
    body = (issue.get("body") or "").lower()
    code_indicators = ["```", "#!/bin/", "reproducer", "steps to reproduce"]
    script_indicators = ["pkexec", "pkcheck", "busctl", "gdbus", "dbus-send"]
    has_code = any(ind in body for ind in code_indicators)
    has_polkit_tool = any(ind in body for ind in script_indicators)
    return has_code and has_polkit_tool


def communicate(
    github: GitHubClient,
    issue: dict,
    design_result: DesignResult,
) -> str | None:
    if design_result.kind != "reproducer" or design_result.reproducer is None:
        return None

    if _issue_already_has_reproducer(issue):
        log.info("Issue #%s already contains a reproducer, skipping", issue["number"])
        return None

    repro = design_result.reproducer
    log.info("Posting reproducer for issue #%s", issue["number"])
    comment = textwrap.dedent(f"""\
        ### Automated Reproducer

        Based on the issue description, here is an automatically generated minimal \
        reproducer. **Please verify** that it accurately reflects the problem you reported.

        **What it does:** {repro.explanation}

        **Reproducer** (`{repro.script_filename}`):
        ```
        {repro.reproducer_script}
        ```

        **Environment:** `{repro.base_image}`{(
            ', additional packages: ' + ', '.join(f'`{p}`' for p in repro.extra_packages)
        ) if repro.extra_packages else ''}

        ---
        *This reproducer was generated by an AI assistant and may not be perfect. \
        Please review and let us know if adjustments are needed.*
    """)

    github.post_comment(issue["number"], comment)
    return comment


# ---------------------------------------------------------------------------
# Feature 6: Validate
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
        extra_packages=", ".join(repro.extra_packages) if repro.extra_packages else "none",
        script_filename=repro.script_filename,
    )
    dockerfile_content = gemini.generate(dockerfile_prompt)
    dockerfile_content = dockerfile_content.strip()
    if dockerfile_content.startswith("```"):
        first_nl = dockerfile_content.index("\n")
        dockerfile_content = dockerfile_content[first_nl + 1:]
        if dockerfile_content.endswith("```"):
            dockerfile_content = dockerfile_content[:-3]
        dockerfile_content = dockerfile_content.strip()

    result = ValidationResult()

    with tempfile.TemporaryDirectory(prefix="polkit-validate-") as tmpdir:
        dockerfile_path = os.path.join(tmpdir, "Dockerfile")
        reproducer_path = os.path.join(tmpdir, repro.script_filename)

        with open(dockerfile_path, "w") as f:
            f.write(dockerfile_content)

        with open(reproducer_path, "w") as f:
            f.write(repro.reproducer_script)
        os.chmod(reproducer_path, 0o755)

        repo_root = _find_repo_root()
        tag = f"polkit-validate-{issue['number']}"

        try:
            build_proc = subprocess.run(
                [
                    "docker", "build",
                    "-t", tag,
                    "-f", dockerfile_path,
                    "--build-arg", f"POLKIT_SRC={repo_root}",
                    tmpdir,
                ],
                capture_output=True,
                text=True,
                timeout=DOCKER_TIMEOUT_SECONDS,
                cwd=repo_root,
            )
            if build_proc.returncode != 0:
                log.error("Docker build failed:\n%s", build_proc.stderr[-2000:])
                result.stderr = build_proc.stderr[-2000:]
                result.exit_code = build_proc.returncode
                _post_validation_results(github, issue, result)
                return result

            run_proc = subprocess.run(
                [
                    "docker", "run",
                    "--rm",
                    "--network=none",
                    f"--memory={DOCKER_MEMORY_LIMIT}",
                    tag,
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
                ["docker", "rmi", "-f", tag],
                capture_output=True,
                timeout=30,
            )

    _post_validation_results(github, issue, result)
    return result


def _find_repo_root() -> str:
    """Locate the polkit repo root (where meson.build lives)."""
    candidate = os.environ.get("GITHUB_WORKSPACE", "")
    if candidate and os.path.isfile(os.path.join(candidate, "meson.build")):
        return candidate
    here = os.path.dirname(os.path.abspath(__file__))
    for _ in range(5):
        if os.path.isfile(os.path.join(here, "meson.build")):
            return here
        here = os.path.dirname(here)
    return os.getcwd()


def _post_validation_results(
    github: GitHubClient,
    issue: dict,
    result: ValidationResult,
) -> None:
    status = "reproduced (exit 0)" if result.success else f"failed (exit {result.exit_code})"
    parts = [
        "### Automated Reproducer Validation\n",
        f"**Status:** {status}\n",
    ]
    if result.stdout.strip():
        parts.append(f"**stdout** (last 4KB):\n```\n{result.stdout.strip()}\n```\n")
    if result.stderr.strip():
        parts.append(f"**stderr** (last 4KB):\n```\n{result.stderr.strip()}\n```\n")
    parts.append(
        "\n---\n*This validation was run automatically in an isolated Docker "
        "container. Results may differ from your environment.*"
    )
    github.post_comment(issue["number"], "\n".join(parts))


# ---------------------------------------------------------------------------
# CLI and pipeline
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="AI-powered issue triage for the polkit project",
    )
    parser.add_argument("--issue-number", type=int, required=True, help="GitHub issue number")
    parser.add_argument("--repo", required=True, help="owner/repo (e.g. polkit-org/polkit)")
    parser.add_argument("--gemini-api-key", required=True, help="Gemini API key")
    parser.add_argument("--github-token", required=True, help="GitHub token")
    parser.add_argument(
        "--model", default="gemini-2.0-flash",
        help="Gemini model name (default: gemini-2.0-flash)",
    )

    for feat in ("assess", "label", "elicit", "design", "communicate", "validate"):
        parser.add_argument(
            f"--{feat}", action=argparse.BooleanOptionalAction, default=True,
            help=f"Enable/disable the {feat} stage",
        )

    return parser


def run_pipeline(args: argparse.Namespace) -> None:
    gemini = GeminiClient(api_key=args.gemini_api_key, model=args.model)
    github = GitHubClient(token=args.github_token, repo=args.repo)

    issue = github.get_issue(args.issue_number)
    log.info("Fetched issue #%d: %s", args.issue_number, issue["title"])

    assessment: AssessmentResult | None = None
    applied_labels: list[str] = []
    design_result: DesignResult | None = None

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

    # Stage 2: Label
    if args.label and assessment:
        try:
            applied_labels = label(gemini, github, issue, assessment)
            log.info("Applied labels: %s", applied_labels)
        except Exception:
            log.exception("Labeling failed")

    # Stage 3: Elicit
    if args.elicit and assessment:
        try:
            elicit(gemini, github, issue, assessment)
        except Exception:
            log.exception("Elicitation failed")

    # Stage 4: Design
    if args.design and assessment:
        try:
            design_result = design(gemini, issue, assessment)
            if design_result:
                log.info("Design complete: kind=%s", design_result.kind)
        except Exception:
            log.exception("Design failed")

    # Stage 5: Communicate
    if args.communicate and design_result:
        try:
            communicate(github, issue, design_result)
        except Exception:
            log.exception("Communication failed")

    # Stage 6: Validate
    if args.validate and design_result:
        try:
            result = validate(gemini, github, issue, design_result)
            if result:
                log.info("Validation: success=%s exit_code=%d", result.success, result.exit_code)
        except Exception:
            log.exception("Validation failed")

    log.info("Pipeline complete for issue #%d", args.issue_number)


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    run_pipeline(args)


if __name__ == "__main__":
    main()
