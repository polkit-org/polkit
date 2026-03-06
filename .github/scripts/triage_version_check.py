#!/usr/bin/env python3
"""Check if a GitHub issue mentions the polkit version using Gemini REST API."""

import json
import os
import sys
import urllib.request
import urllib.error

GEMINI_API_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    "gemini-2.0-flash:generateContent"
)

def main():
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("Error: GEMINI_API_KEY not set", file=sys.stderr)
        sys.exit(1)

    issue_title = os.environ.get("ISSUE_TITLE", "")
    issue_body = os.environ.get("ISSUE_BODY", "")

    prompt = f"""You are a bug triage assistant for the polkit project.

Analyze the following GitHub issue and determine whether the reporter mentioned which version of polkit they are using.

Issue title: {issue_title}

Issue body:
{issue_body}

Answer with one of:
- YES — if the issue clearly states the polkit version (e.g. "polkit 0.120", "version 121", a package version string, or a git commit/tag)
- NO — if the polkit version is not mentioned at all

Then write a short, friendly comment (2-3 sentences) to post on the issue:
- If YES: acknowledge that the version info was provided and thank the reporter.
- If NO: politely ask the reporter to provide the polkit version they are using, explaining it helps reproduce and fix the issue faster.

Respond in this exact format:
VERDICT: <YES or NO>
COMMENT: <your comment text>
"""

    payload = json.dumps({
        "contents": [{"parts": [{"text": prompt}]}]
    }).encode()

    req = urllib.request.Request(
        GEMINI_API_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "x-goog-api-key": api_key,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req) as resp:
            data = json.load(resp)
    except urllib.error.HTTPError as e:
        print(f"Gemini API error {e.code}: {e.read().decode()}", file=sys.stderr)
        sys.exit(1)

    try:
        text = data["candidates"][0]["content"]["parts"][0]["text"].strip()
    except (KeyError, IndexError) as e:
        print(f"Unexpected Gemini response structure: {data}", file=sys.stderr)
        sys.exit(1)

    comment = ""
    for line in text.splitlines():
        if line.startswith("COMMENT:"):
            comment = line[len("COMMENT:"):].strip()
            break

    if not comment:
        print("Error: could not parse Gemini response", file=sys.stderr)
        print(text, file=sys.stderr)
        sys.exit(1)

    print(comment)


if __name__ == "__main__":
    main()
