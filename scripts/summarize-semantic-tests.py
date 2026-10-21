"""Publish bounded JUnit failures as annotations, without changing test results.

CI-only tooling. No target code or runtime dependency is introduced into Cline.
"""
import os
from pathlib import Path
import sys
import xml.etree.ElementTree as ET


def escape(value):
    return str(value).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def summarize(path):
    raw = Path(path).read_bytes()
    if len(raw) > 16 * 1024 * 1024 or b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise ValueError("JUnit report exceeds safe diagnostic format")
    root = ET.fromstring(raw)
    cases = list(root.iter("testcase"))
    problems = []
    for case in cases:
        for result in case:
            if result.tag in ("failure", "error"):
                label = f'{case.get("classname", "")}: {case.get("name", "")}'
                details = "".join(result.itertext()).strip() or result.get("message", "No failure details")
                problems.append(f"{label}\n{details}"[:6000])
    # Collection/startup failures can be represented at suite level.
    for suite in root.iter("testsuite"):
        for result in suite:
            if result.tag in ("failure", "error"):
                problems.append(f'{suite.get("name", "suite")}: {"".join(result.itertext())}'[:6000])
    if not cases:
        raise ValueError("JUnit report contains no test cases")
    if not problems and any(int(s.get("failures", "0")) or int(s.get("errors", "0")) for s in root.iter("testsuite")):
        raise ValueError("JUnit reports failures without diagnostic entries")
    return len(cases), problems


def main():
    try:
        count, problems = summarize(sys.argv[1])
    except Exception as error:
        print(f"::error title=Semantic diagnostic report unavailable::{escape(error)}")
        return 1
    print(f"Semantic JUnit: {count} test cases, {len(problems)} failure/error entries")
    for problem in problems[:15]:
        print(f"::error title=Semantic regression failure::{escape(problem)}")
    if len(problems) > 15:
        print("Additional failures are retained in the full JUnit artifact.")
    if os.getenv("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as handle:
            handle.write(f"## Semantic regression diagnostics\n\n{count} cases; {len(problems)} failure/error entries. See annotations and full JUnit artifact.\n")
    # The preceding Vitest step owns pass/fail. This step never makes it green.
    return 0


if __name__ == "__main__":
    sys.exit(main())
