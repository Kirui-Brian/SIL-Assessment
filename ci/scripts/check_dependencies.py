#!/usr/bin/env python3
"""Catch AI-hallucinated and typosquatted dependencies before they reach a build.

For every requirement (PyPI) or dependency (npm) it checks:
  1. The package exists on the public registry              -> missing = likely hallucination
  2. Its first release is older than MIN_AGE_DAYS           -> brand-new = possible slopsquatting
  3. It is not a near-miss of a popular package             -> typosquat heuristic
  4. (optional) It is in the org allow-list file            -> strict mode
Exit code 1 on any finding, so it can gate a pipeline.
Usage: check_dependencies.py requirements.txt [package.json ...] [--min-age 30] [--allowlist deps-allowlist.txt]
"""
import argparse, difflib, json, re, sys, urllib.error, urllib.request
from datetime import datetime, timezone

POPULAR_PY = {"requests", "numpy", "pandas", "flask", "django", "fastapi", "pydantic", "sqlalchemy", "boto3", "urllib3",
              "cryptography", "pyjwt", "uvicorn", "httpx", "pytest", "psycopg2", "psycopg2-binary", "scipy", "pillow", "jinja2"}
POPULAR_NPM = {"react", "express", "lodash", "axios", "webpack", "typescript", "next", "vue", "jsonwebtoken", "moment"}


def fetch(url):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "sil-dep-check"}), timeout=15) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def first_release_pypi(data):
    times = [datetime.fromisoformat(f["upload_time_iso_8601"].replace("Z", "+00:00"))
             for files in data["releases"].values() for f in files]
    return min(times) if times else None


def first_release_npm(data):
    created = data.get("time", {}).get("created")
    return datetime.fromisoformat(created.replace("Z", "+00:00")) if created else None


def parse_requirements(path):
    for line in open(path):
        line = line.split("#")[0].strip()
        if line and not line.startswith(("-", "git+", "http")):
            yield re.split(r"[<>=!~;\[ ]", line, maxsplit=1)[0].lower().replace("_", "-")


def parse_package_json(path):
    j = json.load(open(path))
    for section in ("dependencies", "devDependencies"):
        yield from j.get(section, {})


def check(name, eco, min_age, allow):
    findings = []
    data = fetch(f"https://pypi.org/pypi/{name}/json") if eco == "pypi" else fetch(f"https://registry.npmjs.org/{name}")
    if data is None:
        return [f"{eco}:{name}  DOES NOT EXIST on the registry (possible AI hallucination)"]
    first = first_release_pypi(data) if eco == "pypi" else first_release_npm(data)
    if first and (datetime.now(timezone.utc) - first).days < min_age:
        findings.append(f"{eco}:{name}  first published {first.date()}, under {min_age} days old (possible slopsquat)")
    popular = POPULAR_PY if eco == "pypi" else POPULAR_NPM
    if name not in popular:
        near = difflib.get_close_matches(name, popular, n=1, cutoff=0.88)
        if near:
            findings.append(f"{eco}:{name}  looks like a typosquat of '{near[0]}'")
    if allow is not None and name not in allow:
        findings.append(f"{eco}:{name}  not in the approved dependency allow-list")
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--min-age", type=int, default=30)
    ap.add_argument("--allowlist")
    a = ap.parse_args()
    allow = {l.strip().lower() for l in open(a.allowlist)} if a.allowlist else None
    bad = []
    for f in a.files:
        eco, names = ("npm", parse_package_json(f)) if f.endswith("package.json") else ("pypi", parse_requirements(f))
        for n in names:
            bad += check(n, eco, a.min_age, allow)
    for b in bad:
        print("FAIL", b)
    print(f"{len(bad)} finding(s)")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
