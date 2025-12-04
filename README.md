# SMART Rule Optimizer

[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/awillard1/optimize_rules/ci.yml?branch=main&label=ci&logo=github)](https://github.com/awillard1/optimize_rules/actions)
[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/awillard1/optimize_rules?style=social)](https://github.com/awillard1/optimize_rules/stargazers)

> A high-performance utility to analyze, aggregate, and generate **optimized Hashcat rule sets** from large `.rule` collections. Produces a compact, reproducible SMART ruleset plus optional ONERULE-style bonus files and Hashcat mask files.

---

## Quick links
- **Repository:** `awillard1/optimize_rules` (suggested)
- **Primary script:** `optimize_rules.py`
- **Recommended license:** MIT (editable — add `LICENSE`)

---

## Table of contents
1. [Why this project](#why-this-project)
2. [Features](#features)
3. [Badges & CI tips](#badges--ci-tips)
4. [Install](#install)
5. [Usage (examples)](#usage-examples)
6. [CLI options](#cli-options)
7. [Output files](#output-files)
8. [Mask generation summary](#mask-generation-summary)
9. [Cache behavior & performance](#cache-behavior--performance)
10. [Contributing](#contributing)
11. [Security & Ethics](#security--ethics)
12. [License](#license)
13. [Credits & contact](#credits--contact)

---

## Why this project
Many red/blue teams and security researchers maintain large libraries of Hashcat `.rule` files collected from public repositories, tools, and legacy collections. Manually curating and combining these is slow, error-prone, and yields bloated rulesets. **SMART Rule Optimizer** automates discovery of real prefixes/suffixes, normalizes patterns, deduplicates rules, and emits a compact, practical ruleset suitable for distributed or optimized cracking workflows.

---

## Features
- Parallel, **I/O‑efficient parsing** of many `.rule` files with robust caching.
- Normalization and deduplication of logical patterns (years, repeated symbols, token collapsing).
- Controlled combo generator (prefixes, suffixes, 2‑digit years, 20xx ranges, common numeric sequences).
- Optional **ONERULE bonus** file (toggles emitted on their own lines) for toggle-first experiments.
- Optional mask file emission (`.hcmask`) for **hybrid** (-a 6/7) and **pure mask** (-a 3) attacks.
- Atomic writes, safe cache persistence, verbose diagnostics, and deterministic outputs.

---

## Badges & CI tips
- The badges above are sample placeholders. Add a `ci.yml` GitHub Actions workflow to run tests/linting and the CI badge will show real status.
- Suggested checks for CI:
  - `python -m pytest` (unit tests)
  - `python -m pip install -r requirements-dev.txt` (if you add dev deps)
  - `ruff` / `black` for linting and formatting
- Add a `CODEOWNERS` file and `pull_request_template.md` to streamline contributions.

---

## Install
**Requirements:** Python 3.8+

```bash
git clone https://github.com/awillard1/optimize_rules.git
cd optimize_rules
# optionally create venv
python3 -m venv .venv && source .venv/bin/activate
python3 optimize_rules.py --help
```

No external dependencies are required by default — the script uses only the standard library.

---

## Usage (examples)
Run the optimizer against a folder or single `.rule` file.

**Basic:**
```bash
python3 optimize_rules.py /path/to/rules/dir
```

**Custom output & verbose:**
```bash
python3 optimize_rules.py /path/to/rules -o optimized_rules --verbose
```

**Emit masks & sample many literals for hybrids:**
```bash
python3 optimize_rules.py /path/to/rules -o optimized_rules --emit-masks --mask-sample 1000
```

**Generate a compact ruleset and use with Hashcat (-O optimized):**
```bash
hashcat -a 0 -w 3 -O -m 0 hashes.txt wordlist.txt -r optimized_rules/SMART_prefix_suffix.rule
```

---

## CLI options
Short summary of the most used CLI flags (see `--help` in the script for full list):

- `input` — Path to a `.rule` file or directory of `.rule` files (positional).
- `-o, --output` — Output directory (default: `optimized_rules`).
- `--cache` — Cache file path (default: `~/.cache/optimize_rules/cache.json`).
- `--keep-prefixes`, `--keep-suffixes` — How many top token sequences to retain.
- `--combo-limit` — Max combos per prefix/suffix (defaults tuned to be conservative).
- `--no-onerule` — Disable ONERULE bonus file emission.
- `--emit-masks` — Write `masks.full.hcmask`, `masks.right.hcmask`, `masks.left.hcmask`.
- `--mask-sample` — How many literal prefixes/suffixes to sample for mask hybrids.
- `--threads` — Worker threads for parsing (auto-tuned by default).
- `-v, --verbose` — Enable DEBUG logging.

---

## Output files
- `SMART_prefix_suffix.rule` — Main optimized ruleset (core output).
- `ONERULE_bonus.rule` — Optional toggles‑on‑their‑own‑lines bonus file.
- `masks.full.hcmask` — Pure mask lines for `-a 3` attacks.
- `masks.right.hcmask` — Append masks (hybrid append `-a 6`).
- `masks.left.hcmask` — Prepend masks (hybrid prepend `-a 7`).
- Cache JSON (default `~/.cache/optimize_rules/cache.json`) — speeds up re-runs.

---

## Mask generation summary
- Mask patterns include common numeric masks (e.g. `?d?d`, `?d?d?d`, `?d?d?d?d`) and hybrids combining numeric masks with literal prefixes/suffixes converted from token sequences.
- Literals are escaped for mask syntax safety. Files are written atomically to avoid partial outputs.

---

## Cache behavior & performance
- Files are fingerprinted via **SHA-256 + size + mtime**; if hashing fails, a stat-only signature is used as a fallback.
- The cache stores extracted fragments (prefixes/suffixes/patterns) to avoid re-parsing unchanged inputs.
- Threaded parsing speeds up I/O-heavy workloads; tune `--threads` for your machine.

---

## Contributing
Contributions welcome — suggested workflow:
1. Fork the repository
2. Create a feature branch
3. Add focused changes and tests where applicable
4. Open a PR with a clear description and rationale

Recommended additions:
- Unit tests (pytest) for `normalize_rule_line`, `build_combo_rules`, `tokens_to_literal`, and mask emission
- CI workflow (GitHub Actions) running tests & linters
- Small performance-focused optimizations or additional mask heuristics

---

## Security & Ethics
**Do not use this tool without explicit authorization.** Password cracking is illegal and unethical without permission. This project is intended strictly for security research, authorized assessments, and education.

---

## License
This README assumes an **MIT** license by default. Add a `LICENSE` file to the repo root. Example MIT content is available in `LICENSE` templates — change to Apache‑2.0 or other license if preferred.

---

## Credits & contact
Inspired by the Hashcat community and rule authors.

For issues, suggestions, or contributions open a GitHub issue or contact the maintainer via the repository.

