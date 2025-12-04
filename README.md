```markdown
# SMART Rule Optimizer

A high-performance utility to analyze, aggregate, and generate optimized Hashcat rule sets from many existing `.rule` files. The script collects frequently used prefixes, suffixes and patterns, deduplicates and normalizes input rules, and produces a compact, effective SMART ruleset with optional ONERULE-style bonus rules and mask files for hybrid/pure mask attacks.

This project is intended for security researchers and penetration testers who maintain large collections of rule files and want an automated way to produce a safe, high‑quality, and reproducible optimized ruleset.

Highlights
- Fast parallel parsing of many `.rule` files with robust caching.
- Normalization and deduplication of logical patterns.
- Controlled combination generator to create safe prefix/suffix + year/number rules.
- Optional ONERULE bonus file that emits toggles on their own lines.
- Optional mask file emission for Hashcat hybrids and pure mask attacks.
- Atomic writes and safe caching to avoid partial output files.
- Verbose logging and diagnostics for tuning.

Table of Contents
- Features
- Install
- Usage
- Options
- Output files
- Mask generation
- Cache behavior
- Performance & tuning
- Example workflows
- Contributing
- Troubleshooting
- License

Features
- Normalize rules by collapsing common tokens (years, numeric placeholders, symbols).
- Collect real prefixes (e.g. `^f ^a ^m`) and suffixes (e.g. `$1 $2 $3`) and rank them by frequency.
- Generate combination rules such as prefix + 2-digit year or numeric append sequences in a controlled way to avoid overly long or invalid rules.
- Emit optional ONERULE bonus file with toggles emitted on their own lines (helpful when trying toggles independently).
- Emit three mask files (masks.full.hcmask, masks.right.hcmask, masks.left.hcmask) for hybrid and mask-only attacks.
- Threaded parsing for faster processing of large collections of rule files.
- Safe atomic output writes and a content-aware cache to avoid re-parsing unchanged files.

Install
Requirements
- Python 3.8+ recommended
- No external packages required (uses standard library)

Clone the repository:
```bash
git clone https://github.com/awillard1/optimize_rules.git
cd optimize_rules
```

Usage
Run the optimizer against a single `.rule` file or a directory containing `.rule` files:

Basic:
```bash
python3 optimize_rules.py /path/to/rules/dir
```

Write outputs to a custom directory and enable verbose logging:
```bash
python3 optimize_rules.py /path/to/rules/dir -o optimized_rules --verbose
```

Generate masks and sample 1000 literal prefixes/suffixes for mask hybrids:
```bash
python3 optimize_rules.py /path/to/rules/dir -o optimized_rules --emit-masks --mask-sample 1000
```

Options (matching CLI flags)
- input (positional): Path to a `.rule` file or a directory containing `.rule` files.
- -o, --output: Output directory (default: optimized_rules).
- --cache: Cache file path (default: ~/.cache/optimize_rules/cache.json).
- --keep-prefixes: How many top prefixes to keep (default: 25000).
- --keep-suffixes: How many top suffixes to keep (default: 25000).
- --combo-limit: Limit combos per prefix/suffix when generating (default: 180).
- --no-onerule: Do not create ONERULE bonus file.
- --threads: Worker threads for parsing files (default: auto tuned to available CPUs).
- --emit-masks: Emit mask files for Hashcat (masks.full/left/right.hcmask).
- --mask-sample: How many literal prefixes/suffixes to sample for mask hybrid combos (default: 500).
- -v, --verbose: Verbose logging (DEBUG).

Output files
- SMART_prefix_suffix.rule
  - The main optimized ruleset containing generated combos and a few classic toggles and rules.
- ONERULE_bonus.rule (optional)
  - A “toggles-on-their-own-lines” bonus ruleset useful when enabling toggles independently.
- masks.full.hcmask (optional)
  - Pure mask attacks (no wordlist).
- masks.right.hcmask (optional)
  - Append masks intended for hybrid append attacks (-a 6).
- masks.left.hcmask (optional)
  - Prepend masks intended for hybrid prepend attacks (-a 7).
- Cache file (configurable)
  - Stores per-input-file signatures and extracted fragments to accelerate incremental runs.

Mask generation
- Numeric mask patterns are configurable and include common digit patterns like `?d?d`, `?d?d?d`, etc.
- The tool will attempt to convert literal token sequences into mask literals (e.g., `^f ^a ^m` -> `fam`) and escape characters that interfere with mask syntax.
- Mask files are emitted atomically and include a mixture of numeric-only masks and hybrids that combine numeric masks with literal prefixes/suffixes.

Cache behavior
- The tool computes a stable signature per source file using a SHA-256 content hash plus size and mtime.
- If hashing fails for some reason, it falls back to a size/mtime stat-only signature so caching still provides benefit.
- Cache is written atomically to the configured cache file at the end of processing.

Performance & tuning
- Threaded parsing is used to speed up I/O-bound work; tune --threads for your machine.
- Keep the COMBO_LIMIT and keep-prefixes/keep-suffixes settings reasonable (defaults aim to be practical).
- MAX_RULE_TOKENS protects against producing overly long rules.
- Use --mask-sample to limit the number of literal sequences sampled to generate hybrid mask lines.

Example workflows
- Fast rule refresh after adding a few rule files:
  - Add new `.rule` files to the rules directory and re-run; cache will avoid reprocessing unchanged files.
- Generate compact ruleset for distributed cracking:
  - Run with default limits to create SMART_prefix_suffix.rule and use `-O` in hashcat to enable optimized rules:
    ```bash
    hashcat -a 0 -w 3 -O -m 0 hashes.txt wordlist.txt -r optimized_rules/SMART_prefix_suffix.rule
    ```
- Hybrid attacks using generated masks:
    ```bash
    # append masks to words (-a 6)
    hashcat -a 6 -m 0 hashes.txt wordlist.txt -m optimized_rules/masks.right.hcmask

    # prepend masks to words (-a 7)
    hashcat -a 7 -m 0 hashes.txt wordlist.txt -m optimized_rules/masks.left.hcmask

    # pure mask attack (example)
    hashcat -a 3 -m 0 hashes.txt ?d?d?d?d
    ```

Contributing
Contributions are welcome. Good contributions include:
- Bug reports with reproduction steps.
- Small focused pull requests adding tests, improvements, or documentation.
- Suggestions for additional mask patterns or rule heuristics.

Suggested workflow:
1. Fork the repository.
2. Create a feature branch and add tests where applicable.
3. Open a pull request with a clear description of intent and rationale.

Troubleshooting
- "No .rule files found": Ensure you passed a valid directory or `.rule` file path and that files have `.rule` extension.
- "Cache corrupted or unreadable": The tool will rebuild the cache automatically. You can also remove the cache file to force a fresh scan.
- "Failed to write ...": Check permissions for the output and cache directories.

Security and ethics
This tool is intended for legitimate security testing and research. Always have explicit authorization before attempting to crack or test password security. Using these techniques without consent is illegal and unethical.

License
No license file is included in this repository. To make usage and contribution terms explicit, add a LICENSE file (e.g., MIT, Apache-2.0) at the repository root.

Acknowledgements
- Thanks to the Hashcat community and rule authors whose work inspired the heuristics and combos implemented here.

Contact
For questions or feedback, open an issue on the repository or contact the maintainer via GitHub.

```
