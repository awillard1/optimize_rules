#!/usr/bin/env python3
"""
optimize_rules.py

SMART Rule Optimizer – full updated script with optional mask emission

Features:
- Collect prefixes/suffixes/patterns from many .rule files (parallel)
- Robust cache (content hash fallback to stat)
- Controlled combo rule generation with diagnostics
- ONERULE bonus file (toggles written on their own lines)
- Optional mask files for hashcat (.hcmask): masks.full.hcmask, masks.right.hcmask, masks.left.hcmask
- Verbose logging (use --verbose)
- Safe atomic writes for outputs and cache

Usage:
    python3 optimize_rules.py /path/to/rules/dir -o optimized_rules --emit-masks --mask-sample 500 --verbose
"""

from __future__ import annotations

import argparse
import json
import hashlib
import logging
import os
import re
import sys
from collections import defaultdict, OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

# ----------------------------
# DEFAULT CONFIG
# ----------------------------
DEFAULT_OUTPUT_DIR = Path("optimized_rules")
DEFAULT_CACHE_DIR = Path.home() / ".cache" / "optimize_rules"
DEFAULT_CACHE_FILE = DEFAULT_CACHE_DIR / "cache.json"

MAX_RULE_TOKENS = 14               # maximum number of tokens in a rule to keep
KEEP_TOP_PREFIXES = 25000
KEEP_TOP_SUFFIXES = 25000
COMBO_LIMIT = 180                  # cap per prefix/suffix when generating combos
ADD_ONERULE_STYLE = True
THREADS = min(32, (os.cpu_count() or 4) * 4)

# Masks defaults
MASK_SAMPLE_DEFAULT = 500
MASK_NUMERIC_PATTERNS = ["?d?d", "?d?d?d", "?d?d?d?d", "?l?l?l?d?d"]

# Regexes for token validation
TOKEN_RE = re.compile(r"""
    ^
    (?:
        \^[A-Za-z] |                # prefix token: ^a
        \$[\dA-Za-z!@#%\^&\*\?] |  # suffix-like token: $0-9 or letter or special single symbol
        :\s*\S+ |                  # toggle operator starting with ':' (like ": l")
        [luc] |                    # single char toggles
        T\d+ |                     # Tn toggles
        s[aeio][^\s]* |            # substitution-ish tokens like sa@, se3
        .                          # allow other tokens but validated later minimally
    )
    $
""", re.X)

# ----------------------------
# Utilities
# ----------------------------
def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format="%(asctime)s %(levelname)s: %(message)s",
        level=level,
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def atomic_write(path: Path, data: str, encoding: str = "utf-8") -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(tmp, "w", encoding=encoding) as f:
        f.write(data)
    tmp.replace(path)


def file_signature(path: Path) -> Optional[str]:
    """Return a stable signature for a file.
    Try full content sha256 + size + mtime. If hashing fails, fall back to size+mtime so caching still works."""
    try:
        stat = path.stat()
    except Exception:
        return None

    try:
        hasher = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(8 * 1024 * 1024), b""):
                hasher.update(chunk)
        return f"{hasher.hexdigest()}_{stat.st_size}_{int(stat.st_mtime)}"
    except Exception:
        # Fallback: use stat-only signature so we can still detect unchanged files when hashing fails
        return f"stat_{stat.st_size}_{int(stat.st_mtime)}"


def normalize_rule_line(line: str) -> Optional[Tuple[str, str]]:
    """Normalize a rule line for deduplication/pattern detection.
    Returns (normalized_key, original_rule_tokens_joined) or None for ignorable lines."""
    raw = line.strip()
    if not raw:
        return None
    if raw.startswith("#"):
        return None
    if raw == ":":
        return None

    parts = raw.split()
    if not parts:
        return None
    if len(parts) > MAX_RULE_TOKENS:
        return None

    joined = " ".join(parts)
    joined = re.sub(r'(\$\d(?:\s+)){3}\$\d', '$YEAR4', joined)
    joined = re.sub(r'(\$\d(?:\s+)){1,2}\$\d', '$YEAR2', joined)
    joined = re.sub(r'\$[!\@\#\$\%\^&\*\?]{1,}', '$SYM', joined)
    joined = re.sub(r'\^[A-Za-z]\b', '^X', joined)
    joined = re.sub(r'\$\d\b', '$N', joined)
    joined = re.sub(r's[a-zA-Z0-9]+', 'sX', joined)

    return joined, " ".join(parts)


# ----------------------------
# Processing single file
# ----------------------------
def process_rule_file(path: Path, cache: Dict, verbose: bool = False) -> Tuple[Dict[str, int], Dict[str, int], Set[str]]:
    prefixes: Dict[str, int] = defaultdict(int)
    suffixes: Dict[str, int] = defaultdict(int)
    patterns: Set[str] = set()

    if not path.exists():
        logging.warning("File not found: %s", path)
        return prefixes, suffixes, patterns

    sig = file_signature(path)
    key = str(path.resolve())

    # If signature exists and matches cache, return cached data
    if sig and key in cache and cache[key].get("sig") == sig:
        d = cache[key]["data"]
        logging.debug("Cache hit: %s", path.name)
        return defaultdict(int, d.get("prefixes", {})), defaultdict(int, d.get("suffixes", {})), set(d.get("patterns", []))

    logging.debug("Cache miss or changed: %s (sig=%s)", path.name, sig)
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for raw in fh:
                norm = normalize_rule_line(raw)
                if not norm:
                    continue
                norm_key, orig = norm
                patterns.add(norm_key)
                parts = orig.split()
                # Extract contiguous prefix tokens from start: ^a ^b ...
                pref = []
                for t in parts:
                    if t.startswith("^") and len(t) == 2 and t[1].isalpha():
                        pref.append(t)
                    else:
                        break
                if pref:
                    prefixes[" ".join(pref)] += 1

                # Extract contiguous suffix tokens from end: $1 $2 $! ...
                suff = []
                for t in reversed(parts):
                    if t.startswith("$") and len(t) == 2 and (t[1].isdigit() or t[1].isalpha() or t[1] in "!@#$%^&*?"):
                        suff.append(t)
                    else:
                        break
                if suff:
                    suffixes[" ".join(reversed(suff))] += 1
    except Exception as exc:
        logging.warning("Error reading %s: %s", path, exc)

    # Update in-memory cache (main will persist once)
    cache[key] = {
        "sig": sig,
        "data": {
            "prefixes": dict(prefixes),
            "suffixes": dict(suffixes),
            "patterns": list(patterns),
        }
    }

    if verbose:
        logging.debug("[%s] prefixes=%d suffixes=%d patterns=%d", path.name, len(prefixes), len(suffixes), len(patterns))

    return prefixes, suffixes, patterns


# ----------------------------
# Rule generation helpers
# ----------------------------
def validate_token(token: str) -> bool:
    """Lightweight validation of a single token."""
    if TOKEN_RE.match(token):
        return True
    if token.startswith("$") or token.startswith("^") or token.startswith(":") or token.startswith("s"):
        return True
    return False


def join_tokens(tokens: Iterable[str]) -> str:
    return " ".join(tokens)


def generate_year_tokens_2digit(year_two: str) -> List[str]:
    return [f"${d}" for d in year_two]


def build_combo_rules(prefixes: List[str], suffixes: List[str], combo_limit: int) -> Tuple[List[str], Dict[str, int]]:
    """
    Build a safe set of combo rules using prefixes/suffixes and year patterns.
    Returns (rules_list, diagnostics_dict).
    Diagnostics include counts for candidates, added, dups, bad_token, too_long.
    """
    rules: List[str] = []
    seen: Set[str] = set()

    # diagnostic counters
    diag = {
        "candidates": 0,
        "added": 0,
        "dup": 0,
        "bad_token": 0,
        "too_long": 0,
    }

    years_2d = [f"{i:02d}" for i in range(0, 26)]
    years_00_99 = [f"{i:02d}" for i in range(0, 100)]

    def maybe_add(tokens: List[str]) -> None:
        diag["candidates"] += 1
        line = join_tokens(tokens)
        if not line:
            return
        if line in seen:
            diag["dup"] += 1
            return
        if any(not validate_token(t) for t in tokens):
            diag["bad_token"] += 1
            return
        if len(tokens) > MAX_RULE_TOKENS:
            diag["too_long"] += 1
            return
        seen.add(line)
        rules.append(line)
        diag["added"] += 1

    # PREFIX + 2-digit YEAR combos (limited)
    for p in prefixes[:combo_limit]:
        pref_tokens = p.split() if p.strip() else []
        for y in years_2d:
            maybe_add(pref_tokens + generate_year_tokens_2digit(y))

    # PREFIX + SHORT NUM SEQ (123 / 1234)
    for p in prefixes[:combo_limit]:
        pref_tokens = p.split() if p.strip() else []
        maybe_add(pref_tokens + ["$1", "$2", "$3"])
        maybe_add(pref_tokens + ["$1", "$2", "$3", "$4"])

    # YEAR + SUFFIX combos
    for s in suffixes[:combo_limit]:
        suf_tokens = s.split() if s.strip() else []
        for y in years_2d:
            maybe_add(generate_year_tokens_2digit(y) + suf_tokens)

    # ALL 2-digit years + SUFFIXES (broader)
    for s in suffixes[:combo_limit]:
        suf_tokens = s.split() if s.strip() else []
        for y in years_00_99:
            maybe_add([f"${y[0]}", f"${y[1]}"] + suf_tokens)

    # 20xx! style (2000-2040)
    for s in suffixes[:combo_limit]:
        suf_tokens = s.split() if s.strip() else []
        for year in range(2000, 2041):
            y_str = str(year)
            maybe_add([f"${d}" for d in y_str] + ["$!"] + suf_tokens)

    # Some classic standalone append rules (hot suffixes)
    classic = [
        ["$1", "$2", "$3"],
        ["$1", "$2", "$3", "$4"],
        ["$1", "$2", "$3", "$4", "$5"],
        ["$1", "$2", "$3", "$4", "$5", "$6"],
        ["$2", "$0", "$2", "$5"],
        ["$2", "$0", "$2", "$4"],
        ["$2", "$0", "$2", "$3"],
        ["$!"],
        ["$@", "$#"]
    ]
    for t in classic:
        maybe_add(t)

    return rules, diag


# ----------------------------
# Convert token sequences to literal strings (for masks)
# ----------------------------
def tokens_to_literal(token_seq: str) -> Optional[str]:
    """
    Convert a token sequence like '$f $a $m $i $l $y' or '^f ^a ^m' into a literal 'family' or 'fam'.
    Returns None if tokens contain non-single-char tokens or unexpected forms.
    """
    parts = token_seq.split()
    chars = []
    for p in parts:
        if (p.startswith("$") or p.startswith("^")) and len(p) == 2:
            chars.append(p[1])
        else:
            return None
    return "".join(chars)


def escape_mask_literal(s: str) -> str:
    """
    Escape characters in literals that would be interpreted as mask tokens.
    We escape only backslash and question mark and spaces.
    """
    return s.replace("\\", "\\\\").replace("?", "\\?").replace(" ", "\\ ")


# ----------------------------
# ONERULE bonus generation (toggles on their own lines)
# ----------------------------
def generate_onerule_file(output: Path, top_prefixes: List[str], top_suffixes: List[str], toggles: str, limits: Dict[str, int]) -> int:
    """Create ONERULE-style bonus file with toggles on their own lines."""
    count = 0
    lines: List[str] = []
    toggles_tokens = toggles.split()

    max_suffixes = min(limits.get("suffixes", KEEP_TOP_SUFFIXES), len(top_suffixes))
    max_prefixes = min(limits.get("prefixes", 12000), len(top_prefixes))

    lines.append("# ONERULE_bonus.rule – suffix-heavy edition\n")
    lines.append(f"# Generated: {datetime.now().isoformat()}\n")
    lines.append("# Suffixes prioritized first (empirically effective)\n\n")

    # TOP SUFFIXES: write base rule, then base + each toggle on its own line
    lines.append("# === TOP SUFFIXES + TOGGLES ===\n")
    for s in top_suffixes[:max_suffixes]:
        s_clean = s.strip()
        if not s_clean:
            continue
        parts = s_clean.split()
        parts = [p if p.startswith("$") else f"${p}" for p in parts]
        rev = list(reversed(parts))
        base_tokens = rev
        # base line (no toggles)
        if all(validate_token(t) for t in base_tokens) and len(base_tokens) <= MAX_RULE_TOKENS:
            lines.append(join_tokens(base_tokens) + "\n")
            count += 1
        # base + single-toggle lines (one toggle per line)
        for tog in toggles_tokens:
            rule_tokens = base_tokens + [tog]
            if all(validate_token(t) for t in rule_tokens) and len(rule_tokens) <= MAX_RULE_TOKENS:
                lines.append(join_tokens(rule_tokens) + "\n")
                count += 1

    # TOP PREFIXES: write base line, then base + each toggle on its own line
    lines.append("\n# === TOP PREFIXES + TOGGLES ===\n")
    for p in top_prefixes[:max_prefixes]:
        p_clean = p.strip()
        if not p_clean:
            continue
        p_tokens = p_clean.split()
        # base line
        if all(validate_token(t) for t in p_tokens) and len(p_tokens) <= MAX_RULE_TOKENS:
            lines.append(join_tokens(p_tokens) + "\n")
            count += 1
        # per-toggle lines
        for tog in toggles_tokens:
            rule_tokens = p_tokens + [tog]
            if all(validate_token(t) for t in rule_tokens) and len(rule_tokens) <= MAX_RULE_TOKENS:
                lines.append(join_tokens(rule_tokens) + "\n")
                count += 1

    # Hot standalone suffixes: write base and base + single-toggle lines
    lines.append("\n# === Ultra-hot standalone suffix rules ===\n")
    hot_suffix_rules = [
        "$1 $2 $3", "$1 $2 $3 $4", "$1 $2 $3 $4 $5",
        "$1 $2 $3 $4 $5 $6 $7 $8", "$2 $0 $2 $5", "$2 $0 $2 $4",
        "$2 $0 $2 $3", "$2 $0 $2 $5 $!", "$!",
        "$! $!", "$@ $#", "$2 $3", "$1 $9 $9 $0", "$2 $0 $0 $0",
        "$0 $0 $0", "$1 $1 $1 $1", "$q $w $e $r $t $y", "$a $a $a",
        "$8 $8 $8 $8", "$9 $9 $9 $9", "$f $a $m $i $l $y", "$l $o $v $e",
        "$m $o $m", "$d $a $d", "$w $o $r $d"
    ]
    for r in hot_suffix_rules:
        tokens = r.split()
        # base
        if all(validate_token(t) for t in tokens) and len(tokens) <= MAX_RULE_TOKENS:
            lines.append(join_tokens(tokens) + "\n")
            count += 1
        # base + single-toggle lines
        for tog in toggles_tokens:
            rule_tokens = tokens + [tog]
            if all(validate_token(t) for t in rule_tokens) and len(rule_tokens) <= MAX_RULE_TOKENS:
                lines.append(join_tokens(rule_tokens) + "\n")
                count += 1

    try:
        atomic_write(output, "".join(lines))
        logging.info("ONERULE file written: %s (%d rules)", output, count)
    except Exception as exc:
        logging.warning("Failed to write ONERULE file: %s", exc)

    return count


# ----------------------------
# Mask generation
# ----------------------------
def generate_mask_files(output_dir: Path,
                        numeric_patterns: List[str],
                        top_prefixes: List[str],
                        top_suffixes: List[str],
                        sample_limit: int,
                        verbose: bool = False) -> Dict[str, int]:
    """
    Emit three mask files:
    - masks.full.hcmask : standalone masks (no wordlist)
    - masks.right.hcmask : masks appended to wordlist words (-a 6)
    - masks.left.hcmask  : masks prepended to wordlist words (-a 7)

    For prefix/suffix masks we only include those token sequences convertible to literal strings
    (e.g., '^a ^b' -> 'ab' or '$f $a $m' -> 'fam').
    Returns dict with counts written for each file.
    """
    out_counts = {"full": 0, "right": 0, "left": 0}
    full_path = output_dir / "masks.full.hcmask"
    right_path = output_dir / "masks.right.hcmask"
    left_path = output_dir / "masks.left.hcmask"

    full_lines: List[str] = []
    right_lines: List[str] = []
    left_lines: List[str] = []

    # Basic numeric/mixed full masks
    for m in numeric_patterns:
        full_lines.append(m + "\n")
        out_counts["full"] += 1

    # Convert top prefixes/suffixes to literal strings (if possible)
    literal_prefixes: List[str] = []
    literal_suffixes: List[str] = []

    for p in top_prefixes:
        lit = tokens_to_literal(p)
        if lit:
            literal_prefixes.append(lit)
            if len(literal_prefixes) >= sample_limit:
                break

    for s in top_suffixes:
        lit = tokens_to_literal(s)
        if lit:
            literal_suffixes.append(lit)
            if len(literal_suffixes) >= sample_limit:
                break

    if verbose:
        logging.debug("Mask generation: literal_prefixes=%d literal_suffixes=%d", len(literal_prefixes), len(literal_suffixes))

    # Right masks (append to word)
    # Include numeric masks and combinations like numeric + literal_suffix
    for m in numeric_patterns:
        right_lines.append(m + "\n")
        out_counts["right"] += 1
        for suf in literal_suffixes:
            escaped = escape_mask_literal(suf)
            right_lines.append(f"{m}{escaped}\n")
            out_counts["right"] += 1

    # Left masks (prepend to word)
    for m in numeric_patterns:
        left_lines.append(m + "\n")
        out_counts["left"] += 1
        for pref in literal_prefixes:
            escaped = escape_mask_literal(pref)
            left_lines.append(f"{escaped}{m}\n")
            out_counts["left"] += 1

    # Write atomically
    try:
        atomic_write(full_path, "".join(full_lines))
        atomic_write(right_path, "".join(right_lines))
        atomic_write(left_path, "".join(left_lines))
        logging.info("Mask files written: %s (%d), %s (%d), %s (%d)",
                     full_path, out_counts["full"], right_path, out_counts["right"], left_path, out_counts["left"])
    except Exception as exc:
        logging.warning("Failed to write mask files: %s", exc)

    return out_counts


# ----------------------------
# MAIN
# ----------------------------
def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="SMART Rule Optimizer – collect rule fragments and generate optimized combos")
    parser.add_argument("input", help="Path to a .rule file or a directory containing .rule files")
    parser.add_argument("-o", "--output", default=str(DEFAULT_OUTPUT_DIR), help="Output directory (default: optimized_rules)")
    parser.add_argument("--cache", default=str(DEFAULT_CACHE_FILE), help="Cache file path (default: ~/.cache/optimize_rules/cache.json)")
    parser.add_argument("--keep-prefixes", type=int, default=KEEP_TOP_PREFIXES, help="How many top prefixes to keep")
    parser.add_argument("--keep-suffixes", type=int, default=KEEP_TOP_SUFFIXES, help="How many top suffixes to keep")
    parser.add_argument("--combo-limit", type=int, default=COMBO_LIMIT, help="Limit combos per prefix/suffix when generating")
    parser.add_argument("--no-onerule", action="store_true", help="Do not create ONERULE bonus file")
    parser.add_argument("--threads", type=int, default=THREADS, help="Worker threads for parsing files")
    parser.add_argument("--emit-masks", action="store_true", help="Emit mask files for hashcat (masks.full/left/right.hcmask)")
    parser.add_argument("--mask-sample", type=int, default=MASK_SAMPLE_DEFAULT, help=f"How many literal prefixes/suffixes to sample for mask hybrid combos (default: {MASK_SAMPLE_DEFAULT})")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging (DEBUG)")
    args = parser.parse_args(argv)

    setup_logging(args.verbose)

    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    cache_file = Path(args.cache)
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        if cache_file.exists():
            with open(cache_file, "r", encoding="utf-8") as cf:
                cache = json.load(cf)
            logging.debug("Loaded cache entries: %d", len(cache))
        else:
            cache = {}
    except Exception:
        logging.info("Cache corrupted or unreadable, rebuilding.")
        cache = {}

    input_path = Path(args.input)
    rule_files: List[Path] = []
    if input_path.is_dir():
        rule_files = sorted([p for p in input_path.rglob("*.rule")])
    elif input_path.is_file():
        rule_files = [input_path]
    else:
        logging.error("Input path does not exist: %s", input_path)
        return 2

    if not rule_files:
        logging.error("No .rule files found under: %s", input_path)
        return 2

    logging.info("Found %d .rule files", len(rule_files))

    aggregated_prefixes: Dict[str, int] = defaultdict(int)
    aggregated_suffixes: Dict[str, int] = defaultdict(int)
    aggregated_patterns: Set[str] = set()

    # Process files in parallel (IO-bound). process_rule_file updates in-memory cache but does not persist it.
    with ThreadPoolExecutor(max_workers=max(2, args.threads)) as ex:
        futures = {ex.submit(process_rule_file, p, cache, args.verbose): p for p in rule_files}
        for fut in as_completed(futures):
            p = futures[fut]
            try:
                pref, suff, pats = fut.result()
                for k, v in pref.items():
                    aggregated_prefixes[k] += v
                for k, v in suff.items():
                    aggregated_suffixes[k] += v
                aggregated_patterns.update(pats)
            except Exception as exc:
                logging.warning("Failed to process %s: %s", p, exc)

    # Persist cache once (atomic) after all processing completes
    try:
        atomic_write(cache_file, json.dumps(cache, indent=2))
        logging.debug("Persisted cache entries: %d", len(cache))
    except Exception as exc:
        logging.debug("Failed to persist cache: %s", exc)

    logging.info("Unique logical patterns : %d", len(aggregated_patterns))
    logging.info("Unique real prefixes    : %d", len(aggregated_prefixes))
    logging.info("Unique real suffixes    : %d", len(aggregated_suffixes))

    top_prefixes = [p for p, _ in sorted(aggregated_prefixes.items(), key=lambda x: -x[1])[: args.keep_prefixes]]
    top_suffixes = [s for s, _ in sorted(aggregated_suffixes.items(), key=lambda x: -x[1])[: args.keep_suffixes]]

    logging.info("Top prefixes chosen: %d  Top suffixes chosen: %d", len(top_prefixes), len(top_suffixes))

    # Build main SMART file
    main_file = out_dir / "SMART_prefix_suffix.rule"
    header_lines = [
        "# SMART Optimized Prefix/Suffix + Year Ruleset\n",
        f"# Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n",
        f"# From {len(rule_files)} input file(s) -> {len(aggregated_patterns):,} unique patterns analyzed\n",
        f"# Top {len(top_prefixes):,} prefixes + {len(top_suffixes):,} suffixes kept\n",
        "# 100% valid for Hashcat (-O optimized)\n\n",
    ]

    combo_rules, diag = build_combo_rules(top_prefixes, top_suffixes, args.combo_limit)
    logging.info("Combo generator produced %d candidate rules (added=%d dup=%d bad_token=%d too_long=%d)",
                 diag["candidates"], diag["added"], diag["dup"], diag["bad_token"], diag["too_long"])
    if args.verbose:
        logging.debug("Diagnostics detail: %s", diag)

    # Build a deterministic ordered set of lines (preserve header, then combos, then some toggles/hot rules)
    unique_rules_ordered: "OrderedDict[str, None]" = OrderedDict()
    for r in combo_rules:
        unique_rules_ordered[r] = None

    # Add some classic standalone rules and simple toggles/substitutions (kept short and valid)
    classic_simple = [
        ": l", ": u", ": c",
        ": T0", ": T1", ": T2",
        ": sa@", ": se3", ": si1", ": so0",
    ]
    for c in classic_simple:
        unique_rules_ordered[c] = None

    try:
        lines_out = header_lines + [r + "\n" for r in unique_rules_ordered.keys()]
        atomic_write(main_file, "".join(lines_out))
        logging.info("Main ruleset written: %s (%d rules)", main_file, len(unique_rules_ordered))
    except Exception as exc:
        logging.error("Failed to write main ruleset: %s", exc)
        return 3

    # Optionally write ONERULE bonus
    if not args.no_onerule and ADD_ONERULE_STYLE and top_prefixes:
        onerule_file = out_dir / "ONERULE_bonus.rule"
        toggles = "l u c sa@ se3 si1 so0 T0 T1 T2 T3 T4 T5 T6 T7 T8 T9"
        limits = {"suffixes": min(args.keep_suffixes, 25000), "prefixes": 12000}
        generate_onerule_file(onerule_file, top_prefixes, top_suffixes, toggles, limits)

    # Optionally emit masks
    mask_counts = {}
    if args.emit_masks:
        mask_counts = generate_mask_files(out_dir, MASK_NUMERIC_PATTERNS, top_prefixes, top_suffixes, args.mask_sample, args.verbose)

    total_rules_written = len([l for l in unique_rules_ordered.keys() if l and not l.startswith("#")])
    print("\n[+] ALL DONE")
    print(f"    Main ruleset  → {main_file} ({total_rules_written:,} rules)")
    if not args.no_onerule and ADD_ONERULE_STYLE and top_prefixes:
        print(f"    ONERULE bonus  → {out_dir / 'ONERULE_bonus.rule'}")
    if args.emit_masks:
        print(f"    Masks (full)   → {out_dir / 'masks.full.hcmask'} ({mask_counts.get('full',0):,})")
        print(f"    Masks (right)  → {out_dir / 'masks.right.hcmask'} ({mask_counts.get('right',0):,})")
        print(f"    Masks (left)   → {out_dir / 'masks.left.hcmask'} ({mask_counts.get('left',0):,})")
    print(f"    Cache file     → {cache_file}")
    print("\nRecommended usage examples:")
    print(f"    hashcat -a 0 -w 3 -O -m 0 hashes.txt wordlist.txt -r {main_file}")
    if args.emit_masks:
        print("    # Right hybrid (append masks to words):")
        print(f"    hashcat -a 6 -m 0 hashes.txt wordlist.txt -m {out_dir / 'masks.right.hcmask'}")
        print("    # Left hybrid (prepend masks to words):")
        print(f"    hashcat -a 7 -m 0 hashes.txt wordlist.txt -m {out_dir / 'masks.left.hcmask'}")
        print("    # Pure mask attack examples (use masks.full.hcmask or individual masks):")
        print(f"    hashcat -a 3 -m 0 hashes.txt -w 3 ?d?d?d?d")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        raise