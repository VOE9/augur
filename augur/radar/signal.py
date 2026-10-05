"""Signal strategy hierarchy. Every concrete Signal is a pure, deterministic
regex/keyword check against one commit -- no model, no invented facts.
Ported from silent-patch-finder's already-debugged heuristics (same
keyword lists, same weights, same known-fixed false-positive guards for
translation files and 'feat:' commits) rather than re-derived from
scratch, since re-deriving proven logic risks reintroducing bugs that
were already found and fixed there."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
import re

from .commit import Commit

LOUD_DISCLOSURE_KEYWORDS = [
    "cve-", "security fix", "security patch", "security vulnerability",
    "vulnerability", "exploit", "xss", "sqli", "sql injection", "rce",
    "remote code execution", "privilege escalation", "ghsa-", "cwe-",
]

# Keywords that are acronyms must match as whole words. Matching them as raw
# substrings made the loud-disclosure filter drop ordinary English words that
# merely contain the letters: "resource", "sources" and "force" all contain
# "rce", so every commit mentioning a resource, a source tree or a forced
# reallocation was excluded from the scan as if it had announced a security
# fix. That is silent loss of coverage, and it is the wrong direction: the
# whole purpose of this filter is to skip commits that are NOT what the radar
# is looking for, so a false positive here discards real candidates with no
# trace. Confirmed by running the filter over plain commit subjects.
_LOUD_WORD_BOUNDARY_KEYWORDS = {"rce", "xss", "sqli"}
# Phrases and hyphenated forms are already anchored by their separators, so
# substring matching is correct for them and no boundary is applied.
_LOUD_PHRASE_KEYWORDS = [kw for kw in LOUD_DISCLOSURE_KEYWORDS if kw not in _LOUD_WORD_BOUNDARY_KEYWORDS]

VAGUE_MESSAGE_MARKERS = [
    "cleanup", "clean up", "minor fix", "minor change", "misc fix",
    "tidy", "polish", "small fix", "small change", "update", "improve",
    "improvement", "refactor", "tweak", "adjust", "housekeeping",
]

DEFENSIVE_CALL_KEYWORDS = [
    "authoriz", "permission", "canaccess", "hasaccess", "isadmin",
    "checktoken", "validate", "sanitiz", "escape", "htmlspecialchars",
    "parameteriz", "bind_param", "preparedstatement", "constanttimecompare",
    "compare_digest", "hmac.compare", "path.clean", "filepath.abs",
    "realpath", "os.path.abspath", "startswith(base", "verifysignature",
    "checkorigin", "csrftoken", "ratelimit", "escapeshellarg",
]

DANGEROUS_SINK_KEYWORDS = [
    "os.system(", "exec(", "eval(", "subprocess.call(", "shell=true",
    " query(\"", " query('", "unmarshal(", "pickle.loads(", "yaml.load(",
    "readfile(", "include(", "require(",
]

# Experimental C/C++ memory-safety vocabulary. This is opt-in so the default
# Radar remains an unchanged baseline for comparison.
MEMORY_SAFETY_RE = re.compile(
    r"\b(null|nullptr|size|len|length|count|capacity|alloc|malloc|calloc|"
    r"realloc|memcpy|memmove|strcpy|strncpy|snprintf|free|overflow|"
    r"underflow|bound)\b",
    re.IGNORECASE,
)
MEMORY_GUARD_RE = re.compile(
    r"\b(if|else|assert|return|check|validate|guard|prevent|avoid)\b"
    r"|(?:!=|==|<=|>=|<|>)",
    re.IGNORECASE,
)
C_CPP_SUFFIXES = {".c", ".h", ".cc", ".hh", ".cpp", ".hpp", ".cxx", ".hxx"}

STRONG_SENSITIVE_PATH_KEYWORDS = [
    "auth", "login", "session", "password", "secret", "crypto", "cipher",
    "jwt", "oauth", "saml", "acl", "deserial", "unmarshal", "sanitiz",
    "ssrf", "csrf", "cors", "token", "xml",
]
WEAK_SENSITIVE_PATH_KEYWORDS = [
    "permission", "access", "upload", "parse", "escape", "validat", "sql",
    "query", "exec", "eval", "template", "redirect", "proxy", "admin",
    "middleware",
]

NON_FIX_CONVENTIONAL_TYPES = {"feat", "feature"}


def is_loudly_disclosed(commit: Commit) -> bool:
    """True if the commit already announces itself as security-relevant --
    out of scope for a tool whose whole point is finding UNannounced fixes."""
    lowered = commit.message.lower()
    if any(kw in lowered for kw in _LOUD_PHRASE_KEYWORDS):
        return True
    words = set(re.findall(r"[a-z0-9]+", lowered))
    return any(kw in words for kw in _LOUD_WORD_BOUNDARY_KEYWORDS)


@dataclass(frozen=True)
class SignalResult:
    name: str
    weight: float
    fired: bool
    detail: str


class Signal(ABC):
    """One heuristic vote. `weight` is the score contributed when fired;
    `evaluate` never raises for malformed input -- worst case is a
    correctly-not-fired result, never an exception that aborts a scan."""

    name: str
    weight: float

    @abstractmethod
    def evaluate(self, commit: Commit) -> SignalResult: ...


class SensitivePathSignal(Signal):
    """Fires when a commit touches a file whose path names a security-sensitive
    area.

    `keyword_frequencies` is an optional map of keyword -> the fraction of
    commits in the scanned window that touch a path matching it. When given,
    a keyword that matches nearly every commit is discounted, because it
    carries no information about this commit.

    That discount is not a guess. Measured on real clones: in openssl the
    keyword `crypto` matches 642 changed paths across a 400-commit window,
    598 of them under the single `crypto/` directory the entire project lives
    in, and this signal fired on 132 of openssl's 138 candidates -- 96% of
    the report, saying nothing. A keyword that appears in most commits is a
    fact about the repository's layout, not about any one fix.

    The discount only applies when a window large enough to estimate from is
    available; below that the signal behaves exactly as it always did.
    """
    name = "sensitive_path"
    weight = 1.5

    # Calibrated on measured per-keyword frequencies across eight real
    # projects, 400 commits each:
    #
    #   openssl  crypto   30.5% of commits   -> 0.00  (the whole project
    #                                              lives under crypto/)
    #   libpng   auth     10.0%             -> 1.00
    #   sqlite   sql       6.3%             -> 1.00
    #   curl     auth      2.5%             -> 1.00
    #
    # The two marks bracket that gap. This is a calibration over eight
    # projects, not a law: a project where a genuinely security-critical
    # area occupies 30% of its commits will have that keyword ignored.
    # That trade is deliberate -- ignoring it produces a report where a
    # third of every project's commits qualify, which is not a report.
    LOW_FREQUENCY = 0.10
    HIGH_FREQUENCY = 0.30

    def __init__(self, keyword_frequencies: dict[str, float] | None = None):
        self.keyword_frequencies = dict(keyword_frequencies or {})

    def frequency_multiplier(self, keyword: str) -> float:
        frequency = self.keyword_frequencies.get(keyword)
        if frequency is None:
            return 1.0
        if frequency <= self.LOW_FREQUENCY:
            return 1.0
        if frequency >= self.HIGH_FREQUENCY:
            return 0.0
        span = self.HIGH_FREQUENCY - self.LOW_FREQUENCY
        return (self.HIGH_FREQUENCY - frequency) / span

    def evaluate(self, commit: Commit) -> SignalResult:
        matched_files, matched_keywords, strong_hit = [], set(), False
        discounted = set()
        for f in commit.changed_files:
            lowered = f.filename.lower()
            hits = [kw for kw in STRONG_SENSITIVE_PATH_KEYWORDS + WEAK_SENSITIVE_PATH_KEYWORDS if kw in lowered]
            if not hits:
                continue
            matched_files.append(f.filename)
            for kw in hits:
                if self.frequency_multiplier(kw) == 0.0:
                    discounted.add(kw)
                else:
                    matched_keywords.add(kw)
            if any(
                kw in STRONG_SENSITIVE_PATH_KEYWORDS
                and self.frequency_multiplier(kw) > 0.0
                for kw in hits
            ):
                strong_hit = True

        weak_matches = matched_keywords & set(WEAK_SENSITIVE_PATH_KEYWORDS)
        # A single generic/weak word alone is too weak (e.g. "proxy" in a
        # codebase organized entirely around proxying); require either one
        # strong specific keyword, or two distinct weak ones corroborating.
        fired = strong_hit or len(weak_matches) >= 2

        if fired:
            detail = f"{len(matched_files)} file(s) touch sensitive paths (matched: {', '.join(sorted(matched_keywords))})"
        elif matched_files and discounted and not matched_keywords:
            detail = (
                f"Only keywords that match nearly every commit in this window "
                f"({', '.join(sorted(discounted))}) -- no evidence about this commit."
            )
        elif matched_files:
            detail = f"Only one generic keyword matched ({', '.join(sorted(matched_keywords))}) -- too weak alone."
        else:
            detail = "No file paths matched a sensitive-area keyword."
        return SignalResult(self.name, self.weight, fired, detail)


class DefensiveDiffShapeSignal(Signal):
    name = "defensive_diff_shape"
    weight = 1.5

    def evaluate(self, commit: Commit) -> SignalResult:
        added = commit.added_lines().lower()
        removed = commit.removed_lines().lower()
        added_hits = sorted({kw for kw in DEFENSIVE_CALL_KEYWORDS if kw in added})
        sink_removed_hits = sorted({kw for kw in DANGEROUS_SINK_KEYWORDS if kw in removed})

        fired = bool(added_hits) or bool(sink_removed_hits)
        parts = []
        if added_hits:
            parts.append(f"added line(s) call {', '.join(added_hits)}")
        if sink_removed_hits:
            parts.append(f"removed line(s) had {', '.join(sink_removed_hits)}")
        detail = "; ".join(parts) if fired else "No defensive-shaped diff pattern matched."
        return SignalResult(self.name, self.weight, fired, detail)


class VagueMessageSignal(Signal):
    """The flagship signal: a diff that LOOKS defensive, paired with a
    message that does not say so. Depends on DefensiveDiffShapeSignal's
    result, passed in rather than recomputed -- see RadarEngine."""

    name = "vague_message_defensive_diff"
    weight = 3.0

    def evaluate(self, commit: Commit, diff_shape_fired: bool = False) -> SignalResult:
        if not diff_shape_fired:
            return SignalResult(self.name, self.weight, False, "Skipped: no defensive diff shape to compare against.")
        if commit.conventional_type() in NON_FIX_CONVENTIONAL_TYPES:
            return SignalResult(
                self.name, self.weight, False,
                "Commit is explicitly typed as a new feature ('feat:') -- nothing prior to silently correct.",
            )
        lowered = commit.message.lower()
        first_line = commit.subject.lower()
        mentions_defense = any(kw in lowered for kw in ("fix", "secur", "safe", "guard", "protect", "validat", "sanitiz"))
        is_vague = any(marker in first_line for marker in VAGUE_MESSAGE_MARKERS)

        fired = is_vague or not mentions_defense
        if fired:
            detail = f"Diff looks defensive but message ('{commit.subject[:80]}') "
            detail += "uses a downplaying phrase " if is_vague else ""
            detail += "and never uses a fix/security-adjacent word" if not mentions_defense else ""
        else:
            detail = "Diff looks defensive and the message plainly says so -- not silent."
        return SignalResult(self.name, self.weight, fired, detail.strip())


class SmallFocusedDiffSignal(Signal):
    name = "small_focused_diff"
    weight = 0.5

    def evaluate(self, commit: Commit) -> SignalResult:
        n_files = len(commit.changed_files)
        n_lines = commit.total_changed_lines()
        fired = 0 < n_files <= 3 and 0 < n_lines <= 40
        detail = f"{n_files} file(s), {n_lines} line(s) changed"
        detail += " -- small and focused." if fired else " -- too broad or too small for a single targeted patch."
        return SignalResult(self.name, self.weight, fired, detail)


class MemorySafetyDiffSignal(Signal):
    """Opt-in signal for added C/C++ memory-safety guards.

    A commit fires when added source lines contain at least one memory/size
    token and at least one guard/comparison token. The rule is transparent and
    intentionally isolated from the default Radar baseline.
    """

    name = "memory_safety_diff"
    weight = 1.5

    def evaluate(self, commit: Commit) -> SignalResult:
        added = commit.added_lines_for_suffixes(C_CPP_SUFFIXES)
        memory_lines = [line for line in added.splitlines() if MEMORY_SAFETY_RE.search(line)]
        guard_lines = [line for line in added.splitlines() if MEMORY_GUARD_RE.search(line)]
        fired = bool(memory_lines and guard_lines)
        if fired:
            detail = (
                f"added source lines contain {len(memory_lines)} memory-safety line(s) "
                f"and {len(guard_lines)} guard/comparison line(s)"
            )
        else:
            detail = "No added source-line combination matched memory-safety plus guard vocabulary."
        return SignalResult(self.name, self.weight, fired, detail)
