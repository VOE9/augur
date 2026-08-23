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

from .commit import Commit

LOUD_DISCLOSURE_KEYWORDS = [
    "cve-", "security fix", "security patch", "security vulnerability",
    "vulnerability", "exploit", "xss", "sqli", "sql injection", "rce",
    "remote code execution", "privilege escalation", "ghsa-", "cwe-",
]

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
    return any(kw in lowered for kw in LOUD_DISCLOSURE_KEYWORDS)


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
    name = "sensitive_path"
    weight = 1.5

    def evaluate(self, commit: Commit) -> SignalResult:
        matched_files, matched_keywords, strong_hit = [], set(), False
        for f in commit.changed_files:
            lowered = f.filename.lower()
            hits = [kw for kw in STRONG_SENSITIVE_PATH_KEYWORDS + WEAK_SENSITIVE_PATH_KEYWORDS if kw in lowered]
            if hits:
                matched_files.append(f.filename)
                matched_keywords.update(hits)
                if any(kw in STRONG_SENSITIVE_PATH_KEYWORDS for kw in hits):
                    strong_hit = True

        weak_matches = matched_keywords & set(WEAK_SENSITIVE_PATH_KEYWORDS)
        # A single generic/weak word alone is too weak (e.g. "proxy" in a
        # codebase organized entirely around proxying); require either one
        # strong specific keyword, or two distinct weak ones corroborating.
        fired = strong_hit or len(weak_matches) >= 2

        if fired:
            detail = f"{len(matched_files)} file(s) touch sensitive paths (matched: {', '.join(sorted(matched_keywords))})"
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
