"""The Commit entity: one git commit from a local clone, with the parsed
views (added lines, removed lines, touched files) the signal strategies
need. Parsing happens once, lazily, and is cached on the instance."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

_ADDED_LINE_RE = re.compile(r"^\+(?!\+\+)(.*)$", re.MULTILINE)
_REMOVED_LINE_RE = re.compile(r"^-(?!--)(.*)$", re.MULTILINE)
_DIFF_FILE_HEADER_RE = re.compile(r"^diff --git a/(.+?) b/(.+?)$", re.MULTILINE)

# Same restriction silent-patch-finder uses, and for the same reason: a
# translation-only commit (locale JSON updated via a translation service)
# can contain words like "escape" or "permission" as ordinary correctly
# translated UI text, not code -- confirmed as a real false positive
# during that tool's own development against go-gitea/gitea.
SOURCE_EXTENSIONS = {
    ".go", ".php", ".java", ".py", ".js", ".ts", ".rb", ".cs", ".kt",
    ".c", ".h", ".cc", ".cpp", ".hpp",
}


@dataclass(frozen=True)
class ChangedFile:
    filename: str

    def is_source_file(self) -> bool:
        return any(self.filename.endswith(ext) for ext in SOURCE_EXTENSIONS)


class Commit:
    """A single commit, read from `git log`/`git show` output."""

    def __init__(self, sha: str, message: str, author: str, date: str, raw_diff: str):
        self.sha = sha
        self.message = message
        self.author = author
        self.date = date
        self._raw_diff = raw_diff
        self._changed_files: list[ChangedFile] | None = None

    @property
    def subject(self) -> str:
        return self.message.splitlines()[0] if self.message else ""

    @property
    def changed_files(self) -> list[ChangedFile]:
        if self._changed_files is None:
            names = set()
            for m in _DIFF_FILE_HEADER_RE.finditer(self._raw_diff):
                names.add(m.group(2))
            self._changed_files = [ChangedFile(n) for n in sorted(names)]
        return self._changed_files

    def _source_diff_text(self) -> str:
        """Splits the raw diff back into per-file chunks and keeps only
        chunks for recognized source extensions, so binary/lockfile/
        translation noise never reaches a signal's regex."""
        chunks = re.split(r"(?=^diff --git )", self._raw_diff, flags=re.MULTILINE)
        kept = [c for c in chunks if any(f.filename in c for f in self.changed_files if f.is_source_file())]
        return "\n".join(kept)

    def added_lines(self) -> str:
        return "\n".join(_ADDED_LINE_RE.findall(self._source_diff_text()))

    def added_lines_for_suffixes(self, suffixes: set[str]) -> str:
        """Added lines from source files whose suffix is in ``suffixes``.

        Experimental language-specific signals use this to avoid treating
        ordinary words in documentation or another programming language as
        C/C++ memory-safety evidence.
        """
        chunks = re.split(r"(?=^diff --git )", self._raw_diff, flags=re.MULTILINE)
        kept = []
        for chunk in chunks:
            match = _DIFF_FILE_HEADER_RE.search(chunk)
            if not match:
                continue
            filename = match.group(2)
            if any(filename.lower().endswith(suffix.lower()) for suffix in suffixes):
                kept.append(chunk)
        return "\n".join(_ADDED_LINE_RE.findall("\n".join(kept)))

    def removed_lines(self) -> str:
        return "\n".join(_REMOVED_LINE_RE.findall(self._source_diff_text()))

    def total_changed_lines(self) -> int:
        text = self._source_diff_text()
        return len(_ADDED_LINE_RE.findall(text)) + len(_REMOVED_LINE_RE.findall(text))

    def conventional_type(self) -> str | None:
        match = re.match(r"^(\w+)(?:\([^)]*\))?!?:\s", self.subject, re.IGNORECASE)
        return match.group(1).lower() if match else None
