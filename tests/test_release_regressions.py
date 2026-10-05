"""Independent counterexamples for the pre-release correctness review."""
from pathlib import Path
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys

import pytest

from augur.harness.generator import DifferentialHarnessGenerator, UnsupportedSignatureError
from augur.harness.pipeline import HarnessPipeline, Verdict
from augur.harness.sanitizer_runner import SanitizerRunner
from augur.pattern.format_string_prefix import FormatStringPrefixDeriver
from augur.pattern.function_extractor import FunctionExtractor
from augur.pattern.unbounded_copy import UnboundedCopyDetector
from augur.provenance.introduction_finder import VulnerabilityIntroductionFinder
from augur.provenance.pipeline import ProvenancePipeline
from augur.radar.commit import Commit
from augur.radar.repository import GitRepository
from augur.radar.engine import RadarEngine


EXTRACTOR = FunctionExtractor(prefer_clang=False)
OLD = 'void f(const char *src, int n) { char b[8]; memcpy(b, src, 8); (void)n; }'
NEW = 'void f(const char *input, int count) { char b[8]; if (strlen(input) < 8) return; memcpy(b, input, 8); (void)count; }'
needs_gcc = pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc unavailable")
needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git unavailable")
PROJECT = Path(__file__).resolve().parents[1]


def generate(old=OLD, new=NEW, seed="ABCDEFGH"):
    a, b = EXTRACTOR.find_function(old, "f"), EXTRACTOR.find_function(new, "f")
    finding = UnboundedCopyDetector().find(a.full_text, {"src"})
    return DifferentialHarnessGenerator().generate(a, b, finding, seed, {"n": "0"})


@pytest.mark.parametrize("header", ["while (flag)", "for (; flag;)", "for (int i=0; i<flag; ++i)", "if (flag)"])
def test_conditional_guard_cannot_hide_copy(header):
    source = f'void f(const char *src, int flag) {{ char b[8]; {header} if (strlen(src) < 8) return; memcpy(b, src, 8); }}'
    findings = UnboundedCopyDetector().find_all(source, {"src"})
    assert len(findings) == 1 and not findings[0].guarded


@needs_gcc
def test_conditional_guard_reproduces_real_overread(tmp_path):
    source = ('#include <stdlib.h>\n#include <string.h>\n'
              'void f(const char *src, int flag) { char b[8]; while (flag) if (strlen(src)<8) return; memcpy(b,src,8); }\n'
              'int main(void) { char *p=malloc(1); if (!p) return 3; p[0]=0; f(p,0); free(p); }')
    runner = SanitizerRunner()
    binary = tmp_path / "conditional"
    runner.compile(source, binary)
    result = runner.run_one(binary, "old", 0)
    assert result.crashed and result.error_kind == "heap-buffer-overflow"


@pytest.mark.parametrize("body", [
    'char *p="abcdefghijklmnop"; memcpy(b,p,8); p=src;',
    'char *p=src; p="abcdefghijklmnop"; memcpy(b,p,8);',
    'char *p=resource; memcpy(b,p,8);',
])
def test_unrelated_pointer_not_reported_as_input(body):
    source = 'void f(const char *src) { char b[8]; ' + body + ' }'
    assert not UnboundedCopyDetector().find_all(source, {"src"})


def test_later_reassignment_does_not_erase_an_earlier_copy():
    source = 'void f(const char *src) { char b[8]; char *p=src; memcpy(b,p,8); p="safe"; }'
    assert len(UnboundedCopyDetector().find_all(source, {"src"})) == 1


def test_conditional_reassignment_does_not_erase_possible_taint():
    source = 'void f(const char *src, int flag) { char b[8]; char *p=src; if (flag) p="safe"; memcpy(b,p,8); }'
    assert len(UnboundedCopyDetector().find_all(source, {"src"})) == 1


def test_null_comparison_is_not_a_pointer_assignment():
    source = 'void f(const char *src) { char b[8]; char *p=strstr(src,"prefix"); if (p == NULL) return; memcpy(b,p,8); }'
    assert len(UnboundedCopyDetector().find_all(source, {"src"})) == 1


def test_changed_parameter_names_generate_same_arguments():
    assert "new_f(buf, 0);" in generate()


@pytest.mark.parametrize("new", [
    'void f(char **src, int n) { (void)src; (void)n; }',
    'void f(const char *src, int *n) { (void)src; (void)n; }',
    'void f(int n, const char *src) { (void)src; (void)n; }',
    'void f(const char *src) { (void)src; }',
])
def test_changed_parameter_types_are_refused(new):
    with pytest.raises(UnsupportedSignatureError):
        generate(new=new)


def test_embedded_nul_seed_is_refused():
    with pytest.raises(UnsupportedSignatureError, match="NUL"):
        generate(seed="A\0B")


@needs_gcc
@pytest.mark.parametrize("seed", ["ABCDEFGH", "\u0627BCDEFGH"])
def test_renamed_parameters_and_utf8_sweep_use_real_bytes(tmp_path, seed):
    result = HarnessPipeline(extractor=EXTRACTOR).analyze(OLD, NEW, "f", seed, {"n": "0"}, tmp_path)
    assert result.verdict == Verdict.CONFIRMED_REGRESSION_FIX
    expected = len(seed.encode("utf-8"))
    assert [run.length for run in result.new_results] == list(range(expected + 1))
    # Independently round-trip the generated C literal through the compiler.
    binary = tmp_path / "seed"
    escaped = DifferentialHarnessGenerator._escape_c_string(seed)
    runner = SanitizerRunner()
    runner.compile('#include <stdio.h>\nint main(void) { const char s[]="' + escaped + '"; fwrite(s,1,sizeof(s)-1,stdout); }', binary)
    raw = subprocess.run([str(binary)], capture_output=True, check=True, env=runner._env())
    assert raw.stdout == seed.encode("utf-8")


@needs_gcc
def test_function_name_inside_return_type_compiles(tmp_path):
    old = OLD.replace("void f", "float f").replace("(void)n;", "(void)n; return 0.0;")
    new = NEW.replace("void f", "float f").replace("return;", "return 0.0;").replace("(void)count;", "(void)count; return 0.0;")
    result = HarnessPipeline(extractor=EXTRACTOR).analyze(old, new, "f", "ABCDEFGH", {"n": "0"}, tmp_path)
    assert result.verdict == Verdict.CONFIRMED_REGRESSION_FIX


def test_documentation_mentions_do_not_enter_source_diff():
    diff = ('diff --git a/a.c b/a.c\n--- a/a.c\n+++ b/a.c\n@@ -1 +1 @@\n-old\n+int a;\n'
            'diff --git a/readme.txt b/readme.txt\n--- a/readme.txt\n+++ b/readme.txt\n@@ -1 +1 @@\n-old\n+validate a.c example\n')
    commit = Commit("abc", "cleanup", "test", "2026-10-05", diff)
    assert commit.added_lines() == "int a;"
    assert commit.total_changed_lines() == 2


@pytest.mark.parametrize("old_lengths,new_lengths", [([], []), ([0], []), ([0, 1], [0]), ([0, 1], [0, 0]), ([0, 2], [0, 2])])
def test_incomplete_sweeps_cannot_confirm(old_lengths, new_lengths):
    from augur.harness.sanitizer_runner import RunResult
    old = [RunResult("old", length, True, "asan", 1) for length in old_lengths]
    new = [RunResult("new", length, False, None, 0) for length in new_lengths]
    verdict, _ = HarnessPipeline(extractor=EXTRACTOR)._classify(old, new)
    assert verdict == Verdict.INCONCLUSIVE


def test_engine_does_not_retain_discounts_from_previous_scan():
    commit = Commit("abc", "cleanup", "test", "2026-10-05", "diff --git a/crypto/a.c b/crypto/a.c\n--- a/crypto/a.c\n+++ b/crypto/a.c\n@@ -1 +1 @@\n-old\n+int a;\n")
    class Repository:
        def recent_commits(self, limit):
            return [commit] * limit
    engine = RadarEngine()
    assert engine.scan(Repository(), limit=50, discount_common_path_keywords=True) == []
    assert len(engine.scan(Repository(), limit=1)) == 1


@pytest.mark.parametrize("config", [{"high_threshold": float("nan")}, {"weight_overrides": {"sensitive_path": float("inf")}}])
def test_api_rejects_nonfinite_scores(config):
    with pytest.raises(ValueError, match="finite"):
        RadarEngine(**config)


def test_cli_missing_source_reports_error_without_traceback(tmp_path):
    result = subprocess.run([sys.executable, "-m", "augur", "harness", "--old", str(tmp_path / "missing.c"), "--new", str(tmp_path / "other.c"), "--function", "f"], cwd=PROJECT, capture_output=True, text=True)
    assert result.returncode == 1 and "[!]" in result.stderr
    assert "Traceback" not in result.stderr and not result.stdout


def test_code_and_distribution_versions_agree():
    from augur import __version__
    metadata = (PROJECT / "pyproject.toml").read_text(encoding="utf-8")
    assert re.search(r'^version = "([^"]+)"', metadata, re.MULTILINE).group(1) == __version__


@needs_gcc
def test_cli_records_all_runs_and_exact_source_hashes(tmp_path):
    old, new = tmp_path / "old.c", tmp_path / "new.c"
    old.write_text(OLD, encoding="utf-8")
    new.write_text(NEW, encoding="utf-8")
    result = subprocess.run([sys.executable, "-m", "augur", "harness", "--old", str(old), "--new", str(new), "--function", "f", "--seed", "ABCDEFGH", "--param", "n=0"], cwd=PROJECT, capture_output=True, text=True, timeout=90)
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["source_sha256"]["old"] == hashlib.sha256(old.read_bytes()).hexdigest()
    assert payload["source_sha256"]["new"] == hashlib.sha256(new.read_bytes()).hexdigest()
    assert len(payload["old_runs"]) == len(payload["new_runs"]) == 9
    assert all(run["status"] == "clean" for run in payload["new_runs"])


@pytest.mark.parametrize("value,expected", [("123456", "#12"), ("0001", "#1 "), ("0x10", "#16"), ("-1", "#-1"), ("08", None), ("n+1", None)])
def test_prefix_matches_c_integer_and_buffer_semantics(value, expected):
    source = 'void f(const char *src, int n) { char needle[4]; snprintf(needle,4,"#%d ",n); strstr(src,needle); }'
    result = FormatStringPrefixDeriver().derive(source, "src", {"n": value})
    assert (result.literal_bytes if result else None) == expected


def test_comments_and_modified_needles_do_not_derive_prefix():
    for body in ['/* snprintf(needle,8,"#%d ",n); */', 'snprintf(needle,8,"#%d ",n); needle[0]=0;']:
        assert FormatStringPrefixDeriver().derive(body + 'strstr(src,needle);', "src", {"n": "0"}) is None


def test_literal_braces_and_commented_function_do_not_break_extraction():
    source = '/*\nvoid f(const char *x) { return; }\n*/\nvoid f(const char *src) { const char *s="}"; char b[8]; memcpy(b,src,8); }'
    function = EXTRACTOR.find_function(source, "f")
    assert function.signature.parameters[0].name == "src"
    assert "memcpy(b,src,8);" in function.full_text


@pytest.mark.skipif(shutil.which("clang") is None, reason="clang unavailable")
def test_clang_preserves_utf8_and_crlf_byte_offsets():
    from augur.pattern.clang_function_extractor import ClangFunctionExtractor
    source = '/* \u0627\u062e\u062a\u0628\u0627\u0631 */\r\nvoid before(void) {}\r\nvoid f(const char *src) { const char *s="}"; (void)s; (void)src; }\r\nvoid after(void) {}'
    function = ClangFunctionExtractor().find_function(source, "f")
    assert function is not None
    assert function.full_text.startswith("void f(")
    assert function.full_text.endswith("}")
    assert "after" not in function.full_text


@needs_git
def test_provenance_follows_renames_and_worktrees(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")

    def git(*args):
        return subprocess.run(["git", "-C", str(repo), *args], env=env, check=True, capture_output=True, text=True).stdout.strip()

    def commit(message):
        git("add", "-A")
        git("commit", "-qm", message)
        return git("rev-parse", "HEAD")

    git("init", "-q")
    git("config", "user.name", "Release test")
    git("config", "user.email", "test@example.invalid")
    git("config", "commit.gpgsign", "false")
    safe = 'void f(const char *src) { char b[8]; if (strlen(src)<8) return; memcpy(b,src,8); }'
    unsafe = safe.replace('if (strlen(src)<8) return; ', '')
    (repo / "old.c").write_text(safe, encoding="utf-8")
    commit("safe")
    (repo / "old.c").write_text(unsafe, encoding="utf-8")
    introduced = commit("introduce bug")
    git("tag", "v1-vulnerable")
    git("mv", "old.c", "middle name.c")
    commit("rename")
    git("mv", "middle name.c", "new.c")
    renamed = commit("rename again")
    git("tag", "v2-vulnerable")
    (repo / "new.c").write_text(safe, encoding="utf-8")
    fixed = commit("fix")
    git("tag", "v3-fixed")
    repository = GitRepository(repo)
    finder = VulnerabilityIntroductionFinder(extractor=EXTRACTOR)
    result = ProvenancePipeline(introduction_finder=finder).analyze(repository, "new.c", "f", fixed, "src")
    assert result.introduction.introduction_commit == introduced
    assert result.version_range.vulnerable_tags == ["v1-vulnerable", "v2-vulnerable"]
    assert result.version_range.first_fixed_tag == "v3-fixed"
    assert repository.file_history_before("new.c", fixed)[-1] == renamed
    worktree = tmp_path / "worktree"
    git("worktree", "add", "--detach", str(worktree), "HEAD")
    assert GitRepository(worktree).recent_commits(1)[0].sha == fixed
