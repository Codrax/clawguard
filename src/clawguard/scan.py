"""Search files, staged changes and git history for the exact values of vault secrets.

Secret values only ever live in memory, inside `Needle` objects. Nothing here prints,
logs or writes a value; findings carry the vault path of the secret, never the secret.
"""
from __future__ import annotations

import base64
import fnmatch
import os
import subprocess
import urllib.parse
from dataclasses import dataclass, field
from typing import Iterable, Iterator, Optional

IGNORE_FILE = ".clawguardignore"
INLINE_ALLOW = b"clawguard:allow"
DEFAULT_MIN_LENGTH = 8
DEFAULT_MAX_BYTES = 5 * 1024 * 1024
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache", "dist", "build"}


@dataclass(frozen=True)
class Needle:
    secret: str  # vault path, plus "#KEY" for one line of an env-type secret
    vault: str
    variant: str  # raw, base64, base64url, url
    value: bytes = field(repr=False)


@dataclass(frozen=True)
class Finding:
    file: str
    line: int
    secret: str
    vault: str
    variant: str
    source: str = "worktree"  # worktree, staged, history
    commit: Optional[str] = None

    def to_dict(self) -> dict:
        d = {"file": self.file, "line": self.line, "secret": self.secret, "vault": self.vault,
             "variant": self.variant, "source": self.source}
        if self.commit:
            d["commit"] = self.commit
        return d


# ---------- needles ----------
def variants(value: bytes) -> dict[str, bytes]:
    """The value as written, plus the encodings it commonly hides in."""
    out = {"raw": value}
    b64 = base64.b64encode(value)
    out["base64"] = b64.rstrip(b"=") if len(value) % 3 else b64
    out["base64url"] = base64.urlsafe_b64encode(value).rstrip(b"=")
    url = urllib.parse.quote(value.decode("utf-8", "replace"), safe="").encode()
    if url != value:
        out["url"] = url
    # drop duplicates (e.g. base64url == base64 when no +/ appear)
    seen, uniq = set(), {}
    for k, v in out.items():
        if v not in seen:
            seen.add(v)
            uniq[k] = v
    return uniq


def env_pairs(text: str) -> Iterator[tuple[str, str]]:
    """KEY=value lines of a .env-style secret."""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[7:]
        k, v = line.split("=", 1)
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        yield k.strip(), v


def build_needles(secrets: Iterable[tuple[str, str, str, str]], min_length: int = DEFAULT_MIN_LENGTH,
                  encodings: bool = True) -> tuple[list[Needle], int]:
    """secrets: (vault, path, type, value). Returns (needles, number of values too short to search)."""
    needles, short = [], 0
    for vault, path, typ, value in secrets:
        parts = [(path, value)]
        if typ == "env":
            parts = [(f"{path}#{k}", v) for k, v in env_pairs(value)] or parts
        for name, val in parts:
            val = val.strip()
            if len(val) < min_length:
                short += 1
                continue
            raw = val.encode()
            forms = variants(raw) if encodings else {"raw": raw}
            for variant, form in forms.items():
                needles.append(Needle(name, vault, variant, form))
    return needles, short


# ---------- matching ----------
def is_binary(data: bytes) -> bool:
    return b"\0" in data[:8192]


def scan_bytes(data: bytes, needles: list[Needle], name: str, source: str = "worktree",
               commit: Optional[str] = None) -> list[Finding]:
    found = []
    seen = set()
    for n in needles:
        start = 0
        while True:
            i = data.find(n.value, start)
            if i < 0:
                break
            start = i + 1
            line_no = data.count(b"\n", 0, i) + 1
            ls = data.rfind(b"\n", 0, i) + 1
            le = data.find(b"\n", i)
            if INLINE_ALLOW in data[ls:le if le >= 0 else len(data)]:
                continue
            key = (line_no, n.secret)
            if key in seen:  # one finding per secret per line, whichever encoding hit first
                continue
            seen.add(key)
            found.append(Finding(name, line_no, n.secret, n.vault, n.variant, source, commit))
    return found


# ---------- ignore rules ----------
def load_ignore(root: str) -> list[str]:
    path = os.path.join(root, IGNORE_FILE)
    if not os.path.isfile(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [ln.strip() for ln in f if ln.strip() and not ln.lstrip().startswith("#")]


def ignored(rel: str, patterns: list[str]) -> bool:
    rel = rel.replace(os.sep, "/")
    for p in patterns:
        p = p.rstrip("/")
        if fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(os.path.basename(rel), p):
            return True
        if rel.startswith(p + "/") or fnmatch.fnmatch(rel, p + "/*"):
            return True
    return False


# ---------- git ----------
def git(root: str, *args: str, input: Optional[bytes] = None) -> Optional[bytes]:
    try:
        r = subprocess.run(["git", "-C", root, *args], input=input, capture_output=True)
    except FileNotFoundError:
        return None
    return r.stdout if r.returncode == 0 else None


def in_git_repo(root: str) -> bool:
    out = git(root, "rev-parse", "--is-inside-work-tree")
    return out is not None and out.strip() == b"true"


# ---------- sources ----------
@dataclass
class Stats:
    files: int = 0
    skipped_binary: int = 0
    skipped_large: int = 0
    skipped_ignored: int = 0
    blobs: int = 0


class _Filter:
    """The skip rules every source shares: ignore globs, size limit, binary content.

    Each check bumps the matching counter in `stats`, so the CLI can say what was left out.
    """

    def __init__(self, root: str, exclude: Optional[list[str]], max_bytes: int, stats: Stats):
        self.patterns = load_ignore(root) + list(exclude or [])
        self.max_bytes = max_bytes
        self.stats = stats

    def skip_path(self, rel: str) -> bool:
        if ignored(rel, self.patterns):
            self.stats.skipped_ignored += 1
            return True
        return False

    def skip_size(self, size: int) -> bool:
        if size > self.max_bytes:
            self.stats.skipped_large += 1
            return True
        return False

    def skip_data(self, data: bytes) -> bool:
        if self.skip_size(len(data)):
            return True
        if is_binary(data):
            self.stats.skipped_binary += 1
            return True
        return False


def _read_file(path: str) -> Optional[bytes]:
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError:  # vanished or unreadable between listing and reading; not worth failing over
        return None


def worktree_files(root: str, paths: list[str]) -> Iterator[str]:
    """Relative paths to scan: git's tracked + untracked-not-ignored files, or a plain walk."""
    if in_git_repo(root):
        out = git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", *(paths or ["."]))
        seen = set()
        for p in (out or b"").split(b"\0"):
            if p and p not in seen:
                seen.add(p)
                rel = p.decode("utf-8", "surrogateescape")
                # ls-files still lists tracked files that were deleted locally
                if os.path.isfile(os.path.join(root, rel)):
                    yield rel
        return
    for base in paths or ["."]:
        full = os.path.join(root, base)
        if os.path.isfile(full):
            yield os.path.relpath(full, root)
            continue
        for dirpath, dirnames, filenames in os.walk(full):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            for fn in sorted(filenames):
                yield os.path.relpath(os.path.join(dirpath, fn), root)


def scan_worktree(root: str, paths: list[str], needles: list[Needle], max_bytes: int = DEFAULT_MAX_BYTES,
                  exclude: Optional[list[str]] = None, stats: Optional[Stats] = None) -> list[Finding]:
    """Files on disk, as they are right now."""
    stats = stats or Stats()
    filt = _Filter(root, exclude, max_bytes, stats)
    out = []
    for rel in worktree_files(root, paths):
        full = os.path.join(root, rel)
        if filt.skip_path(rel):
            continue
        try:
            # check the size before reading, so a huge file never lands in memory
            if filt.skip_size(os.path.getsize(full)):
                continue
        except OSError:
            continue
        data = _read_file(full)
        if data is None or filt.skip_data(data):
            continue
        stats.files += 1
        out += scan_bytes(data, needles, rel.replace(os.sep, "/"))
    return out


def scan_staged(root: str, needles: list[Needle], max_bytes: int = DEFAULT_MAX_BYTES,
                exclude: Optional[list[str]] = None, stats: Optional[Stats] = None) -> list[Finding]:
    """The staged version of every added, copied, modified or renamed file (for pre-commit).

    This reads from the index, not the disk: a file fixed on disk but not re-staged still
    commits the old content, and that is what gets checked.
    """
    stats = stats or Stats()
    if not in_git_repo(root):
        raise RuntimeError("--staged needs a git repository")
    filt = _Filter(root, exclude, max_bytes, stats)
    names = git(root, "diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR") or b""
    out = []
    for p in names.split(b"\0"):
        if not p:
            continue
        rel = p.decode("utf-8", "surrogateescape")
        if filt.skip_path(rel):
            continue
        data = git(root, "show", ":" + rel)  # ":path" is the index version
        if data is None or filt.skip_data(data):
            continue
        stats.files += 1
        out += scan_bytes(data, needles, rel, "staged")
    return out


def _history_blobs(root: str) -> dict[str, str]:
    """Map of blob sha -> a path it appeared under, for every object reachable from any ref."""
    listing = git(root, "rev-list", "--all", "--objects") or b""
    paths: dict[str, str] = {}
    for line in listing.splitlines():
        parts = line.decode("utf-8", "surrogateescape").split(" ", 1)
        # commits come without a path; trees and blobs with one. Keep the first path seen.
        if len(parts) == 2 and parts[1] and parts[0] not in paths:
            paths[parts[0]] = parts[1]
    return paths


def _cat_blobs(root: str, shas: list[str]) -> Iterator[tuple[str, bytes]]:
    """Stream blob contents through one long-running `git cat-file --batch`."""
    proc = subprocess.Popen(["git", "-C", root, "cat-file", "--batch"], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE)
    try:
        for sha in shas:
            proc.stdin.write(sha.encode() + b"\n")
            proc.stdin.flush()
            header = proc.stdout.readline().split()  # "<sha> blob <size>"
            data = proc.stdout.read(int(header[2]))
            proc.stdout.read(1)  # trailing newline after each object
            yield sha, data
    finally:
        proc.stdin.close()
        proc.stdout.close()
        proc.wait()


def scan_history(root: str, needles: list[Needle], max_bytes: int = DEFAULT_MAX_BYTES,
                 exclude: Optional[list[str]] = None, stats: Optional[Stats] = None) -> list[Finding]:
    """Every blob reachable from any ref. Each hit names the commit that first added that blob."""
    stats = stats or Stats()
    if not in_git_repo(root):
        raise RuntimeError("--history needs a git repository")
    filt = _Filter(root, exclude, max_bytes, stats)
    paths = _history_blobs(root)
    if not paths:
        return []
    # ask for type and size of everything in one go, so trees and big blobs are never read
    check = git(root, "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)",
                input=("\n".join(paths) + "\n").encode()) or b""
    wanted = []
    for line in check.splitlines():
        sha, typ, size = line.decode().split(" ")
        if typ == "blob" and not filt.skip_size(int(size)) and not filt.skip_path(paths[sha]):
            wanted.append(sha)
    out = []
    for sha, data in _cat_blobs(root, wanted):
        if filt.skip_data(data):
            continue
        stats.blobs += 1
        hits = scan_bytes(data, needles, paths[sha], "history")
        if hits:
            # only look up the commit for blobs that matched; it is the slow part
            commit = first_commit_with(root, sha)
            out += [Finding(h.file, h.line, h.secret, h.vault, h.variant, "history", commit) for h in hits]
    return out


def first_commit_with(root: str, blob: str) -> Optional[str]:
    out = git(root, "log", "--all", "--reverse", "--format=%h", "--find-object=" + blob)
    lines = (out or b"").decode().split()
    return lines[0] if lines else None
