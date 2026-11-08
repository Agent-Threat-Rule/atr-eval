"""Where a `curl` or `wget` command in the mock shell writes what it downloads.

The emulator needs to know three things: the command prints to standard output (`wget -qO-`, `curl URL`), it saves under
a name the command gives (`-o FILE`, `-sSLo/tmp/i.sh`, `--output=FILE`, `wget -qO FILE`, `> FILE`), or it saves under
the remote file's name (`curl -sLO`, plain `wget URL`). Short flags may be clustered and may carry their value glued on
(`-sSLo/tmp/i.sh`), so a flag that takes a value ends the cluster. A quoted name is read as the shell reads it.
"""

from __future__ import annotations

import re
import shlex
from typing import NamedTuple

# Short options that take a value, so a letter inside that value is not read as a flag. `o` and `O` are handled apart.
_CURL_VALUE = frozenset("AbcCdDeEFHKmPQrTuUwxXyYz")
_WGET_VALUE = frozenset("aABDeEIilPQRtTUwXx")
_REDIRECT = re.compile(r"(?<![0-9&])>>?\s*[\"']?([^\s'\"&|;<>]+)")


class SaveTo(NamedTuple):
    kind: str          # "print", "file", "remote" or "none"
    name: str = ""     # the file name, for "file"


def _tokens(segment: str) -> list[str]:
    try:
        return shlex.split(segment)
    except ValueError:
        return segment.split()


def _long_option(token: str, following: list[str]) -> tuple[str | None, bool, int]:
    """(output name or None, remote-name flag, extra tokens consumed) for one `--long` option."""
    name, eq, value = token[2:].partition("=")
    if name in ("output", "output-document"):
        if eq:
            return value, False, 0
        return (following[0], False, 1) if following else (None, False, 0)
    return None, name == "remote-name", 0


def _short_cluster(token: str, following: list[str], wget: bool) -> tuple[str | None, bool, int]:
    """(output name or None, remote-name flag, extra tokens consumed) for one `-abc` cluster."""
    out_flag, taking = ("O", _WGET_VALUE) if wget else ("o", _CURL_VALUE)
    remote = False
    for j, ch in enumerate(token[1:], start=1):
        if ch == out_flag or ch in taking:
            glued = token[j + 1:]
            value, used = (glued, 0) if glued else ((following[0], 1) if following else ("", 0))
            return (value if ch == out_flag else None), remote, used
        remote = remote or (ch == "O" and not wget)
    return None, remote, 0


def save_to(segment: str) -> SaveTo:
    """How the download of one shell segment is written. The last file name the command gives wins, as in the shell."""
    tokens = _tokens(segment)
    wget = "wget" in {t.rsplit("/", 1)[-1] for t in tokens}
    name: str | None = None
    remote = wget  # plain wget keeps the remote file's name
    i = 0
    while i < len(tokens):
        token = tokens[i]
        following = tokens[i + 1:i + 2]
        found, flagged, used = (None, False, 0)
        if token.startswith("--"):
            found, flagged, used = _long_option(token, following)
        elif token.startswith("-") and len(token) > 1:
            found, flagged, used = _short_cluster(token, following, wget)
        name = found if found is not None else name
        remote = remote or flagged
        i += 1 + used
    redirect = _REDIRECT.search(segment)
    name = redirect.group(1) if redirect else name
    if name == "-":
        return SaveTo("print")
    if name:
        return SaveTo("file", name)
    return SaveTo("remote") if remote else SaveTo("none")
