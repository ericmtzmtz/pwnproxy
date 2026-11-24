"""Guard: the honest limit of the `agent` scope is written in the three documents.

The scope matrix is a promise made to whoever installs the MCP: an `agent` token
cannot read or write a declared secret. The promise is bounded, and the bound is
the part a user gets wrong — ``agent`` keeps secrets out of the *tools*, it does
not contain an agent that already has a shell on the same machine, because that
agent can read the `full` token file.

Each of the three documents says it with the same sentence, and this guard fails
when one of them loses it (a rewrite, a translation, a summary that "simplifies"
the caveat away). Whitespace is collapsed before comparing: the sentence is
wrapped by hand in each file, and the guard is about the words, not the layout.

The sentence is also the closing line of task D.6 in
``openspec/changes/plugin-config-api``.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

#: Documents that must carry the limit. ``docs/plugin-architecture.md`` is where a
#: plugin author reads it, ``docs/api.md`` where an integrator does, ``docs/mcp.md``
#: where the person wiring the MCP does.
DOCUMENTS = (
    Path("docs/api.md"),
    Path("docs/mcp.md"),
    Path("docs/plugin-architecture.md"),
)

#: The sentence, word for word (task D.6). Kept in one piece here so a change to
#: the wording is one edit in the code and three in the documents.
HONEST_LIMIT = (
    "The `agent` scope keeps secrets out of the MCP tools, but it does not contain an agent with a "
    "shell on the machine: such an agent can read `~/.pwnproxy/api-token` and get `full`."
)

_WHITESPACE = re.compile(r"\s+")


def _flat(text: str) -> str:
    """Collapse every run of whitespace to one space, so wrapping does not matter."""
    return _WHITESPACE.sub(" ", text).strip()


@pytest.mark.parametrize("document", DOCUMENTS, ids=[path.name for path in DOCUMENTS])
def test_the_honest_limit_of_the_agent_scope_is_documented(document: Path):
    """Every document states, verbatim, that `agent` is not a sandbox."""
    path = REPO_ROOT / document

    assert path.is_file(), f"{document} is missing"

    assert HONEST_LIMIT in _flat(path.read_text(encoding="utf-8")), (
        f"{document} no longer states the honest limit of the `agent` scope:\n{HONEST_LIMIT}"
    )
