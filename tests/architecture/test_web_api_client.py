"""Guards that keep every Web UI network call behind the single wrapper.

Two rules are enforced here, both textual on purpose (an AST walk cannot see a
call hidden inside a template string or an Astro `<script>` block):

1. **No raw HTTP** (:class:`TestNoRawFetch`). The API token lives in
   ``localStorage`` and must ride on ``Authorization: Bearer`` for every
   ``/api/v1/*`` request. ``apps/web/src/api/client.ts`` is the only file allowed
   to call ``fetch``; every other module goes through ``apiFetch``.
2. **No raw socket** (:class:`TestNoRawWebSocket`). The token travels in the
   ``Sec-WebSocket-Protocol`` header, which only
   ``apps/web/src/hooks/useWebSocket.ts`` knows how to build.

A violation is reported as ``archivo:línea (texto de la línea)``. The allow-list
is deliberately empty of exceptions: if a component needs the network, the call
goes to ``api/*/calls.ts``. Without these guards a new ``fetch`` compiles, works
locally and returns ``401`` only in the browser — invisible to the Python suite.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
WEB_SRC = REPO_ROOT / "apps" / "web" / "src"

#: The one module allowed to call ``fetch`` (it adds ``Authorization``).
FETCH_ALLOWED = (Path("api/client.ts"),)

#: The one module allowed to construct a ``WebSocket`` (it offers the subprotocol).
WS_ALLOWED = (Path("hooks/useWebSocket.ts"),)

#: Build output and installed dependencies carry vendored copies of both calls.
PRUNED_DIR_NAMES = {"node_modules", "dist", ".astro", "__pycache__", ".vite"}

#: Suffixes that can hold a browser network call. Assets cannot.
SCANNED_SUFFIXES = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".astro"}

#: ``fetch(`` as a call — not ``apiFetch(``, ``prefetch(`` or ``$fetch(``… the
#: lookbehind only lets a bare identifier through, so ``apiFetch(`` is skipped
#: because ``i`` precedes the ``f``.
FETCH_PATTERN = re.compile(r"(?<!\w)fetch\s*\(")

#: The socket constructor, however it is spelled with whitespace.
WS_PATTERN = re.compile(r"new\s+WebSocket\s*\(")


def _iter_web_files(root: Path = WEB_SRC) -> list[Path]:
    """Every source file the guards inspect, sorted for a stable message."""
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in PRUNED_DIR_NAMES for part in path.parts):
            continue
        if path.suffix.lower() not in SCANNED_SUFFIXES:
            continue
        files.append(path)
    return sorted(files)


def _display(path: Path) -> str:
    """Repo-relative path when possible, absolute otherwise (mutation trees)."""
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def _scan(
    pattern: re.Pattern[str],
    allowed: tuple[Path, ...],
    root: Path = WEB_SRC,
) -> list[str]:
    """Collect ``archivo:línea (línea)`` for each hit outside the allow-list."""
    violations: list[str] = []
    for path in _iter_web_files(root):
        if path.relative_to(root) in allowed:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if pattern.search(line):
                violations.append(f"{_display(path)}:{lineno} ({line.strip()})")
    return violations


class TestNoRawFetch:
    def test_no_raw_fetch_outside_the_wrapper(self):
        violations = _scan(FETCH_PATTERN, FETCH_ALLOWED)
        assert violations == [], (
            "Ningún archivo de apps/web/src llama a fetch directo: usa "
            '`apiFetch` de "@/api/client" (que pone el Authorization) desde un '
            "módulo de apps/web/src/api/*/calls.ts. Offenders:\n"
            + "\n".join(violations)
        )

    def test_guard_detects_a_raw_fetch(self, tmp_path):
        """The rule must fail on the shape it exists to forbid."""
        (tmp_path / "api").mkdir()
        (tmp_path / "api" / "client.ts").write_text(
            "export async function apiFetch() {\n"
            "  return await fetch('/x');\n"
            "}\n",
            encoding="utf-8",
        )
        (tmp_path / "components").mkdir()
        (tmp_path / "components" / "Page.tsx").write_text(
            "const res = await apiFetch('/ok');\n"
            "const raw = await fetch('/api/v1/flows');\n",
            encoding="utf-8",
        )
        violations = _scan(FETCH_PATTERN, FETCH_ALLOWED, root=tmp_path)
        assert [v.split(" (")[0] for v in violations] == [
            f"{tmp_path.as_posix()}/components/Page.tsx:2",
        ]


class TestNoRawWebSocket:
    def test_no_raw_websocket_outside_the_hook(self):
        violations = _scan(WS_PATTERN, WS_ALLOWED)
        assert violations == [], (
            "El único WebSocket de la Web UI es useWebSocket.ts, que ofrece "
            "['pwnproxy', 'pwnproxy-token.<token>']. Usa `useWebSocket({ url: "
            'wsUrl("/ws/events"), … })`. Offenders:\n'
            + "\n".join(violations)
        )

    def test_guard_detects_a_raw_websocket(self, tmp_path):
        (tmp_path / "hooks").mkdir()
        (tmp_path / "hooks" / "useWebSocket.ts").write_text(
            "const ws = new WebSocket(url, protocols);\n",
            encoding="utf-8",
        )
        (tmp_path / "components").mkdir()
        (tmp_path / "components" / "Live.tsx").write_text(
            "const ws = new  WebSocket(`ws://${host}/ws/events`);\n",
            encoding="utf-8",
        )
        violations = _scan(WS_PATTERN, WS_ALLOWED, root=tmp_path)
        assert [v.split(" (")[0] for v in violations] == [
            f"{tmp_path.as_posix()}/components/Live.tsx:1",
        ]


class TestGuardIsNotVacuous:
    """A moved wrapper must break the suite instead of silently passing it."""

    @pytest.mark.parametrize(
        ("relative", "pattern"),
        [
            (FETCH_ALLOWED[0], FETCH_PATTERN),
            (WS_ALLOWED[0], WS_PATTERN),
        ],
    )
    def test_the_allowed_file_exists_and_still_calls_it(self, relative, pattern):
        path = WEB_SRC / relative
        assert path.is_file(), f"falta {_display(path)}"
        assert pattern.search(path.read_text(encoding="utf-8")), (
            f"{_display(path)} ya no hace la llamada que el resto del frontend "
            "espera encontrar solo ahí (¿se movió el wrapper?)"
        )

    def test_the_scan_covers_the_real_tree(self):
        files = _iter_web_files()
        assert len(files) >= 60, f"la guarda solo recorrió {len(files)} archivos"
        assert WEB_SRC / "api" / "traffic" / "calls.ts" in files
        assert WEB_SRC / "ui" / "Sidebar.astro" in files


class TestTokenGateIsMounted:
    """Every route must be able to ask for the token, and only one key names it."""

    def test_base_layout_captures_the_fragment_and_mounts_the_gate(self):
        layout = (WEB_SRC / "layouts" / "Base.astro").read_text(encoding="utf-8")
        assert 'from "@/api/client"' in layout
        assert "TOKEN_STORAGE_KEY" in layout
        assert "location.hash" in layout
        assert "history.replaceState" in layout
        assert "<TokenGate client:load />" in layout

    def test_the_storage_key_is_not_repeated(self):
        layout = (WEB_SRC / "layouts" / "Base.astro").read_text(encoding="utf-8")
        assert '"pwnproxy.api.token"' not in layout, (
            "la clave del token vive en api/client.ts (TOKEN_STORAGE_KEY); "
            "pásala al script con define:vars"
        )
