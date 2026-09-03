"""SQL validity of control payloads and boolean pairs against a real DB engine.

These payloads are sent by value-substitution into query contexts. If a payload
raises a real SQL error when substituted into a genuinely injectable point, the
scanner either suppresses a true positive (status differential control) or never
differentiates (boolean pair). Regression guard: payloads must parse as valid
SQL in the context the scanner actually uses them, so this class of bug (e.g. a
numeric no-quote pair missing its leading digit -> "id = OR 1=1--", a syntax
error) cannot silently return.
"""
import sqlite3

import pytest

from pwnproxy.plugins.scanners.sqli.payloads import (
    BOOLEAN_PAIRS,
    CONTROL_PAYLOADS,
)

# Raw-garbage controls are deliberately not valid SQL; excluded from validity.
_CONTROL_NON_SQL = {"\x00\x01\x02\x03", "A" * 512}

# String-context boolean pairs are wrapped in the app's own quotes/parens the
# way each payload was authored to break out of. Map payload -> wrapper template.
_STRING_WRAP = "SELECT * FROM t WHERE name = '{p}'"
_PAREN_WRAP = "SELECT * FROM t WHERE name = ('{p}')"
_NUMERIC_WRAP = "SELECT * FROM t WHERE id = {p}"


def _is_numeric_style(payload: str) -> bool:
    """Numeric no-quote pairs start with a digit and carry no leading quote."""
    return payload[:1].isdigit()


def _is_paren_style(payload: str) -> bool:
    return payload.startswith("')")


def _wrap(payload: str) -> str:
    if _is_numeric_style(payload):
        return _NUMERIC_WRAP.format(p=payload)
    if _is_paren_style(payload):
        return _PAREN_WRAP.format(p=payload)
    return _STRING_WRAP.format(p=payload)


@pytest.fixture
def db():
    con = sqlite3.connect(":memory:")
    con.executescript(
        "CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT);"
        "INSERT INTO t VALUES (1, 'alpha'), (2, 'beta');"
    )
    yield con
    con.close()


def _assert_valid(db, payload, label):
    sql = _wrap(payload)
    try:
        db.execute(sql).fetchall()
    except sqlite3.Error as e:  # pragma: no cover - failure surfaces the bug
        pytest.fail(f"{label} raised SQL error in its context: {e}\n  SQL: {sql}")


class TestControlPayloadsValidSql:
    def test_valid_sql_lookalike_controls_parse_in_string_context(self, db):
        for p in CONTROL_PAYLOADS:
            if p.value in _CONTROL_NON_SQL:
                continue
            sql = f"SELECT * FROM t WHERE name = '{p.value}'"
            try:
                db.execute(sql).fetchall()
            except sqlite3.Error as e:
                pytest.fail(f"control {p.value!r} invalid in string context: {e}\n  SQL: {sql}")

    def test_valid_sql_lookalike_controls_parse_in_numeric_context(self, db):
        for p in CONTROL_PAYLOADS:
            if p.value in _CONTROL_NON_SQL:
                continue
            sql = f"SELECT * FROM t WHERE id = {p.value}"
            try:
                db.execute(sql).fetchall()
            except sqlite3.Error as e:
                pytest.fail(f"control {p.value!r} invalid in numeric context: {e}\n  SQL: {sql}")


class TestBooleanPairsValidSql:
    def test_boolean_pairs_parse_in_their_context(self, db):
        """Each pair parses under the wrapper the payload targets (numeric,
        quoted string, or parenthesized string) — no syntax errors."""
        for true_payload, false_payload in BOOLEAN_PAIRS:
            _assert_valid(db, true_payload, f"TRUE {true_payload!r}")
            _assert_valid(db, false_payload, f"FALSE {false_payload!r}")

    def test_numeric_pairs_parse_in_numeric_context(self, db):
        """The numeric no-quote pairs are substituted raw into a numeric column;
        they MUST carry a leading value so 'id = 1 OR 1=1--' is valid SQL."""
        for true_payload, false_payload in BOOLEAN_PAIRS:
            if not (_is_numeric_style(true_payload) and _is_numeric_style(false_payload)):
                continue
            sql_true = f"SELECT * FROM t WHERE id = {true_payload}"
            sql_false = f"SELECT * FROM t WHERE id = {false_payload}"
            db.execute(sql_true).fetchall()
            db.execute(sql_false).fetchall()

    def test_true_false_still_differentiable(self, db):
        """TRUE must return rows and FALSE must not, in the payload's numeric
        context — a pair that breaks identically is useless."""
        for true_payload, false_payload in BOOLEAN_PAIRS:
            if not (_is_numeric_style(true_payload) and _is_numeric_style(false_payload)):
                continue
            rows_true = db.execute(
                f"SELECT COUNT(*) FROM t WHERE id = {true_payload}"
            ).fetchone()[0]
            rows_false = db.execute(
                f"SELECT COUNT(*) FROM t WHERE id = {false_payload}"
            ).fetchone()[0]
            assert rows_true > rows_false, (
                f"numeric pair not differentiable: "
                f"true={true_payload!r} rows={rows_true}, false={false_payload!r} rows={rows_false}"
            )
