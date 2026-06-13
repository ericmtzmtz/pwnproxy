import pytest
from unittest.mock import AsyncMock, MagicMock

from pwnproxy.services.scanners.sqli.detector import ErrorBasedDetector


class TestErrorBasedDetector:
    def test_mysql_error_detected(self):
        detector = ErrorBasedDetector()
        resp = MagicMock()
        resp.text = "You have an error in your SQL syntax near 'test'"
        finding = detector.check(resp)
        assert finding is not None
        assert finding.dbms == "mysql"
        assert finding.technique == "error-based"

    def test_postgresql_error_detected(self):
        detector = ErrorBasedDetector()
        resp = MagicMock()
        resp.text = "ERROR: syntax error at or near 'test'"
        finding = detector.check(resp)
        assert finding is not None
        assert finding.dbms == "postgresql"

    def test_mssql_error_detected(self):
        detector = ErrorBasedDetector()
        resp = MagicMock()
        resp.text = "Unclosed quotation mark after the character string"
        finding = detector.check(resp)
        assert finding is not None
        assert finding.dbms == "mssql"

    def test_sqlite_error_detected(self):
        detector = ErrorBasedDetector()
        resp = MagicMock()
        resp.text = 'near "SELECT": syntax error'
        finding = detector.check(resp)
        assert finding is not None
        assert finding.dbms == "sqlite"

    def test_oracle_error_detected(self):
        detector = ErrorBasedDetector()
        resp = MagicMock()
        resp.text = "ORA-01756: quoted string not properly terminated"
        finding = detector.check(resp)
        assert finding is not None
        assert finding.dbms == "oracle"

    def test_no_error_no_finding(self):
        detector = ErrorBasedDetector()
        resp = MagicMock()
        resp.text = "<html><body>OK</body></html>"
        finding = detector.check(resp)
        assert finding is None
