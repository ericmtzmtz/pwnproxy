import re

ERROR_SIGNATURES: dict[str, list[re.Pattern]] = {
    "mysql": [
        re.compile(r"you have an error in your sql syntax", re.IGNORECASE),
        re.compile(r"warning: mysql", re.IGNORECASE),
        re.compile(r"mysql_fetch", re.IGNORECASE),
        re.compile(r"mysql_num_rows", re.IGNORECASE),
        re.compile(r"mysql_result", re.IGNORECASE),
        re.compile(r"unknown column", re.IGNORECASE),
    ],
    "postgresql": [
        re.compile(r"error:\s+syntax error at or near", re.IGNORECASE),
        re.compile(r"pg_query\(\):", re.IGNORECASE),
        re.compile(r"pg_exec\(\):", re.IGNORECASE),
        re.compile(r"invalid input syntax for type", re.IGNORECASE),
        re.compile(r"column\s+\S+\s+does not exist", re.IGNORECASE),
        re.compile(r"relation\s+\S+\s+does not exist", re.IGNORECASE),
    ],
    "mssql": [
        re.compile(r"unclosed quotation mark after the character string", re.IGNORECASE),
        re.compile(r"microsoft ole db", re.IGNORECASE),
        re.compile(r"microsoft sql native client", re.IGNORECASE),
        re.compile(r"incorrect syntax near", re.IGNORECASE),
        re.compile(r"line \d+:", re.IGNORECASE),
        re.compile(r"conversion failed when converting", re.IGNORECASE),
    ],
    "sqlite": [
        re.compile(r'near\s+".*"\s*:\s*syntax error', re.IGNORECASE),
        re.compile(r"sqlite_error", re.IGNORECASE),
        re.compile(r"sql logic error", re.IGNORECASE),
        re.compile(r"no such table", re.IGNORECASE),
        re.compile(r"no such column", re.IGNORECASE),
    ],
    "oracle": [
        re.compile(r"ora-\d{5}", re.IGNORECASE),
        re.compile(r"oracle error", re.IGNORECASE),
        re.compile(r"pl/sql:", re.IGNORECASE),
        re.compile(r"ora-\d{4}", re.IGNORECASE),
    ],
}
