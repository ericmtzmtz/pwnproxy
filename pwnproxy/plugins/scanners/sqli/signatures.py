import re

ERROR_SIGNATURES: dict[str, list[re.Pattern]] = {
    "mysql": [
        re.compile(r"you have an error in your sql syntax", re.I),
        re.compile(r"warning: mysql", re.I),
        re.compile(r"mysql_fetch", re.I),
        re.compile(r"mysql_num_rows", re.I),
        re.compile(r"mysql_result", re.I),
        re.compile(r"unknown column", re.I),
    ],
    "postgresql": [
        re.compile(r"error:\s+syntax error at or near", re.I),
        re.compile(r"pg_query\(\):", re.I),
        re.compile(r"pg_exec\(\):", re.I),
        re.compile(r"invalid input syntax for type", re.I),
        re.compile(r"column\s+\S+\s+does not exist", re.I),
        re.compile(r"relation\s+\S+\s+does not exist", re.I),
    ],
    "mssql": [
        re.compile(r"unclosed quotation mark after the character string", re.I),
        re.compile(r"microsoft ole db", re.I),
        re.compile(r"microsoft sql native client", re.I),
        re.compile(r"incorrect syntax near", re.I),
        re.compile(r"line \d+:", re.I),
        re.compile(r"conversion failed when converting", re.I),
    ],
    "sqlite": [
        re.compile(r'near\s+".*"\s*:\s*syntax error', re.I),
        re.compile(r"sqlite_error", re.I),
        re.compile(r"sql logic error", re.I),
        re.compile(r"no such table", re.I),
        re.compile(r"no such column", re.I),
    ],
    "oracle": [
        re.compile(r"ora-\d{5}", re.I),
        re.compile(r"oracle error", re.I),
        re.compile(r"pl/sql:", re.I),
        re.compile(r"ora-\d{4}", re.I),
    ],
}
