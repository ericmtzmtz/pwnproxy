"""WAF evasion techniques for scanner payloads.

Provides encoding transforms that modify payloads to bypass common WAFs.
"""
import logging
import re
import urllib.parse
from enum import Enum

logger = logging.getLogger(__name__)


class EvasionLevel(str, Enum):
    """WAF evasion level."""
    NONE = "none"           # No evasion
    LIGHT = "light"         # Basic encoding
    AGGRESSIVE = "aggressive"  # Multiple encoding layers


def apply_evasion(payload: str, level: EvasionLevel) -> str:
    """Apply WAF evasion encoding to a payload.
    
    Args:
        payload: The original payload
        level: Evasion level to apply
        
    Returns:
        Encoded payload
    """
    if level == EvasionLevel.NONE:
        return payload
    
    if level == EvasionLevel.LIGHT:
        return double_url_encode(payload)
    
    if level == EvasionLevel.AGGRESSIVE:
        # Apply multiple encoding layers
        result = payload
        result = unicode_escape(result)
        result = double_url_encode(result)
        return result
    
    return payload


def double_url_encode(payload: str) -> str:
    """Double URL encode special characters.
    
    Example: ' -> %27 -> %2527
    """
    # First URL encode
    encoded = urllib.parse.quote(payload, safe="")
    # Second URL encode (encode the % signs)
    return encoded.replace("%", "%25")


def unicode_escape(payload: str) -> str:
    """Escape special characters using Unicode escapes.
    
    Example: ' -> \u0027
    """
    # Order matters: escape \ last to avoid double-escaping
    result = payload
    result = result.replace("<", "\\u003c")
    result = result.replace(">", "\\u003e")
    result = result.replace("&", "\\u0026")
    result = result.replace("'", "\\u0027")
    result = result.replace('"', "\\u0022")
    result = result.replace("/", "\\u002f")
    return result


def html_entity_encode(payload: str) -> str:
    """Encode special characters as HTML entities.
    
    Example: ' -> &#39;
    """
    # & must be replaced FIRST to avoid double-encoding
    result = payload.replace("&", "&amp;")
    result = result.replace("'", "&#39;")
    result = result.replace('"', "&quot;")
    result = result.replace("<", "&lt;")
    result = result.replace(">", "&gt;")
    return result


def null_byte_inject(payload: str) -> str:
    """Insert null bytes to bypass WAF pattern matching.
    
    Example: <script> -> <%00script>
    """
    # Insert null byte after < 
    result = payload.replace("<", "<\x00")
    return result


def case_variation(payload: str) -> str:
    """Randomize case of alphabetic characters.
    
    Example: <script> -> <ScRiPt>
    """
    import random
    result = ""
    for char in payload:
        if char.isalpha():
            result += random.choice([char.upper(), char.lower()])
        else:
            result += char
    return result


def whitespace_inject(payload: str) -> str:
    """Inject whitespace characters to break WAF patterns.
    
    Example: <script> -> <\tscript\n>
    """
    # Add whitespace after < and before >
    result = payload.replace("<", "<\t").replace(">", "\n>")
    return result


# Mapping of evasion techniques
EVASION_TECHNIQUES = {
    "double_url": double_url_encode,
    "unicode": unicode_escape,
    "html_entity": html_entity_encode,
    "null_byte": null_byte_inject,
    "case_variation": case_variation,
    "whitespace": whitespace_inject,
}


def apply_technique(payload: str, technique: str) -> str:
    """Apply a specific evasion technique.
    
    Args:
        payload: The original payload
        technique: Name of the technique to apply
        
    Returns:
        Encoded payload
    """
    func = EVASION_TECHNIQUES.get(technique)
    if func is None:
        logger.warning("Unknown evasion technique: %s", technique)
        return payload
    return func(payload)
