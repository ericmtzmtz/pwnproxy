import re
from typing import List, Tuple


Marker = Tuple[int, str]  # (position_index, base_value)


def parse_markers(raw: str) -> tuple[str, list[Marker]]:
    """Parse raw HTTP request and extract § delimited markers.

    Returns (template_str, list_of_markers) where template_str has § removed.
    """
    markers: list[Marker] = []
    pos = 0
    template_parts: list[str] = []

    pattern = re.compile(r"§(.*?)§")

    cursor = 0
    for match in pattern.finditer(raw):
        start, end = match.start(), match.end()
        template_parts.append(raw[cursor:start])
        base_value = match.group(1)
        markers.append((pos, base_value))
        template_parts.append(f"{{{pos}}}")
        cursor = end
        pos += 1

    template_parts.append(raw[cursor:])
    template = "".join(template_parts)

    return template, markers
