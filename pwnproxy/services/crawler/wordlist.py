import importlib.resources
from typing import List, Union

BUILTIN_NAMES = ("small", "medium", "large")

_sizes_cache: dict[str, int] | None = None


def _load_builtin(name: str) -> List[str]:
    """Load a built-in wordlist from the package data."""
    try:
        files = importlib.resources.files("pwnproxy.services.crawler.wordlists")
        data = files.joinpath(f"{name}.txt").read_text(encoding="utf-8")
    except AttributeError:
        with importlib.resources.open_binary("pwnproxy.services.crawler.wordlists", f"{name}.txt") as f:
            data = f.read().decode("utf-8")
    return [line.strip() for line in data.splitlines() if line.strip()]


def builtin_sizes() -> dict[str, int]:
    """Entry counts per built-in wordlist. Computed lazily and cached."""
    global _sizes_cache
    if _sizes_cache is None:
        _sizes_cache = {name: len(_load_builtin(name)) for name in BUILTIN_NAMES}
    return _sizes_cache


def resolve_wordlist(source: Union[str, List[str]]) -> List[str]:
    """
    Resolve a wordlist source to a list of strings.
    If source is a string and matches a built-in name, load that file.
    If source is a list, validate non-empty and return it.
    """
    if isinstance(source, list):
        if len(source) == 0:
            raise ValueError("Wordlist list cannot be empty")
        return source
    if isinstance(source, str):
        if source in BUILTIN_NAMES:
            words = _load_builtin(source)
            if not words:
                raise ValueError(f"Built-in wordlist '{source}' is empty")
            return words
        raise ValueError(f"Unknown built-in wordlist name: {source}")
    raise TypeError("Source must be a builtin name string or a list of strings")


def estimate_requests(words: List[str], extensions: List[str], base_urls: List[str]) -> int:
    """
    Estimate number of HTTP requests for directory bruteforce.
    Formula: len(words) * (1 + len(extensions)) * len(base_urls)
    """
    return len(words) * (1 + len(extensions)) * len(base_urls)
