import re


def slugify(title):
    """Lowercase the words of a title and join them with hyphens."""
    words = re.findall(r"[a-z]+", title.lower())
    return "-".join(words)
