"""Turn titles into URL slugs."""
import re


def slugify(title):
    """Lower-case words of letters and digits, joined by single hyphens."""
    words = re.findall(r"[a-z0-9]+", title)
    return "-".join(words)
