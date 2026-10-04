"""``tag=value; tag=value`` lists, the syntax shared by DKIM keys and DMARC records (RFC 6376 3.2)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_TAG_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")


@dataclass
class TagList:
    tags: dict[str, str] = field(default_factory=dict)  # lower-cased name -> stripped value
    order: list[str] = field(default_factory=list)  # names in the order they appear
    errors: list[str] = field(default_factory=list)


def parse_tag_list(text: str) -> TagList:
    """Parse leniently and collect every syntax problem instead of stopping at the first.

    A trailing ``;`` and whitespace around ``=`` are legal. A duplicated tag makes
    the whole list invalid (RFC 6376 3.2), which is reported as an error.
    """
    result = TagList()
    for part in text.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            result.errors.append(f"'{part}' is not a tag=value pair")
            continue
        name, value = part.split("=", 1)
        name = name.strip()
        if not _TAG_NAME.match(name):
            result.errors.append(f"'{name}' is not a valid tag name")
            continue
        key = name.lower()
        if key in result.tags:
            result.errors.append(f"tag '{key}' appears more than once")
            continue
        result.tags[key] = value.strip()
        result.order.append(key)
    return result
