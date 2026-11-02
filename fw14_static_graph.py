from __future__ import annotations

import hashlib
import hmac
import re
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Mapping
from urllib.parse import urlsplit


IMPORT_RE = re.compile(
    r"(?:\bimport\s*(?:[^;'\"]*?\s+from\s*)?|\bexport\s+[^;'\"]*?\s+from\s*|\bimport\s*\(\s*)"
    r"['\"]([^'\"]+)['\"]"
)
WORKER_RE = re.compile(r"(?:\bnew\s+Worker\s*\(|\bimportScripts\s*\()\s*['\"]([^'\"]+)['\"]")


class _ScriptParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.sources: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "script":
            values = dict(attrs)
            if values.get("src") is not None:
                self.sources.append(values["src"] or "")


def _local_dependency(parent: str, reference: str) -> str:
    parsed = urlsplit(reference)
    if parsed.scheme or parsed.netloc or parsed.fragment or not parsed.path:
        raise ValueError(f"non-local or malformed static dependency {reference!r} from {parent}")
    if parsed.path.startswith("/"):
        candidate = PurePosixPath(parsed.path)
    else:
        candidate = PurePosixPath(parent).parent / parsed.path
    normalized = "/" + str(candidate).lstrip("/")
    if ".." in PurePosixPath(normalized).parts or not normalized.endswith(".js"):
        raise ValueError(f"unsafe or non-JavaScript dependency {reference!r} from {parent}")
    return normalized


def load_static_graph(
    root: Path,
    expected_hashes: Mapping[str, str] | None,
    *,
    stage_page: str,
) -> tuple[Mapping[str, bytes], Mapping[str, str], str]:
    root = root.resolve()
    pending = [stage_page]
    payloads: dict[str, bytes] = {}
    hashes: dict[str, str] = {}
    while pending:
        request_path = pending.pop()
        if request_path in payloads:
            continue
        try:
            source = (root / request_path.removeprefix("/")).resolve(strict=True)
            source.relative_to(root)
            if not source.is_file():
                raise ValueError("not a regular file")
            payload = source.read_bytes()
        except (OSError, ValueError) as error:
            raise ValueError(
                f"required static file escapes the root or is unreadable: {request_path}: {error}"
            ) from error
        payloads[request_path] = payload
        hashes[request_path] = hashlib.sha256(payload).hexdigest()
        try:
            text = payload.decode("utf-8")
        except UnicodeError as error:
            raise ValueError(f"required static file is not UTF-8: {request_path}: {error}") from error
        if request_path == stage_page:
            parser = _ScriptParser()
            parser.feed(text)
            references = parser.sources + IMPORT_RE.findall(text) + WORKER_RE.findall(text)
            if not references:
                raise ValueError(f"{stage_page} loads no JavaScript")
        else:
            references = IMPORT_RE.findall(text) + WORKER_RE.findall(text)
        pending.extend(_local_dependency(request_path, reference) for reference in references)
    if expected_hashes is not None:
        expected = dict(expected_hashes)
        if set(expected) != set(hashes):
            raise ValueError(
                f"static manifest paths differ: expected={sorted(expected)} discovered={sorted(hashes)}"
            )
        mismatched = [
            path
            for path in sorted(hashes)
            if not hmac.compare_digest(hashes[path], expected[path])
        ]
        if mismatched:
            raise ValueError(f"static manifest hash mismatch: {mismatched}")
    manifest = hashlib.sha256(
        "".join(f"{path} {hashes[path]}\n" for path in sorted(hashes)).encode("ascii")
    ).hexdigest()
    return MappingProxyType(payloads), MappingProxyType(hashes), manifest
