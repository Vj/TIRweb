"""Validation helpers for keeping scan requests inside an explicitly supplied origin."""

from urllib.parse import urlsplit


def _origin(parts):
    if not parts.hostname:
        raise ValueError("URL must include a hostname.")
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError("URL contains an invalid port.") from exc
    scheme = parts.scheme.lower()
    default_port = 443 if scheme == "https" else 80
    return scheme, parts.hostname.rstrip(".").lower(), port or default_port


def validate_scan_scope(target: str, endpoints: list[str] | None = None) -> tuple[str, list[str] | None]:
    """Validate the base URL and ensure every explicit endpoint remains same-origin."""
    target = target.strip()
    if not target or any(ord(ch) < 32 or ch.isspace() for ch in target) or "\\" in target:
        raise ValueError("Target URL must not contain whitespace, control characters, or backslashes.")

    base = urlsplit(target)
    if (
        base.scheme.lower() not in {"http", "https"}
        or not base.hostname
        or base.username is not None
        or base.password is not None
        or base.fragment
        or base.query
        or "://" in base.path
        or target.count("://") != 1
    ):
        raise ValueError("Use an absolute http(s) target URL without credentials, query, or fragment.")
    base_origin = _origin(base)
    normalized_target = target.rstrip("/")

    normalized_endpoints: list[str] = []
    for endpoint in endpoints or []:
        value = endpoint.strip()
        if not value or any(ord(ch) < 32 or ch.isspace() for ch in value) or "\\" in value:
            raise ValueError("Endpoints must be non-empty paths or same-origin URLs without whitespace.")
        parsed = urlsplit(value)
        if parsed.fragment or parsed.username is not None or parsed.password is not None:
            raise ValueError("Endpoint URLs must not contain credentials or fragments.")
        if value.startswith("//") or parsed.netloc and parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("Protocol-relative and unsupported endpoint URLs are not allowed.")
        if parsed.scheme:
            if parsed.scheme.lower() not in {"http", "https"} or _origin(parsed) != base_origin:
                raise ValueError("Absolute endpoints must use the same scheme, host, and port as the target.")
            normalized_endpoints.append(value)
        else:
            if parsed.netloc or "://" in parsed.path:
                raise ValueError("Endpoints must be relative paths or same-origin absolute URLs.")
            normalized_endpoints.append(value)

    return normalized_target, normalized_endpoints if endpoints is not None else None
