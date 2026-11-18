import pytest

from tirweb.scope import validate_scan_scope


@pytest.mark.parametrize(
    "target",
    [
        "ftp://staging.example.in",
        "https://user:secret@staging.example.in",
        "https://staging.example.in/path?query=1",
        "https://staging.example.in/#fragment",
        "https://staging.example.in:invalid",
        "https://staging.example.in\\\\@other.example.in",
    ],
)
def test_rejects_invalid_target_urls(target: str) -> None:
    with pytest.raises(ValueError):
        validate_scan_scope(target)


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://other.example.in/private",
        "http://staging.example.in/private",
        "https://staging.example.in:8443/private",
        "//other.example.in/private",
        "https://user:pass@staging.example.in/private",
        "/private#fragment",
    ],
)
def test_rejects_endpoint_outside_or_invalid_scope(endpoint: str) -> None:
    with pytest.raises(ValueError):
        validate_scan_scope("https://staging.example.in", [endpoint])


def test_accepts_relative_and_same_origin_endpoints() -> None:
    target, endpoints = validate_scan_scope(
        "https://STAGING.example.in/",
        ["/api/v1/profile", "https://staging.example.in:443/api/v1/orders"],
    )
    assert target == "https://STAGING.example.in"
    assert endpoints == ["/api/v1/profile", "https://staging.example.in:443/api/v1/orders"]
