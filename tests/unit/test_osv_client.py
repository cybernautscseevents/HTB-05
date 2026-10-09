"""Unit tests for OSV HTTP client, batching, caching, and retry behavior."""

import httpx
import pytest

from acsa.vulnerability.cache import VulnerabilityCache
from acsa.vulnerability.exceptions import OSVResponseError, OSVTimeoutError
from acsa.vulnerability.osv_client import OSVClient


def test_batch_query_successful() -> None:
    """Verify batch query sends single request and correctly parses matching vuln IDs."""
    call_count = 0

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        assert request.url.path == "/v1/querybatch"
        return httpx.Response(
            200,
            json={
                "results": [
                    {"vulns": [{"id": "GHSA-1111", "modified": "2024-01-01T00:00:00Z"}]},
                    {"vulns": []},
                ]
            },
        )

    cache = VulnerabilityCache(":memory:")
    transport = httpx.MockTransport(mock_handler)
    client = httpx.Client(transport=transport)
    osv = OSVClient(cache=cache, client=client)

    queries = [("npm", "lodash", "4.17.19"), ("npm", "cookie", "0.6.0")]
    results = osv.query_batch(queries)

    assert call_count == 1
    assert results[("npm", "lodash", "4.17.19")] == ["GHSA-1111"]
    assert results[("npm", "cookie", "0.6.0")] == []


def test_cache_hit_and_miss_behavior() -> None:
    """Verify uncached queries trigger HTTP calls while cached queries do not."""
    call_count = 0

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        return httpx.Response(
            200,
            json={"results": [{"vulns": [{"id": "GHSA-2222"}]}]},
        )

    cache = VulnerabilityCache(":memory:")
    transport = httpx.MockTransport(mock_handler)
    client = httpx.Client(transport=transport)
    osv = OSVClient(cache=cache, client=client)

    # First call: cache miss, triggers HTTP request
    res1 = osv.query_batch([("npm", "minimist", "0.0.8")])
    assert call_count == 1
    assert res1[("npm", "minimist", "0.0.8")] == ["GHSA-2222"]

    # Second call for same package: cache hit, no HTTP request made!
    res2 = osv.query_batch([("npm", "minimist", "0.0.8")])
    assert call_count == 1
    assert res2[("npm", "minimist", "0.0.8")] == ["GHSA-2222"]


def test_get_vulnerability_caching() -> None:
    """Verify advisory detail fetches are cached locally."""
    call_count = 0

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        assert "/vulns/GHSA-3333" in str(request.url)
        return httpx.Response(
            200,
            json={"id": "GHSA-3333", "summary": "Prototype Pollution in test-pkg"},
        )

    cache = VulnerabilityCache(":memory:")
    transport = httpx.MockTransport(mock_handler)
    client = httpx.Client(transport=transport)
    osv = OSVClient(cache=cache, client=client)

    # First fetch: miss
    adv1 = osv.get_vulnerability("GHSA-3333")
    assert call_count == 1
    assert adv1["id"] == "GHSA-3333"

    # Second fetch: hit
    adv2 = osv.get_vulnerability("GHSA-3333")
    assert call_count == 1
    assert adv2["summary"] == "Prototype Pollution in test-pkg"


def test_transient_retry_success() -> None:
    """Verify client retries on transient HTTP 503 and succeeds on subsequent try."""
    attempts = 0

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return httpx.Response(503, text="Service Unavailable")
        return httpx.Response(200, json={"results": [{"vulns": []}]})

    cache = VulnerabilityCache(":memory:")
    transport = httpx.MockTransport(mock_handler)
    client = httpx.Client(transport=transport)
    osv = OSVClient(cache=cache, client=client, max_retries=2)

    res = osv.query_batch([("npm", "express", "4.18.2")])
    assert attempts == 2
    assert res[("npm", "express", "4.18.2")] == []


def test_osv_error_raises_exception() -> None:
    """Verify permanent HTTP 500 error raises OSVResponseError."""
    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="Internal Server Error")

    cache = VulnerabilityCache(":memory:")
    transport = httpx.MockTransport(mock_handler)
    client = httpx.Client(transport=transport)
    osv = OSVClient(cache=cache, client=client, max_retries=1)

    with pytest.raises(OSVResponseError) as exc_info:
        osv.query_batch([("npm", "express", "4.18.2")])
    assert exc_info.value.status_code == 500


def test_osv_timeout_raises_exception() -> None:
    """Verify timeout triggers OSVTimeoutError after retries."""
    def mock_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("Mock read timeout")

    cache = VulnerabilityCache(":memory:")
    transport = httpx.MockTransport(mock_handler)
    client = httpx.Client(transport=transport)
    osv = OSVClient(cache=cache, client=client, max_retries=1)

    with pytest.raises(OSVTimeoutError):
        osv.query_batch([("npm", "express", "4.18.2")])
