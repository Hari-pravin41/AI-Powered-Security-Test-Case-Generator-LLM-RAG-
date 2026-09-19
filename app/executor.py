"""
executor.py — runs generated TestCase objects against a real target over HTTP.

Safety: by design, this will ONLY send requests to hosts in ALLOWED_HOSTS.
That's not a suggestion — it's enforced in code. Security-testing tooling that
can be pointed at arbitrary third-party hosts by just changing a config value
is how "student project" becomes "unauthorized access" by accident. Add hosts
you own/control to the allowlist as you need them.
"""

import time

import httpx

from generator import TestCase

ALLOWED_HOSTS = {"127.0.0.1", "localhost", "sentinelai-target.onrender.com"}


class TargetNotAllowed(Exception):
    pass


def _check_allowed(base_url: str):
    from urllib.parse import urlparse
    host = urlparse(base_url).hostname
    if host not in ALLOWED_HOSTS:
        raise TargetNotAllowed(
            f"'{host}' is not in ALLOWED_HOSTS ({sorted(ALLOWED_HOSTS)}). "
            "SentinelAI only scans hosts you've explicitly allowlisted in "
            "executor.py — add your own target there once you control it."
        )


def _baseline_request(client: httpx.Client, method: str, url: str, path: str) -> httpx.Response:
    """A 'baseline' request must represent normal, expected behavior — an empty
    search query that matches everything is NOT a valid baseline for a search
    endpoint (it would already leak all rows, masking an injection's effect).
    Use a narrow, benign query so an injection's broader effect is visible as
    a real diff instead of being invisible against an already-broad baseline."""
    try:
        params = {"q": "zzz_no_match_zzz"} if "search" in path else None
        return client.request(method, url, params=params, timeout=5.0)
    except httpx.HTTPError:
        class _Empty:
            status_code = 0
            text = ""
        return _Empty()


def execute_test_case(base_url: str, case: TestCase) -> dict:
    """Runs one test case against base_url + case.path, and returns raw
    request/response data for the classifier + report to consume."""
    _check_allowed(base_url)
    path = case.path.replace("{id}", "101")  # demo path-param substitution
    url = base_url.rstrip("/") + path

    with httpx.Client() as client:
        baseline = _baseline_request(client, case.method, url, path)

        payload = case.mutation.get("payload", "")
        start = time.time()
        try:
            if case.method == "GET":
                # try the payload as a query param if the pattern implies injection
                test_url = url
                params = {"q": payload} if "q=" in path or "search" in path else None
                resp = client.request(case.method, test_url, params=params, timeout=5.0)
            else:
                body = {}
                if case.owasp_category == "Broken Access Control" and "refund" in path:
                    body = {"amount": 4999, "reason": "test"}
                elif "login" in path:
                    body = {"email": "victim@acme.com", "password": payload or "wrong-password"}
                else:
                    body = {"probe": payload}
                resp = client.request(case.method, url, json=body, timeout=5.0)
            elapsed_ms = (time.time() - start) * 1000
        except httpx.HTTPError as e:
            resp = None
            elapsed_ms = 0.0

    return {
        "url": url,
        "method": case.method,
        "payload": payload,
        "baseline_status": getattr(baseline, "status_code", 0),
        "baseline_body": getattr(baseline, "text", ""),
        "status_code": getattr(resp, "status_code", 0) if resp is not None else 0,
        "response_body": getattr(resp, "text", "") if resp is not None else "",
        "elapsed_ms": elapsed_ms,
    }


def probe_bola(base_url: str, path_template: str, my_id: int, other_owned_id: int) -> dict:
    """Direct logic check for Broken Object Level Authorization: request an
    action on a resource *owned by someone else* using the current session,
    and check whether the server let it through. This is a business-logic
    check, not a content-diff one — the ML classifier's response-diff features
    genuinely don't apply here, since a BOLA response often looks perfectly
    well-formed; what's wrong is *who* it was served to, which only a direct
    ownership check can catch."""
    _check_allowed(base_url)
    url = base_url.rstrip("/") + path_template.replace("{id}", str(other_owned_id))
    with httpx.Client() as client:
        try:
            resp = client.post(url, json={"amount": 4999, "reason": "test"}, timeout=5.0)
            body = resp.json() if resp.status_code == 200 else {}
        except (httpx.HTTPError, ValueError):
            return {"vulnerable": False, "detail": "request failed"}

    owner = body.get("order_owner")
    requester = body.get("requested_by", my_id)
    vulnerable = resp.status_code == 200 and owner is not None and owner != requester
    return {
        "vulnerable": vulnerable,
        "status_code": resp.status_code,
        "owner_id": owner,
        "requester_id": requester,
        "raw_response": resp.text if hasattr(resp, "text") else "",
    }


EXPECTED_HARDENING_HEADERS = ["strict-transport-security", "x-content-type-options", "content-security-policy"]
DISCLOSIVE_HEADERS = ["server", "x-powered-by"]


def probe_security_headers(base_url: str, path: str) -> dict:
    """Direct header inspection: response headers are invisible to the
    content-diff classifier (it only sees the body), so misconfigurations
    like missing hardening headers or version disclosure need a dedicated
    check rather than being inferred from response text."""
    _check_allowed(base_url)
    url = base_url.rstrip("/") + path
    with httpx.Client() as client:
        try:
            resp = client.get(url, timeout=5.0)
        except httpx.HTTPError:
            return {"missing_hardening": [], "disclosed": {}}

    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    missing = [h for h in EXPECTED_HARDENING_HEADERS if h not in headers_lower]
    disclosed = {h: headers_lower[h] for h in DISCLOSIVE_HEADERS if h in headers_lower}
    return {"missing_hardening": missing, "disclosed": disclosed}


def probe_rate_limit(base_url: str, path: str, attempts: int = 15) -> dict:
    """Special-cased check for A07 (missing rate limiting): fire repeated
    failed-login attempts and see whether the server ever pushes back."""
    _check_allowed(base_url)
    url = base_url.rstrip("/") + path
    statuses = []
    with httpx.Client() as client:
        for i in range(attempts):
            try:
                resp = client.post(url, json={"email": "victim@acme.com", "password": f"guess_{i}"}, timeout=5.0)
                statuses.append(resp.status_code)
            except httpx.HTTPError:
                statuses.append(0)
    throttled = any(s == 429 for s in statuses)
    return {"attempts": attempts, "statuses": statuses, "throttled": throttled}
