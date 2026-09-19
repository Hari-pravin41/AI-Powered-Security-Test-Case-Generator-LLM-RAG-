"""
engine.py — orchestrates one full scan: for each endpoint, retrieve relevant
OWASP context (RAG), generate test cases, execute them, extract features from
the real response, and classify vulnerability likelihood (ML). This is the
"agent loop" the dashboard visualizes.
"""

import os
import time
import uuid

import joblib

from executor import execute_test_case, probe_bola, probe_rate_limit, probe_security_headers, TargetNotAllowed
from feature_extractor import extract_features
from generator import generate_test_cases
from rag import OwaspRAG

MODEL_PATH = os.path.join(os.path.dirname(__file__), "vuln_classifier.joblib")

_rag = OwaspRAG()
_classifier = joblib.load(MODEL_PATH) if os.path.exists(MODEL_PATH) else None

def _describe_endpoint(endpoint: dict) -> str:
    """Enrich a bare method+path into a fuller description for RAG retrieval.
    Real API scanners have this for free from an OpenAPI spec (parameter names,
    descriptions, request/response schemas) — this hand-rolled version stands
    in for that until you plug in a real spec parser."""
    path = endpoint["path"]
    hints = []
    if "search" in path or "?q=" in path:
        hints.append("accepts a search query parameter, queries a database")
    if "{id}" in path or "/<" in path:
        hints.append("operates on a specific resource by id, may belong to a specific user")
    if "login" in path or "auth" in path:
        hints.append("authenticates a user with credentials")
    if "refund" in path or "payment" in path or "order" in path:
        hints.append("mutates a financial record, ownership-sensitive")
    if "health" in path:
        hints.append("status endpoint, response headers may disclose versions")
    return f"{endpoint['method']} {path} — {', '.join(hints) if hints else 'general API endpoint'}"


SEVERITY_BY_OWASP = {
    "A01": "Critical", "A02": "High", "A03": "Critical", "A04": "Medium",
    "A05": "Low", "A06": "Medium", "A07": "High", "A08": "High",
    "A09": "Low", "A10": "Critical",
}


def run_scan(base_url: str, endpoints: list[dict], categories: list[str] | None = None,
             progress_cb=None) -> dict:
    """endpoints: [{"method": "GET", "path": "/api/v1/users/search"}, ...]
    categories: optional list of OWASP category names to restrict testing to
                (mirrors the checkboxes in the UI). None = infer via RAG per endpoint.
    progress_cb: optional callable(event: dict) invoked after each step, so a
                 caller (e.g. the API layer, streaming to the frontend) can
                 report live progress instead of waiting for the whole scan.
    """
    scan_id = str(uuid.uuid4())[:8]
    findings = []
    total_steps = 0
    step = 0

    def emit(event):
        nonlocal step
        step += 1
        event["step"] = step
        if progress_cb:
            progress_cb(event)

    emit({"type": "info", "message": f"Starting scan {scan_id} against {base_url}"})

    for endpoint in endpoints:
        endpoint_desc = _describe_endpoint(endpoint)
        if categories:
            contexts = _rag.retrieve_by_categories(categories)
        else:
            contexts = _rag.retrieve(endpoint_desc, k=3)

        emit({"type": "info", "message": f"Retrieved {len(contexts)} relevant OWASP categories for {endpoint_desc}"})

        cases = generate_test_cases(endpoint, contexts)
        emit({"type": "info", "message": f"Generated {len(cases)} test cases for {endpoint_desc}"})

        for case in cases:
            try:
                result = execute_test_case(base_url, case)
            except TargetNotAllowed as e:
                emit({"type": "error", "message": str(e)})
                return {"scan_id": scan_id, "error": str(e), "findings": []}

            features = extract_features(
                baseline_body=result["baseline_body"],
                test_body=result["response_body"],
                status_code=result["status_code"],
                elapsed_ms=result["elapsed_ms"],
                payload=str(result["payload"]),
            )

            if _classifier is not None:
                proba = _classifier.predict_proba([features])[0]
                vuln_confidence = float(proba[1])
            else:
                vuln_confidence = 0.5

            is_finding = vuln_confidence >= 0.55

            emit({
                "type": "test_result",
                "endpoint": endpoint_desc,
                "pattern": case.pattern_name,
                "owasp_category": case.owasp_category,
                "severity": SEVERITY_BY_OWASP.get(case.owasp_id, "Medium") if is_finding else None,
                "confidence": round(vuln_confidence, 3),
                "flagged": is_finding,
            })

            if is_finding:
                findings.append({
                    "id": len(findings) + 1,
                    "severity": SEVERITY_BY_OWASP.get(case.owasp_id, "Medium"),
                    "endpoint": endpoint_desc,
                    "vuln": case.pattern_name,
                    "owasp": case.owasp_category,
                    "owasp_id": case.owasp_id,
                    "status": "Confirmed" if vuln_confidence >= 0.75 else "Needs Review",
                    "confidence": round(vuln_confidence, 3),
                    "request": f"{result['method']} {result['url']}\npayload: {result['payload']}",
                    "response": f"HTTP {result['status_code']}\n\n{result['response_body'][:800]}",
                    "source": case.source,
                })

    # A01 (BOLA) gets a dedicated direct logic probe rather than the content-diff
    # classifier: a BOLA response is often well-formed JSON with a 200 status —
    # what's wrong is *who* it was served to, which only an ownership check catches.
    refund_endpoint = next((e for e in endpoints if "refund" in e["path"]), None)
    if refund_endpoint and (not categories or "Broken Access Control" in categories):
        emit({"type": "info", "message": "Probing refund endpoint for object-level authorization..."})
        bola_result = probe_bola(base_url, refund_endpoint["path"], my_id=1, other_owned_id=103)
        if bola_result["vulnerable"]:
            findings.append({
                "id": len(findings) + 1,
                "severity": "Critical",
                "endpoint": refund_endpoint["path"].replace("{id}", "103"),
                "vuln": "Broken Object Level Authorization (BOLA)",
                "owasp": "Broken Access Control",
                "owasp_id": "A01",
                "status": "Confirmed",
                "confidence": 0.97,
                "request": f"POST {base_url}{refund_endpoint['path'].replace('{id}', '103')}\nAuthorization: <user {bola_result['requester_id']}'s token>\n\n{{\"amount\": 4999, \"reason\": \"test\"}}",
                "response": f"HTTP {bola_result['status_code']}\n\n{bola_result['raw_response']}\n\norder_owner={bola_result['owner_id']} but requested_by={bola_result['requester_id']}",
                "source": "direct_probe",
            })
            emit({"type": "test_result", "endpoint": refund_endpoint["path"], "pattern": "BOLA probe",
                  "owasp_category": "Broken Access Control", "severity": "Critical", "confidence": 0.97, "flagged": True})

    # A07 gets a dedicated real probe (repeated real requests) rather than
    # a single request + classifier, since rate limiting is inherently about
    # request *volume* over time, not a single response's content.
    login_endpoint = next((e for e in endpoints if "login" in e["path"]), None)
    if login_endpoint and (not categories or "Identification and Authentication Failures" in categories):
        emit({"type": "info", "message": "Probing login endpoint for rate limiting (15 requests)..."})
        rl_result = probe_rate_limit(base_url, login_endpoint["path"])
        if not rl_result["throttled"]:
            findings.append({
                "id": len(findings) + 1,
                "severity": "High",
                "endpoint": f"POST {login_endpoint['path']}",
                "vuln": "Missing rate limiting on login",
                "owasp": "Identification and Authentication Failures",
                "owasp_id": "A07",
                "status": "Confirmed",
                "confidence": 0.95,
                "request": f"POST {base_url}{login_endpoint['path']}  x{rl_result['attempts']} in <5s",
                "response": f"Status codes observed: {rl_result['statuses']}\nNo HTTP 429 seen across {rl_result['attempts']} attempts.",
                "source": "direct_probe",
            })
            emit({"type": "test_result", "endpoint": login_endpoint["path"], "pattern": "Rate limit probe",
                  "owasp_category": "Identification and Authentication Failures", "severity": "High", "confidence": 0.95, "flagged": True})

    # A05: direct header inspection — invisible to the content-diff classifier.
    health_endpoint = next((e for e in endpoints if endpoints), endpoints[0]) if endpoints else None
    if health_endpoint and (not categories or "Security Misconfiguration" in categories):
        emit({"type": "info", "message": "Inspecting response headers for misconfiguration..."})
        hdr_result = probe_security_headers(base_url, health_endpoint["path"])
        if hdr_result["disclosed"]:
            findings.append({
                "id": len(findings) + 1,
                "severity": "Low",
                "endpoint": health_endpoint["path"],
                "vuln": "Version disclosure in response headers",
                "owasp": "Security Misconfiguration",
                "owasp_id": "A05",
                "status": "Confirmed",
                "confidence": 0.9,
                "request": f"GET {base_url}{health_endpoint['path']}",
                "response": f"Disclosed headers: {hdr_result['disclosed']}",
                "source": "direct_probe",
            })
            emit({"type": "test_result", "endpoint": health_endpoint["path"], "pattern": "Header inspection",
                  "owasp_category": "Security Misconfiguration", "severity": "Low", "confidence": 0.9, "flagged": True})
        if hdr_result["missing_hardening"]:
            findings.append({
                "id": len(findings) + 1,
                "severity": "Low",
                "endpoint": health_endpoint["path"],
                "vuln": "Missing security headers",
                "owasp": "Security Misconfiguration",
                "owasp_id": "A05",
                "status": "Confirmed",
                "confidence": 0.85,
                "request": f"GET {base_url}{health_endpoint['path']}",
                "response": f"Missing hardening headers: {hdr_result['missing_hardening']}",
                "source": "direct_probe",
            })

    emit({"type": "done", "message": f"Scan complete — {len(findings)} findings"})

    risk_score = min(100, sum({"Critical": 25, "High": 15, "Medium": 8, "Low": 3}.get(f["severity"], 5) for f in findings))

    return {
        "scan_id": scan_id,
        "target": base_url,
        "endpoints_tested": len(endpoints),
        "findings": findings,
        "risk_score": risk_score,
    }


if __name__ == "__main__":
    # Requires the vulnerable_target Flask app running on :5001 (see README)
    endpoints = [
        {"method": "GET", "path": "/api/v1/users/search"},
        {"method": "POST", "path": "/api/v1/orders/{id}/refund"},
        {"method": "POST", "path": "/api/v1/auth/login"},
        {"method": "GET", "path": "/api/v1/health"},
    ]
    result = run_scan("http://127.0.0.1:5001", endpoints, progress_cb=lambda e: print(e))
    print("\n=== SUMMARY ===")
    print(f"Findings: {len(result['findings'])}, Risk score: {result.get('risk_score')}")
    for f in result["findings"]:
        print(f"  [{f['severity']}] {f['vuln']} @ {f['endpoint']} (confidence={f['confidence']})")
