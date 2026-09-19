"""
feature_extractor.py — turns a (baseline_response, test_response, test_case,
elapsed_ms) tuple into the numeric feature vector the RandomForest classifier
was trained on. This is where "raw HTTP traffic" becomes "ML input."
"""

import re

ERROR_KEYWORDS = ["error", "exception", "stack", "traceback", "syntax", "unauthorized", "forbidden"]
SQL_KEYWORDS = ["sql", "sqlite", "syntax error", "select", "union", "mysql", "postgres"]


def _status_bucket(status_code: int) -> int:
    if 200 <= status_code < 300:
        return 0
    if 400 <= status_code < 500:
        return 1
    return 2


def extract_features(baseline_body: str, test_body: str, status_code: int,
                      elapsed_ms: float, payload: str) -> list[float]:
    baseline_len = max(len(baseline_body), 1)
    test_len = len(test_body)
    size_ratio = test_len / baseline_len

    lower_test = test_body.lower()
    contains_error_kw = int(any(kw in lower_test for kw in ERROR_KEYWORDS))
    contains_sql_kw = int(any(kw in lower_test for kw in SQL_KEYWORDS))

    reflects_payload = int(bool(payload) and payload.lower() in lower_test)

    # crude but real: character-level difference ratio vs baseline
    diff_chars = sum(1 for a, b in zip(baseline_body, test_body) if a != b)
    diff_chars += abs(len(baseline_body) - len(test_body))
    baseline_diff_ratio = min(diff_chars / baseline_len, 1.0)

    return [
        _status_bucket(status_code),
        min(size_ratio, 5.0),
        contains_error_kw,
        contains_sql_kw,
        elapsed_ms,
        reflects_payload,
        baseline_diff_ratio,
    ]
