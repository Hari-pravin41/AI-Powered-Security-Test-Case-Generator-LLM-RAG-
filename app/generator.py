"""
generator.py — turns RAG-retrieved OWASP context into concrete, executable test cases.

Two modes:
  - LLM mode: if an API key is present in the environment (ANTHROPIC_API_KEY or
    OPENAI_API_KEY), the retrieved OWASP context is fed to the model as grounding
    and it drafts concrete request parameters for the target endpoint. This is the
    real RAG+LLM pipeline described in the project.
  - Template mode (default, no key required): falls back to the `payload_template`
    already attached to each retrieved OWASP test pattern. This keeps the whole
    pipeline runnable end-to-end with zero external API dependency, which is what
    you want for local development, grading, and demos.

Both modes return the same TestCase shape, so the executor doesn't care which one
produced it.
"""

import os
from dataclasses import dataclass, field

from rag import RetrievedContext


@dataclass
class TestCase:
    owasp_id: str
    owasp_category: str
    pattern_name: str
    method: str
    path: str
    description: str
    mutation: dict = field(default_factory=dict)  # what to change vs. a baseline request
    source: str = "template"  # "template" or "llm"


def _llm_available() -> str | None:
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"
    return None


def _generate_with_llm(provider: str, endpoint: dict, context: RetrievedContext) -> TestCase | None:
    """Ask an LLM to draft a concrete test case grounded in the retrieved OWASP
    pattern. Kept isolated so it fails soft (falls back to template) if the API
    call errors, times out, or the response can't be parsed — a scan should never
    hard-fail just because the LLM provider had a bad moment."""
    prompt = f"""You are a security test-case generator grounded in OWASP guidance.

OWASP category: {context.category} ({context.owasp_id})
Guidance: {context.description}
Known pattern: {context.test_patterns[0]['name']} — {context.test_patterns[0]['method']}

Target endpoint: {endpoint['method']} {endpoint['path']}

Respond with ONLY a JSON object: {{"mutation": {{...}}, "description": "one sentence"}}
describing the minimal change to a baseline request that would test for this
specific vulnerability against this specific endpoint."""

    try:
        if provider == "anthropic":
            import anthropic
            client = anthropic.Anthropic()
            resp = client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=300,
                messages=[{"role": "user", "content": prompt}],
            )
            text = resp.content[0].text
        else:
            import openai
            client = openai.OpenAI()
            resp = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
            )
            text = resp.choices[0].message.content

        import json
        parsed = json.loads(text[text.index("{"):text.rindex("}") + 1])
        return TestCase(
            owasp_id=context.owasp_id,
            owasp_category=context.category,
            pattern_name=context.test_patterns[0]["name"],
            method=endpoint["method"],
            path=endpoint["path"],
            description=parsed.get("description", context.test_patterns[0]["method"]),
            mutation=parsed.get("mutation", {}),
            source="llm",
        )
    except Exception:
        return None  # soft fail -> caller falls back to template mode


def generate_test_cases(endpoint: dict, contexts: list[RetrievedContext], max_per_category: int = 2) -> list[TestCase]:
    """endpoint: {"method": "GET", "path": "/api/v1/users/search"}
    contexts: RAG-retrieved OwaspRAG.RetrievedContext list for this endpoint.
    Returns concrete TestCase objects ready for the executor."""
    provider = _llm_available()
    cases: list[TestCase] = []

    for ctx in contexts:
        for pattern in ctx.test_patterns[:max_per_category]:
            case = None
            if provider:
                case = _generate_with_llm(provider, endpoint, ctx)
            if case is None:
                case = TestCase(
                    owasp_id=ctx.owasp_id,
                    owasp_category=ctx.category,
                    pattern_name=pattern["name"],
                    method=endpoint["method"],
                    path=endpoint["path"],
                    description=pattern["method"],
                    mutation={"payload": pattern["payload_template"]},
                    source="template",
                )
            cases.append(case)
    return cases


if __name__ == "__main__":
    from rag import OwaspRAG
    rag = OwaspRAG()
    endpoint = {"method": "GET", "path": "/api/v1/users/search"}
    contexts = rag.retrieve("GET /users/search searches users by query string", k=2)
    for tc in generate_test_cases(endpoint, contexts):
        print(f"[{tc.source}] {tc.owasp_category} :: {tc.pattern_name} -> {tc.mutation}")
