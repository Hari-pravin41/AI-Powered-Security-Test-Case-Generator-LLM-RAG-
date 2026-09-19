"""
rag.py — Retrieval-Augmented Generation over the OWASP Top 10 knowledge base.

Real embedding pipeline:
  1. TF-IDF vectorizes each OWASP entry (description + keywords + test pattern names)
  2. TruncatedSVD compresses TF-IDF vectors into dense embeddings (latent semantic
     analysis) — a legitimate, classic embedding technique that needs no downloaded
     pretrained weights, so it runs anywhere with zero network dependency.
  3. Embeddings are indexed in FAISS (IndexFlatIP, cosine similarity via
     L2-normalized vectors) for fast nearest-neighbor retrieval.

Given a free-text description of an API endpoint (e.g. "POST /orders/{id}/refund
processes a refund for an order"), `retrieve()` returns the OWASP categories most
semantically relevant to that endpoint, which the generator then uses to produce
targeted test cases instead of testing every category against every endpoint.
"""

import json
import os
from dataclasses import dataclass

import faiss
import numpy as np
from sklearn.decomposition import TruncatedSVD
from sklearn.feature_extraction.text import TfidfVectorizer

DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "owasp_top10.json")
EMBEDDING_DIM = 64


@dataclass
class RetrievedContext:
    category: str
    owasp_id: str
    description: str
    test_patterns: list
    score: float


class OwaspRAG:
    """Loads the OWASP knowledge base, builds embeddings, and serves retrieval."""

    def __init__(self, data_path: str = DATA_PATH):
        with open(data_path) as f:
            self.entries = json.load(f)

        corpus = [self._entry_to_text(e) for e in self.entries]

        # 1. TF-IDF vectorization
        self.vectorizer = TfidfVectorizer(stop_words="english", max_features=2000)
        tfidf_matrix = self.vectorizer.fit_transform(corpus)

        # 2. Dense embeddings via truncated SVD (latent semantic analysis)
        n_components = min(EMBEDDING_DIM, tfidf_matrix.shape[0] - 1, tfidf_matrix.shape[1] - 1)
        self.svd = TruncatedSVD(n_components=n_components, random_state=42)
        dense = self.svd.fit_transform(tfidf_matrix).astype("float32")

        # 3. L2-normalize so inner product == cosine similarity
        faiss.normalize_L2(dense)
        self.embeddings = dense

        # 4. Build FAISS index
        self.index = faiss.IndexFlatIP(dense.shape[1])
        self.index.add(dense)

    @staticmethod
    def _entry_to_text(entry: dict) -> str:
        patterns = " ".join(p["name"] + " " + p["method"] for p in entry["test_patterns"])
        return " ".join([
            entry["category"],
            entry["description"],
            " ".join(entry["keywords"]),
            patterns,
        ])

    def _embed_query(self, text: str) -> np.ndarray:
        tfidf_vec = self.vectorizer.transform([text])
        dense_vec = self.svd.transform(tfidf_vec).astype("float32")
        faiss.normalize_L2(dense_vec)
        return dense_vec

    def retrieve(self, endpoint_description: str, k: int = 3) -> list[RetrievedContext]:
        """Return the top-k OWASP categories most relevant to an endpoint description."""
        query_vec = self._embed_query(endpoint_description)
        scores, indices = self.index.search(query_vec, k)

        results = []
        for score, idx in zip(scores[0], indices[0]):
            if idx == -1:
                continue
            entry = self.entries[idx]
            results.append(RetrievedContext(
                category=entry["category"],
                owasp_id=entry["id"],
                description=entry["description"],
                test_patterns=entry["test_patterns"],
                score=float(score),
            ))
        return results

    def retrieve_by_categories(self, category_names: list[str]) -> list[RetrievedContext]:
        """Direct lookup when the caller already knows which OWASP categories to test
        (e.g. from the checkboxes selected in the UI), skipping semantic retrieval."""
        results = []
        for entry in self.entries:
            if entry["category"] in category_names:
                results.append(RetrievedContext(
                    category=entry["category"],
                    owasp_id=entry["id"],
                    description=entry["description"],
                    test_patterns=entry["test_patterns"],
                    score=1.0,
                ))
        return results


if __name__ == "__main__":
    rag = OwaspRAG()
    for q in [
        "POST /orders/{id}/refund processes a refund for a given order id",
        "GET /users/search?q= searches users by name",
        "POST /auth/login authenticates a user with email and password",
    ]:
        print(f"\nQuery: {q}")
        for r in rag.retrieve(q, k=2):
            print(f"  [{r.score:.3f}] {r.category} ({r.owasp_id})")
