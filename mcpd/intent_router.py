from __future__ import annotations

import logging
import os
from typing import Any, Dict, Iterable, List, Sequence, Tuple

LOGGER = logging.getLogger(__name__)


def _flatten_example_values(values: Any) -> List[str]:
    if values is None:
        return []
    if isinstance(values, str):
        text = values.strip()
        return [text] if text else []
    if isinstance(values, dict):
        out: List[str] = []
        for key, item in values.items():
            out.extend(_flatten_example_values(key))
            out.extend(_flatten_example_values(item))
        return out
    if isinstance(values, (list, tuple, set)):
        out: List[str] = []
        for item in values:
            out.extend(_flatten_example_values(item))
        return out
    return [str(values)]


def semantic_document_for_action(action: Any) -> str:
    description = str(getattr(action, "description", "") or "")
    intent_tags = _flatten_example_values(getattr(action, "intent_tags", ()))
    examples = _flatten_example_values(getattr(action, "examples", ()))
    parts = [description, " ".join(intent_tags), " ".join(examples)]
    return "\n".join(part for part in parts if part.strip())


def semantic_document_for_capability(capability: Any) -> str:
    name = str(getattr(capability, "name", "") or "")
    description = str(getattr(capability, "description", "") or "")
    intent_tags = _flatten_example_values(getattr(capability, "intent_tags", ()))
    examples = _flatten_example_values(getattr(capability, "examples", ()))
    provider_ids = _flatten_example_values(getattr(capability, "provider_ids", ()))
    parts = [name, description, " ".join(intent_tags), " ".join(examples), " ".join(provider_ids)]
    return "\n".join(part for part in parts if part.strip())


class LocalSemanticScorer:
    def __init__(self) -> None:
        self._backend: str = "uninitialized"
        self._model: Any = None
        self._cache: Dict[str, Any] = {}

    def _enabled_by_env(self) -> bool:
        raw = os.getenv("MCPD_SEMANTIC_ROUTING", "auto").strip().lower()
        return raw not in {"0", "off", "false", "disabled"}

    def _resolve_backend(self) -> str:
        if self._backend != "uninitialized":
            return self._backend
        if not self._enabled_by_env():
            self._backend = "disabled"
            return self._backend
        try:
            from sentence_transformers import SentenceTransformer  # type: ignore
        except Exception as exc:  # pragma: no cover - depends on runtime environment
            LOGGER.debug("semantic router disabled: %s", exc)
            self._backend = "unavailable"
            return self._backend

        model_name = os.getenv(
            "MCPD_EMBED_MODEL",
            "sentence-transformers/all-MiniLM-L6-v2",
        ).strip() or "sentence-transformers/all-MiniLM-L6-v2"
        try:
            self._model = SentenceTransformer(model_name)
        except Exception as exc:  # pragma: no cover - depends on runtime environment
            LOGGER.warning("semantic router model load failed (%s): %s", model_name, exc)
            self._backend = "unavailable"
            return self._backend
        self._backend = "sentence-transformers"
        return self._backend

    def backend(self) -> str:
        return self._resolve_backend()

    def _encode_one(self, text: str) -> Any:
        vector = self._cache.get(text)
        if vector is not None:
            return vector
        assert self._model is not None
        encoded = self._model.encode(text, normalize_embeddings=True)
        self._cache[text] = encoded
        return encoded

    def encode(self, text: str) -> Any:
        if not text.strip():
            return None
        if self._resolve_backend() != "sentence-transformers" or self._model is None:
            return None
        return self._encode_one(text)

    def score(self, query: str, documents: Sequence[str]) -> List[float]:
        if not query.strip() or not documents:
            return [0.0 for _ in documents]
        if self._resolve_backend() != "sentence-transformers" or self._model is None:
            return [0.0 for _ in documents]
        query_vec = self._encode_one(query)
        out: List[float] = []
        for document in documents:
            doc_vec = self._encode_one(document)
            # sentence-transformers already returns normalized embeddings.
            cosine = float(query_vec.dot(doc_vec))
            out.append(max(-1.0, min(1.0, cosine)))
        return out


_SEMANTIC_SCORER = LocalSemanticScorer()
_CANDIDATE_VECTOR_CACHE: Dict[Tuple[str, int], Any] = {}


def _clamp_cosine(value: float) -> float:
    return max(-1.0, min(1.0, value))


def register_candidate_semantic_embeddings(
    candidates: Iterable[Tuple[str, int, str]],
) -> Tuple[str, int]:
    backend = _SEMANTIC_SCORER.backend()
    if backend != "sentence-transformers":
        return backend, 0
    registered = 0
    for namespace, candidate_id, document in candidates:
        key = (str(namespace), int(candidate_id))
        if key in _CANDIDATE_VECTOR_CACHE:
            continue
        vec = _SEMANTIC_SCORER.encode(str(document))
        if vec is None:
            continue
        _CANDIDATE_VECTOR_CACHE[key] = vec
        registered += 1
    return backend, registered


def semantic_scores_for_candidates(
    intent_text: str,
    candidates: Iterable[Tuple[str, int, str]],
) -> Tuple[str, Dict[Tuple[str, int], float]]:
    indexed = list(candidates)
    if not indexed:
        return _SEMANTIC_SCORER.backend(), {}
    backend = _SEMANTIC_SCORER.backend()
    if backend != "sentence-transformers":
        scores = _SEMANTIC_SCORER.score(intent_text, [doc for _, _, doc in indexed])
        out: Dict[Tuple[str, int], float] = {}
        for (provider_id, action_id, _), score in zip(indexed, scores):
            out[(provider_id, action_id)] = score
        return backend, out

    query_vec = _SEMANTIC_SCORER.encode(intent_text)
    if query_vec is None:
        return backend, {(provider_id, action_id): 0.0 for provider_id, action_id, _ in indexed}

    out: Dict[Tuple[str, int], float] = {}
    for provider_id, action_id, document in indexed:
        key = (str(provider_id), int(action_id))
        doc_vec = _CANDIDATE_VECTOR_CACHE.get(key)
        if doc_vec is None:
            encoded = _SEMANTIC_SCORER.encode(str(document))
            if encoded is None:
                out[key] = 0.0
                continue
            doc_vec = encoded
            _CANDIDATE_VECTOR_CACHE[key] = doc_vec
        cosine = float(query_vec.dot(doc_vec))
        out[key] = _clamp_cosine(cosine)
    return backend, out
