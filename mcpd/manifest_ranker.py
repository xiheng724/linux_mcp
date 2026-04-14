from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any, Iterable, List, Mapping, Sequence

_TOKEN_RE = re.compile(r"[a-z0-9]+")
_PATHISH_RE = re.compile(
    r"(?:\.\.?/)?[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)+|[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+"
)


def tokenize_text(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        normalized = _PATHISH_RE.sub(" path ", value.lower())
        return _TOKEN_RE.findall(normalized)
    if isinstance(value, Mapping):
        out: List[str] = []
        for key, item in value.items():
            out.extend(tokenize_text(key))
            out.extend(tokenize_text(item))
        return out
    if isinstance(value, (list, tuple, set)):
        out: List[str] = []
        for item in value:
            out.extend(tokenize_text(item))
        return out
    return _TOKEN_RE.findall(str(value).lower())


def normalize_tokens(tokens: Sequence[str]) -> List[str]:
    normalized: List[str] = []
    seen: set[str] = set()
    for token in tokens:
        if not token:
            continue
        variants = [token]
        if len(token) > 5 and token.endswith("e"):
            variants.append(token[:-1])
        for suffix in ("ations", "ation", "ions", "ion", "ing", "ed", "es", "s"):
            if len(token) > len(suffix) + 2 and token.endswith(suffix):
                variants.append(token[: -len(suffix)])
        for variant in variants:
            if variant and variant not in seen:
                normalized.append(variant)
                seen.add(variant)
    return normalized


def lexical_scores(query_text: str, documents: Iterable[str]) -> List[float]:
    docs = list(documents)
    if not docs:
        return []
    query_tokens = normalize_tokens(tokenize_text(query_text))
    if not query_tokens:
        return [0.0 for _ in docs]

    tokenized_docs = [normalize_tokens(tokenize_text(doc)) for doc in docs]
    doc_counters = [Counter(tokens) for tokens in tokenized_docs]
    doc_lengths = [max(len(tokens), 1) for tokens in tokenized_docs]
    avg_doc_len = sum(doc_lengths) / max(len(doc_lengths), 1)
    doc_freq: Counter[str] = Counter()
    for tokens in tokenized_docs:
        for token in set(tokens):
            doc_freq[token] += 1

    query_counter = Counter(query_tokens)
    out: List[float] = []
    doc_count = len(tokenized_docs)
    k1 = 1.5
    b = 0.75
    for doc_counter, doc_len in zip(doc_counters, doc_lengths):
        score = 0.0
        for token, query_tf in query_counter.items():
            df = doc_freq.get(token, 0)
            if df <= 0:
                continue
            idf = math.log(1.0 + ((doc_count - df + 0.5) / (df + 0.5)))
            tf = float(doc_counter.get(token, 0))
            if tf <= 0:
                continue
            norm = tf + k1 * (1.0 - b + b * (doc_len / max(avg_doc_len, 1.0)))
            score += idf * ((tf * (k1 + 1.0)) / norm) * float(query_tf)
        out.append(score)
    return out
