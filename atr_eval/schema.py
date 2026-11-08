"""JSON Schema validation for atomics, profiles, receipt predicates, re-performance statements and shares (draft 0.9)."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

_DIR = Path(__file__).parent / "schemas"
_NAMES = ("profile.schema.json", "atomic.schema.json", "receipt-predicate.schema.json", "reperformance-predicate.schema.json",
          "share.schema.json")


@lru_cache(maxsize=1)
def _registry() -> tuple[Registry, dict]:
    docs = {n: json.loads((_DIR / n).read_text(encoding="utf-8")) for n in _NAMES}
    resources = [(d["$id"], Resource.from_contents(d)) for d in docs.values()]
    resources += [(n, Resource.from_contents(d)) for n, d in docs.items()]
    return Registry().with_resources(resources), docs


def _errors(schema_name: str, instance) -> list[str]:
    registry, docs = _registry()
    validator = Draft202012Validator(docs[schema_name], registry=registry)
    return [f"{'/'.join(map(str, e.absolute_path)) or '<root>'}: {e.message[:200]}" for e in validator.iter_errors(instance)]


def atomic_errors(atomic: dict) -> list[str]:
    return _errors("atomic.schema.json", atomic)


def predicate_errors(predicate: dict) -> list[str]:
    return _errors("receipt-predicate.schema.json", predicate)


def profile_errors(profile: dict) -> list[str]:
    return _errors("profile.schema.json", profile)


def share_errors(share: dict) -> list[str]:
    return _errors("share.schema.json", share)


def reperformance_errors(predicate: dict) -> list[str]:
    return _errors("reperformance-predicate.schema.json", predicate)
