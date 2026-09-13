from typing import Any, Callable, Dict, Set

class FactBag:
    def __init__(self):
        self._facts: Dict[str, Any] = {}
        self._missing_facts: Set[str] = set()
        self._fact_errors: Dict[str, str] = {}

    def get(self, key: str, default: Any = None) -> Any:
        return self._facts.get(key, default)

    def set(self, key: str, value: Any):
        self._facts[key] = value

    def update(self, facts: Dict[str, Any]) -> None:
        self._facts.update(facts)

    def unset(self, key: str):
        self._facts.pop(key, None)

    def has(self, key: str) -> bool:
        return key in self._facts

    def mark_missing(self, key: str):
        self._missing_facts.add(key)

    def is_missing(self, key: str) -> bool:
        return key in self._missing_facts

    def mark_error(self, key: str, error: str):
        self._fact_errors[key] = error
        self.mark_missing(key)

    def get_error(self, key: str) -> str | None:
        return self._fact_errors.get(key)

    def get_errors(self) -> Dict[str, str]:
        return dict(self._fact_errors)

    def to_dict(self) -> Dict[str, Any]:
        return dict(self._facts)
