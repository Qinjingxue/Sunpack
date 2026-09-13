from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

@dataclass
class RuleEffect:
    decision: str  # "reject", "accept", "pass", "require"
    reason: Optional[str] = None
    required_facts: set[str] = field(default_factory=set)

    @classmethod
    def reject(cls, reason: str) -> "RuleEffect":
        return cls(decision="reject", reason=reason)

    @classmethod
    def accept(cls, reason: str) -> "RuleEffect":
        return cls(decision="accept", reason=reason)

    @classmethod
    def pass_(cls) -> "RuleEffect":
        return cls(decision="pass")

    @classmethod
    def require_facts(cls, fact_names: set[str]) -> "RuleEffect":
        return cls(decision="require", required_facts=set(fact_names))

@dataclass
class RuleDecision:
    should_extract: bool
    matched_rules: List[str]
    stop_reason: Optional[str] = None
    decision: str = "not_archive"
    decision_stage: str = ""
    discarded_at: Optional[str] = None
    deciding_rule: Optional[str] = None
