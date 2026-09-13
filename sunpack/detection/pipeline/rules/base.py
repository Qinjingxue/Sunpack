from typing import Dict, Any
from sunpack.contracts.rules import RuleEffect
from sunpack.contracts.detection import FactBag
from sunpack.detection.pipeline.rules.fact_requirements import FactRequirement

class RuleBase:
    required_facts: set[str] = set()
    fact_requirements: list[FactRequirement] = []
    produced_facts: set[str] = set()
    config_schema: Dict[str, Dict[str, Any]] = {}
    # Routing metadata is only an execution hint.  A match may move a strict
    # identity precheck earlier, but never changes the rule's decision.
    routing_formats: set[str] = set()
    routing_extensions: set[str] = set()
    can_be_promoted: bool = False

    def evaluate(self, facts: FactBag, config: Dict[str, Any]) -> RuleEffect:
        raise NotImplementedError()
