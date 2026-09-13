from typing import Any

from sunpack.detection.pipeline.rules.registry import discover_rules, get_rule_registry


def discover_rule_metadata() -> dict[str, dict[str, Any]]:
    discover_rules()
    registry = get_rule_registry()
    metadata: dict[str, dict[str, Any]] = {}
    for layer in ("precheck",):
        for name, rule_cls in registry.get_all_rules(layer).items():
            fact_requirements = []
            for requirement in getattr(rule_cls, "fact_requirements", []) or []:
                fact_requirements.append({
                    "fact": requirement.fact_name,
                    "condition": type(requirement.condition).__name__ if requirement.condition else "Always",
                    "prerequisite_facts": sorted(requirement.prerequisite_facts),
                })
            metadata[name] = {
                "name": name,
                "layer": layer,
                "class": rule_cls,
                "required_facts": sorted(getattr(rule_cls, "required_facts", set())),
                "fact_requirements": fact_requirements,
                "produced_facts": sorted(getattr(rule_cls, "produced_facts", set())),
                "config_schema": getattr(rule_cls, "config_schema", {}) or {},
            }
    return metadata


def rule_metadata(rule_name: str) -> dict[str, Any]:
    metadata = discover_rule_metadata()
    if rule_name not in metadata:
        raise ValueError(f"Unknown rule: {rule_name}")
    return metadata[rule_name]
