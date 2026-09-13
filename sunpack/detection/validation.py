from typing import Any

from sunpack.config.detection_view import rule_pipeline_config
from sunpack.detection.pipeline.facts.registry import discover_collectors, get_registry as get_fact_registry
from sunpack.detection.pipeline.facts.schema import known_fact_names
from sunpack.detection.pipeline.rules.metadata import discover_rule_metadata
from sunpack.detection.scheduler import DetectionScheduler


def validate_detection_contracts(payload: dict) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    errors.extend(DetectionScheduler(payload).validate_config())

    discover_collectors()
    fact_registry = get_fact_registry()
    for fact_name, schema in fact_registry.get_all_schemas().items():
        if not schema.get("type"):
            errors.append(f"Fact collector {fact_name} is missing schema type")
        if not schema.get("description"):
            errors.append(f"Fact collector {fact_name} is missing schema description")

    metadata = discover_rule_metadata()
    known_facts = known_fact_names()
    for rule_name, info in metadata.items():
        for fact in set(info["required_facts"]) | set(info["produced_facts"]):
            if fact not in known_facts:
                errors.append(f"Rule {rule_name} declares unknown fact {fact}")

    configured = []
    for layer in ("precheck",):
        rules = rule_pipeline_config(payload).get(layer, [])
        if not isinstance(rules, list):
            errors.append(f"detection.rule_pipeline.{layer} must be a list")
            continue
        configured.extend(rule.get("name") for rule in rules if isinstance(rule, dict))

    return {
        "errors": errors,
        "warnings": warnings,
        "configured_rules": configured,
        "available_rules": sorted(metadata),
        "registered_facts": sorted(known_fact_names()),
    }
