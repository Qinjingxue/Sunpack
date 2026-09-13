from typing import Any, Dict

from sunpack.config.detection_view import rule_pipeline_config
from sunpack.detection.pipeline.facts.schema import known_fact_names, matches_schema_type


class RuleConfigValidator:
    RULE_CONTROL_FIELDS = {"name", "enabled"}

    def __init__(self, registry):
        self.registry = registry

    def validate_pipeline_config(self, config: dict[str, Any]) -> list[str]:
        errors: list[str] = []
        pipeline_config = rule_pipeline_config(config)
        if not isinstance(pipeline_config, dict):
            return ["detection.rule_pipeline must be an object"]
        unknown_layers = sorted(set(pipeline_config) - {"precheck"})
        if unknown_layers:
            errors.append(
                "Unknown detection.rule_pipeline field(s): " + ", ".join(unknown_layers)
            )
        for layer in ("precheck",):
            rules = pipeline_config.get(layer, [])
            if not isinstance(rules, list):
                errors.append(f"detection.rule_pipeline.{layer} must be a list")
                continue
            for index, rule_cfg in enumerate(rules):
                if not isinstance(rule_cfg, dict):
                    errors.append(f"detection.rule_pipeline.{layer}[{index}] must be an object")
                    continue
                rule_name = rule_cfg.get("name")
                if not isinstance(rule_name, str) or not rule_name.strip():
                    errors.append(f"detection.rule_pipeline.{layer}[{index}] must declare a rule name")
                    continue
                rule_cls = self.registry.get_rule(layer, rule_name)
                if not rule_cls:
                    errors.append(f"Unknown rule configured for {layer}: {rule_name}")
                    continue
                try:
                    self.validate_rule(layer, rule_name, rule_cls, rule_cfg)
                except Exception as exc:
                    errors.append(str(exc))
        return errors

    def validate_rule(self, layer: str, rule_name: str, rule_cls: Any, rule_cfg: Dict[str, Any]):
        self.validate_rule_facts(layer, rule_name, rule_cls)
        self.validate_rule_config(layer, rule_name, rule_cls, rule_cfg)

    def validate_rule_facts(self, layer: str, rule_name: str, rule_cls: Any):
        known = known_fact_names()
        facts = set(getattr(rule_cls, "required_facts", set())) | set(getattr(rule_cls, "produced_facts", set()))
        for requirement in getattr(rule_cls, "fact_requirements", []) or []:
            facts.add(requirement.fact_name)
            facts.update(requirement.prerequisite_facts)
        unknown = sorted(fact for fact in facts if fact not in known)
        module_name = getattr(rule_cls, "__module__", "")
        if unknown and module_name.startswith("sunpack.detection.pipeline.rules."):
            raise ValueError(f"Unknown fact(s) declared by rule {layer}.{rule_name}: {', '.join(unknown)}")

    def validate_rule_config(self, layer: str, rule_name: str, rule_cls: Any, rule_cfg: Dict[str, Any]):
        config_schema = getattr(rule_cls, "config_schema", {}) or {}
        allowed_fields = self.RULE_CONTROL_FIELDS | set(config_schema)
        unknown_fields = sorted(set(rule_cfg) - allowed_fields)
        if unknown_fields:
            raise ValueError(
                f"Unknown config field(s) for rule {layer}.{rule_name}: {', '.join(unknown_fields)}"
            )

        required_fields = {field for field, schema in config_schema.items() if schema.get("required")}
        missing_fields = sorted(required_fields - set(rule_cfg))
        if missing_fields:
            raise ValueError(
                f"Missing required config field(s) for rule {layer}.{rule_name}: {', '.join(missing_fields)}"
            )
        for field, value in rule_cfg.items():
            if field in self.RULE_CONTROL_FIELDS:
                continue
            self.validate_config_value(layer, rule_name, field, value, config_schema.get(field, {}))

    def validate_config_value(self, layer: str, rule_name: str, field: str, value: Any, schema: Dict[str, Any]):
        expected = schema.get("type")
        if matches_schema_type(value, expected):
            return
        raise ValueError(
            f"Invalid type for rule {layer}.{rule_name}.{field}: expected {expected}, got {type(value).__name__}"
        )
