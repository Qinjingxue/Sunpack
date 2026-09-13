from typing import Any, List

from sunpack.config.detection_view import rule_pipeline_config
from sunpack.detection.pipeline.rules.config_validator import RuleConfigValidator
from sunpack.detection.pipeline.rules.types import PreparedRule


class RulePreparer:
    def __init__(self, config: dict[str, Any], registry, validator: RuleConfigValidator):
        self.config = config
        self.registry = registry
        self.validator = validator

    def prepare(self, layer: str) -> List[PreparedRule]:
        prepared: List[PreparedRule] = []
        pipeline_config = rule_pipeline_config(self.config)
        for rule_cfg in pipeline_config.get(layer, []):
            if not rule_cfg.get("enabled", False):
                continue

            rule_name = rule_cfg["name"]
            rule_cls = self.registry.get_rule(layer, rule_name)
            if not rule_cls:
                raise ValueError(f"Unknown rule configured for {layer}: {rule_name}")

            self.validator.validate_rule(layer, rule_name, rule_cls, rule_cfg)
            rule_instance = rule_cls()
            rule_config = dict(rule_cfg)
            prepare_config = getattr(rule_instance, "prepare_config", None)
            if callable(prepare_config):
                rule_config = prepare_config(rule_config)
            prepared.append(PreparedRule(rule_name, rule_instance, rule_config))
        return prepared
