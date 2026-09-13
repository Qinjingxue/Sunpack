from dataclasses import dataclass
from typing import Any

from sunpack.config.detection_view import detection_config
from sunpack.detection.pipeline.facts.batch_provider import BatchFactProvider
from sunpack.detection.pipeline.facts.provider import FactProvider
from sunpack.detection.pipeline.facts.registry import discover_collectors, get_registry
from sunpack.detection.pipeline.processors.registry import discover_processors
from sunpack.detection.pipeline.processors.registry import get_processor_registry
from sunpack.detection.pipeline.processors.runner import ProcessingCoordinator
from sunpack.detection.pipeline.rules.manager import RuleManager
from sunpack.contracts.detection import FactBag
from sunpack.contracts.rules import RuleDecision
from sunpack.detection.deep_scan import evaluate_deep_bag
from sunpack.detection.options import DetectionOptions


@dataclass(frozen=True)
class DetectionResult:
    fact_bag: FactBag
    decision: RuleDecision


class DetectionScheduler:
    """Coordinates fact collection, fact processing, and rule evaluation."""

    def __init__(self, config: dict[str, Any], options: DetectionOptions | None = None):
        self.config = config
        self.options = options or DetectionOptions()
        discover_collectors()
        discover_processors()
        detector_config = detection_config(config)
        self.enabled_fact_modules = self._enabled_module_names(detector_config.get("fact_collectors"))
        self.enabled_processors = self._enabled_module_names(detector_config.get("processors"))
        self.fact_config_defaults = self._fact_config_defaults(
            detector_config.get("fact_collectors"),
            detector_config.get("processors"),
        )
        self.rule_manager = RuleManager(
            config,
            ensure_pool_facts=self._ensure_pool_facts,
            fact_config_defaults=self.fact_config_defaults,
        )

    def validate_config(self) -> list[str]:
        return self.rule_manager.validate_config()

    def evaluate_bag(
        self,
        fact_bag: FactBag,
        fact_provider: FactProvider | None = None,
    ) -> RuleDecision:
        if fact_provider is not None and not fact_bag.has("file.path"):
            fact_bag.set("file.path", fact_provider.base_path)
        return self.evaluate_pool([fact_bag])[fact_bag]

    def evaluate(
        self,
        fact_bag: FactBag,
        fact_provider: FactProvider | None = None,
    ) -> RuleDecision:
        return self.evaluate_bag(fact_bag, fact_provider)

    def evaluate_pool(
        self,
        fact_bags: list[FactBag],
        scan_session: Any = None,
    ) -> dict[FactBag, RuleDecision]:
        if self.options.deep_scan:
            return {fact_bag: evaluate_deep_bag(fact_bag) for fact_bag in fact_bags}
        self._active_scan_session = scan_session
        self.rule_manager.ensure_pool_facts = self._ensure_pool_facts
        try:
            self._prefill_precheck_head_facts(fact_bags)
            return self.rule_manager.evaluate_pool(fact_bags)
        finally:
            self._active_scan_session = None

    def evaluate_precheck_pool(
        self,
        fact_bags: list[FactBag],
        scan_session: Any = None,
    ) -> tuple[dict[FactBag, RuleDecision], list[FactBag]]:
        """Evaluate strict prechecks without finalizing ordinary candidates."""
        self._active_scan_session = scan_session
        self.rule_manager.ensure_pool_facts = self._ensure_pool_facts
        try:
            self._prefill_precheck_head_facts(fact_bags)
            return self.rule_manager.evaluate_precheck_pool(fact_bags)
        finally:
            self._active_scan_session = None

    def evaluate_bags(
        self,
        fact_bags: list[FactBag],
        scan_session: Any = None,
    ) -> list[DetectionResult]:
        decisions = self.evaluate_pool(fact_bags, scan_session=scan_session)
        return [
            DetectionResult(fact_bag=bag, decision=decision)
            for bag in fact_bags
            if (decision := decisions.get(bag)) is not None
        ]

    def _provider_for(
        self,
        fact_bag: FactBag,
        fact_configs: dict[str, dict[str, Any]] | None = None,
    ) -> FactProvider:
        return FactProvider(
            fact_bag.get("file.path", ""),
            config=self.config,
            fact_configs=self._merge_fact_configs(fact_configs),
            enabled_fact_modules=self.enabled_fact_modules,
            scan_session=getattr(self, "_active_scan_session", None),
        )

    def _ensure_pool_facts(
        self,
        fact_bags: list[FactBag],
        required_facts: set[str],
        fact_configs: dict[str, dict[str, Any]] | None = None,
    ):
        if not required_facts:
            return
        effective_fact_configs = self._merge_fact_configs(fact_configs)
        BatchFactProvider(
            config=self.config,
            fact_configs=effective_fact_configs,
            enabled_fact_modules=self.enabled_fact_modules,
            scan_session=getattr(self, "_active_scan_session", None),
        ).prefill_facts(fact_bags, required_facts | self._processor_input_facts(required_facts))
        for bag in fact_bags:
            provider = self._provider_for(bag, fact_configs=effective_fact_configs)
            ProcessingCoordinator(
                provider,
                config=self.config,
                fact_configs=provider.fact_configs,
                enabled_processors=self.enabled_processors,
            ).ensure_facts(bag, required_facts)

    def _prefill_precheck_head_facts(self, fact_bags: list[FactBag]) -> None:
        scan_session = getattr(self, "_active_scan_session", None)
        if not fact_bags or scan_session is None:
            return
        BatchFactProvider(
            config=self.config,
            fact_configs=self.fact_config_defaults,
            enabled_fact_modules=self.enabled_fact_modules,
            scan_session=scan_session,
        ).prefill_facts(fact_bags, {"file.size", "file.magic_bytes"})

    def _processor_input_facts(self, fact_names: set[str]) -> set[str]:
        inputs: set[str] = set()
        pending = list(fact_names)
        seen = set(fact_names)
        registry = get_processor_registry()
        while pending:
            fact_name = pending.pop()
            processor = registry.get_by_output(fact_name)
            if processor is None:
                continue
            for input_fact in processor.input_facts:
                inputs.add(input_fact)
                if input_fact not in seen:
                    seen.add(input_fact)
                    pending.append(input_fact)
        return inputs

    def _enabled_module_names(self, modules_config) -> set[str] | None:
        if not isinstance(modules_config, list):
            return None
        enabled: set[str] = set()
        for item in modules_config:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            if isinstance(name, str) and name.strip() and item.get("enabled", False):
                enabled.add(name.strip())
        return enabled

    def _module_configs(self, modules_config) -> dict[str, dict[str, Any]]:
        if not isinstance(modules_config, list):
            return {}
        configs: dict[str, dict[str, Any]] = {}
        for item in modules_config:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            if not isinstance(name, str) or not name.strip() or not item.get("enabled", False):
                continue
            module_config = {
                key: value
                for key, value in item.items()
                if key not in {"name", "enabled"}
            }
            if module_config:
                configs[name.strip()] = module_config
        return configs

    def _fact_config_defaults(self, collector_modules_config, processor_modules_config) -> dict[str, dict[str, Any]]:
        defaults: dict[str, dict[str, Any]] = {}
        collector_configs = self._module_configs(collector_modules_config)
        processor_configs = self._module_configs(processor_modules_config)

        for fact_name, collector in get_registry().get_all_collectors().items():
            module_name = collector.__module__.rsplit(".", 1)[-1]
            if module_name in collector_configs:
                defaults[fact_name] = dict(collector_configs[module_name])

        for processor in get_processor_registry().all().values():
            if processor.name not in processor_configs:
                continue
            for output_fact in processor.output_facts:
                defaults[output_fact] = dict(processor_configs[processor.name])

        if not defaults:
            return {}

        changed = True
        while changed:
            changed = False
            for processor in get_processor_registry().all().values():
                inherited: dict[str, Any] = {}
                for input_fact in processor.input_facts:
                    inherited.update(defaults.get(input_fact, {}))
                if not inherited:
                    continue
                for output_fact in processor.output_facts:
                    merged = dict(inherited)
                    merged.update(defaults.get(output_fact, {}))
                    if merged != defaults.get(output_fact):
                        defaults[output_fact] = merged
                        changed = True
        return defaults

    def _merge_fact_configs(
        self,
        fact_configs: dict[str, dict[str, Any]] | None,
    ) -> dict[str, dict[str, Any]]:
        merged = {fact_name: dict(config) for fact_name, config in self.fact_config_defaults.items()}
        for fact_name, config in (fact_configs or {}).items():
            effective = dict(merged.get(fact_name, {}))
            effective.update(config)
            merged[fact_name] = effective
        return merged
