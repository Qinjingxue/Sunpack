from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntEnum


class AnalysisCost(IntEnum):
    CHEAP = 1
    STANDARD = 2
    EXPENSIVE = 3
    DEEP = 4


class AnalysisCapability(str, Enum):
    SIGNATURE_PREPASS = "signature_prepass"
    FORMAT_STRUCTURE = "format_structure"

    @property
    def cost(self) -> AnalysisCost:
        return _CAPABILITY_COSTS[self]


_CAPABILITY_COSTS = {
    AnalysisCapability.SIGNATURE_PREPASS: AnalysisCost.CHEAP,
    AnalysisCapability.FORMAT_STRUCTURE: AnalysisCost.EXPENSIVE,
}


DEFAULT_ANALYSIS_CAPABILITIES = frozenset(AnalysisCapability)


@dataclass(frozen=True, slots=True)
class AnalysisBudget:
    max_cost: AnalysisCost = AnalysisCost.DEEP
    max_capabilities: int | None = None

    def validate(self, capabilities: frozenset[AnalysisCapability]) -> None:
        if self.max_capabilities is not None and len(capabilities) > max(0, int(self.max_capabilities)):
            raise ValueError(
                f"analysis request needs {len(capabilities)} capabilities; budget allows {self.max_capabilities}"
            )
        over_budget = sorted(
            (capability for capability in capabilities if capability.cost > self.max_cost),
            key=lambda capability: capability.cost,
        )
        if over_budget:
            names = ", ".join(capability.value for capability in over_budget)
            raise ValueError(f"analysis capabilities exceed {self.max_cost.name.lower()} budget: {names}")


@dataclass(frozen=True, slots=True)
class AnalysisRequest:
    capabilities: frozenset[AnalysisCapability] = field(default_factory=lambda: DEFAULT_ANALYSIS_CAPABILITIES)
    budget: AnalysisBudget = field(default_factory=AnalysisBudget)
    initial_prepass: dict | None = None

    def __post_init__(self) -> None:
        normalized = frozenset(AnalysisCapability(item) for item in self.capabilities)
        object.__setattr__(self, "capabilities", normalized)
        if self.initial_prepass is not None:
            object.__setattr__(self, "initial_prepass", dict(self.initial_prepass))
        self.budget.validate(normalized)

    def includes(self, capability: AnalysisCapability) -> bool:
        return capability in self.capabilities

