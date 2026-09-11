from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from sunpack.contracts.results import RunSummary


@dataclass(frozen=True)
class PipelineTarget:
    path: str
    output: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class PipelineArtifacts:
    flatten_targets: tuple[str, ...] = ()
    shell_refresh_paths: tuple[str, ...] = ()


@dataclass(frozen=True)
class PipelineResponse:
    request_id: str
    summary: RunSummary
    artifacts: PipelineArtifacts = field(default_factory=PipelineArtifacts)
    recent_passwords: tuple[str, ...] = ()
