from typing import Any, Dict

from sunpack.contracts.detection import FactBag
from sunpack.contracts.rules import RuleEffect
from sunpack.detection.pipeline.rules.base import RuleBase
from sunpack.detection.pipeline.rules.registry import register_rule


@register_rule(name="relation_archive_accept", layer="precheck")
class RelationArchiveAcceptRule(RuleBase):
    """Accept RAR/7z/ZIP identities already resolved by Relations without I/O."""

    routing_formats = {"rar", "7z", "zip"}
    can_be_promoted = True
    produced_facts = {
        "file.detected_ext",
        "file.magic_matched",
        "file.probe_detected_archive",
        "file.probe_offset",
        "file.embedded_archive_found",
        "file.container_type",
    }

    def evaluate(self, facts: FactBag, config: Dict[str, Any]) -> RuleEffect:
        del config
        anchor = facts.get("relation.volume_anchor")
        if not isinstance(anchor, dict) or not anchor.get("relation_confirmed"):
            return RuleEffect.pass_()

        archive_format = str(anchor.get("format") or "").lower().lstrip(".")
        if archive_format not in {"rar", "7z", "zip"}:
            return RuleEffect.pass_()

        archive_input = facts.get("archive.input")
        if isinstance(archive_input, dict):
            input_format = str(archive_input.get("format_hint") or "").lower().lstrip(".")
            if input_format and input_format != archive_format:
                return RuleEffect.pass_()

        offset = int(anchor.get("structure_offset") or 0)
        facts.set("file.detected_ext", {"rar": ".rar", "7z": ".7z", "zip": ".zip"}[archive_format])
        facts.set("file.probe_detected_archive", True)
        facts.set("file.probe_offset", offset)
        if offset == 0:
            facts.set("file.magic_matched", True)
        if offset > 0:
            facts.set("file.embedded_archive_found", True)
        if anchor.get("sfx") and anchor.get("pe_structure"):
            facts.set("file.container_type", "pe")
        return RuleEffect.accept("Relations confirmed native archive identity")
