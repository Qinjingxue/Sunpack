from typing import Any, Dict

from sunpack.contracts.detection import FactBag
from sunpack.contracts.rules import RuleEffect
from sunpack.detection.pipeline.rules.base import RuleBase
from sunpack.detection.pipeline.rules.registry import register_rule


@register_rule(name="zip_structure_accept", layer="precheck")
class ZipStructureAcceptRule(RuleBase):
    routing_formats = {"zip"}
    routing_extensions = {".zip", ".zipx", ".jar", ".apk", ".docx", ".xlsx", ".z01"}
    can_be_promoted = True
    required_facts = {"zip.eocd_structure"}
    fact_requirements = []
    produced_facts = {"file.detected_ext", "file.probe_detected_archive", "file.probe_offset"}
    config_schema = {
        "accept_empty_zip": {
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Whether a structurally valid empty ZIP EOCD can be accepted before extraction.",
        },
        "max_cd_entries_to_walk": {
            "type": "int",
            "required": False,
            "description": "Maximum central directory entries checked by the ZIP structure processor.",
        },
    }

    def evaluate(self, facts: FactBag, config: Dict[str, Any]) -> RuleEffect:
        structure = facts.get("zip.eocd_structure") or {}
        if not structure.get("plausible"):
            return RuleEffect.pass_()
        if not structure.get("archive_starts_at_zero"):
            return RuleEffect.pass_()
        if int(structure.get("archive_offset") or 0) != 0:
            return RuleEffect.pass_()

        central_directory_present = bool(structure.get("central_directory_present"))
        central_directory_walk_ok = bool(structure.get("central_directory_walk_ok"))
        local_header_links_ok = bool(structure.get("local_header_links_ok"))
        empty_zip = (
            int(structure.get("total_entries") or 0) == 0
            and int(structure.get("central_directory_size") or 0) == 0
        )
        if central_directory_present and not (central_directory_walk_ok and local_header_links_ok):
            return RuleEffect.pass_()
        if not central_directory_present and not (empty_zip and config.get("accept_empty_zip", True)):
            return RuleEffect.pass_()

        facts.set("file.detected_ext", ".zip")
        facts.set("file.probe_detected_archive", True)
        facts.set("file.probe_offset", 0)
        return RuleEffect.accept("ZIP structure accept: EOCD and central directory")
