"""Sparse reporting receipts from the shared execution, without retained tasks."""

from sunpack.core.contracts.failures import FailureKind


def scan_items(task, result, i18n):
    children = {item.input.input_id: item.result for item in result.input_results}
    for node in task.inputs:
        current = children.get(node.input_id, result)
        descriptor = node.descriptor
        extent = descriptor.primary_extent
        item = {"main_path": extent.path if extent else descriptor.entry_path,
                "input_id": node.input_id}
        if descriptor.format_hint:
            item["format"] = descriptor.format_hint
        if extent and (extent.start or descriptor.open_mode in {"file_range", "concat_ranges"}
                       or extent.end is not None and descriptor.analysis.get("segment_source") == "embedded"):
            item.update(offset=extent.start, end_offset=extent.end)
        facts = current.diagnostics.get("result", {})
        failure = node.failure or current.failure
        if "format" not in item and facts.get("archive_type"):
            item["format"] = facts["archive_type"]
        if current.password_used is not None and (current.password_used or facts.get("encrypted")):
            item["password_used"] = current.password_used
        elif node.password is not None:
            item["password_used"] = node.password
        elif (facts.get("encrypted") is True or descriptor.analysis.get("password_required") is True
              or failure and failure.kind in {FailureKind.PASSWORD_REQUIRED, FailureKind.WRONG_PASSWORD}):
            item["password_used"] = None
        completeness = "missing" if failure and failure.is_confirmed_missing_volume else node.volume_completeness
        plan = descriptor.volume_attempts
        if plan is not None:
            # Domains are shared, not copied per slot or expanded into products.
            item["volume_attempts"] = plan.to_dict()
            item["volume_completeness"] = "missing" if completeness == "missing" else "pending"
        else:
            parts = descriptor.part_paths()
            if (completeness == "missing" or len(parts) > 1 or descriptor.volume_style
                    or descriptor.open_mode in {"native_volumes", "sfx_with_volumes"}):
                item["all_parts"] = parts
                if completeness in {"complete", "missing"}:
                    item["volume_completeness"] = completeness
        if failure is not None:
            item["error"] = (i18n.t(failure.message_key, **failure.message_params)
                             if failure.message_key else failure.message)
        if task.discovery_source:
            item["discovery_source"] = task.discovery_source
        if descriptor.analysis.get("damage_flags"):
            item["damage_flags"] = descriptor.analysis["damage_flags"]
        yield item
