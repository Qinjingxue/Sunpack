from sunpack.pipeline.verification.evidence import VerificationEvidence
from sunpack.pipeline.verification.registry import register_verification_method
from sunpack.core.contracts.verification import FileVerificationObservation, VerificationIssue, VerificationStep

from sunpack_native import sample_directory_readability as _sample_directory_readability
from sunpack.pipeline.verification.methods._output_stats import output_inventory_for_evidence


@register_verification_method("sample_readability")
class SampleReadabilityMethod:
    name = "sample_readability"

    def verify(self, evidence: VerificationEvidence, config: dict) -> VerificationStep:
        inventory = output_inventory_for_evidence(evidence)
        if (
            inventory.worker_inventory_complete and inventory.identity_paths
            and inventory.worker_crc_available
            and inventory.all_crc_ok()
        ):
            return VerificationStep(method=self.name, status="skipped", issues=[VerificationIssue(
                method=self.name, code="info.worker_output_already_verified",
                message="Complete worker CRC inventory makes sample rereads unnecessary",
                path=evidence.output_dir,
            )])
        max_samples = max(1, int(config.get("max_samples", 64) or 64))
        read_bytes = max(1, int(config.get("read_bytes", 4096) or 4096))
        sample = _sample_directory_readability(evidence.output_dir, max_samples, read_bytes)

        status = str(sample.get("status") or "")
        if status != "ok":
            return VerificationStep(method=self.name, status="skipped")

        total_files = int(sample.get("total_files", 0) or 0)
        sampled_files = int(sample.get("sampled_files", 0) or 0)
        readable_files = int(sample.get("readable_files", 0) or 0)
        unreadable_files = int(sample.get("unreadable_files", 0) or 0)
        empty_files = int(sample.get("empty_files", 0) or 0)
        errors = list(sample.get("errors") or [])
        samples = [item for item in sample.get("samples") or [] if isinstance(item, dict)]
        if total_files <= 0 or sampled_files <= 0:
            return VerificationStep(method=self.name, status="skipped")

        issues: list[VerificationIssue] = []
        if unreadable_files:
            all_unreadable = readable_files == 0
            issues.append(VerificationIssue(
                method=self.name,
                code="fail.sample_unreadable",
                message="Some sampled output files could not be read",
                path=evidence.output_dir,
                expected=0,
                actual={
                    "unreadable_files": unreadable_files,
                    "sampled_files": sampled_files,
                    "errors": errors[: int(config.get("max_reported_items", 20) or 20)],
                },
            ))

        if empty_files and empty_files == sampled_files:
            issues.append(VerificationIssue(
                method=self.name,
                code="warning.sample_all_empty",
                message="All sampled output files are empty",
                path=evidence.output_dir,
                expected="non-empty sample",
                actual={"empty_files": empty_files, "sampled_files": sampled_files},
            ))
        elif empty_files:
            issues.append(VerificationIssue(
                method=self.name,
                code="warning.sample_empty_files",
                message="Some sampled output files are empty",
                path=evidence.output_dir,
                expected=0,
                actual={"empty_files": empty_files, "sampled_files": sampled_files},
            ))

        if not issues:
            return VerificationStep(
                method=self.name,
                status="passed",
                completeness_hint=1.0,
                file_observations=_sample_observations(samples, errors, self.name),
                issues=[VerificationIssue(
                    method=self.name,
                    code="info.sample_readability_coverage",
                    message="Sampled output files were readable",
                    path=evidence.output_dir,
                    expected=sampled_files,
                    actual={
                        "total_files": total_files,
                        "sampled_files": sampled_files,
                        "readable_files": readable_files,
                        "unreadable_files": unreadable_files,
                        "sample_ratio": round(sampled_files / max(1, total_files), 6),
                    },
                )],
            )
        return VerificationStep(
            method=self.name,
            status="warning",
            issues=issues,
            completeness_hint=readable_files / max(1, sampled_files),
            file_observations=_sample_observations(samples, errors, self.name, issues=issues),
        )


def _sample_observations(
    samples: list[dict],
    errors: list,
    method: str,
    *,
    issues: list[VerificationIssue] | None = None,
) -> list[FileVerificationObservation]:
    observations = [
        FileVerificationObservation(
            path=str(item.get("path") or ""),
            archive_path=str(item.get("path") or ""),
            state="unverified",
            method=method,
            bytes_written=int(item.get("size", 0) or 0),
            progress=1.0,
            details={
                "bytes_read": int(item.get("bytes_read", 0) or 0),
                "empty": bool(item.get("empty", False)),
                "usability": "readable",
            },
        )
        for item in samples
    ]
    for item in errors:
        if not isinstance(item, dict):
            continue
        observations.append(FileVerificationObservation(
            path=str(item.get("path") or ""),
            archive_path=str(item.get("path") or ""),
            state="failed",
            method=method,
            progress=0.0,
            issues=list(issues or []),
            details={"message": item.get("message"), "usability": "unreadable"},
        ))
    return observations
