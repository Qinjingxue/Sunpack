from typing import Any, Callable, Optional

from sunpack.extraction.internal.sevenzip.metadata import ArchiveMetadataScanner
from sunpack.support.output_paths import default_output_dir_for_task
from sunpack.extraction.internal.workflow.preflight import PreExtractInspector
from sunpack.extraction.internal.workflow.retry_policy import ExtractRetryPolicy
from sunpack.extraction.internal.sevenzip.sevenzip_runner import SevenZipRunner
from sunpack.extraction.internal.workflow.single_archive_extractor import SingleArchiveExtractor
from sunpack.extraction.internal.workflow.split_entry import SplitEntryResolver
from sunpack.contracts.extraction import ExtractionResult
from sunpack.contracts.tasks import ArchiveTask, SplitArchiveInfo
from sunpack.passwords import ArchivePasswordTester, PasswordResolver, PasswordSession, PasswordStore


class ExtractionScheduler:
    def __init__(
        self,
        cli_passwords: list[str] | None = None,
        builtin_passwords: list[str] | None = None,
        max_retries: int = 3,
        process_config: dict | None = None,
        output_config: dict | None = None,
        extraction_config: dict | None = None,
        sevenzip_runner: SevenZipRunner | None = None,
        output_stream=None,
    ):
        self.password_store = PasswordStore.from_sources(
            cli_passwords=cli_passwords or [],
            builtin_passwords=builtin_passwords or [],
        )
        self.password_session = PasswordSession()
        self.password_tester = ArchivePasswordTester(password_store=self.password_store)
        self.password_resolver = PasswordResolver(self.password_tester, self.password_session)
        extraction_config = extraction_config if isinstance(extraction_config, dict) else {}
        self.metadata_scanner = ArchiveMetadataScanner(language=str(extraction_config.get("language") or "en"))
        self.seven_z_path = ""
        self.split_entry_resolver = SplitEntryResolver()
        self.max_retries = max(1, max_retries)
        self.output_config = output_config if isinstance(output_config, dict) else None
        self.extraction_config = extraction_config
        self.process_config = {
            key: value
            for key, value in (process_config or {}).items()
            if value is not None
        }
        self.retry_policy = ExtractRetryPolicy(self.max_retries)
        self.sevenzip_runner = sevenzip_runner or SevenZipRunner(self.process_config)
        self.output_stream = output_stream

    def set_progress_callback(self, callback: Callable[[ArchiveTask, dict], None] | None) -> None:
        self.sevenzip_runner.progress_callback = callback

    def emit_semantic_event(
        self,
        task: ArchiveTask,
        event: str,
        *,
        critical: bool = False,
        **payload: Any,
    ) -> None:
        self.sevenzip_runner.emit_semantic_event(
            task,
            event,
            critical=critical,
            **payload,
        )

    @property
    def recent_passwords(self) -> list[str]:
        return self.password_store.recent_passwords

    def default_output_dir_for_task(self, task: ArchiveTask) -> str:
        return default_output_dir_for_task(task, self.output_config)

    def inspect(self, task: ArchiveTask, out_dir: str):
        return PreExtractInspector(self.password_resolver).inspect(task, out_dir)

    def extract(
        self,
        task: ArchiveTask,
        out_dir: str,
        split_info: Optional[SplitArchiveInfo] = None,
        phase_timer: Any = None,
        phase_prefix: str = "extract",
    ) -> ExtractionResult:
        return self._single_archive_extractor().extract(
            task,
            out_dir,
            split_info=split_info,
            phase_timer=phase_timer,
            phase_prefix=phase_prefix,
        )

    async def extract_asyncio(
        self,
        broker,
        task: ArchiveTask,
        out_dir: str,
        split_info: Optional[SplitArchiveInfo] = None,
        *,
        request_id: str,
        file_id: str,
        cancellation,
        phase_timer: Any = None,
        phase_prefix: str = "extract",
    ) -> ExtractionResult:
        return await self._single_archive_extractor().extract_asyncio(
            broker,
            task,
            out_dir,
            split_info=split_info,
            request_id=request_id,
            file_id=file_id,
            cancellation=cancellation,
            phase_timer=phase_timer,
            phase_prefix=phase_prefix,
        )

    def close(self) -> None:
        self.sevenzip_runner.close()

    def _failed(self, archive: str, out_dir: str, all_parts: list[str], error: str) -> ExtractionResult:
        return ExtractionResult(
            success=False,
            archive=archive,
            out_dir=out_dir,
            all_parts=list(all_parts or []),
            error=error,
        )

    def _single_archive_extractor(self) -> SingleArchiveExtractor:
        return SingleArchiveExtractor(
            seven_z_path=self.seven_z_path,
            password_store=self.password_store,
            password_resolver=self.password_resolver,
            metadata_scanner=self.metadata_scanner,
            retry_policy=self.retry_policy,
            split_entry_resolver=self.split_entry_resolver,
            sevenzip_runner=self.sevenzip_runner,
            best_effort=True,
            write_progress_manifest=bool(self.extraction_config.get("write_progress_manifest", False)),
            quiet=bool(self.extraction_config.get("quiet", False)),
            language=str(self.extraction_config.get("language") or "en"),
            output_stream=self.output_stream,
        )
