from types import SimpleNamespace

from sunpack.core.contracts.archive_input import ArchiveInputDescriptor
from sunpack.core.passwords.job import PasswordJob
from tests.helpers.archive_tasks import make_archive_task, make_task_from_descriptor
from sunpack.core.passwords.result import PasswordResolutionStatus
from sunpack.core.passwords.scheduler import PasswordScheduler, PasswordSearchResult, PasswordSearchStatus
from sunpack.core.passwords import PasswordResolver, PasswordSession, PasswordStore
from sunpack.core.passwords.internal.store import MAX_RECENT_PASSWORDS
from sunpack.core.passwords.verifier import PasswordBatchVerification, PasswordVerifierChain


def _task_with_structure(format_hint: str, structure: dict, *, path: str | None = None):
    task = make_archive_task(path or f"sample.{format_hint}", format_hint=format_hint)
    knowledge = task.knowledge()
    knowledge.set(
        f"format.{format_hint}.structure",
        structure,
        source_layer="tests",
        source_module="password_store",
    )
    task.set_knowledge(knowledge)
    return task


def _task_with_knowledge(path: str, payload: dict, *, format_hint: str = ""):
    task = make_archive_task(path, format_hint=format_hint)
    knowledge = task.knowledge()
    knowledge.merge(payload, source_layer="tests", source_module="password_store")
    task.set_knowledge(knowledge)
    return task


def test_password_store_orders_user_recent_builtin_and_dedupes():
    store = PasswordStore.from_sources(
        cli_passwords=["cli", "shared"],
        clipboard_passwords=["clip", "builtin"],
        recent_passwords=["recent"],
        builtin_passwords=["builtin", "shared"],
    )

    assert store.candidates(directory_passwords=["dir", "clip"]) == ["recent", "dir", "clip", "cli", "shared", "builtin"]


def test_password_store_remembers_success_at_front():
    store = PasswordStore.from_sources(
        cli_passwords=["cli"],
        recent_passwords=["old", "secret"],
        builtin_passwords=["secret"],
    )

    store.remember_success("secret")

    assert store.recent_passwords == ["secret", "old"]
    assert store.candidates() == ["secret", "old", "cli"]


def test_password_store_bounds_recent_success_history():
    store = PasswordStore.from_sources()
    for index in range(MAX_RECENT_PASSWORDS + 20):
        store.remember_success(f"password-{index}")

    assert len(store.recent_passwords) == MAX_RECENT_PASSWORDS
    assert store.recent_passwords[0] == f"password-{MAX_RECENT_PASSWORDS + 19}"


def test_password_store_bounds_initial_recent_success_history():
    store = PasswordStore.from_sources(
        recent_passwords=[f"password-{index}" for index in range(MAX_RECENT_PASSWORDS + 1)]
    )

    assert len(store.recent_passwords) == MAX_RECENT_PASSWORDS


def test_password_resolver_falls_back_to_relations_archive_input_before_analysis():
    descriptor = ArchiveInputDescriptor.from_dict({
        "kind": "archive_input",
        "entry_path": "carrier.exe",
        "open_mode": "file_range",
        "format_hint": "rar",
        "logical_name": "carrier",
        "parts": [{"path": "carrier.exe", "start": 8192}],
    }, archive_path="carrier.exe")
    task = make_task_from_descriptor(descriptor)

    selected = PasswordResolver._archive_input_for_password_probe(task)

    assert selected["open_mode"] == "file_range"
    assert selected["parts"][0]["start"] == 8192
    assert task.logical_name == "carrier"


def test_password_resolver_prefers_formal_password_probe_input():
    task = _task_with_knowledge("carrier.exe", {
        "source": {
            "password_probe_input": {
                "kind": "archive_input",
                "entry_path": "carrier.exe",
                "open_mode": "file_range",
                "format_hint": "rar",
                "parts": [{"path": "carrier.exe", "start": 4096}],
            },
        },
    }, format_hint="rar")

    selected = PasswordResolver._archive_input_for_password_probe(task)

    assert selected["open_mode"] == "file_range"
    assert selected["parts"][0]["start"] == 4096


class FakePasswordTester:
    passwords = ["secret"]

    def __init__(self):
        self.test_without_password_calls = 0
        self.search_calls = 0
        self.password_store = PasswordStore.from_sources(cli_passwords=["secret", "fallback"], builtin_passwords=[])
        self.password_scheduler = FakePasswordScheduler(self)

    def add_recent_password(self, password):
        self.password_store.remember_success(password)

    def test_without_password(self, archive_path, part_paths=None):
        self.test_without_password_calls += 1
        return SimpleNamespace(status="no_match", message="encrypted")

    def search_passwords(self, job: PasswordJob):
        self.search_calls += 1
        return PasswordSearchResult(password="secret", status=PasswordSearchStatus.FOUND, test_result=SimpleNamespace(returncode=0), error_text="")


class FakeFailingPasswordTester(FakePasswordTester):
    def test_without_password(self, archive_path, part_paths=None):
        self.test_without_password_calls += 1
        return SimpleNamespace(status="damaged", message="headers error")

    def search_passwords(self, job: PasswordJob):
        self.search_calls += 1
        return PasswordSearchResult(password=None, status=PasswordSearchStatus.EXHAUSTED, test_result=SimpleNamespace(returncode=2), error_text="password rejected")


class FakeDamagedPasswordTester(FakeFailingPasswordTester):
    def search_passwords(self, job: PasswordJob):
        self.search_calls += 1
        return PasswordSearchResult(password=None, status=PasswordSearchStatus.DAMAGED, test_result=SimpleNamespace(returncode=2), error_text="headers error")


class FakePasswordScheduler:
    def __init__(self, tester):
        self.tester = tester

    def run(self, job: PasswordJob):
        return self.tester.search_passwords(job)

    def plan_for_extraction(self, job: PasswordJob):
        return self.tester.search_passwords(job)

    def remember_extraction_success(self, fingerprint_key, password):
        pass

    def remember_extraction_rejection(self, fingerprint_key, password):
        pass


class QueuePasswordScheduler:
    def __init__(self, candidate_evidence=""):
        self.planned = []
        self.candidate_evidence = candidate_evidence

    def plan_for_extraction(self, job: PasswordJob):
        candidates = tuple(candidate.value for candidate in job.candidate_pipeline())
        self.planned.extend(candidates)
        return PasswordSearchResult(
            password=None,
            status=PasswordSearchStatus.INCONCLUSIVE,
            extraction_candidates=candidates,
            extraction_candidate_evidence=self.candidate_evidence,
        )

    def remember_extraction_success(self, fingerprint_key, password):
        pass

    def remember_extraction_rejection(self, fingerprint_key, password):
        pass


class RecordingNotRequiredFastVerifier:
    def __init__(self):
        self.batches = []

    def verify_batch(self, archive_path, passwords, *, part_paths=None, archive_input=None):
        self.batches.append(list(passwords))
        return PasswordBatchVerification(
            ok=True,
            status="not_required",
            matched_index=-1,
            final_confirmation_required=False,
        )


def test_password_resolver_records_archive_password_in_session():
    session = PasswordSession()
    resolver = PasswordResolver(FakePasswordTester(), session)

    result = resolver.resolve("sample.zip", archive_key="archive-key")

    assert result.password == "secret"
    assert result.archive_key == "archive-key"
    assert session.get_resolved("archive-key") == "secret"


def test_password_resolver_trusts_validated_unencrypted_structure_without_retesting():
    bag = _task_with_structure("zip", {
        "plausible": True,
        "central_directory_present": True,
        "central_directory_walk_ok": True,
        "central_directory_encrypted_entries": 0,
        "encryption_scan_complete": True,
        "password_required": False,
    })
    tester = FakePasswordTester()
    session = PasswordSession()
    resolver = PasswordResolver(tester, session)

    result = resolver.resolve("sample.zip", task=bag, archive_key="archive-key")

    assert result.password == ""
    assert result.encrypted is False
    assert session.get_resolved("archive-key") == ""
    assert tester.test_without_password_calls == 0
    assert tester.search_calls == 0
    assert result.archive_key == "archive-key"


def test_password_resolver_trusts_validated_encrypted_structure_without_empty_password_test():
    bag = _task_with_structure("zip", {
        "plausible": True,
        "central_directory_present": True,
        "central_directory_walk_ok": True,
        "central_directory_encrypted_entries": 1,
        "encryption_scan_complete": True,
        "password_required": True,
    })
    tester = FakePasswordTester()
    session = PasswordSession()
    resolver = PasswordResolver(tester, session)

    result = resolver.resolve("sample.zip", task=bag, archive_key="archive-key")

    assert result.password == "secret"
    assert tester.test_without_password_calls == 0
    assert tester.search_calls == 1


def test_password_resolver_uses_validated_rar_structure_password_marker():
    bag = _task_with_structure("rar", {
        "plausible": True,
        "strong_accept": True,
        "header_crc_ok": True,
        "header_encrypted": True,
        "password_required": True,
    })
    tester = FakePasswordTester()
    session = PasswordSession()
    resolver = PasswordResolver(tester, session)

    result = resolver.resolve("sample.rar", task=bag, archive_key="archive-key")

    assert result.password == "secret"
    assert result.encrypted is True
    assert tester.test_without_password_calls == 0
    assert tester.search_calls == 1


def test_password_resolver_uses_validated_seven_zip_encryption_fact():
    bag = _task_with_structure("7z", {
        "plausible": True,
        "strong_accept": True,
        "next_header_crc_ok": True,
        "next_header_nid_valid": True,
        "password_required": True,
        "encrypted_header": True,
        "encryption_scan_complete": True,
    })
    tester = FakePasswordTester()
    resolver = PasswordResolver(tester, PasswordSession())

    result = resolver.resolve("sample.7z", task=bag, archive_key="archive-key")

    assert result.password == "secret"
    assert result.encrypted is True
    assert tester.test_without_password_calls == 0
    assert tester.search_calls == 1


def test_password_resolver_does_not_recheck_clear_wrong_password_after_encrypted_search():
    bag = _task_with_structure("zip", {
        "plausible": True,
        "central_directory_present": True,
        "central_directory_walk_ok": True,
        "central_directory_encrypted_entries": 1,
        "encryption_scan_complete": True,
        "password_required": True,
    })
    tester = FakeFailingPasswordTester()
    session = PasswordSession()
    resolver = PasswordResolver(tester, session)

    result = resolver.resolve("sample.zip", task=bag, archive_key="archive-key")

    assert result.password is None
    assert result.status == PasswordResolutionStatus.CANDIDATES_EXHAUSTED
    assert tester.search_calls == 1
    assert tester.test_without_password_calls == 0


def test_password_resolver_preserves_fast_damage_result_without_full_retest():
    bag = _task_with_structure("zip", {
        "plausible": True,
        "central_directory_present": True,
        "central_directory_walk_ok": True,
        "central_directory_encrypted_entries": 1,
        "encryption_scan_complete": True,
        "password_required": True,
    })
    tester = FakeDamagedPasswordTester()
    session = PasswordSession()
    resolver = PasswordResolver(tester, session)

    result = resolver.resolve("sample.zip", task=bag, archive_key="archive-key")

    assert result.password is None
    assert result.status == PasswordResolutionStatus.DAMAGED
    assert result.error_text == "headers error"
    assert tester.search_calls == 1
    assert tester.test_without_password_calls == 0


def test_password_resolver_reuses_session_password_without_retesting():
    session = PasswordSession()
    session.set_resolved("archive-key", "secret")
    tester = FakePasswordTester()
    resolver = PasswordResolver(tester, session)

    result = resolver.resolve("sample.zip", archive_key="archive-key")

    assert result.password == "secret"


def test_password_resolver_submits_all_inconclusive_candidates_as_one_batch():
    tester = FakePasswordTester()
    tester.password_store = PasswordStore.from_sources(
        cli_passwords=["user-password"],
        builtin_passwords=["builtin-password"],
    )
    tester.passwords = tester.password_store.candidates()
    session = PasswordSession()
    scheduler = QueuePasswordScheduler()
    resolver = PasswordResolver(tester, session, scheduler)

    first = resolver.resolve("large.rar", archive_key="archive-key")

    assert scheduler.planned == ["", "user-password", "builtin-password"]
    assert first.password == ""
    assert first.candidate_passwords == ("", "user-password", "builtin-password")
    assert first.requires_extraction_confirmation is True
    assert tester.test_without_password_calls == 0
    assert session.has_resolved("archive-key") is False

    resolver.confirm_extraction(first, password="builtin-password")

    assert session.get_resolved("archive-key") == "builtin-password"
    assert tester.password_store.recent_passwords == ["builtin-password"]


def test_password_resolver_routes_unknown_embedded_range_through_normal_scheduler():
    tester = FakePasswordTester()
    tester.password_store = PasswordStore.from_sources(
        cli_passwords=["wrong-password"],
        builtin_passwords=[],
    )
    fast = RecordingNotRequiredFastVerifier()
    scheduler = PasswordScheduler(PasswordVerifierChain([fast]))
    resolver = PasswordResolver(tester, PasswordSession(), scheduler)
    bag = _task_with_knowledge("carrier.bin", {
        "source": {
            "password_probe_input": {
                "open_mode": "file_range",
                "entry_path": "carrier.bin",
                "parts": [{"path": "carrier.bin", "start": 100, "length": 200}],
            },
        },
    })

    result = resolver.resolve("carrier.bin", task=bag, archive_key="carrier#segment-1")

    assert fast.batches == [["", "wrong-password"]]
    assert result.password == ""
    assert result.status == PasswordResolutionStatus.UNENCRYPTED
    assert result.requires_extraction_confirmation is False


def test_password_resolver_scopes_structure_facts_to_active_embedded_format():
    tester = FakePasswordTester()
    scheduler = QueuePasswordScheduler()
    resolver = PasswordResolver(tester, PasswordSession(), scheduler)
    bag = _task_with_structure("zip", {
        "plausible": True,
        "central_directory_present": True,
        "central_directory_walk_ok": True,
        "central_directory_encrypted_entries": 2,
        "encryption_scan_complete": True,
        "password_required": True,
    })
    knowledge = bag.knowledge()
    knowledge.set(
        "source.password_probe_input",
        {
            "kind": "archive_input",
            "entry_path": "carrier.bin",
            "open_mode": "file_range",
            "format_hint": "tar",
            "parts": [{"path": "carrier.bin", "start": 100, "end": 200}],
        },
        source_layer="tests",
        source_module="password_store",
    )
    bag.set_knowledge(knowledge)

    result = resolver.resolve("carrier.bin", task=bag, archive_key="carrier#tar")

    # The carrier's encrypted ZIP fact belongs to a different logical range.
    # The authoritative TAR descriptor proves that the active segment has no
    # archive-level password mechanism and must not enter any password probe.
    assert result.password == ""
    assert result.status == PasswordResolutionStatus.UNENCRYPTED
    assert result.requires_extraction_confirmation is False
    assert scheduler.planned == []


def test_password_resolver_skips_candidates_for_intrinsically_unencrypted_formats():
    for index, format_hint in enumerate(("tar", "gzip", "bzip2", "xz", "zstd")):
        tester = FakePasswordTester()
        scheduler = QueuePasswordScheduler()
        resolver = PasswordResolver(tester, PasswordSession(), scheduler)
        bag = _task_with_knowledge("carrier.bin", {
            "source": {
                "password_probe_input": {
                    "kind": "archive_input",
                    "entry_path": "carrier.bin",
                    "open_mode": "file_range",
                    "format_hint": format_hint,
                    "parts": [{"path": "carrier.bin", "start": index * 100, "end": (index + 1) * 100}],
                },
            },
        })

        result = resolver.resolve(
            "carrier.bin",
            task=bag,
            archive_key=f"carrier#{format_hint}",
        )

        assert result.password == ""
        assert result.status == PasswordResolutionStatus.UNENCRYPTED
        assert result.requires_extraction_confirmation is False
        assert scheduler.planned == []


def test_password_resolver_preserves_candidate_evidence_across_batch_confirmation():
    tester = FakePasswordTester()
    tester.password_store = PasswordStore.from_sources(
        cli_passwords=["first", "second"],
        builtin_passwords=[],
    )
    resolver = PasswordResolver(
        tester,
        PasswordSession(),
        QueuePasswordScheduler(candidate_evidence="zipcrypto_header_byte"),
    )

    first = resolver.resolve("payload.zip", archive_key="archive-key")
    assert first.candidate_evidence == "zipcrypto_header_byte"
    assert first.candidate_passwords == ("", "first", "second")


def test_password_resolver_uses_directory_passwords_before_user_and_builtin():
    tester = FakePasswordTester()
    tester.password_store = PasswordStore.from_sources(
        cli_passwords=["user-password"],
        clipboard_passwords=["clipboard-password"],
        builtin_passwords=["builtin-password"],
    )
    scheduler = QueuePasswordScheduler()
    resolver = PasswordResolver(tester, PasswordSession(), scheduler)

    first = resolver.resolve(
        "large.rar",
        archive_key="archive-key",
        directory_passwords=["directory-password", "user-password"],
    )

    assert scheduler.planned == ["", "directory-password", "user-password", "clipboard-password", "builtin-password"]
    assert first.password == ""


def test_confirmed_password_is_promoted_across_already_planned_archives():
    tester = FakePasswordTester()
    tester.password_store = PasswordStore.from_sources(
        cli_passwords=["wrong-a", "wrong-b", "shared-secret"],
        builtin_passwords=[],
    )

    resolver = PasswordResolver(tester, PasswordSession(), QueuePasswordScheduler())
    required = _task_with_structure("zip", {
        "plausible": True,
        "central_directory_present": True,
        "central_directory_walk_ok": True,
        "central_directory_encrypted_entries": 1,
        "encryption_scan_complete": True,
        "password_required": True,
    })
    archive_a = resolver.resolve("first.unknown", task=required, archive_key="first")
    archive_b = resolver.resolve("second.unknown", task=required, archive_key="second")

    resolver.confirm_extraction(archive_a, password="shared-secret")
    promoted_b = resolver.resolve("second.unknown", task=required, archive_key="second")

    assert archive_a.candidate_passwords == ("wrong-a", "wrong-b", "shared-secret")
    assert promoted_b.password == "shared-secret"


def test_hundreds_of_archives_reuse_confirmed_password_after_one_candidate_batch():
    passwords = [f"wrong-{index}" for index in range(499)] + ["shared-secret"]
    tester = FakePasswordTester()
    tester.password_store = PasswordStore.from_sources(cli_passwords=passwords, builtin_passwords=[])

    resolver = PasswordResolver(tester, PasswordSession(), QueuePasswordScheduler())
    required = _task_with_structure("zip", {
        "plausible": True,
        "central_directory_present": True,
        "central_directory_walk_ok": True,
        "central_directory_encrypted_entries": 1,
        "encryption_scan_complete": True,
        "password_required": True,
    })
    resolution = resolver.resolve("archive-0.mixed", task=required, archive_key="archive-0")
    assert resolution.candidate_passwords == tuple(passwords)
    resolver.confirm_extraction(resolution, password="shared-secret")

    for index in range(1, 100):
        resolution = resolver.resolve(
            f"archive-{index}.mixed",
            task=required,
            archive_key=f"archive-{index}",
        )
        assert resolution.password == "shared-secret"
        resolver.confirm_extraction(resolution)


def test_password_store_reads_structured_builtin_file(tmp_path):
    builtin_file = tmp_path / "builtin_passwords.txt"
    builtin_file.write_text(
        "# Built-in common password list. You can edit this file; use one password per line.\n"
        "#secret\n"
        "# The following section is managed automatically by SunPack Watch.\n"
        "#!SUNPACK-WATCH-CLIPBOARD-BEGIN\n"
        "clip-secret\n"
        "#!SUNPACK-WATCH-CLIPBOARD-END\n",
        encoding="utf-8",
    )

    store = PasswordStore.from_sources(builtin_passwords_file=str(builtin_file))

    assert store.builtin_passwords == ["#secret", "clip-secret"]
