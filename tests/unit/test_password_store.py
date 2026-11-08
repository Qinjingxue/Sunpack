import json
from sunpack.core.passwords.internal.builtin import _parse_document
from types import MappingProxyType

from sunpack.core.contracts.archive_input import ArchiveInputDescriptor
from sunpack.core.passwords.job import PasswordJob
from tests.helpers.archive_tasks import make_archive_task, make_task_from_descriptor
from sunpack.core.passwords.result import PasswordResolutionStatus
from sunpack.core.passwords.scheduler import PasswordScheduler, PasswordSearchResult, PasswordSearchStatus
from sunpack.core.passwords import PasswordResolver, PasswordSession, PasswordStore
from sunpack.core.passwords.internal.store import MAX_RECENT_PASSWORDS, PasswordSnapshot, password_scope_key
from sunpack.core.passwords.verifier import PasswordBatchVerification, PasswordVerifierChain


def _task_with_knowledge(path: str, payload: dict, *, format_hint: str = ""):
    task = make_archive_task(path, format_hint=format_hint)
    knowledge = task.knowledge()
    probe = (payload.get("source") or {}).get("password_probe_input")
    if probe:
        task.password_probe_input = ArchiveInputDescriptor.from_dict(probe)
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

    store.snapshot = _parse_document(json.dumps({"passwords": [
        {"value": "builtin"}, {"value": "dir", "scopes": ["D:/Work"]}, {"value": "clip", "scopes": ["D:/Work"]}
    ]}))[0]
    assert store.candidates("D:/Work") == ["dir", "clip", "cli", "shared", "builtin"]


def test_scoped_password_candidates_stop_reading_after_early_match():
    # Ordering tests exhaust all candidates and miss eager copies. Observe a
    # real immutable bucket so early success must leave its tail untouched.
    visited = []

    class ObservedBucket(tuple):
        def __iter__(self):
            for value in super().__iter__():
                visited.append(value)
                yield value

    snapshot = PasswordSnapshot(scoped_index=MappingProxyType({
        password_scope_key("D:/Work"): ObservedBucket(("secret", "unused", "also-unused")),
    }))
    store = PasswordStore.from_sources(password_snapshot=snapshot)
    visited.clear()
    candidates = store.candidate_values("D:/Work/Child")
    try:
        assert next(candidates) == ("secret", "scope", 15)
        assert visited == ["secret"]
    finally:
        candidates.close()


def test_password_store_remembers_success_at_front():
    store = PasswordStore.from_sources(
        cli_passwords=["cli"],
        recent_passwords=["old", "secret"],
        builtin_passwords=["secret"],
    )

    store.remember_success("secret")

    assert store.recent_passwords == ["secret", "old"]
    assert store.candidates() == ["secret", "cli"]


def test_password_store_bounds_recent_success_history():
    store = PasswordStore.from_sources(recent_passwords=[f"initial-{i}" for i in range(MAX_RECENT_PASSWORDS + 1)])
    assert len(store.recent_passwords) == MAX_RECENT_PASSWORDS
    for index in range(MAX_RECENT_PASSWORDS + 20):
        store.remember_success(f"password-{index}")

    assert len(store.recent_passwords) == MAX_RECENT_PASSWORDS
    assert store.recent_passwords[0] == f"password-{MAX_RECENT_PASSWORDS + 19}"


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

    selected = PasswordResolver._archive_input_for_password_probe(task).to_dict()

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

    selected = PasswordResolver._archive_input_for_password_probe(task).to_dict()

    assert selected["open_mode"] == "file_range"
    assert selected["parts"][0]["start"] == 4096


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


def test_password_resolver_submits_all_inconclusive_candidates_as_one_batch():
    store = PasswordStore.from_sources(
        cli_passwords=["user-password"],
        builtin_passwords=["builtin-password"],
    )
    session = PasswordSession()
    scheduler = QueuePasswordScheduler(candidate_evidence="zipcrypto_header_byte")
    resolver = PasswordResolver(store, session, scheduler)

    first = resolver.resolve("large.rar", archive_key="archive-key")

    assert scheduler.planned == ["", "user-password", "builtin-password"]
    assert first.candidate_evidence == "zipcrypto_header_byte"
    assert first.password == ""
    assert first.candidate_passwords == ("", "user-password", "builtin-password")
    assert first.requires_extraction_confirmation is True
    assert session.get_resolved("archive-key") is None

    resolver.confirm_extraction(first, password="builtin-password")

    assert session.get_resolved("archive-key") == "builtin-password"
    assert store.recent_passwords == ["builtin-password"]


def test_password_resolver_routes_unknown_embedded_range_through_normal_scheduler():
    store = PasswordStore.from_sources(
        cli_passwords=["wrong-password"],
        builtin_passwords=[],
    )
    fast = RecordingNotRequiredFastVerifier()
    scheduler = PasswordScheduler(PasswordVerifierChain([fast]))
    resolver = PasswordResolver(store, PasswordSession(), scheduler)
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


def test_password_resolver_unknown_without_candidates_skips_bounded_verifier():
    scheduler = QueuePasswordScheduler()
    resolver = PasswordResolver(PasswordStore(), PasswordSession(), scheduler)
    bag = _task_with_knowledge("carrier.bin", {
        "source": {
            "password_probe_input": {
                "kind": "archive_input",
                "open_mode": "file_range",
                "entry_path": "carrier.bin",
                "format_hint": "zip",
                "logical_name": "payload",
                "parts": [{"path": "carrier.bin", "start": 100, "length": 200}],
            },
        },
    }, format_hint="zip")

    result = resolver.resolve("carrier.bin", task=bag, archive_key="carrier#payload")

    assert scheduler.planned == []
    assert result.password == ""
    assert result.status == PasswordResolutionStatus.RESOLVED
    assert result.requires_extraction_confirmation is True


def test_password_resolver_uses_active_embedded_format():
    scheduler = QueuePasswordScheduler()
    resolver = PasswordResolver(PasswordStore.from_sources(cli_passwords=["secret"]), PasswordSession(), scheduler)
    bag = make_archive_task("carrier.bin", format_hint="zip")
    bag.password_probe_input = ArchiveInputDescriptor.from_dict({
        "entry_path": "carrier.bin", "open_mode": "file_range", "format_hint": "tar",
        "parts": [{"path": "carrier.bin", "start": 100, "end": 200}],
    })

    result = resolver.resolve("carrier.bin", task=bag, archive_key="carrier#tar")

    # The authoritative TAR descriptor proves that the active segment has no
    # archive-level password mechanism and must not enter any password probe.
    assert result.password == ""
    assert result.status == PasswordResolutionStatus.UNENCRYPTED
    assert result.requires_extraction_confirmation is False
    assert scheduler.planned == []


def test_password_resolver_skips_candidates_for_intrinsically_unencrypted_formats():
    for index, format_hint in enumerate(("tar", "gzip", "bzip2", "xz", "zstd")):
        scheduler = QueuePasswordScheduler()
        resolver = PasswordResolver(PasswordStore.from_sources(cli_passwords=["secret"]), PasswordSession(), scheduler)
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


def test_password_resolver_uses_scoped_passwords_before_user_and_builtin():
    store = PasswordStore.from_sources(
        cli_passwords=["user-password"],
        clipboard_passwords=["clipboard-password"],
        builtin_passwords=["builtin-password"],
    )
    scheduler = QueuePasswordScheduler()
    resolver = PasswordResolver(store, PasswordSession(), scheduler)

    store.snapshot = _parse_document(json.dumps({"passwords": [
        {"value": "builtin-password"}, {"value": "directory-password", "scopes": ["D:/Work"]},
        {"value": "user-password", "scopes": ["D:/Work"]}
    ]}))[0]
    first = resolver.resolve("large.rar", archive_key="archive-key", scope_path="D:/Work")

    assert scheduler.planned == ["", "directory-password", "user-password", "clipboard-password", "builtin-password"]
    assert first.password == ""


def test_confirmed_password_is_promoted_across_already_planned_archives():
    store = PasswordStore.from_sources(
        cli_passwords=["wrong-a", "wrong-b", "shared-secret"],
        builtin_passwords=[],
    )

    resolver = PasswordResolver(store, PasswordSession(), QueuePasswordScheduler())
    required = make_archive_task("sample.zip", format_hint="zip", analysis={"password_required": True})
    archive_a = resolver.resolve("first.unknown", task=required, archive_key="first")
    resolver.resolve("second.unknown", task=required, archive_key="second")

    resolver.confirm_extraction(archive_a, password="shared-secret")
    promoted_b = resolver.resolve("second.unknown", task=required, archive_key="second")

    assert archive_a.candidate_passwords == ("wrong-a", "wrong-b", "shared-secret")
    assert promoted_b.password == "shared-secret"


def test_hundreds_of_archives_reuse_confirmed_password_after_one_candidate_batch():
    passwords = [f"wrong-{index}" for index in range(499)] + ["shared-secret"]
    store = PasswordStore.from_sources(cli_passwords=passwords)

    resolver = PasswordResolver(store, PasswordSession(), QueuePasswordScheduler())
    required = make_archive_task("sample.zip", format_hint="zip", analysis={"password_required": True})
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
    from tests.helpers.passwords import write_password_json
    path = tmp_path / "builtin_passwords.json"
    write_password_json(path, ["#secret"], history=["clip-secret"])
    store = PasswordStore.from_sources(builtin_passwords_file=str(path))
    assert store.builtin_passwords == ("#secret", "clip-secret")


def test_required_password_lifecycle(subtests):
    cases = [
        (PasswordSearchStatus.FOUND, PasswordResolutionStatus.RESOLVED, "secret"),
        (PasswordSearchStatus.EXHAUSTED, PasswordResolutionStatus.CANDIDATES_EXHAUSTED, None),
        (PasswordSearchStatus.DAMAGED, PasswordResolutionStatus.DAMAGED, None),
    ]
    for search_status, expected_status, password in cases:
        with subtests.test(status=expected_status):
            task = make_archive_task("sample.zip", format_hint="zip", analysis={"password_required": True})
            jobs = []

            def plan(job):
                jobs.append(job)
                return PasswordSearchResult(password=password, status=search_status)

            scheduler = QueuePasswordScheduler()
            scheduler.plan_for_extraction = plan
            session = PasswordSession()
            store = PasswordStore.from_sources(cli_passwords=["secret", "fallback"])
            resolver = PasswordResolver(store, session, scheduler)
            result = resolver.resolve("sample.zip", task=task, archive_key="archive-key")
            assert result.password == password and result.status == expected_status
            assert len(jobs) == 1
            if password is not None:
                assert session.get_resolved("archive-key") == password
                assert resolver.resolve("sample.zip", archive_key="archive-key").password == password
                assert len(jobs) == 1
