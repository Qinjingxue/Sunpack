"""Test native artifact selection without relying on a local release build."""
import pytest

from tests.helpers import native_build


@pytest.mark.parametrize("arch", ["x64", "arm64"])
@pytest.mark.parametrize("profile", ["ci", "release"])
def test_native_artifact_uses_only_selected_architecture_and_profile(monkeypatch, tmp_path, arch, profile):
    monkeypatch.setattr(native_build, "ROOT", tmp_path)
    monkeypatch.setenv("SUNPACK_TEST_ARCH", arch)
    monkeypatch.setenv("SUNPACK_TEST_BUILD_PROFILE", profile)
    expected = None
    for candidate_arch in ("x64", "arm64"):
        for candidate_profile in ("ci", "release"):
            suffix = "-ci" if candidate_profile == "ci" else ""
            artifact = (tmp_path / "native/sevenzip_bridge" /
                        f"build-{candidate_arch}{suffix}/Release/sunpack_sevenzip_worker.exe")
            artifact.parent.mkdir(parents=True)
            artifact.touch()
            if (candidate_arch, candidate_profile) == (arch, profile):
                expected = artifact
    assert native_build.sevenzip_artifact("sunpack_sevenzip_worker.exe") == expected
    expected.unlink()
    with pytest.raises(FileNotFoundError, match="matching -Arch and -BuildProfile") as error:
        native_build.sevenzip_artifact("sunpack_sevenzip_worker.exe")
    assert str(expected) in str(error.value)


@pytest.mark.parametrize("platform,arch", [("win-amd64", "x64"), ("win-arm64", "arm64")])
def test_direct_pytest_defaults_match_development_setup(monkeypatch, tmp_path, platform, arch):
    monkeypatch.setattr(native_build, "ROOT", tmp_path)
    monkeypatch.setattr(native_build.sysconfig, "get_platform", lambda: platform)
    monkeypatch.delenv("SUNPACK_TEST_ARCH", raising=False)
    monkeypatch.delenv("SUNPACK_TEST_BUILD_PROFILE", raising=False)
    assert native_build.sevenzip_build_dir() == tmp_path / f"native/sevenzip_bridge/build-{arch}-ci/Release"


@pytest.mark.parametrize("variable,value", [
    ("SUNPACK_TEST_ARCH", "x86"),
    ("SUNPACK_TEST_BUILD_PROFILE", "debug"),
])
def test_invalid_native_selection_is_reported(monkeypatch, variable, value):
    monkeypatch.setenv(variable, value)
    with pytest.raises(ValueError, match=variable):
        native_build.sevenzip_build_dir()
