from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_release_workflow_authenticode_signs_and_verifies_installers():
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")

    assert "SUNPACK_SIGNING_PFX_BASE64" in workflow
    assert "SUNPACK_SIGNING_PASSWORD" in workflow
    assert "signtool.exe" in workflow
    assert " sign " in workflow
    assert "/fd SHA256" in workflow
    assert "/td SHA256" in workflow
    assert "/tr http://timestamp.digicert.com" in workflow
    assert " verify " in workflow
    assert "/pa" in workflow


def test_release_workflow_publishes_sha256_checksums():
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")

    assert "SHA256SUMS.txt" in workflow
    assert "sha256sum" in workflow
    assert 'gh release upload "${TAG_NAME}" "${release_assets[@]}" --clobber' in workflow
