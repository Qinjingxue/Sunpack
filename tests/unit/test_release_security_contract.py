from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

def test_release_workflow_publishes_sha256_checksums():
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")

    assert "SHA256SUMS.txt" in workflow
    assert "sha256sum" in workflow
    assert 'gh release upload "${TAG_NAME}" "${release_assets[@]}" --clobber' in workflow
