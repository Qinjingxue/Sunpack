from sunpack.core.config.schema import normalize_config
from sunpack.pipeline.postprocess.actions import PostProcessActions
import sunpack.pipeline.postprocess.internal.cleanup as cleanup_module


def test_cleanup_defaults_to_config_language_and_localized_label(tmp_path, monkeypatch, capsys):
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"archive")
    recycled = []
    monkeypatch.setattr(cleanup_module, "send2trash", recycled.append)

    PostProcessActions(
        normalize_config({"cli": {"language": "zh"}, "verification": {}})
    ).apply(
        cleanup_archives=True,
        flatten_outputs=False,
        archives_to_clean=[[str(archive)]],
    )

    output = capsys.readouterr().out
    assert "[清理] 任务完成，开始清理成功解压的原压缩包..." in output
    assert "[清理] 移动到回收站：sample.zip" in output
    assert "[CLEAN]" not in output
    assert recycled == [str(archive)]
