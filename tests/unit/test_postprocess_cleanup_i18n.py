from sunpack.core.config.schema import normalize_config
from sunpack.pipeline.postprocess.actions import PostProcessActions
import sunpack.pipeline.postprocess.internal.cleanup as cleanup_module
from sunpack_native import file_generation_tokens
from sunpack.core.support.path_keys import absolute_path_key


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
        expected_generations={absolute_path_key(archive): file_generation_tokens([str(archive)])[0]},
    )

    output = capsys.readouterr().out
    assert "[清理] 任务完成，开始清理成功解压的原压缩包..." in output
    assert "[清理] 移动到回收站：sample.zip" in output
    assert "[CLEAN]" not in output
    assert len(recycled) == 1
    assert recycled[0] != str(archive)
    assert ".sunpack-cleanup-" in recycled[0]
