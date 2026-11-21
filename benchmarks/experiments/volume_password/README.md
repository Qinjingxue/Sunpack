# 混淆卷组与密码实验复现

在 Windows 仓库根目录运行。首轮的[报告、冻结语料与逐次结果](../../../SPE/实验/RQ2-卷布局与密码/实验报告.md)记录了二进制版本、两类快照边界和各工具的计数单位。四个工作流均使用每个快照对应的同一套可见文件。真值只由评估器读取。

## 准备

使用仓库既有的 `.venv`、`tools/7z.exe`、`dist/sunpack-x64` 和 Rust 编译器。将 [NZBGet 26.3 Windows setup](https://github.com/nzbgetcom/nzbget/releases/tag/v26.3) 用 7-Zip 解开到 `$kit/nzb-bin`，其中应有 `nzbget.exe`、`nzbget.conf.template`、`unrar.exe` 和 `7za.exe`。将 [SABnzbd 5.1.3 Windows x64 portable ZIP](https://github.com/sabnzbd/sabnzbd/releases/tag/5.1.3) 解开到 `$kit/sab-bin`，其中应有 `SABnzbd/SABnzbd-console.exe` 和发行包自带的解码器。两个客户端均在回环地址运行，不使用已安装的下载服务。

下方示例使用本轮缓存的客户端；选用一个全新的运行目录。冻结包包含准确的输入和逐字节比较用的期望文件。若要另制一批带随机加密盐的样本，可改用 `corpus.py 新目录`，需要 PATH 中的 RAR 命令行工具。重新生成的样本应另报结果。

```powershell
$kit = (Resolve-Path .cache/SPE-rq2/tools).Path
$run = Join-Path (Resolve-Path .cache) ("rq2-repeat-" + [guid]::NewGuid().ToString("N"))
$corpus = Join-Path $run corpus
$timed = Join-Path $run timed
$diag = Join-Path $run diagnostic
$scripts = 'benchmarks/experiments/volume_password'
$python = '.venv/Scripts/python.exe'
$env:PYTHONPATH = (Get-Location).Path
$archive = (Resolve-Path 'SPE/实验/RQ2-卷布局与密码/corpus.zip').Path
Expand-Archive -LiteralPath $archive -DestinationPath $corpus
Copy-Item -LiteralPath $archive -Destination $corpus
```

## 计时与诊断

依次执行可避开客户端间的额外 CPU 竞争。SunPack 的常规轮使用正式 Worker。每轮独立创建安装目录与 ProgramData，使正确密码不会从前一个快照进入下一个快照。外部客户端每个任务单独启动，使用密码文件，等待终态。NServ 根据同一可见目录生成 NZB。时钟范围和进程启动边界见报告。

```powershell
Remove-Item Env:RQ2_OBSERVER -ErrorAction SilentlyContinue
& $python "$scripts/sunpack_runs.py" $corpus $timed joint
& $python "$scripts/sunpack_runs.py" $corpus $timed serial
& $python "$scripts/news_runs.py" $kit $corpus $timed nzbget
& $python "$scripts/news_runs.py" $kit $corpus $timed sabnzbd

$observer = Join-Path $run observe.exe
rustc -O "$scripts/observe_frames.rs" -o $observer
$env:RQ2_OBSERVER = $observer
try {
    & $python "$scripts/sunpack_runs.py" $corpus $diag joint
    & $python "$scripts/sunpack_runs.py" $corpus $diag serial
} finally {
    Remove-Item Env:RQ2_OBSERVER
}

& $python "$scripts/evaluate.py" --corpus $corpus --joint $timed --serial $timed --nzbget $timed --sabnzbd $timed --diagnostic $diag --dest (Join-Path $run report)
```

`runs.json` 一行观察对应一个方法与一个快照，记录预期值、文件树、物理来源或重命名证据、外部终态和成本。SunPack 的 `worker_calls` 附诊断轮各作业的输入卷、候选和返回选择。没有暴露的解码器内部尝试数不能由这些计数推出。`evidence.zip` 保存两类 CLI 的 JSON 结果、诊断帧、下载器任务日志和终态。原始未筛选客户端日志在各轮的私有工作目录中。
