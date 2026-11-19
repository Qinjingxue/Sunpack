function Initialize-ExitCodeProbe {
    if ("SunPack.ProcessExit" -as [type]) {
        return
    }
    Add-Type -Namespace SunPack -Name ProcessExit -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
public static extern bool GetExitCodeProcess(System.IntPtr hProcess, out uint lpExitCode);

public static bool TryGetExitCode(System.IntPtr hProcess, ref int exitCode) {
    uint code;
    if (!GetExitCodeProcess(hProcess, out code)) {
        return false;
    }
    exitCode = unchecked((int)code);
    return true;
}
'@
}

function Get-ChildExitCode {
    param(
        [Parameter(Mandatory = $true)][System.Diagnostics.Process]$Process,
        $ProcessHandle = $null
    )

    # Windows PowerShell 5.1 can leave Start-Process -PassThru ExitCode unset ($null), and
    # [int]$null silently becomes 0, which would report a failing pytest run as exit 0.
    if ($null -ne $Process.ExitCode) {
        return [int]$Process.ExitCode
    }
    if ($ProcessHandle -is [IntPtr] -and $ProcessHandle -ne [IntPtr]::Zero) {
        try {
            Initialize-ExitCodeProbe
            $code = 0
            # 259 is STILL_ACTIVE: the handle outlived the process without an exit code.
            if ([SunPack.ProcessExit]::TryGetExitCode($ProcessHandle, [ref]$code) -and $code -ne 259) {
                return [int]$code
            }
        } catch {
        }
    }
    return $null
}

function Initialize-TestProcessOutput {
    if ("SunPack.Acceptance.TestOutputSignal" -as [type]) {
        return
    }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;

namespace SunPack.Acceptance {
    public sealed class TestOutputSignal : IDisposable {
        private readonly AutoResetEvent changed = new AutoResetEvent(false);
        private readonly FileSystemWatcher watcher;
        private readonly Process process;

        public TestOutputSignal(Process process, string directory, string filter) {
            this.process = process;
            watcher = new FileSystemWatcher(directory, filter);
            try {
                watcher.NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite;
                watcher.Created += OnChange;
                watcher.Changed += OnChange;
                watcher.Error += OnError;
                watcher.EnableRaisingEvents = true;
                process.Exited += OnExit;
                process.EnableRaisingEvents = true;
            } catch {
                Dispose();
                throw;
            }
        }

        private void OnChange(object sender, FileSystemEventArgs e) { Signal(); }
        private void OnError(object sender, ErrorEventArgs e) { Signal(); }
        private void OnExit(object sender, EventArgs e) { Signal(); }

        private void Signal() {
            try { changed.Set(); } catch (ObjectDisposedException) { }
        }

        public bool Wait(int milliseconds) { return changed.WaitOne(milliseconds); }

        public void Dispose() {
            process.Exited -= OnExit;
            watcher.Dispose();
            changed.Dispose();
        }
    }

    public sealed class TestOutputLog : IDisposable {
        private readonly string path;
        private readonly Decoder decoder = Encoding.UTF8.GetDecoder();
        private readonly byte[] bytes = new byte[4096];
        private readonly char[] chars = new char[Encoding.UTF8.GetMaxCharCount(4096)];
        private FileStream stream;
        private bool firstChunk = true;

        public TestOutputLog(string path) { this.path = path; }

        public IEnumerable<string> ReadChunks(bool finished) {
            if (stream == null) {
                if (!File.Exists(path)) yield break;
                stream = new FileStream(path, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete);
            }

            long remaining = stream.Length - stream.Position;
            while (remaining > 0) {
                int count = stream.Read(bytes, 0, (int)Math.Min(remaining, bytes.Length));
                if (count == 0) break;
                remaining -= count;
                string chunk = Decode(count, false);
                if (chunk.Length != 0) yield return chunk;
            }

            if (finished) {
                string tail = Decode(0, true);
                if (tail.Length != 0) yield return tail;
            }
        }

        private string Decode(int count, bool finished) {
            int length = decoder.GetChars(bytes, 0, count, chars, 0, finished);
            string text = new string(chars, 0, length);
            if (firstChunk && text.Length != 0) {
                firstChunk = false;
                text = text.TrimStart('\uFEFF');
            }
            return text;
        }

        public void Dispose() {
            if (stream != null) stream.Dispose();
        }
    }
}
'@
}

function Receive-TestProcessOutput {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string[]]$Paths,
        [int]$TimeoutMilliseconds = -1,
        [scriptblock]$OnTimeout
    )

    Initialize-TestProcessOutput
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $directory = Split-Path -Parent $Paths[0]
    $filter = if ($Paths.Count -eq 1) { Split-Path -Leaf $Paths[0] } else { "*.bin" }
    $signal = [SunPack.Acceptance.TestOutputSignal]::new($Process, $directory, $filter)
    $logs = @($Paths | ForEach-Object { [SunPack.Acceptance.TestOutputLog]::new($_) })
    try {
        $timedOut = $false
        $needsNewline = $false
        $lastLog = $null
        while ($true) {
            $exited = $Process.HasExited
            if ($exited) {
                # Flush any asynchronous redirection performed by Start-Process.
                $Process.WaitForExit()
            }
            foreach ($log in $logs) {
                foreach ($chunk in $log.ReadChunks($exited)) {
                    if ($needsNewline -and $lastLog -ne $log) { Write-Host "" }
                    Write-Host -NoNewline $chunk
                    $lastLog = $log
                    $needsNewline = -not $chunk.EndsWith("`n")
                }
            }
            if ($exited) {
                if ($needsNewline) { Write-Host "" }
                return (-not $timedOut)
            }

            $remaining = if ($TimeoutMilliseconds -lt 0) { -1 } else {
                [Math]::Max(0, $TimeoutMilliseconds - $timer.ElapsedMilliseconds)
            }
            if (($remaining -eq 0 -or -not $signal.Wait($remaining)) -and -not $Process.HasExited) {
                $timedOut = $true
                & $OnTimeout
            }
        }
    } finally {
        foreach ($log in $logs) { $log.Dispose() }
        $signal.Dispose()
    }
}
