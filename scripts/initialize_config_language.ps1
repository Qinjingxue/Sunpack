param(
    [Parameter(Mandatory = $true)][string]$UserConfig,
    [Parameter(Mandatory = $true)][string]$AdvancedConfig,
    [Parameter(Mandatory = $true)][ValidateSet("en", "zh")][string]$Language,
    [switch]$InitializeUserConfig
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Set-ConfigLanguage([string]$Path, [string]$Value) {
    # Only the packaged defaults are edited: keep the rest of the JSON byte-for-byte.
    $source = [IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8)
    $match = [regex]::Match($source, '("cli"\s*:\s*\{\s*"language"\s*:\s*")(?<value>[^"]*)(")')
    if (-not $match.Success) { throw "Missing cli.language in packaged configuration: $Path" }
    $token = $match.Groups["value"]
    if ($token.Value -eq $Value) { return }
    $updated = $source.Substring(0, $token.Index) + $Value + $source.Substring($token.Index + $token.Length)
    [IO.File]::WriteAllText($Path, $updated, (New-Object Text.UTF8Encoding($false)))
}

if ($InitializeUserConfig) {
    # Only a newly created config inherits the installer's (OS-selected) language.
    Set-ConfigLanguage -Path $UserConfig -Value $Language
} else {
    # Existing users own their language setting, even when setup runs in another language.
    try {
        $config = [IO.File]::ReadAllText($UserConfig, [Text.Encoding]::UTF8) | ConvertFrom-Json
        $stored = ([string]$config.cli.language).Trim().ToLowerInvariant()
    } catch {
        exit 0
    }
    if ($stored -ne "en" -and $stored -ne "zh") { exit 0 }
    $Language = $stored
}

# The shipped advanced file is replaced on upgrades; align its language with
# the effective user setting so both configuration editors display one language.
Set-ConfigLanguage -Path $AdvancedConfig -Value $Language
