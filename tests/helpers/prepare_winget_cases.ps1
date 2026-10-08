param(
    [Parameter(Mandatory = $true)][string]$PrepareScript,
    [Parameter(Mandatory = $true)][string]$CasesPath,
    [Parameter(Mandatory = $true)][string]$ResultsPath
)

$ErrorActionPreference = "Stop"
# Invoke each real script in its own script scope, within one PowerShell host.
# Catch expected validation failures so later cases still execute.
$cases = Get-Content -LiteralPath $CasesPath -Raw -Encoding UTF8 | ConvertFrom-Json
$results = foreach ($case in $cases) {
    $arguments = @{}
    foreach ($property in $case.arguments.PSObject.Properties) {
        $arguments[$property.Name] = $property.Value
    }
    $output = ""
    $errorText = ""
    $code = 0
    try {
        $output = & $PrepareScript @arguments *>&1 | Out-String
    } catch {
        $code = 1
        $errorText = $_ | Out-String
    }
    [pscustomobject]@{
        id = $case.id
        returncode = $code
        stdout = $output
        stderr = $errorText
    }
}
[IO.File]::WriteAllText(
    $ResultsPath, (ConvertTo-Json -InputObject @($results) -Depth 5),
    [Text.UTF8Encoding]::new($false)
)
