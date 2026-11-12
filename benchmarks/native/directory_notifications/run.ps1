param([int]$Runs=5)
$ErrorActionPreference='Stop'
$repo=(Resolve-Path (Join-Path $PSScriptRoot '../../..')).Path
$cache=Join-Path $repo '.cache'
$exe=Join-Path $cache 'directory-notifications-bench.exe'
& rustc -O --edition=2021 (Join-Path $PSScriptRoot 'benchmark.rs') -o $exe
if($LASTEXITCODE){throw 'rustc failed'}
$report=Join-Path $cache ('notify-buffer-exact-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'.jsonl')
foreach($rep in 1..$Runs){
 foreach($scenario in @(@(0,0,0),@(3000,0,0),@(3000,10000,0))){
  $sizes=if($rep%2){@(4096,64000)}else{@(64000,4096)}
  foreach($bytes in $sizes){
   $root=[IO.Path]::GetFullPath((Join-Path $cache ('notify-bench-'+[guid]::NewGuid().ToString('N'))))
   if(-not $root.StartsWith($cache+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){throw 'invalid benchmark root'}
   $line=& $exe $root $bytes $scenario[0] $scenario[1] $scenario[2]
   if($LASTEXITCODE){throw "benchmark failed; preserve $root for diagnosis"}
   $row=$line|ConvertFrom-Json
   $row|Add-Member rep $rep
   $json=$row|ConvertTo-Json -Compress
   $json|Add-Content $report
   Write-Output $json
  }
 }
}
Write-Output "RESULT=$report"
