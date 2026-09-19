function Get-CoffSymbol {

    param(
        [Parameter(Mandatory = $true)][string]$ObjectPath,
        [Parameter(Mandatory = $true)][string]$SymbolName,
        [int]$Length = 32
    )

    if (-not (Test-Path -LiteralPath $ObjectPath)) { return $null }

    $bytes = [System.IO.File]::ReadAllBytes($ObjectPath)
    if ($bytes.Length -lt 20) { return $null }

    $sectionCount = [System.BitConverter]::ToUInt16($bytes, 2)
    $symbolTableOffset = [System.BitConverter]::ToInt32($bytes, 8)
    $symbolCount = [System.BitConverter]::ToInt32($bytes, 12)
    if ($sectionCount -le 0 -or $sectionCount -gt 96 -or $symbolCount -le 0) { return $null }
    if ($symbolTableOffset -le 0 -or $symbolTableOffset -ge $bytes.Length) { return $null }
    if (($symbolTableOffset + ($symbolCount * 18)) -gt $bytes.Length) { return $null }
    $sections = @{}
    for ($i = 0; $i -lt $sectionCount; $i++) {
        $headerOffset = 20 + ($i * 40)
        if ($headerOffset + 40 -gt $bytes.Length) { return $null }
        $nameEnd = $headerOffset
        while ($nameEnd -lt $headerOffset + 8 -and $bytes[$nameEnd] -ne 0) { $nameEnd++ }
        $virtualSize = [System.BitConverter]::ToInt32($bytes, $headerOffset + 8)
        $rawSize = [System.BitConverter]::ToInt32($bytes, $headerOffset + 16)
        $rawPointer = [System.BitConverter]::ToInt32($bytes, $headerOffset + 20)
        $sections[$i + 1] = [pscustomobject]@{
            Name       = [System.Text.Encoding]::ASCII.GetString($bytes, $headerOffset, $nameEnd - $headerOffset)
            Size       = $(if ($rawSize -gt 0) { $rawSize } else { $virtualSize })
            RawPointer = $rawPointer
        }
    }

    $stringTableOffset = $symbolTableOffset + ($symbolCount * 18)

    $index = 0
    while ($index -lt $symbolCount) {
        $entryOffset = $symbolTableOffset + ($index * 18)
        if ($entryOffset + 18 -gt $bytes.Length) { return $null }

        $value = [System.BitConverter]::ToInt32($bytes, $entryOffset + 8)
        $sectionNumber = [System.BitConverter]::ToInt16($bytes, $entryOffset + 12)
        $type = [System.BitConverter]::ToUInt16($bytes, $entryOffset + 14)
        $storageClass = $bytes[$entryOffset + 16]
        $auxCount = [int]$bytes[$entryOffset + 17]
        $index += 1 + $auxCount

        if ($storageClass -ne 2 -or $type -ne 0x20) { continue }  # external function
        if (-not $sections.ContainsKey([int]$sectionNumber)) { continue }
        if ($bytes[$entryOffset] -eq 0 -and $bytes[$entryOffset + 1] -eq 0 -and
            $bytes[$entryOffset + 2] -eq 0 -and $bytes[$entryOffset + 3] -eq 0) {
            $nameOffset = [System.BitConverter]::ToInt32($bytes, $entryOffset + 4)
            $start = $stringTableOffset + $nameOffset
            if ($start -lt 0 -or $start -ge $bytes.Length) { continue }
            $end = $start
            while ($end -lt $bytes.Length -and $bytes[$end] -ne 0) { $end++ }
            $candidateName = [System.Text.Encoding]::ASCII.GetString($bytes, $start, $end - $start)
        } else {
            $end = $entryOffset
            while ($end -lt $entryOffset + 8 -and $bytes[$end] -ne 0) { $end++ }
            $candidateName = [System.Text.Encoding]::ASCII.GetString($bytes, $entryOffset, $end - $entryOffset)
        }

        if ($candidateName -cne $SymbolName) { continue }

        $section = $sections[[int]$sectionNumber]
        if ($section.RawPointer -le 0 -or $section.Size -le 0) { continue }
        if ($value -lt 0 -or $value -ge $section.Size) { continue }

        $count = [Math]::Min($Length, $section.Size - $value)
        if ($count -lt 8) { continue }

        $payload = New-Object byte[] $count
        [Array]::Copy($bytes, $section.RawPointer + $value, $payload, 0, $count)
        return [pscustomobject]@{ Name = $candidateName; Bytes = $payload }
    }

    return $null
}

function Test-BytePatternInFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][byte[]]$Pattern
    )

    if (-not (Test-Path -LiteralPath $Path)) { return -1 }

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt $Pattern.Length) { return 0 }

    $hits = 0
    $limit = $bytes.Length - $Pattern.Length
    for ($i = 0; $i -le $limit; $i++) {
        if ($bytes[$i] -ne $Pattern[0]) { continue }
        $matched = $true
        for ($j = 1; $j -lt $Pattern.Length; $j++) {
            if ($bytes[$i + $j] -ne $Pattern[$j]) { $matched = $false; break }
        }
        if ($matched) { $hits++ }
    }
    return $hits
}

function Get-CachedCMakeOption {
    param(
        [Parameter(Mandatory = $true)][string]$BuildDir,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $cachePath = Join-Path $BuildDir "CMakeCache.txt"
    if (-not (Test-Path -LiteralPath $cachePath)) { return $null }

    foreach ($line in Get-Content -LiteralPath $cachePath) {
        if ($line -like "$Name`:BOOL=*") {
            return ($line.Substring("$Name`:BOOL=".Length).Trim() -eq "ON")
        }
    }
    return $null
}

function Assert-SevenZipAsmSelection {
    param(
        [Parameter(Mandatory = $true)][string]$BuildDir,
        [Parameter(Mandatory = $true)][string]$BuildArch,
        [string[]]$ArtifactPaths,
        [string]$ExpectedSymbol = "LzmaDec_DecodeReal_3"
    )

    if ($BuildArch -ne "x64") {
        Write-Host "7-Zip asm check skipped: $BuildArch keeps the upstream C/intrinsics implementations." -ForegroundColor Yellow
        return
    }

    if ((Get-CachedCMakeOption -BuildDir $BuildDir -Name "SUP7Z_USE_X64_ASM") -eq $false) {
        Write-Host "7-Zip asm check skipped: $BuildDir was configured with SUP7Z_USE_X64_ASM=OFF." -ForegroundColor Yellow
        return
    }

    $asmObject = Join-Path $BuildDir "sunpack_7zip_asm_objects.dir\Release\LzmaDecOpt.obj"
    if (-not (Test-Path -LiteralPath $asmObject)) {
        throw ("7-Zip asm check failed: $asmObject does not exist, so the x64 build did not " +
               "assemble LzmaDecOpt.asm. Configure with -DSUP7Z_USE_X64_ASM=OFF to build " +
               "without the assembly hot paths on purpose.")
    }

    $symbol = Get-CoffSymbol -ObjectPath $asmObject -SymbolName $ExpectedSymbol
    if ($null -eq $symbol) {
        throw ("7-Zip asm check failed: $asmObject does not define the external function " +
               "$ExpectedSymbol, so the MASM object cannot be the source of that symbol.")
    }

    $targets = @(
        (Join-Path $BuildDir "Release\sunpack_sevenzip.dll"),
        (Join-Path $BuildDir "Release\sunpack_sevenzip_worker.exe")
    )
    if ($ArtifactPaths) { $targets += $ArtifactPaths }

    foreach ($target in $targets) {
        if (-not (Test-Path -LiteralPath $target)) {
            throw "7-Zip asm check failed: expected binary $target does not exist."
        }
        $hits = Test-BytePatternInFile -Path $target -Pattern $symbol.Bytes
        if ($hits -lt 1) {
            throw ("7-Zip asm check failed: $ExpectedSymbol from LzmaDecOpt.asm is not present " +
                   "in $target. That binary fell back to the C LZMA decoder.")
        }
        Write-Host ("7-Zip asm check passed: $ExpectedSymbol present in " +
                    "$(Split-Path $target -Leaf) ($hits match(es), " +
                    "$($symbol.Bytes.Length) byte prologue).") -ForegroundColor Green
    }
}
