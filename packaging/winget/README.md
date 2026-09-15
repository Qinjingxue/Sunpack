# WinGet preparation

This directory is local staging for a future `Qinjingxue.SunPack` submission. It
is intentionally outside the `manifests/` root used by `microsoft/winget-pkgs`,
so a draft cannot be mistaken for a ready upstream submission.

No manifest is checked in for `v0.5.0`; that release is known to contain bugs
and must not be submitted.

After a fixed release has been published, prepare the three-file manifest with
the hashes from that exact release:

```powershell
.\scripts\prepare_winget_manifest.ps1 `
    -Version 0.8.0 `
    -X64Sha256 <64-hex-character-sha256> `
    -Arm64Sha256 <64-hex-character-sha256>
```

The command writes the manifest set under
`packaging/winget/manifests/q/Qinjingxue/SunPack/<version>/` and refuses to
overwrite an existing set unless `-Force` is supplied. It derives the stable
GitHub release URLs from the repository and tag, records the architecture-
specific Inno Setup Add/Remove Programs identity, and emits the required
Inno Setup silent-install switches:

```text
/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-
```

Before any upstream submission, run `winget validate --manifest` against the
generated manifest directory (WinGet validates the complete multi-file set):

```powershell
.\scripts\validate_winget_manifest.ps1 `
    -ManifestRoot .\packaging\winget\manifests\q\Qinjingxue\SunPack\<version>
```

Then install the same manifest in a clean Windows environment and run the
repository's installer smoke test against the exact release installer. Submit
only one package version and only the three manifest files to
`microsoft/winget-pkgs`.
