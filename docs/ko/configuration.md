# 설정 가이드

[简体中文](../zh-CN/configuration.md) | [English](../configuration.md) | [繁體中文](../zh-TW/configuration.md) | [日本語](../ja/configuration.md) | **한국어**

일반 설정은 `sunpack_config.json`에서 변경합니다. 개발 빌드에서는 프로젝트 루트, 설치 버전에서는 `%ProgramData%\SunPack`에 있습니다. `sunpack_advanced_config.json`은 나머지 기본값을 제공하며, 같은 항목이 있으면 일반 설정이 우선합니다. 환경 변수 `SUNPACK_CONFIG_OVERRIDES`는 마지막에 적용합니다. 객체는 필드별로, `filesystem.scan_filters`는 `name`별로 병합합니다. 다른 배열은 전체를 대체합니다. Watch는 설정 변경을 자동으로 다시 읽습니다.

```powershell
sunpack.exe config validate
sunpack.exe config show
```

## 자주 쓰는 설정

| 설정 | 값 |
| --- | --- |
| `cli.language` | `zh` 중국어 간체, `en` 영어, `zh-TW` 중국어 번체, `ja` 일본어, `ko` 한국어. 인식할 수 없는 값은 영어를 사용합니다. |
| `recursive_extract` | `"*"`는 중첩 대상이 있는 동안 계속, 양의 정수는 처리 단계 수를 지정, `"?"`는 각 단계 뒤에 계속할지 확인. |
| `recursive_authorization.enabled` | `true`로 중첩 압축 파일 선택 정책을 사용합니다. |
| `post_extract.archive_cleanup_mode` | 완전히 성공한 원본을 `"r"`은 휴지통으로 이동, `"k"`는 유지, `"d"`는 삭제합니다. |
| `post_extract.flatten_single_directory` | `true`이면 최상위 폴더가 하나일 때 그 내용을 한 단계 위로 옮깁니다. |
| `post_extract.flatten_directory_name` | 구조를 단순화한 출력 폴더에 외부 이름 `"outer"`(기본값) 또는 내부 이름 `"inner"`를 사용합니다. |
| `passwords.clipboard_passwords_enabled` | 기본값은 `true`입니다. 현재 클립보드를 CLI 암호 후보에 포함합니다. |
| `watch.clipboard_monitor_enabled` | 기본값은 `true`입니다. Watch가 클립보드 기록을 저장합니다. |
| `watch.clipboard_builtin_max_entries` | 클립보드 기록 개수로, 기본값 30, 최솟값 1입니다. |
| `watch.toast_report_retention_days` | 실패 보고서 보관 일수로, 기본값 30일, 최솟값 1일입니다. |
| `watch.event_log_retention_days` | CLI와 Watch가 공유하는 작업 내역과 이벤트의 보관 일수입니다. |
| `watch.deduplication` | `"none"`, `"file_id"`, `"hash"` 중 하나를 지정합니다. |
| `watch.deduplication_scope` | `"root"`(기본값) 또는 `"global"`을 지정합니다. |
| `extraction.content_requirement` | `"complete"`는 완전한 결과만 허용하며 기본값입니다. `"allow_partial"`은 부분 결과도 보관합니다. |

GUI 설정 화면에서도 언어를 선택할 수 있습니다. 다음 예는 한국어를 선택하고 원본 압축 파일을 유지합니다.

```json
{
  "cli": {
    "language": "ko"
  },
  "post_extract": {
    "archive_cleanup_mode": "k"
  }
}
```

입력 폴더는 기본적으로 현재 깊이만 검색합니다. 하위 폴더 검색은 `-R`, 중첩 압축 해제는 `-r`로 제어합니다. `-r`, `-c`, `-o` 등으로 한 번의 실행에 적용할 동작을 지정할 수 있습니다. [CLI 옵션 설명](cli_parameters.md)을 참고하세요.

## 압축 해제 결과와 부분 성공

worker가 디코딩과 출력 쓰기, 닫기를 마친 뒤 보고하는 최종 결과를 사용합니다. 정상적인 빈 압축 파일과 폴더만 포함된 압축 파일도 완전히 성공할 수 있습니다. 컨테이너 구조 경고만으로 원본을 다시 읽거나 출력 CRC를 재검사하지 않습니다. 성공은 worker에 전달된 논리 입력과 처리한 항목을 기준으로 합니다.

`"allow_partial"`에서는 손상 또는 분할 볼륨 누락이 있더라도 worker의 최종 보고에 완료된 파일이 하나 이상 있으면 보관합니다. 0바이트 파일도 포함합니다. 완료되지 않았거나 보고되지 않은 파일은 포함하지 않습니다. 암호, 프로세스 및 출력 I/O 문제는 계속 실패로 처리합니다. 완전히 성공한 입력만 원본 정리를 승인하며, 한 물리 파일에 여러 압축 데이터가 있을 때는 공유 원본을 보호합니다. CLI, Watch 및 중첩 압축 해제는 같은 체크포인트와 복구 경로를 사용합니다.

업그레이드 시 이전 `verification` 설정을 제거합니다. 부분 결과 보관은 `extraction.content_requirement`에서 설정합니다.

## 검색 필터

`filesystem.scan_filters_enabled=false`로 모든 검색 필터를 끕니다. 특정 필터를 바꾸려면 `filesystem.scan_filters`에 해당하는 `name`을 지정합니다. `blacklist`, `whitelist`, `size_range`, `mtime_range`를 사용할 수 있습니다. 확장자 필터로 인해 확장자가 위장된 압축 파일이 검색에서 빠질 수 있습니다.

```json
{
  "filesystem": {
    "scan_filters": [
      { "name": "size_range", "enabled": true, "min_bytes": 1, "max_bytes": null },
      { "name": "mtime_range", "enabled": true, "start_utc": "2024-01-01T00:00Z", "end_utc": "2027-01-01T00:00Z" }
    ]
  }
}
```

GUI는 Windows 로컬 시간대로 시간을 입력받아 UTC로 저장합니다. 크기 단위의 소수는 바이트 단위로 반올림합니다. 비교식, 이전 필드 별칭, 초 또는 소수 초를 포함한 타임스탬프는 사용할 수 없습니다.

차단 목록과 허용 목록의 레코드에서 `paths`는 폴더, `files`는 확장자가 없는 파일 이름, `extensions`는 확장자, `full_names`는 전체 파일 이름과 일치합니다.

```json
{
  "name": "blacklist",
  "enabled": true,
  "paths": [{ "value": ".git", "regex": false }],
  "files": [{ "value": "보고서*", "regex": false }],
  "extensions": [{ "value": "zip", "regex": false }],
  "full_names": [{ "value": "\\.(?:tmp|log|bak)\\z", "regex": true }]
}
```

- `regex=false`일 때 `*`는 임의의 문자열, `?`는 유니코드 문자 하나에 일치하며 나머지는 문자 그대로 비교합니다. `*`는 경로 구분자 `/`를 넘지 않으며, 여러 개를 이어도 재귀 일치를 의미하지 않습니다.
- `regex=true`이면 Rust regex 문법으로 검색합니다. 전후방 탐색 및 역참조는 지원하지 않습니다. 모든 필드는 기본적으로 대소문자를 구분하며 정규식 인라인 플래그는 적용됩니다.
- 마지막 점을 기준으로 이름을 나눕니다. `bundle.part01.rar.jpg`의 이름은 `bundle.part01.rar`, 확장자는 `jpg`입니다. 점이 없으면 확장자가 없고, 끝의 점은 빈 확장자를 의미합니다. `.zip`의 이름은 비어 있고 확장자는 `zip`입니다.
- `paths`는 파일 이름을 제외한 폴더만 비교합니다. 구분자가 없는 일반 패턴은 모든 깊이에서 폴더 구성 요소에, 구분자가 있는 패턴은 검색 루트의 상대 경로에 적용합니다. 정규식은 `/`로 나눈 상대 경로에 적용합니다. `\Adownloads\z`는 루트 아래 `downloads`와 그 하위 트리를 선택합니다. 검색 루트 자체는 제외하지 않으며 허용 목록은 일치할 수 있는 하위 폴더로 이어지는 경로를 남깁니다.
- 같은 목록의 항목은 OR로 결합합니다. 차단 목록은 일치하는 필드가 있으면 제외하며, 허용 목록은 비어 있지 않은 모든 필드를 만족해야 합니다. 빈 목록은 제약하지 않습니다.
- GUI에서는 정규식 체크 상자를 선택하고 Enter로 확정합니다. 파란 태그는 정규식이며 클릭하여 편집할 수 있습니다. 검증에 실패하면 초안을 유지하고 디스크에 저장하지 않습니다. GUI에는 역슬래시를 하나만 입력하면 저장 시 JSON 이스케이프가 적용됩니다.

## Watch 및 암호

감시 루트는 `sunpack_watch_roots.txt`에 저장하며 GUI 또는 `watch add/remove`로 관리합니다. `watch enable/disable`로 감시를 시작하거나 일시 중지합니다. 시작이나 다시 로드할 때 NTFS/ReFS가 아닌 것으로 확인된 경로를 감시 목록에서 제거하고 설정 언어를 사용해 Windows 오류 창으로 알립니다. 나머지 폴더의 감시는 계속되고 실제 폴더와 파일은 그대로 남습니다. 일시적으로 오프라인인 경로도 유지합니다.

```powershell
sunpack.exe watch add C:\Downloads -o E:\Output -R
sunpack.exe watch list
```

`-o`를 생략하면 원본 옆에 풉니다. `-R`은 감시 루트별로 저장합니다. GZIP, BZIP2, XZ, Zstandard, LZ4는 먼저 바깥 스트림을 풀고 결과로 생성된 TAR를 일반 재귀 경로에서 처리합니다. 일반 TAR 분석은 오프셋 0부터 시작하고, 그 외 오프셋의 후보는 Embedded 검색에서 찾습니다.

암호는 `builtin_passwords.json`에 저장합니다. `enabled`는 불리언 값입니다. `scopes`에 지정한 절대 경로 및 그 하위 폴더에 적용되며, 생략하면 전역 암호입니다. `clipboard_history`는 문자열 배열입니다.

```json
{
  "passwords": [
    { "value": "전역 암호", "enabled": true },
    { "value": "폴더 암호", "enabled": true, "scopes": ["D:/Downloads", "E:/Archives"] }
  ],
  "clipboard_history": []
}
```

현재 클립보드를 CLI 암호로 사용하는 기능과 Watch 클립보드 기록 수집은 독립 설정입니다. 둘 다 꺼도 기존 기록은 남습니다. 기록은 평문으로 저장됩니다.

## Watch 중복 제거

제공되는 일반 설정의 기본값은 `file_id`, 고급 설정 및 별도 설정이 없을 때의 기본값은 `none`입니다. `file_id`는 파일 ID(하드 링크)를 비교합니다. `hash`는 크기가 같은 대상을 스트리밍 XXH3-128로 비교합니다. 압축 파일로 판명되고 논리 구조가 확정된 입력만 인덱스에 넣습니다. 볼륨 순서와 내장 영역은 구별하며, 풀린 내용이나 CLI 해제에는 영향을 주지 않습니다.

중복을 건너뛰어도 원본을 삭제하지 않고 기존 입력을 계속 재시도할 수 있습니다. GUI에는 중복으로 건너뛴 항목으로 표시합니다. `global`은 다른 감시 루트와 볼륨도 비교합니다. 파일 ID는 볼륨 ID와 함께 비교합니다. 중첩 루트에서 같은 입력 경로를 발견해도 하나로 취급합니다. 모드 또는 범위를 바꾸면 인덱스를 다시 구축합니다. 설정을 바꾸지 않고 재시작할 때는 저장된 인덱스를 검사하고 재사용합니다.

## 자동 설정과 업그레이드

검색 과정에서 실행 계획을 한 번 생성합니다. 심층 검사는 각 단계에서 Embedded를 사용하며, 일반 모드와 같은 암호 및 볼륨 확인 경로를 재사용합니다. 공유 캐시는 64 MiB, worker의 작업당 버퍼 예산은 32 MiB, 대기열 용량은 4096입니다. 디스크 여유 공간 부족 시 중지·복구와 유휴 캐시 정리는 자동입니다. `watch.runtime_cache_cleanup_idle_seconds`의 기본값은 10초이며 이벤트와 기한에 따라 동작합니다. 실패 보고서는 `watch.toast_report_retention_days`만큼 보관하고 새 보고서 생성 시 만료된 보고서와 남은 임시 파일을 정리합니다. 상태 경로는 쓰기 가능한 데이터 폴더의 `.sunpack_watch`입니다.

설치 프로그램과 `scripts/upgrade_config.ps1`에서 설정을 이전합니다. 식별할 수 있는 1.2.6 이상 설치 버전은 기존 일반 설정, 감시 루트, 암호 및 클립보드 기록을 보존합니다. 루트의 `initial_scanned`를 유지하고 새 항목에 기본값을 채워 넣고 이전 항목을 제거합니다. 고급 설정 파일은 새 템플릿으로 교체합니다. 필터는 이름으로 일치시키며 사용자가 생략한 모듈은 복원하지 않습니다. 릴리스 v1.3.0–v1.3.4의 이전 필터를 변환하고 v1.3.5 형식은 보존합니다.

복구 작업, 인덱스, 이벤트 내역, 캐시, 실패 보고서 등은 업그레이드 시 초기화합니다. 1.2.6보다 이전 버전은 새로 설치하는 방식으로 처리합니다. 기존 데이터가 있으나 설치 버전을 식별할 수 없거나 설정이 손상되어 있으면 프로그램 파일을 바꾸기 전에 업그레이드를 중단합니다.
