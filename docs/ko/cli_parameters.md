# CLI 옵션 설명

[简体中文](../zh-CN/cli_parameters.md) | [English](../cli_parameters.md) | [繁體中文](../zh-TW/cli_parameters.md) | [日本語](../ja/cli_parameters.md) | **한국어**

```powershell
sunpack.exe <command> [options] [paths...]
```

| 명령 | 기능 |
| --- | --- |
| `extract`, `e` | 검색, 식별, 압축 해제, 검증, 후처리 및 정리 |
| `scan`, `s` | 읽기 전용 압축 파일 검색 및 암호 확인 |
| `watch`, `w` | 폴더 감시 및 쓰기가 안정된 파일의 자동 처리 |
| `daemon`, `d` | 백그라운드 프로세스와 로그인 시 시작 관리 |
| `passwords`, `pw` | 암호 후보 출처 요약 |
| `config`, `cfg` | 병합된 유효 설정의 표시 및 검사 |
| `doctor`, `doc` | 설정과 실행 환경의 읽기 전용 진단 |
| `version`, `ver` | 설치된 버전 표시 |

옵션은 아래에 나오는 짧은 형식으로 입력합니다. 값이 있는 옵션은 `-r 3`처럼 공백으로 구분합니다. `-p PASSWORD`에서 다음 인수는 `-`로 시작해도 원문 그대로 암호로 읽습니다. 암호를 옵션에 붙이거나 등호로 연결할 수 없습니다.

## 공통 옵션

| 옵션 | 설명 |
| --- | --- |
| `-R` | 입력 아래의 하위 폴더까지 검색합니다. 중첩 압축 해제용 `-r`과는 독립적입니다. |
| `-j` | 결과를 JSON으로 출력합니다. 별칭을 사용해도 JSON의 `command`는 원래 명령 이름입니다. |
| `-v` | 검색과 진단 세부 정보를 추가합니다. |
| `-pa` | 종료 전에 키 입력을 기다립니다. |
| `-npa` | 종료할 때 키 입력을 기다리지 않습니다. |

`extract`와 `scan`은 일반 메시지를 표준 출력에, 오류를 표준 오류에 기록합니다. `-j`를 사용하면 텍스트 메시지 대신 `command`, `inputs`, `summary`, `errors`, `items`, `tasks`, `logs` 필드가 있는 JSON을 출력합니다. 일부 경로를 읽을 수 없어도 나머지 입력은 계속 처리합니다.

압축 해제 실패는 `failed_count`, 잘못된 입력은 `input_error_count`, 파일 시스템 검색 오류는 `scan_error_count`에 집계됩니다. 검색 진단의 세부 항목은 보고서당 최대 100개, 디렉터리당 최대 20개이며, 초과분은 개수만 집계합니다. 이 한도는 압축 파일 처리 결과와 별개입니다. `extract -j`는 처리 또는 입력 실패를 `tasks[].failures`에, `scan -j`는 논리적 압축 파일 오류를 `items[].error`와 `items[].error_kind`에 보고합니다. 보존된 복구 출력은 `summary.recovered_outputs`에 나옵니다.

포그라운드 `extract`와 `scan`은 높은 프로세스 우선순위로 동작합니다. 마지막 포그라운드 요청이 끝난 뒤 Watch가 동작 중이면 유휴 기한까지 우선순위를 유지하며, 그렇지 않으면 즉시 `runtime.process_mode`로 돌아갑니다.

## extract

```powershell
sunpack.exe extract [options] <paths...>
sunpack.exe extract D:\A.7z -p 123456 -p secret
sunpack.exe extract D:\Archives -o E:\Unpacked -P .\passwords.txt -c k
sunpack.exe extract D:\Nested -r "*" -nf
sunpack.exe extract -d D:\MaybeArchive.bin
```

| 옵션 | 설명 |
| --- | --- |
| `-p PASSWORD` | 압축 해제 암호를 지정합니다. 여러 번 지정할 수 있습니다. |
| `-P PASSWORD_FILE` | 한 줄에 하나씩 저장된 암호를 텍스트 파일에서 읽습니다. |
| `-a` | 터미널에서 대화형으로 암호를 입력합니다. 빈 줄에서 입력을 마칩니다. |
| `-d` | 전체 파일에 대한 Embedded 검색만 사용합니다. 첫 단계는 파일 시스템 필터 없이 모든 입력을 검사합니다. 중첩 단계에는 필터와 `embedded_scan.recursive_candidate_ratio`, 재귀 깊이 및 승인 설정을 적용합니다. |
| `-r VALUE` | 중첩 압축 해제 설정을 재정의합니다. 양의 정수는 단계 수, `*`는 대상이 있는 동안 계속, `?`는 각 단계 뒤 사용자 확인을 의미합니다. |
| `-c VALUE` | 완전히 성공한 원본의 처리 방식입니다. `d`는 삭제, `r`은 휴지통, `k`는 유지입니다. |
| `-o OUTPUT_DIR` | 출력 루트를 지정합니다. 상대 경로는 명령의 현재 작업 폴더를 기준으로 해석합니다. |
| `-f` / `-nf` | 최상위 폴더가 하나일 때 그 안의 내용을 한 단계 위로 옮기는 처리를 켜거나 끕니다. |

기본 출력은 원본 파일 옆에 생성합니다. `-o`를 지정하면 「출력 루트 / 공통 입력 루트에서 계산한 상대 경로 / 압축 파일 이름」을 사용합니다. 출력 루트 안에 생성된 중첩 압축 파일은 자신의 위치를 기준으로 처리됩니다. 내장 구간과 중첩 압축 파일은 작업 트리에서 각각 진행률·상태·오류를 가집니다. 출력을 리디렉션하면 루트 작업이 끝난 뒤 전체 트리를 기록합니다.

| 종료 코드 | 의미 |
| --- | --- |
| `0` | 모든 작업이 완전히 성공했습니다. |
| `1` | 실패한 작업이 있습니다. |
| `2` | 인수, 경로 또는 설정이 잘못되었습니다. |
| `3` | 런타임 오류가 발생했습니다. |
| `4` | 실패한 작업은 없지만 일부 작업이 부분적으로만 성공했습니다. |

## scan

```powershell
sunpack.exe scan [options] <paths...>
sunpack.exe scan D:\Downloads -R -v -d -j
```

`extract`와 같은 검색·계획·암호 확인 경로를 사용합니다. 물리 파일과 논리 압축 파일별로 확인한 형식, 바이트 범위, 볼륨, 암호 및 오류를 표시합니다. 내장 범위는 `[시작, 끝)`이며 끝을 알 수 없으면 `?`를 표시합니다. 분할 볼륨 조합이 미확정이면 조합을 펼치지 않고 `pending`, 누락이 확인되면 `missing`을 표시합니다.

암호 확인으로 압축 파일의 전체 내용이나 분할 볼륨 세트의 무결성이 보장되지는 않습니다. 압축 해제, 출력 폴더 생성, 중첩 처리 및 원본 정리는 수행하지 않습니다. `-d`는 일반 Relations/Detection과 파일 시스템 필터를 건너뛰고 Embedded 검색으로 기준 볼륨을 찾습니다. 이후 기존 암호·분할 볼륨 확인 경로를 재사용합니다. 심층 검사 설정은 요청별로 독립적입니다.

## watch

```powershell
sunpack.exe watch <add|remove|list|enable|disable|reload|relog|status> [options]
sunpack.exe watch add D:\Downloads -o E:\Output -R -d
sunpack.exe watch list
sunpack.exe daemon start
```

감시 폴더는 데이터 디렉터리의 `sunpack_watch_roots.txt`에 저장합니다. 열 순서는 `입력 폴더 | 출력 루트 | deep_detect | initial_scanned | recursive | enabled`입니다.

```text
C:\Downloads | | false | false | false | true
E:\Archives | E:\Output | false | false | false | true
F:\Incoming | . | true | false | true | true
G:\Incoming | | true | false | false | false
```

출력 열이 비어 있으면 압축 파일 옆에 풉니다. 상대 출력 경로는 해당 입력 폴더를 기준으로 하며 절대 경로로 저장됩니다. 감시 입력은 읽을 수 있는 USN 저널이 있는 NTFS 또는 ReFS 볼륨이어야 합니다. `deep_detect`와 `recursive`의 기본값은 `false`입니다. 심층 검사를 켠 입력 루트에서는 파일 시스템 검색 필터를 건너뛰며, 중첩 압축 해제·암호 재시도·복구에서도 해당 루트의 설정을 적용합니다.

`initial_scanned`가 비어 있거나 `false`이면 첫 검색에서 후보를 대기열에 넣은 뒤 `true`로 갱신합니다. 입력 경로를 바꾸면 초기화되며 출력 위치나 심층 검사만 바꿀 때는 유지됩니다. 검색을 마친 경로에서 프로그램이 중단된 동안 발생한 변경은 USN으로 복구합니다. `enabled=false`는 해당 폴더의 감시를 중지합니다.

| 하위 명령 | 기능 |
| --- | --- |
| `add PATH...` | 감시 루트를 추가합니다. `-o DIR`는 입력 하나에만 사용할 수 있습니다. `-R`은 재귀 검색, `-d`는 기존 루트를 포함해 심층 검사를 켭니다. |
| `remove PATH...`, `rm` | 입력 경로로 감시 루트를 제거합니다. |
| `list`, `ls` | 저장된 루트를 나열합니다. |
| `enable`, `ea` | 감시를 다시 시작합니다. |
| `disable`, `da` | 백그라운드 프로세스와 알림 영역 아이콘은 유지하면서 감시를 일시 중지하고 상태를 저장합니다. |
| `reload`, `rl` | 설정과 감시 루트를 다시 읽습니다. |
| `relog`, `rlg` | 로그를 다시 구성합니다. |
| `status`, `st` | 감시 상태를 표시합니다. JSON에는 대기 건수, 마지막 오류 및 루트도 포함됩니다. |

등록된 루트의 출력 위치를 바꾸려면 루트를 제거한 뒤 다시 추가합니다. 여러 입력이 같은 출력 루트를 사용할 수 있습니다. 출력 루트끼리 상위·하위 폴더 관계가 되는 것은 지원하지 않습니다. 기존 루트를 추가할 때 `-d`를 생략하면 기존 값을 유지합니다. 심층 검사를 끄려면 세 번째 열을 `false`로 바꾸거나 비웁니다. 감시 일시 중지 중에 발생한 변경은 감시를 다시 켜도 작업으로 등록되지 않습니다. 감시가 켜진 상태에서 프로세스를 종료하고 다시 실행하면 중단 기간의 변경을 복구합니다.

쓰기, 이동, 수정은 후보 확인을 시작합니다. 새 후보에는 고정 지연이 없으며, 후속 변경은 실제 쓰기 간격을 바탕으로 안정화 대기 시간을 조정합니다. 새 분할 볼륨이 들어오거나 암호 후보가 달라지면 해당 작업을 다시 시도합니다. Watch는 파이프라인이 만든 출력 하위 트리를 제외하므로 이후에 그 안에 넣은 파일도 무시합니다.

## daemon(별칭 d)

```powershell
sunpack.exe daemon <start|stop|startup>
sunpack.exe daemon startup <enable|disable|status>
```

`start`는 저장된 감시 상태를 복원합니다. `start -nt`는 이번 시작에서 알림 영역 아이콘을 끕니다. `stop`은 프로세스 종료를 기다리며 감시 설정은 그대로 두고, `-j`와 `-h`를 받습니다. `startup`은 현재 사용자의 로그인 시 실행을 관리합니다.

## passwords

```powershell
sunpack.exe passwords [-j]
sunpack.exe passwords -P .\passwords.txt -j
```

`-p`, `-P`, `-a`를 사용할 수 있습니다. 압축 파일 경로를 받지 않으므로 전역 암호 후보의 출처만 보여 줍니다. 압축 해제 시에는 유효한 최근 성공 암호, 범위가 지정된 JSON 암호, CLI 입력, 현재 클립보드, 전역 JSON 암호, 클립보드 기록 순으로 사용합니다. 중복을 제거하며 필요한 경우 빈 암호를 먼저 시도합니다.

## config

```powershell
sunpack.exe config [options] <show|validate>
sunpack.exe config validate -j
```

`show`는 유효 설정을 표시하고, `validate`는 JSON, 필드값, 검색 규칙 이름과 규칙 설정을 검사합니다. `-j`는 JSON 출력입니다. 자세한 내용은 [설정 가이드](configuration.md)를 참고하세요.

## doctor

```powershell
sunpack.exe doctor [-j]
sunpack.exe doc [-j]
```

설정, 네이티브 구성 요소, worker, Windows 알림 및 감시 루트를 읽기 전용으로 검사합니다. 존재하지 않는 감시 루트는 경고로 보고합니다. 실패 항목이 있으면 `1`, 성공·경고·건너뜀만 있으면 `0`으로 종료합니다.

## version

```powershell
sunpack.exe version
```

현재 실행 파일과 같은 폴더의 `VERSION.txt`를 읽어 `version=` 뒤의 버전을 출력합니다.

## Windows 마우스 오른쪽 버튼 메뉴

관리 화면의 설정 또는 다음 명령으로 현재 사용자의 탐색기 메뉴를 관리합니다. 종료 코드 `0`은 성공을 의미합니다. 개발 빌드에서는 `--app-root`와 `--cli`를 지정할 수 있습니다.

```powershell
.\SunPackGUI.exe --context-menu enable
.\SunPackGUI.exe --context-menu disable
```

폴더와 폴더 배경 메뉴에는 직접 압축 해제, 재귀 압축 해제, 암호 입력, 감시, 재귀 감시 및 감시 해제가 있습니다. 감시 메뉴는 `watch add`에 이어 `daemon start`를 실행하며 저장된 일시 중지 상태를 유지합니다. 파일 메뉴는 기본적으로 심층 검사를 사용합니다.

```text
extract "%1" -d -pa
extract "%1" -a -d -pa
```

같은 재귀 감시 루트에 속한 여러 하위 폴더에 분산된 볼륨은 함께 검사할 수 있습니다. 서로 독립적인 감시 루트의 볼륨은 결합하지 않습니다. Watch의 첫 출력은 감시 루트에 지정한 출력 경로에, CLI의 기본 출력은 원본(분할 압축의 경우 기준 볼륨) 옆에 생성됩니다.
