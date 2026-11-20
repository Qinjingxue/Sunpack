# 라이선스와 배포

[English](../licensing.md) | [繁體中文](../zh-TW/licensing.md) | [日本語](../ja/licensing.md) | **한국어**

이 문서는 SunPack 저장소의 라이선스 적용 범위와 배포할 때 보존해야 하는 자료를 설명합니다. 요약과 원문이 다른 경우 원문이 우선합니다.

## SunPack 자체 코드

SunPack용으로 작성한 소스 코드는 루트의 [MIT 라이선스](../../LICENSE)를 따릅니다. 함께 포함한 타사 코드에는 각 업스트림 프로젝트 및 [THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md)에 명시된 원래 라이선스가 적용됩니다.

## 포함된 7-Zip 26.05 소스

필요한 부분을 골라 로컬에서 수정한 7-Zip 26.05 소스는 기존 경로인 `sunpack/sevenzip_bridge/7z2604-src/`에 있습니다. 이 트리에는 업스트림 7-Zip 소스 라이선스가 적용됩니다. 원문은 [소스 트리의 License.txt](../../sunpack/sevenzip_bridge/7z2604-src/DOC/License.txt), 배포용 사본은 [licenses/7zip-source-license.txt](../../licenses/7zip-source-license.txt)에 있습니다.

| 파일 | 적용 조건 |
| --- | --- |
| `CPP/7zip/Compress/Rar*` | GNU LGPL 및 unRAR 라이선스 제한 |
| `CPP/7zip/Compress/LzfseDecoder.cpp` | BSD 3-Clause |
| `C/ZstdDec.c` | BSD 3-Clause |
| `C/Xxh64.c` | BSD 2-Clause |
| 퍼블릭 도메인이라고 명시된 파일 | 기존 상태 유지 |
| 나머지 7-Zip 소스 | GNU LGPL 2.1 이상 |

[GNU LGPL 2.1 전문](../../licenses/LGPL-2.1.txt)도 포함되어 있습니다. LGPL이 적용된 파일을 수정할 때는 업스트림 저작권과 라이선스 고지를 유지하고, 수정 사실과 수정 날짜를 표시합니다. unRAR 제한이 적용되는 압축 해제 소스에는 독점 RAR 압축 알고리즘을 재현하는 데 사용할 수 없다는 업스트림 제한을 유지합니다. 정확한 조건은 업스트림 라이선스 원문을 참고하세요.

SunPack 전용 통합 코드는 가능하면 `7z2604-src/` 트리 밖에 둡니다. 이렇게 하면 업스트림에서 온 코드의 범위를 추적하기 쉽고 버전 업데이트 시 병합 부담이 줄어듭니다.

## 포함된 zlib-ng 2.3.3과 개발 도구

ZIP Deflate 고속 처리의 소스는 `sunpack/sevenzip_bridge/zlib-ng-2.3.3/`에 있습니다. 업스트림 커밋 `12731092979c6d07f42da27da673a9f6c7b13586`에 고정되며 업스트림 zlib 라이선스를 따릅니다. 소스나 바이너리를 재배포할 때는 업스트림 저작권 및 허가 고지를 보존합니다. [배포용 라이선스 사본](../../licenses/zlib-ng-license.txt)을 참고하세요.

개발 환경 설정에서 내려받는 `7z.exe`, `7z.dll`, `7zCon.sfx`는 테스트 데이터 생성용입니다. [7-Zip 바이너리 배포 조건](../../licenses/7zip-license.txt)이 적용됩니다.

## 릴리스 패키지

`scripts/generate_license_bundle.ps1`로 생성한 `THIRD_PARTY_LICENSES.txt`를 설치합니다. SunPack의 MIT 라이선스, 타사 구성 요소 개요, 저장소의 `licenses/`, FreeType과 stb를 포함한 GUI 의존성 고지, 대상 Windows의 잠긴 Cargo 의존성에 대한 라이선스와 고지를 포함합니다. 빌드·테스트 의존성 고지도 포함될 수 있습니다. 적용 범위는 원래 고지를 따릅니다.

라이선스 원본은 저장소와 GUI 의존성 소스에 보관합니다. 설치 프로그램은 루트 MIT 라이선스를 표시하며 별도의 라이선스 소스 트리를 설치하지 않습니다. 필수 자료가 없으면 통합 파일을 생성하지 못합니다. 새 의존성을 추가할 때는 해당 라이선스 조건도 검토하세요.

LGPL 적용 7-Zip 코드를 컴파일하거나 링크한 릴리스는 실제 빌드에 사용한 정확한 소스 및 수령자가 해당 코드를 수정하고 결합된 결과를 다시 빌드·링크할 수 있어야 한다는 적용 조건을 충족해야 합니다. 배포 과정에서 관련 소스나 빌드 자료를 빼기 전에 라이선스를 검토하세요.

## 7-Zip 업데이트

1. 업스트림 라이선스 파일을 소스와 함께 가져옵니다.
2. 같은 버전의 원문으로 `licenses/7zip-source-license.txt`를 갱신합니다.
3. RAR, BSD 및 퍼블릭 도메인 예외를 포함해 업스트림 조건의 변경 사항을 확인합니다.
4. 경로, 버전 또는 조건이 바뀌면 타사 고지와 이 문서를 갱신합니다.
5. 통합 문서에 필수 라이선스와 저작자 표시가 모두 남는지 릴리스 패키지 테스트로 검증합니다.
