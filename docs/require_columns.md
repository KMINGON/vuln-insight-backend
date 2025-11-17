# Raw Data Required Columns

`docs/DataSechma.md` 에 정의된 스키마를 기준으로, 현재 파이프라인에서 분석 단계에 바로 활용할 필드만을 선별했다. 모든 경로는 원본 JSON/XML 구조 그대로 표기했으며, 배열 요소는 `[]` 로 표현한다.

## CVE (NVD Vulnerability Feed)

### Feed metadata
| 필드 경로 | 타입/출처 | 분석 활용 |
| --- | --- | --- |
| `resultsPerPage`, `startIndex`, `totalResults` | 정수, 피드 공통 | 다운로드 청크 크기/오프셋을 추적하고 누락 여부를 검증한다. |
| `format`, `version` | 문자열 | 피드 버전 차이 확인 및 역직렬화 스키마 결정. |
| `timestamp` | date-time | 수집 배치 기준 시각 로그 및 증분 적재 기준. |
| `vulnerabilities[]` | 배열 | 개별 CVE 데이터 컬렉션(아래 세부 필드 사용). |

### Vulnerability core
| 필드 경로 | 타입/출처 | 분석 활용 |
| --- | --- | --- |
| `cve.id` | 문자열 (CVE-ID 패턴) | 주요 키이자 모든 조인(CWE, CPE 등)의 기준. |
| `cve.sourceIdentifier` | 문자열 | CNA·발견 소스 추적 및 신뢰도 분류. |
| `cve.vulnStatus` | 문자열 | 분석/공개 상태에 따른 필터링. |
| `cve.published`, `cve.lastModified` | date-time | 타임라인 분석 및 증분 동기화. |
| `cve.evaluatorComment`, `cve.evaluatorSolution`, `cve.evaluatorImpact` | 문자열 | NVD 평가자 메모를 통해 임시 대응책·임팩트 설명 확보. |
| `cve.cisaExploitAdd`, `cve.cisaActionDue`, `cve.cisaRequiredAction`, `cve.cisaVulnerabilityName` | 문자열/날짜 | CISA KEV, 권고 기한 기반의 우선순위 도출. |
| `cve.cveTags[].sourceIdentifier`, `cve.cveTags[].tags[]` | 문자열 | 분쟁(disputed)·지원 종료 등 태그 기반 필터링. |
| `cve.descriptions[].{lang,value}` | 문자열 | 다국어 서술 및 요약 분석. |
| `cve.references[].{url,source,tags[]}` | 문자열/배열 | 증거 자료 링크, 참조 유형별 분류. |

### Severity metrics
| 필드 경로 | 타입/출처 | 분석 활용 |
| --- | --- | --- |
| `metrics.cvssMetricV40[]`, `metrics.cvssMetricV31[]`, `metrics.cvssMetricV30[]`, `metrics.cvssMetricV2[]` | 배열 | CVSS 버전별 여러 출처(Primary/Secondary) 점수를 모두 유지해 시간·버전별 비교. |
| `metrics.cvssMetricV*[].{source,type}` | 문자열 | 점수 제공자 및 기본/보조 여부 구분. |
| `metrics.cvssMetricV*[].cvssData` | 표준 CVSS 오브젝트 | `vectorString`, `baseScore`, `baseSeverity`, 공격 벡터/복잡도/권한/사용자 상호작용, 영향(Conf/Int/Avail) 등 전체 벡터를 유지해 재계산·평균화 가능. |
| `metrics.cvssMetricV*[].exploitabilityScore`, `metrics.cvssMetricV*[].impactScore` | 수치 | 영향도/악용 난이도 분리 통계. |
| V2 전용: `baseSeverity`, `acInsufInfo`, `obtainAllPrivilege`, `obtainUserPrivilege`, `obtainOtherPrivilege`, `userInteractionRequired` | 문자열/불리언 | 레거시 지표 지원 및 과거 취약점 추이 비교. |

### Weaknesses & configurations
| 필드 경로 | 타입/출처 | 분석 활용 |
| --- | --- | --- |
| `weaknesses[].{source,type}` | 문자열 | 어떤 소스가 어떤 약점 분류(CWE 타입)를 부여했는지 추적. |
| `weaknesses[].description[].{lang,value}` | 문자열 | 약점이 지칭하는 실제 CWE-ID 텍스트(CWE-79 등) 및 설명. |
| `configurations[].{operator,negate}` | 문자열/불리언 | AND/OR/Negate 로 구성된 적용 범위 루트 조건 파악. |
| `configurations[].nodes[].{operator,negate}` | 문자열/불리언 | 중첩 노드 논리 이해. |
| `configurations[].nodes[].cpeMatch[].{vulnerable,criteria,matchCriteriaId}` | 불리언/문자열 | CVE ↔ CPE 매핑의 핵심, 취약 대상 식별과 UUID 트래킹. |
| `configurations[].nodes[].cpeMatch[].versionStartIncluding/Excluding`, `versionEndIncluding/Excluding` | 문자열 | 버전 범위 파싱 및 영향 제품 계산. |

### Vendor & reviewer context
| 필드 경로 | 타입/출처 | 분석 활용 |
| --- | --- | --- |
| `vendorComments[].{organization,comment,lastModified}` | 문자열/date-time | 공급업체 공식 코멘트와 최신 수정 시각 추적. |

## CPE Match (Applicability Statements)

### Feed metadata
| 필드 경로 | 타입/출처 | 분석 활용 |
| --- | --- | --- |
| `resultsPerPage`, `startIndex`, `totalResults`, `format`, `version`, `timestamp` | 피드 공통 메타 | 증분 로딩·피드 일관성 검증. |
| `matchStrings[]` | 배열 | 개별 matchString 객체 컨테이너. |

### Match string detail
| 필드 경로 | 타입/출처 | 분석 활용 |
| --- | --- | --- |
| `matchString.{criteria,matchCriteriaId}` | 문자열/UUID | CPE URI 및 고유 매치 식별자. |
| `matchString.versionStartIncluding/Excluding`, `versionEndIncluding/Excluding` | 문자열 | 취약 버전 범위 계산. |
| `matchString.created`, `matchString.lastModified`, `matchString.cpeLastModified` | date-time | CPE 사전 업데이트/변경 이력 추적. |
| `matchString.status` | 문자열 | Active/Inactive 여부로 폐기 여부 판단. |
| `matchString.matches[].{cpeName,cpeNameId}` | 문자열/UUID | 실제 CPE Dictionary 항목과의 직접 매핑(조인 키). |

## CPE Dictionary (Product Catalog)

### Feed metadata
| 필드 경로 | 타입/출처 | 분석 활용 |
| --- | --- | --- |
| `resultsPerPage`, `startIndex`, `totalResults`, `format`, `version`, `timestamp` | 피드 공통 메타 | 전체 사전 증분 수집 관리. |
| `products[]` | 배열 | 개별 CPE 레코드 컨테이너. |

### CPE record detail
| 필드 경로 | 타입/출처 | 분석 활용 |
| --- | --- | --- |
| `cpe.{cpeName,cpeNameId}` | 문자열/UUID | 표준화된 CPE URI와 내부 키, CVE/CPEMatch 조인에 필요. |
| `cpe.deprecated` | 불리언 | 사용 중단 여부로 최신/레거시 제품 구분. |
| `cpe.created`, `cpe.lastModified` | date-time | 제품 정의 변경 이력 관리. |
| `cpe.titles[].{title,lang}` | 문자열 | 사람이 읽는 제품명, 다국어 지원. |
| `cpe.refs[].{ref,type}` | 문자열 | 공급업체/제품/버전/Advisory 링크 메타데이터. |
| `cpe.deprecatedBy[]` | 객체 배열 | 대체 CPE 로의 마이그레이션 경로 추적. |
| `cpe.deprecates[]` | 객체 배열 | 해당 CPE가 폐기시키는 이전 항목 파악. |

## CWE (Weakness Catalog)

### Catalog metadata
| 필드 경로 | 타입/출처 | 분석 활용 |
| --- | --- | --- |
| `Weakness_Catalog.@Name`, `@Version`, `@Date` | 문자열/date | 소스 릴리스 버전, 스냅샷 날짜 기록. |
| `Weakness_Catalog.External_References.External_Reference[]` | 객체 배열 | 외부 분류 체계, 재사용 가능한 Reference_ID 추적. |

### Weakness core
| 필드 경로 | 타입/출처 | 분석 활용 |
| --- | --- | --- |
| `Weaknesses.Weakness.@{ID,Name,Abstraction,Structure,Status,Diagram}` | 속성 | CVE 약점 매핑의 키(CWE ID)와 메타 정보. |
| `Weaknesses.Weakness.Description` | 문자열 | 핵심 약점 요약. |
| `Weaknesses.Weakness.Extended_Description` | 구조화 텍스트 | 상세 원인·맥락 설명. |
| `Weaknesses.Weakness.Related_Weaknesses` | 관계 목록 | 파생·상위/하위 CWE 네트워크 분석. |
| `Weaknesses.Weakness.Weakness_Ordinalities` | 열거 | 시스템 수명주기 위치(설계/구현 등)별 통계. |
| `Weaknesses.Weakness.Applicable_Platforms` | 목록 | 언어/플랫폼 조건 분석. |
| `Weaknesses.Weakness.Background_Details` | 텍스트 | 역사적 배경·발생 원인을 위한 참고. |
| `Weaknesses.Weakness.Alternate_Terms` | 목록 | 검색 시 동의어 매칭. |
| `Weaknesses.Weakness.Modes_Of_Introduction` | 목록 | 도입 단계(요구, 설계 등)별 원인 분석. |
| `Weaknesses.Weakness.Exploitation_Factors` | 목록 | 악용 난이도에 영향을 미치는 요소 파악. |
| `Weaknesses.Weakness.Likelihood_Of_Exploit` | 열거 | 취약점 발생 가능성 평가. |
| `Weaknesses.Weakness.Common_Consequences` | 목록 | CIA 임팩트 매핑. |
| `Weaknesses.Weakness.Detection_Methods` | 목록 | 탐지 커버리지 설계. |
| `Weaknesses.Weakness.Potential_Mitigations` | 목록 | 대응 방안 카탈로그화. |
| `Weaknesses.Weakness.Demonstrative_Examples`, `Observed_Examples` | 목록 | 실 사례/코드 예시, 교육·테스트 데이터로 사용. |
| `Weaknesses.Weakness.Functional_Areas`, `Affected_Resources` | 목록 | 영향을 받는 기능 영역/자원 분류. |
| `Weaknesses.Weakness.Taxonomy_Mappings` | 객체 배열 | CAPEC, OWASP 등 외부 분류 매핑. |
| `Weaknesses.Weakness.Related_Attack_Patterns` | 목록 | CAPEC 연계 분석. |
| `Weaknesses.Weakness.References` | 목록 | 원문/논문 링크 제공. |
| `Weaknesses.Weakness.Mapping_Notes`, `Notes` | 구조화 텍스트 | 맞춤형 매핑 시 참고 메모 보존. |
| `Weaknesses.Weakness.Content_History` | 객체 | CWE 항목 생성/수정 이력 관리. |

위 필드만 유지하면 CVE ↔ CWE ↔ CPE 간 연결, 심각도/영향 분석, 제품·버전별 영향 범위 산출을 모두 수행할 수 있다.
