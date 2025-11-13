BEGIN;

-- 2단계 정규화 테이블부터 삭제 (FK 의존성 때문에 자식 → 부모 순서 또는 CASCADE)
DROP TABLE IF EXISTS
    cve_description,
    cve_reference,
    cve_metric,
    cve_weakness,
    cve_cpe_match,
    cpe_title,
    cpe_ref,
    cpe_deprecation_map,
    cpe_match_name,
    cpe_match_string,
    cve_core,
    cpe,
    cwe_core
CASCADE;

-- 1단계 landing 테이블 삭제
DROP TABLE IF EXISTS
    cve,
    cpe_dictionary,
    cpe_match,
    cwe
CASCADE;

COMMIT;
