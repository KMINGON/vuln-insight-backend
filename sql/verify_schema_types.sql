-- 각 테이블 컬럼과 데이터 타입이 스키마 정의와 일치하는지 확인하는 스크립트
-- information_schema.columns를 조회하여 테이블/컬럼/데이터 타입/nullable 정보를 출력한다.

SELECT
    table_schema,
    table_name,
    column_name,
    data_type,
    udt_name,
    is_nullable,
    character_maximum_length,
    numeric_precision,
    datetime_precision
FROM information_schema.columns
WHERE table_schema = 'public'
  AND table_name IN (
      'cve', 'cpe_dictionary', 'cpe_match', 'cwe',
      'cve_core', 'cve_description', 'cve_reference', 'cve_metric', 'cve_weakness', 'cve_cpe_match',
      'cpe', 'cpe_title', 'cpe_ref', 'cpe_deprecation_map',
      'cpe_match_string', 'cpe_match_name'
  )
ORDER BY table_name, ordinal_position;

-- TIMESTAMPTZ 컬럼이 text로 저장되지 않았는지 확인
SELECT
    table_name,
    column_name,
    data_type
FROM information_schema.columns
WHERE table_schema = 'public'
  AND table_name IN ('cve', 'cpe_dictionary', 'cpe_match', 'cve_core', 'cpe', 'cpe_match_string')
  AND (
        column_name ILIKE '%published%'
        OR column_name ILIKE '%modified%'
        OR column_name ILIKE '%created%'
    );

-- psql -h localhost -U nvduser -d nvddb -f sql/verify_schema_types.sql