-- 기본 행 수 확인
SELECT 'cve' AS table, COUNT(*) AS rows FROM cve
UNION ALL
SELECT 'cpe_dictionary', COUNT(*) FROM cpe_dictionary
UNION ALL
SELECT 'cpe_match', COUNT(*) FROM cpe_match;

-- 정규화 결과 확인
SELECT 'cve_core', COUNT(*) FROM cve_core
UNION ALL
SELECT 'cve_metric', COUNT(*) FROM cve_metric;

-- 타임스탬프 타입/NULL 체크
SELECT COUNT(*) FILTER (WHERE published_ts IS NULL) AS null_published FROM cve_core;

-- psql -h localhost -U nvduser -d nvddb -f sql/verify_etl.sql