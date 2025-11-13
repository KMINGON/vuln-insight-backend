-- reset_nvd_schema.sql
\i drop_nvd_schema.sql
\i create_nvd_schema.sql

-- 사용 예시 `psql -U nvduser -d nvddb -f reset_nvd_schema.sql`