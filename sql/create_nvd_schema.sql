-- 1) CVE 테이블
CREATE TABLE IF NOT EXISTS cve (
    id              SERIAL PRIMARY KEY,
    cve_id          TEXT UNIQUE NOT NULL,
    source_identifier TEXT,
    published       TIMESTAMPTZ,
    last_modified   TIMESTAMPTZ,
    vuln_status     TEXT,
    raw_json        TEXT NOT NULL
);

-- 2) CPE Dictionary 테이블
CREATE TABLE IF NOT EXISTS cpe_dictionary (
    id              SERIAL PRIMARY KEY,
    cpe_name_id     TEXT UNIQUE NOT NULL,
    cpe_name        TEXT NOT NULL,
    deprecated      BOOLEAN,
    created         TIMESTAMPTZ,
    last_modified   TIMESTAMPTZ,
    raw_json        TEXT NOT NULL
);

-- 3) CPE Match 테이블
CREATE TABLE IF NOT EXISTS cpe_match (
    id                  SERIAL PRIMARY KEY,
    match_criteria_id   TEXT UNIQUE NOT NULL,
    criteria            TEXT NOT NULL,
    version_start_including TEXT,
    version_start_excluding TEXT,
    version_end_including   TEXT,
    version_end_excluding   TEXT,
    status              TEXT,
    created             TIMESTAMPTZ,
    last_modified       TIMESTAMPTZ,
    cpe_last_modified   TIMESTAMPTZ,
    raw_json            TEXT NOT NULL
);

-- 4) CWE 테이블
CREATE TABLE IF NOT EXISTS cwe (
    id              SERIAL PRIMARY KEY,
    cwe_id          INT UNIQUE NOT NULL,
    name            TEXT,
    abstraction     TEXT,
    status          TEXT,
    description     TEXT,
    raw_xml         TEXT NOT NULL
);

-- =========================================================
-- 2단계 정규화 스키마
-- Landing 테이블(cve, cpe_dictionary, cpe_match, cwe)은 변경하지 않음
-- =========================================================

-- -----------------------
-- 1) CVE 정규화 레이어
-- -----------------------

CREATE TABLE IF NOT EXISTS cve_core (
    cve_id            TEXT PRIMARY KEY,
    source_identifier TEXT,
    vuln_status       TEXT,
    published_ts      TIMESTAMPTZ,
    last_modified_ts  TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS cve_description (
    id        BIGSERIAL PRIMARY KEY,
    cve_id    TEXT NOT NULL REFERENCES cve_core(cve_id),
    lang      TEXT NOT NULL,
    value     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cve_reference (
    id        BIGSERIAL PRIMARY KEY,
    cve_id    TEXT NOT NULL REFERENCES cve_core(cve_id),
    url       TEXT NOT NULL,
    source    TEXT,
    tags      TEXT[]
);

CREATE TABLE IF NOT EXISTS cve_metric (
    id                   BIGSERIAL PRIMARY KEY,
    cve_id               TEXT NOT NULL REFERENCES cve_core(cve_id),
    cvss_version         TEXT NOT NULL,  -- '2.0', '3.0', '3.1', '4.0'
    source               TEXT,
    metric_type          TEXT,           -- 'Primary', 'Secondary'
    vector_string        TEXT,
    base_score           NUMERIC(3,1),
    base_severity        TEXT,
    exploitability_score NUMERIC(3,1),
    impact_score         NUMERIC(3,1),
    raw_json             JSONB
);

CREATE TABLE IF NOT EXISTS cve_weakness (
    id             BIGSERIAL PRIMARY KEY,
    cve_id         TEXT NOT NULL REFERENCES cve_core(cve_id),
    source         TEXT,
    weakness_type  TEXT,
    cwe_code       TEXT,     -- ex) 'CWE-89'
    cwe_id         INTEGER   -- ex) 89
);

CREATE TABLE IF NOT EXISTS cve_cpe_match (
    id                  BIGSERIAL PRIMARY KEY,
    cve_id              TEXT NOT NULL REFERENCES cve_core(cve_id),
    match_criteria_id   TEXT,
    criteria_cpe_uri    TEXT NOT NULL,
    vulnerable          BOOLEAN,
    config_operator     TEXT,
    node_operator       TEXT,
    node_negate         BOOLEAN,
    version_start_incl  TEXT,
    version_start_excl  TEXT,
    version_end_incl    TEXT,
    version_end_excl    TEXT
);

-- 인덱스(쿼리 편의를 위한 부가 인덱스)
CREATE INDEX IF NOT EXISTS idx_cve_description_cve_id ON cve_description(cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_reference_cve_id ON cve_reference(cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_metric_cve_id ON cve_metric(cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_weakness_cve_id ON cve_weakness(cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_weakness_cwe_id ON cve_weakness(cwe_id);
CREATE INDEX IF NOT EXISTS idx_cve_cpe_match_cve_id ON cve_cpe_match(cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_cpe_match_criteria ON cve_cpe_match(criteria_cpe_uri);


-- -----------------------
-- 2) CPE Dictionary 정규화
-- -----------------------

CREATE TABLE IF NOT EXISTS cpe (
    cpe_name_id       TEXT PRIMARY KEY,
    cpe_uri           TEXT NOT NULL,   -- cpe:2.3:...
    part              TEXT,
    vendor            TEXT,
    product           TEXT,
    cpe_version       TEXT,
    cpe_update        TEXT,
    edition           TEXT,
    language          TEXT,
    sw_edition        TEXT,
    target_sw         TEXT,
    target_hw         TEXT,
    other             TEXT,
    deprecated        BOOLEAN,
    created_ts        TIMESTAMPTZ,
    last_modified_ts  TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS cpe_title (
    id           BIGSERIAL PRIMARY KEY,
    cpe_name_id  TEXT NOT NULL REFERENCES cpe(cpe_name_id),
    lang         TEXT,
    title        TEXT
);

CREATE TABLE IF NOT EXISTS cpe_ref (
    id           BIGSERIAL PRIMARY KEY,
    cpe_name_id  TEXT NOT NULL REFERENCES cpe(cpe_name_id),
    ref          TEXT NOT NULL,
    ref_type     TEXT
);

CREATE TABLE IF NOT EXISTS cpe_deprecation_map (
    id                BIGSERIAL PRIMARY KEY,
    from_cpe_name_id  TEXT NOT NULL REFERENCES cpe(cpe_name_id),
    to_cpe_name_id    TEXT NOT NULL,
    relation_type     TEXT NOT NULL  -- 'deprecatedBy' or 'deprecates'
);


-- -----------------------
-- 3) CPE Match Feed 정규화
-- -----------------------

CREATE TABLE IF NOT EXISTS cpe_match_string (
    match_criteria_id     TEXT PRIMARY KEY,
    criteria_cpe_uri      TEXT NOT NULL,
    version_start_incl    TEXT,
    version_start_excl    TEXT,
    version_end_incl      TEXT,
    version_end_excl      TEXT,
    status                TEXT,
    created_ts            TIMESTAMPTZ,
    last_modified_ts      TIMESTAMPTZ,
    cpe_last_modified_ts  TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS cpe_match_name (
    id                BIGSERIAL PRIMARY KEY,
    match_criteria_id TEXT NOT NULL REFERENCES cpe_match_string(match_criteria_id),
    cpe_name          TEXT,
    cpe_name_id       TEXT
);

CREATE INDEX IF NOT EXISTS idx_cpe_match_string_criteria ON cpe_match_string(criteria_cpe_uri);


-- -----------------------
-- 4) CWE 정규화
-- -----------------------

CREATE TABLE IF NOT EXISTS cwe_core (
    cwe_id                 INTEGER PRIMARY KEY,
    name                   TEXT,
    abstraction            TEXT,
    status                 TEXT,
    likelihood_of_exploit  TEXT,
    description            TEXT,
    extended_description   TEXT
);
