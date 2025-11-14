import json
from datetime import datetime, timezone
from pathlib import Path

from lxml import etree
from sqlalchemy import MetaData, Table, create_engine, text
from sqlalchemy.dialects.postgresql import insert as pg_insert

from api.core.config import settings
# ======================
# DB 연결 설정
# ======================


engine = create_engine(settings.SYNC_DATABASE_URL)

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"


# ======================
# 유틸 함수
# ======================

def parse_iso_ts(ts):
    """Safely parse ISO8601 strings (or datetime values) into timezone-aware datetimes."""
    if ts in (None, ""):
        return None

    if isinstance(ts, datetime):
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)

    value = str(ts).strip()
    if not value:
        return None
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"

    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        # Fallback to common patterns without timezone/milliseconds
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                dt = datetime.strptime(value, fmt)
                break
            except ValueError:
                continue
        else:
            return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def parse_cpe23_uri(uri: str | None):
    """cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other"""
    if not uri:
        return dict(
            part=None, vendor=None, product=None, cpe_version=None,
            cpe_update=None, edition=None, language=None,
            sw_edition=None, target_sw=None, target_hw=None, other=None
        )
    parts = uri.split(":")
    if len(parts) < 13 or parts[0] != "cpe" or parts[1] != "2.3":
        return dict(
            part=None, vendor=None, product=None, cpe_version=None,
            cpe_update=None, edition=None, language=None,
            sw_edition=None, target_sw=None, target_hw=None, other=None
        )
    return dict(
        part=parts[2] or None,
        vendor=parts[3] or None,
        product=parts[4] or None,
        cpe_version=parts[5] or None,
        cpe_update=parts[6] or None,
        edition=parts[7] or None,
        language=parts[8] or None,
        sw_edition=parts[9] or None,
        target_sw=parts[10] or None,
        target_hw=parts[11] or None,
        other=parts[12] or None,
    )


def extract_cwe_id(code: str | None):
    if not code:
        return None
    # 예: "CWE-89"
    if code.upper().startswith("CWE-"):
        num = code[4:]
        if num.isdigit():
            return int(num)
    return None


# ======================
# CVE 정규화 ETL
# ======================

def etl_cve():
    metadata = MetaData()
    cve_core_tbl = Table("cve_core", metadata, autoload_with=engine)
    cve_desc_tbl = Table("cve_description", metadata, autoload_with=engine)
    cve_ref_tbl = Table("cve_reference", metadata, autoload_with=engine)
    cve_metric_tbl = Table("cve_metric", metadata, autoload_with=engine)
    cve_weak_tbl = Table("cve_weakness", metadata, autoload_with=engine)
    cve_cpe_tbl = Table("cve_cpe_match", metadata, autoload_with=engine)

    # 실행할 때마다 깨끗하게 초기화 (오염 방지)
    with engine.begin() as conn:
        conn.execute(text("TRUNCATE cve_description, cve_reference, cve_metric, cve_weakness, cve_cpe_match, cve_core RESTART IDENTITY;"))

    # landing cve 테이블에서 모든 row 읽기
    with engine.connect() as conn:
        result = conn.execution_options(stream_results=True).execute(
            text("SELECT cve_id, source_identifier, published, last_modified, vuln_status, raw_json FROM cve")
        )

        batch_size = 1000
        processed = 0

        while True:
            rows = result.fetchmany(batch_size)
            if not rows:
                break
            processed += len(rows)
            if processed % 10000 == 0:  # 1만 건 단위로 로그
                print(f"[ETL][CVE] 처리 중... {processed} rows", flush=True)
            core_rows = []
            desc_rows = []
            ref_rows = []
            metric_rows = []
            weak_rows = []
            cpe_rows = []

            for row in rows:
                cve_id = row.cve_id
                src = row.source_identifier
                published_ts = parse_iso_ts(row.published)
                last_modified_ts = parse_iso_ts(row.last_modified)
                vuln_status = row.vuln_status

                core_rows.append(
                    {
                        "cve_id": cve_id,
                        "source_identifier": src,
                        "vuln_status": vuln_status,
                        "published_ts": published_ts,
                        "last_modified_ts": last_modified_ts,
                    }
                )

                try:
                    cve_obj = json.loads(row.raw_json)
                except Exception:
                    continue

                # descriptions
                for d in cve_obj.get("descriptions", []):
                    lang = d.get("lang")
                    val = d.get("value")
                    if not lang or not val:
                        continue
                    desc_rows.append(
                        {"cve_id": cve_id, "lang": lang, "value": val}
                    )

                # references
                for r in cve_obj.get("references", []):
                    url = r.get("url")
                    if not url:
                        continue
                    source = r.get("source")
                    tags = r.get("tags") or []
                    ref_rows.append(
                        {
                            "cve_id": cve_id,
                            "url": url,
                            "source": source,
                            "tags": tags,
                        }
                    )

                # metrics
                metrics = cve_obj.get("metrics", {})
                # CVSS v2
                for m in metrics.get("cvssMetricV2", []):
                    cvss_data = m.get("cvssData", {})
                    metric_rows.append(
                        {
                            "cve_id": cve_id,
                            "cvss_version": "2.0",
                            "source": m.get("source"),
                            "metric_type": m.get("type"),
                            "vector_string": cvss_data.get("vectorString"),
                            "base_score": cvss_data.get("baseScore"),
                            "base_severity": m.get("baseSeverity"),
                            "exploitability_score": m.get("exploitabilityScore"),
                            "impact_score": m.get("impactScore"),
                            "raw_json": json.dumps(m),
                        }
                    )
                # CVSS v3.0
                for m in metrics.get("cvssMetricV30", []):
                    cvss_data = m.get("cvssData", {})
                    metric_rows.append(
                        {
                            "cve_id": cve_id,
                            "cvss_version": "3.0",
                            "source": m.get("source"),
                            "metric_type": m.get("type"),
                            "vector_string": cvss_data.get("vectorString"),
                            "base_score": cvss_data.get("baseScore"),
                            "base_severity": cvss_data.get("baseSeverity"),
                            "exploitability_score": m.get("exploitabilityScore"),
                            "impact_score": m.get("impactScore"),
                            "raw_json": json.dumps(m),
                        }
                    )
                # CVSS v3.1
                for m in metrics.get("cvssMetricV31", []):
                    cvss_data = m.get("cvssData", {})
                    metric_rows.append(
                        {
                            "cve_id": cve_id,
                            "cvss_version": "3.1",
                            "source": m.get("source"),
                            "metric_type": m.get("type"),
                            "vector_string": cvss_data.get("vectorString"),
                            "base_score": cvss_data.get("baseScore"),
                            "base_severity": cvss_data.get("baseSeverity"),
                            "exploitability_score": m.get("exploitabilityScore"),
                            "impact_score": m.get("impactScore"),
                            "raw_json": json.dumps(m),
                        }
                    )
                # CVSS v4.0
                for m in metrics.get("cvssMetricV40", []):
                    cvss_data = m.get("cvssData", {})
                    metric_rows.append(
                        {
                            "cve_id": cve_id,
                            "cvss_version": "4.0",
                            "source": m.get("source"),
                            "metric_type": m.get("type"),
                            "vector_string": cvss_data.get("vectorString"),
                            "base_score": cvss_data.get("baseScore"),
                            "base_severity": cvss_data.get("baseSeverity"),
                            "exploitability_score": None,
                            "impact_score": None,
                            "raw_json": json.dumps(m),
                        }
                    )

                # weaknesses → CWE 매핑
                for w in cve_obj.get("weaknesses", []):
                    source_w = w.get("source")
                    wtype = w.get("type")
                    for d in w.get("description", []):
                        val = d.get("value")
                        if not val:
                            continue
                        if val.startswith("CWE-"):
                            cwe_code = val
                            cwe_id = extract_cwe_id(val)
                            weak_rows.append(
                                {
                                    "cve_id": cve_id,
                                    "source": source_w,
                                    "weakness_type": wtype,
                                    "cwe_code": cwe_code,
                                    "cwe_id": cwe_id,
                                }
                            )

                # configurations → cpeMatch
                for conf in cve_obj.get("configurations", []):
                    conf_op = conf.get("operator")
                    for node in conf.get("nodes", []):
                        node_op = node.get("operator")
                        node_neg = node.get("negate")
                        for cm in node.get("cpeMatch", []):
                            criteria = cm.get("criteria")
                            if not criteria:
                                continue
                            cpe_rows.append(
                                {
                                    "cve_id": cve_id,
                                    "match_criteria_id": cm.get("matchCriteriaId"),
                                    "criteria_cpe_uri": criteria,
                                    "vulnerable": cm.get("vulnerable"),
                                    "config_operator": conf_op,
                                    "node_operator": node_op,
                                    "node_negate": node_neg,
                                    "version_start_incl": cm.get("versionStartIncluding"),
                                    "version_start_excl": cm.get("versionStartExcluding"),
                                    "version_end_incl": cm.get("versionEndIncluding"),
                                    "version_end_excl": cm.get("versionEndExcluding"),
                                }
                            )

            # Batch insert
            with engine.begin() as tx:
                if core_rows:
                    stmt = pg_insert(cve_core_tbl).values(core_rows)
                    stmt = stmt.on_conflict_do_update(
                        index_elements=["cve_id"],
                        set_={
                            "source_identifier": stmt.excluded.source_identifier,
                            "vuln_status": stmt.excluded.vuln_status,
                            "published_ts": stmt.excluded.published_ts,
                            "last_modified_ts": stmt.excluded.last_modified_ts,
                        },
                    )
                    tx.execute(stmt)

                if desc_rows:
                    tx.execute(cve_desc_tbl.insert(), desc_rows)

                if ref_rows:
                    tx.execute(cve_ref_tbl.insert(), ref_rows)

                if metric_rows:
                    # raw_json 문자열을 jsonb로 캐스팅하기 위해 python dict로 변환
                    for r in metric_rows:
                        r["raw_json"] = json.loads(r["raw_json"])
                    tx.execute(cve_metric_tbl.insert(), metric_rows)

                if weak_rows:
                    tx.execute(cve_weak_tbl.insert(), weak_rows)

                if cpe_rows:
                    tx.execute(cve_cpe_tbl.insert(), cpe_rows)

    print("[ETL] CVE 정규화 완료")


# ======================
# CPE Dictionary 정규화 ETL
# ======================

def etl_cpe():
    metadata = MetaData()
    cpe_tbl = Table("cpe", metadata, autoload_with=engine)
    cpe_title_tbl = Table("cpe_title", metadata, autoload_with=engine)
    cpe_ref_tbl = Table("cpe_ref", metadata, autoload_with=engine)
    cpe_dep_tbl = Table("cpe_deprecation_map", metadata, autoload_with=engine)

    with engine.begin() as conn:
        conn.execute(text("TRUNCATE cpe_title, cpe_ref, cpe_deprecation_map, cpe RESTART IDENTITY;"))

    with engine.connect() as conn:
        result = conn.execution_options(stream_results=True).execute(
            text("SELECT cpe_name_id, cpe_name, deprecated, created, last_modified, raw_json FROM cpe_dictionary")
        )

        batch_size = 1000
        processed = 0
        while True:
            rows = result.fetchmany(batch_size)
            if not rows:
                break

            processed += len(rows)
            if processed % 10000 == 0:  # 1만 건 단위로 로그
                print(f"[ETL][CPE] 처리 중... {processed} rows", flush=True)
            
            base_rows = []
            title_rows = []
            ref_rows = []
            dep_rows = []

            for row in rows:
                cpe_name_id = row.cpe_name_id
                cpe_uri = row.cpe_name
                deprecated = row.deprecated
                created_ts = parse_iso_ts(row.created)
                last_modified_ts = parse_iso_ts(row.last_modified)

                parsed = parse_cpe23_uri(cpe_uri)

                base_rows.append(
                    {
                        "cpe_name_id": cpe_name_id,
                        "cpe_uri": cpe_uri,
                        "part": parsed["part"],
                        "vendor": parsed["vendor"],
                        "product": parsed["product"],
                        "cpe_version": parsed["cpe_version"],
                        "cpe_update": parsed["cpe_update"],
                        "edition": parsed["edition"],
                        "language": parsed["language"],
                        "sw_edition": parsed["sw_edition"],
                        "target_sw": parsed["target_sw"],
                        "target_hw": parsed["target_hw"],
                        "other": parsed["other"],
                        "deprecated": deprecated,
                        "created_ts": created_ts,
                        "last_modified_ts": last_modified_ts,
                    }
                )

                try:
                    obj = json.loads(row.raw_json)
                except Exception:
                    continue

                # titles
                for t in obj.get("titles", []):
                    title_rows.append(
                        {
                            "cpe_name_id": cpe_name_id,
                            "lang": t.get("lang"),
                            "title": t.get("title"),
                        }
                    )

                # refs
                for r in obj.get("refs", []):
                    ref_rows.append(
                        {
                            "cpe_name_id": cpe_name_id,
                            "ref": r.get("ref"),
                            "ref_type": r.get("type"),
                        }
                    )

                # deprecatedBy
                for d in obj.get("deprecatedBy", []):
                    dep_rows.append(
                        {
                            "from_cpe_name_id": cpe_name_id,
                            "to_cpe_name_id": d.get("cpeNameId"),
                            "relation_type": "deprecatedBy",
                        }
                    )

                # deprecates
                for d in obj.get("deprecates", []):
                    dep_rows.append(
                        {
                            "from_cpe_name_id": cpe_name_id,
                            "to_cpe_name_id": d.get("cpeNameId"),
                            "relation_type": "deprecates",
                        }
                    )

            with engine.begin() as tx:
                if base_rows:
                    stmt = pg_insert(cpe_tbl).values(base_rows)
                    stmt = stmt.on_conflict_do_update(
                        index_elements=["cpe_name_id"],
                        set_={
                            "cpe_uri": stmt.excluded.cpe_uri,
                            "deprecated": stmt.excluded.deprecated,
                            "created_ts": stmt.excluded.created_ts,
                            "last_modified_ts": stmt.excluded.last_modified_ts,
                            "part": stmt.excluded.part,
                            "vendor": stmt.excluded.vendor,
                            "product": stmt.excluded.product,
                            "cpe_version": stmt.excluded.cpe_version,
                            "cpe_update": stmt.excluded.cpe_update,
                            "edition": stmt.excluded.edition,
                            "language": stmt.excluded.language,
                            "sw_edition": stmt.excluded.sw_edition,
                            "target_sw": stmt.excluded.target_sw,
                            "target_hw": stmt.excluded.target_hw,
                            "other": stmt.excluded.other,
                        },
                    )
                    tx.execute(stmt)
                if title_rows:
                    tx.execute(cpe_title_tbl.insert(), title_rows)
                if ref_rows:
                    tx.execute(cpe_ref_tbl.insert(), ref_rows)
                if dep_rows:
                    tx.execute(cpe_dep_tbl.insert(), dep_rows)

    print("[ETL] CPE Dictionary 정규화 완료")


# ======================
# CPE Match Feed 정규화 ETL
# ======================

def etl_cpe_match():
    metadata = MetaData()
    match_tbl = Table("cpe_match_string", metadata, autoload_with=engine)
    match_name_tbl = Table("cpe_match_name", metadata, autoload_with=engine)

    with engine.begin() as conn:
        conn.execute(text("TRUNCATE cpe_match_name, cpe_match_string RESTART IDENTITY;"))

    with engine.connect() as conn:
        result = conn.execution_options(stream_results=True).execute(
            text("SELECT match_criteria_id, criteria, version_start_including, version_start_excluding, version_end_including, version_end_excluding, status, created, last_modified, cpe_last_modified, raw_json FROM cpe_match")
        )

        batch_size = 1000
        processed = 0

        while True:
            rows = result.fetchmany(batch_size)
            if not rows:
                break

            processed += len(rows)
            if processed % 10000 == 0:  # 1만 건 단위로 로그
                print(f"[ETL][CPE_MATCH] 처리 중... {processed} rows", flush=True)
    
            base_rows = []
            name_rows = []

            for row in rows:
                match_id = row.match_criteria_id
                criteria = row.criteria
                base_rows.append(
                    {
                        "match_criteria_id": match_id,
                        "criteria_cpe_uri": criteria,
                        "version_start_incl": row.version_start_including,
                        "version_start_excl": row.version_start_excluding,
                        "version_end_incl": row.version_end_including,
                        "version_end_excl": row.version_end_excluding,
                        "status": row.status,
                        "created_ts": parse_iso_ts(row.created),
                        "last_modified_ts": parse_iso_ts(row.last_modified),
                        "cpe_last_modified_ts": parse_iso_ts(row.cpe_last_modified),
                    }
                )

                try:
                    obj = json.loads(row.raw_json)
                except Exception:
                    continue

                for m in obj.get("matches", []):
                    name_rows.append(
                        {
                            "match_criteria_id": match_id,
                            "cpe_name": m.get("cpeName"),
                            "cpe_name_id": m.get("cpeNameId"),
                        }
                    )

            with engine.begin() as tx:
                if base_rows:
                    stmt = pg_insert(match_tbl).values(base_rows)
                    stmt = stmt.on_conflict_do_update(
                        index_elements=["match_criteria_id"],
                        set_={
                            "criteria_cpe_uri": stmt.excluded.criteria_cpe_uri,
                            "version_start_incl": stmt.excluded.version_start_incl,
                            "version_start_excl": stmt.excluded.version_start_excl,
                            "version_end_incl": stmt.excluded.version_end_incl,
                            "version_end_excl": stmt.excluded.version_end_excl,
                            "status": stmt.excluded.status,
                            "created_ts": stmt.excluded.created_ts,
                            "last_modified_ts": stmt.excluded.last_modified_ts,
                            "cpe_last_modified_ts": stmt.excluded.cpe_last_modified_ts,
                        },
                    )
                    tx.execute(stmt)
                if name_rows:
                    tx.execute(match_name_tbl.insert(), name_rows)

    print("[ETL] CPE Match 정규화 완료")


# ======================
# CWE 정규화 ETL
# ======================

def etl_cwe():
    metadata = MetaData()
    cwe_core_tbl = Table("cwe_core", metadata, autoload_with=engine)

    with engine.begin() as conn:
        conn.execute(text("TRUNCATE cwe_core RESTART IDENTITY;"))

    # landing cwe 테이블에서 raw_xml 사용
    with engine.connect() as conn:
        result = conn.execution_options(stream_results=True).execute(
            text("SELECT cwe_id, raw_xml FROM cwe")
        )

        rows_all = result.fetchall()

    parser = etree.XMLParser(remove_blank_text=True)
    ns = {"cwe": "http://cwe.mitre.org/cwe-7"}

    data_rows = []
    processed = 0
    for row in rows_all:
        cid = row.cwe_id
        if cid is None:
            continue
        xml_str = row.raw_xml
        try:
            elem = etree.fromstring(xml_str.encode("utf-8"), parser=parser)
        except Exception:
            continue

        processed += 1  # 추가
        if processed % 1000 == 0:  # 1000건 단위로 로그
            print(f"[ETL][CWE] 처리 중... {processed} rows", flush=True)  # 추가

        name = elem.get("Name")
        abstraction = elem.get("Abstraction")
        status = elem.get("Status")

        # Description
        desc_elem = elem.find("cwe:Description", namespaces=ns)
        description = desc_elem.text if desc_elem is not None else None

        # Extended_Description
        ext_elem = elem.find("cwe:Extended_Description", namespaces=ns)
        extended_description = ext_elem.text if ext_elem is not None else None

        # Likelihood_Of_Exploit
        like_elem = elem.find("cwe:Likelihood_Of_Exploit", namespaces=ns)
        likelihood = like_elem.text if like_elem is not None else None

        data_rows.append(
            {
                "cwe_id": cid,
                "name": name,
                "abstraction": abstraction,
                "status": status,
                "likelihood_of_exploit": likelihood,
                "description": description,
                "extended_description": extended_description,
            }
        )

    with engine.begin() as tx:
        if data_rows:
            stmt = pg_insert(cwe_core_tbl).values(data_rows)
            stmt = stmt.on_conflict_do_update(
                index_elements=["cwe_id"],
                set_={
                    "name": stmt.excluded.name,
                    "abstraction": stmt.excluded.abstraction,
                    "status": stmt.excluded.status,
                    "likelihood_of_exploit": stmt.excluded.likelihood_of_exploit,
                    "description": stmt.excluded.description,
                    "extended_description": stmt.excluded.extended_description,
                },
            )
            tx.execute(stmt)

    print("[ETL] CWE 정규화 완료")


# ======================
# 메인
# ======================

def main():
    etl_cve()
    etl_cpe()
    etl_cpe_match()
    etl_cwe()


if __name__ == "__main__":
    main()
