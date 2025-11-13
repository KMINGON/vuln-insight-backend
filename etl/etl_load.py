import json
from pathlib import Path

import pandas as pd
from sqlalchemy import create_engine, text
from lxml import etree

# 1) PostgreSQL 연결 설정
DB_USER = "nvduser"
DB_PASS = "20193172"
DB_HOST = "localhost"
DB_NAME = "nvddb"

engine = create_engine(
    f"postgresql+psycopg2://{DB_USER}:{DB_PASS}@{DB_HOST}/{DB_NAME}"
)

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"


# ---- CVE 로드 함수 ----
def load_cve_json(json_path: Path):
    with json_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    rows = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        source = cve.get("sourceIdentifier")
        published = cve.get("published")
        last_modified = cve.get("lastModified")
        vuln_status = cve.get("vulnStatus")

        # raw_json: cve 객체 전체를 문자열로 저장
        raw_json = json.dumps(cve, ensure_ascii=False)

        rows.append(
            {
                "cve_id": cve_id,
                "source_identifier": source,
                "published": published,
                "last_modified": last_modified,
                "vuln_status": vuln_status,
                "raw_json": raw_json,
            }
        )

    if not rows:
        print(f"[CVE] No rows in {json_path}")
        return

    df = pd.DataFrame(rows)
    df.to_sql("cve", engine, if_exists="append", index=False)
    print(f"[CVE] Inserted {len(df)} rows from {json_path.name}")


# ---- CPE Dictionary 로드 함수 ----
def load_cpe_dictionary_json(json_path: Path):
    with json_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    rows = []
    for item in data.get("products", []):
        cpe_obj = item.get("cpe", {})
        cpe_name_id = cpe_obj.get("cpeNameId")
        cpe_name = cpe_obj.get("cpeName")
        deprecated = cpe_obj.get("deprecated")
        created = cpe_obj.get("created")
        last_modified = cpe_obj.get("lastModified")

        raw_json = json.dumps(cpe_obj, ensure_ascii=False)

        # 스키마 상 required 이므로 그대로 사용
        rows.append(
            {
                "cpe_name_id": cpe_name_id,
                "cpe_name": cpe_name,
                "deprecated": deprecated,
                "created": created,
                "last_modified": last_modified,
                "raw_json": raw_json,
            }
        )

    if not rows:
        print(f"[CPE_DICT] No rows in {json_path}")
        return

    df = pd.DataFrame(rows)
    df.to_sql("cpe_dictionary", engine, if_exists="append", index=False)
    print(f"[CPE_DICT] Inserted {len(df)} rows from {json_path.name}")


# ---- CPE Match 로드 함수 ----
def load_cpe_match_json(json_path: Path):
    with json_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    rows = []
    for item in data.get("matchStrings", []):
        m = item.get("matchString", {})
        match_criteria_id = m.get("matchCriteriaId")
        criteria = m.get("criteria")
        version_start_including = m.get("versionStartIncluding")
        version_start_excluding = m.get("versionStartExcluding")
        version_end_including = m.get("versionEndIncluding")
        version_end_excluding = m.get("versionEndExcluding")
        status = m.get("status")
        created = m.get("created")
        last_modified = m.get("lastModified")
        cpe_last_modified = m.get("cpeLastModified")

        raw_json = json.dumps(m, ensure_ascii=False)

        rows.append(
            {
                "match_criteria_id": match_criteria_id,
                "criteria": criteria,
                "version_start_including": version_start_including,
                "version_start_excluding": version_start_excluding,
                "version_end_including": version_end_including,
                "version_end_excluding": version_end_excluding,
                "status": status,
                "created": created,
                "last_modified": last_modified,
                "cpe_last_modified": cpe_last_modified,
                "raw_json": raw_json,
            }
        )

    if not rows:
        print(f"[CPE_MATCH] No rows in {json_path}")
        return

    df = pd.DataFrame(rows)
    df.to_sql("cpe_match", engine, if_exists="append", index=False)
    print(f"[CPE_MATCH] Inserted {len(df)} rows from {json_path.name}")


# ---- CWE XML 로드 함수 ----
def load_cwe_xml(xml_path: Path):
    parser = etree.XMLParser(remove_blank_text=True)
    tree = etree.parse(str(xml_path), parser)

    ns = {"cwe": "http://cwe.mitre.org/cwe-7"}

    rows = []
    # Weakness_Catalog / Weaknesses / Weakness
    for w in tree.xpath("//cwe:Weaknesses/cwe:Weakness", namespaces=ns):
        cwe_id = w.get("ID")
        name = w.get("Name")
        abstraction = w.get("Abstraction")
        status = w.get("Status")

        # <Description> 첫 번째 요소 텍스트
        desc_elem = w.find("cwe:Description", namespaces=ns)
        description = desc_elem.text if desc_elem is not None else None

        raw_xml = etree.tostring(w, encoding="unicode")

        rows.append(
            {
                "cwe_id": int(cwe_id) if cwe_id is not None and cwe_id.isdigit() else None,
                "name": name,
                "abstraction": abstraction,
                "status": status,
                "description": description,
                "raw_xml": raw_xml,
            }
        )

    # cwe_id None 인 것은 일단 제외 (ID가 숫자인 항목만 저장)
    rows = [r for r in rows if r["cwe_id"] is not None]

    if not rows:
        print(f"[CWE] No rows in {xml_path}")
        return

    df = pd.DataFrame(rows)
    df.to_sql("cwe", engine, if_exists="append", index=False)
    print(f"[CWE] Inserted {len(df)} rows from {xml_path.name}")


def main():
    # 0) 이번 실행에서 landing 테이블을 항상 초기화
    #    → 여러 번 실행해도 중복/무결성 문제 없음
    with engine.begin() as conn:
        conn.execute(
            text("TRUNCATE cve, cpe_dictionary, cpe_match, cwe RESTART IDENTITY;")
        )

    # 1) CVE JSON – data/cve 디렉터리 안의 모든 nvdcve-2.0-*.json 청크 적재
    cve_dir = DATA_DIR / "cve"
    if cve_dir.exists():
        files = sorted(cve_dir.glob("nvdcve-2.0-*.json"))
        if not files:
            print("[CVE] No files matching nvdcve-2.0-*.json")
        for cve_file in files:
            print(f"[CVE] Loading {cve_file.name}")
            load_cve_json(cve_file)
    else:
        print(f"[CVE] Directory not found: {cve_dir}")

    # 2) CPE Dictionary JSON – data/cpe_dictionary/nvdcpe-2.0-*.json 전체
    cpe_dict_dir = DATA_DIR / "cpe_dictionary"
    if cpe_dict_dir.exists():
        files = sorted(cpe_dict_dir.glob("nvdcpe-2.0-*.json"))
        if not files:
            print("[CPE_DICT] No files matching nvdcpe-2.0-*.json")
        for cpe_dict_file in files:
            print(f"[CPE_DICT] Loading {cpe_dict_file.name}")
            load_cpe_dictionary_json(cpe_dict_file)
    else:
        print(f"[CPE_DICT] Directory not found: {cpe_dict_dir}")

    # 3) CPE Match JSON – data/cpe_match/nvdcpematch-2.0-*.json 전체
    cpe_match_dir = DATA_DIR / "cpe_match"
    if cpe_match_dir.exists():
        files = sorted(cpe_match_dir.glob("nvdcpematch-2.0-*.json"))
        if not files:
            print("[CPE_MATCH] No files matching nvdcpematch-2.0-*.json")
        for cpe_match_file in files:
            print(f"[CPE_MATCH] Loading {cpe_match_file.name}")
            load_cpe_match_json(cpe_match_file)
    else:
        print(f"[CPE_MATCH] Directory not found: {cpe_match_dir}")

    # 4) CWE XML – 어차피 하나만 있으므로 기존처럼 단일 파일 처리
    cwe_file = DATA_DIR / "cwe" / "cwec_v4.18.xml"
    if cwe_file.exists():
        print(f"[CWE] Loading {cwe_file.name}")
        load_cwe_xml(cwe_file)
    else:
        print(f"[CWE] File not found: {cwe_file}")



if __name__ == "__main__":
    main()
