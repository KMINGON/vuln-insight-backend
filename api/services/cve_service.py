import json
from typing import List, Dict

class CVEService:

    @staticmethod
    def convert_rows(rows):
        data = []
        for r in rows:
            item = dict(r)
            try:
                item["raw_json"] = json.loads(item["raw_json"])
            except:
                item["raw_json"] = None
            data.append(item)
        return data

    @staticmethod
    def convert_summary(raw: dict):
        return {
            "total_cve": raw["total"],
            "last_24_hours": raw["last24"],
            "top_sources": raw["top_sources"]
        }
