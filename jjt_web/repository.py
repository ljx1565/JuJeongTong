from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
from types import SimpleNamespace

import pymysql

from .db import Database
from .time_utils import parse_database_time, quote, to_database_time


JJT_TYPES = (
    ("unix", "Unix Server", "unix_table", "unix_history", 55),
    ("windows", "Windows Server", "windows_table", "windows_history", 62),
    ("network", "Network Device", "network_table", "network_history", 31),
    ("pc", "Windows PC", "pc_table", "pc_history", 18),
    ("dbms", "DBMS", "dbms_table", "dbms_history", 26),
    ("virtual", "Virtualization", "virtual_table", "virtual_history", 25),
    ("web_application", "Web Application", "webapp_table", "webapp_history", 5),
)
JJT_TYPE_MAP = {item[0]: item for item in JJT_TYPES}
JJT_STATUSES = ("양호", "취약", "해당없음", "검토필요", "오류")


def make_jjt_database(settings):
    config = deepcopy(settings.JJT_DATABASE or settings.DATABASE)
    config["database"] = config.get("database") or "jjt_db"
    if settings.JJT_DATABASE is None:
        config["database"] = "jjt_db"
    return Database(SimpleNamespace(DATABASE=config))


class JjtRepository:
    def __init__(self, database):
        self.db = database

    def probe(self):
        try:
            health = self.db.health()
            tables = self.db.query(
                "SELECT TABLE_NAME AS name FROM information_schema.TABLES "
                "WHERE TABLE_SCHEMA = DATABASE()"
            )
        except pymysql.MySQLError:
            return {"available": False, "database": "jjt_db", "tables": []}
        return {
            "available": True,
            "database": health["database_name"],
            "latency_ms": health["latency_ms"],
            "tables": [row["name"] for row in tables],
        }

    def overview(self, start=None, end=None):
        probe = self.probe()
        expected = self.type_metadata(probe.get("tables", []))
        if not probe["available"]:
            return unavailable_overview(probe, expected)

        current_tables = [item for item in JJT_TYPES if item[2] in probe["tables"]]
        history_tables = [item for item in JJT_TYPES if item[3] in probe["tables"]]
        if not current_tables:
            return unavailable_overview(probe, expected, "jjt_db는 연결됐지만 점검 테이블이 없습니다.")

        rows = self.current_rows(current_tables)
        history = self.history_counts(history_tables, start, end)
        return build_overview(probe, expected, rows, history)

    def current_rows(self, table_types):
        selects = []
        for type_id, label, table, _, _ in table_types:
            selects.append(
                f"SELECT '{type_id}' AS asset_type, '{label}' AS asset_label, "
                f"ip, code, title, status, reason, check_date FROM {quote(table)}"
            )
        return self.db.query(" UNION ALL ".join(selects))

    def history_counts(self, table_types, start, end):
        if not table_types:
            return []
        selects = []
        params = []
        for type_id, _, _, history_table, _ in table_types:
            where = []
            if start:
                where.append("archived_at >= %s")
                params.append(to_database_time(start))
            if end:
                where.append("archived_at < %s")
                params.append(to_database_time(end))
            condition = " WHERE " + " AND ".join(where) if where else ""
            selects.append(
                f"SELECT '{type_id}' AS asset_type, DATE(archived_at) AS day, "
                f"COUNT(*) AS changes FROM {quote(history_table)}{condition} GROUP BY DATE(archived_at)"
            )
        return self.db.query(" UNION ALL ".join(selects) + " ORDER BY day", params)

    def rows(self, type_id, status="", query="", page=1, page_size=100):
        item = JJT_TYPE_MAP.get(type_id)
        probe = self.probe()
        if not item or not probe["available"] or item[2] not in probe["tables"]:
            return {"rows": [], "total": 0, "page": page, "page_size": page_size}

        conditions = []
        params = []
        if status in JJT_STATUSES:
            conditions.append("status = %s")
            params.append(status)
        if query:
            conditions.append("CONCAT_WS(' ', ip, code, title, status, reason) LIKE %s")
            params.append("%" + query + "%")
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        table = quote(item[2])
        total = self.db.one(f"SELECT COUNT(*) AS total FROM {table}{where}", params)["total"]
        offset = (page - 1) * page_size
        rows = self.db.query(
            f"SELECT ip, code, title, status, reason, check_date FROM {table}{where} "
            "ORDER BY check_date DESC, ip, code LIMIT %s OFFSET %s",
            [*params, page_size, offset],
        )
        return {"rows": rows, "total": total, "page": page, "page_size": page_size}

    def dated_rows(self, type_id="", ip="", start=None, end=None, status="", query="", page=1, page_size=100):
        probe = self.probe()
        if not probe["available"]:
            return {"rows": [], "total": 0, "page": page, "page_size": page_size}
        items = [JJT_TYPE_MAP[type_id]] if type_id in JJT_TYPE_MAP else list(JJT_TYPES)
        selects = []
        for asset_type, label, current_table, history_table, _ in items:
            if current_table not in probe["tables"]:
                continue
            prefix = f"SELECT '{asset_type}' AS asset_type,'{label}' AS asset_label,ip,code,title,status,reason,check_date AS observed_at"
            selects.append(f"{prefix},'current' AS record_kind FROM {quote(current_table)}")
            if history_table in probe["tables"]:
                selects.append(f"{prefix},'history' AS record_kind FROM {quote(history_table)}")
        if not selects:
            return {"rows": [], "total": 0, "page": page, "page_size": page_size}
        conditions, params = [], []
        if ip:
            conditions.append("ip=%s")
            params.append(ip)
        if start:
            conditions.append("observed_at >= %s")
            params.append(to_database_time(start))
        if end:
            conditions.append("observed_at < %s")
            params.append(to_database_time(end))
        if status in JJT_STATUSES:
            conditions.append("status=%s")
            params.append(status)
        if query:
            conditions.append("CONCAT_WS(' ',asset_label,ip,code,title,status,reason) LIKE %s")
            params.append("%" + query + "%")
        base = " UNION ALL ".join(selects)
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        total = self.db.one(f"SELECT COUNT(*) AS total FROM ({base}) records{where}", params)["total"]
        offset = (page - 1) * page_size
        rows = self.db.query(f"SELECT * FROM ({base}) records{where} ORDER BY observed_at DESC,ip,code LIMIT %s OFFSET %s", [*params, page_size, offset])
        return {"rows": rows, "total": total, "page": page, "page_size": page_size}

    def type_metadata(self, existing_tables):
        return [{
            "id": type_id,
            "label": label,
            "table": table,
            "history_table": history,
            "defined_checks": checks,
            "available": table in existing_tables,
            "history_available": history in existing_tables,
        } for type_id, label, table, history, checks in JJT_TYPES]


def unavailable_overview(probe, types, message="jjt_db 읽기 전용 연결을 기다리고 있습니다."):
    return {
        "available": False,
        "database": probe,
        "message": message,
        "types": types,
        "metrics": {"devices": 0, "items": 0, "good": 0, "vulnerable": 0, "review": 0, "good_rate": None},
        "status_counts": [],
        "recent_vulnerabilities": [],
        "freshness": [],
        "history": [],
        "last_checked": None,
    }


def build_overview(probe, types, rows, history):
    status_counts = Counter(row.get("status") for row in rows)
    devices = {row.get("ip") for row in rows if row.get("ip")}
    actionable = sum(status_counts.get(status, 0) for status in ("양호", "취약", "검토필요", "오류"))
    good_rate = round(status_counts.get("양호", 0) * 100 / actionable, 1) if actionable else None
    current_time = datetime.now(timezone.utc)
    freshness = Counter()
    parsed_times = []
    for row in rows:
        checked = parse_database_time(row.get("check_date"))
        if not checked:
            freshness["unknown"] += 1
            continue
        parsed_times.append(checked)
        age = (current_time - checked).total_seconds()
        if age <= 86400:
            freshness["24h"] += 1
        elif age <= 604800:
            freshness["7d"] += 1
        else:
            freshness["stale"] += 1

    per_type = {item["id"]: Counter() for item in types}
    for row in rows:
        per_type.setdefault(row["asset_type"], Counter())[row.get("status")] += 1
    for item in types:
        counts = per_type[item["id"]]
        item["total"] = sum(counts.values())
        item["good"] = counts.get("양호", 0)
        item["vulnerable"] = counts.get("취약", 0)
        item["review"] = counts.get("검토필요", 0) + counts.get("오류", 0)

    vulnerable = [row for row in rows if row.get("status") in ("취약", "검토필요", "오류")]
    vulnerable.sort(key=lambda row: str(row.get("check_date") or ""), reverse=True)
    return {
        "available": True,
        "database": probe,
        "message": None,
        "types": types,
        "metrics": {
            "devices": len(devices),
            "items": len(rows),
            "good": status_counts.get("양호", 0),
            "vulnerable": status_counts.get("취약", 0),
            "review": status_counts.get("검토필요", 0) + status_counts.get("오류", 0),
            "good_rate": good_rate,
        },
        "status_counts": [{"name": status, "count": status_counts.get(status, 0)} for status in JJT_STATUSES],
        "recent_vulnerabilities": vulnerable[:12],
        "freshness": [{"name": name, "count": freshness.get(name, 0)} for name in ("24h", "7d", "stale", "unknown")],
        "history": history,
        "last_checked": max(parsed_times).isoformat().replace("+00:00", "Z") if parsed_times else None,
    }
