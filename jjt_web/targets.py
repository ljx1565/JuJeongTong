import json
import socket
from datetime import datetime
from pathlib import Path

import paramiko


CHECK_TYPES = {"unix", "windows", "network", "pc", "dbms", "virtual", "web_application"}
JJT_ROOT = Path(__file__).resolve().parents[2] / "jjt"


class TargetRepository:
    def __init__(self, database):
        self.db = database

    def setup(self):
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS jjt_targets (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                hostname VARCHAR(100) NOT NULL UNIQUE,
                ip VARCHAR(45) NOT NULL,
                role VARCHAR(40) NOT NULL DEFAULT '',
                port INT NOT NULL DEFAULT 22,
                username VARCHAR(100) NOT NULL,
                password_value TEXT NOT NULL,
                checks_json TEXT NOT NULL,
                extra_json LONGTEXT NULL,
                enabled TINYINT(1) NOT NULL DEFAULT 1,
                ssh_status VARCHAR(20) NOT NULL DEFAULT 'unknown',
                ssh_message VARCHAR(255) NULL,
                ssh_checked_at DATETIME(6) NULL,
                created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
                INDEX idx_jjt_targets_ip (ip),
                INDEX idx_jjt_targets_enabled (enabled)
            ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
        """)

    def seed(self, path):
        self.setup()
        if self.db.one("SELECT COUNT(*) AS total FROM jjt_targets")["total"]:
            return
        for device in json.loads(Path(path).read_text(encoding="utf-8")):
            conn = device.get("conn_info") or {}
            extra = {key: value for key, value in device.items() if key not in ("hostname", "ip", "role", "checks", "type", "conn_info")}
            self.db.insert(
                "INSERT INTO jjt_targets (hostname, ip, role, port, username, password_value, checks_json, extra_json) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                [device["hostname"], device["ip"], device.get("role", ""), conn.get("port", 22), conn.get("user", ""), conn.get("password", ""), json.dumps(device.get("checks") or [device.get("type")], ensure_ascii=False), json.dumps(extra, ensure_ascii=False)],
            )

    def list(self, include_secret=False):
        rows = self.db.query("SELECT * FROM jjt_targets ORDER BY hostname")
        return [self.decode(row, include_secret) for row in rows]

    def get(self, target_id, include_secret=False):
        row = self.db.one("SELECT * FROM jjt_targets WHERE id=%s", [target_id])
        return self.decode(row, include_secret) if row else None

    def create(self, body):
        values = validate(body, True)
        target_id = self.db.insert(
            "INSERT INTO jjt_targets (hostname,ip,role,port,username,password_value,checks_json,extra_json,enabled) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)", values,
        )
        return self.get(target_id)

    def update(self, target_id, body):
        current = self.get(target_id, True)
        if not current:
            return None
        merged = {**current, **body}
        if not body.get("password"):
            merged["password"] = current["password"]
        values = validate(merged, True)
        self.db.execute("UPDATE jjt_targets SET hostname=%s,ip=%s,role=%s,port=%s,username=%s,password_value=%s,checks_json=%s,extra_json=%s,enabled=%s WHERE id=%s", [*values, target_id])
        return self.get(target_id)

    def delete(self, target_id):
        return self.db.execute("DELETE FROM jjt_targets WHERE id=%s", [target_id])

    def save_probe(self, target_id, status, message):
        self.db.execute("UPDATE jjt_targets SET ssh_status=%s,ssh_message=%s,ssh_checked_at=CURRENT_TIMESTAMP(6) WHERE id=%s", [status, message[:255], target_id])
        return self.get(target_id)

    def decode(self, row, include_secret=False):
        if not row:
            return None
        result = dict(row)
        result["checks"] = json.loads(result.pop("checks_json") or "[]")
        result["extra"] = json.loads(result.pop("extra_json") or "{}")
        password = result.pop("password_value")
        result["has_password"] = bool(password)
        if include_secret:
            result["password"] = password
        return result

    def engine_devices(self):
        devices = []
        for row in self.list(True):
            if not row["enabled"]:
                continue
            device = {"id": row["id"], "hostname": row["hostname"], "ip": row["ip"], "role": row["role"], "checks": row["checks"], "conn_info": {"port": row["port"], "user": row["username"], "password": row["password"]}}
            device.update(row["extra"])
            devices.append(device)
        return devices


def validate(body, require_password=False):
    hostname = str(body.get("hostname", "")).strip()
    ip = str(body.get("ip", "")).strip()
    username = str(body.get("username", "")).strip()
    password = str(body.get("password", ""))
    checks = body.get("checks") or []
    if not hostname or not ip or not username or (require_password and not password):
        raise ValueError("호스트명, IP, 사용자명, 비밀번호는 필수입니다.")
    if not isinstance(checks, list) or not checks or any(item not in CHECK_TYPES for item in checks):
        raise ValueError("점검 유형을 하나 이상 올바르게 선택하세요.")
    port = int(body.get("port", 22))
    if not 1 <= port <= 65535:
        raise ValueError("Port 범위가 올바르지 않습니다.")
    return [hostname, ip, str(body.get("role", "")).strip(), port, username, password, json.dumps(checks, ensure_ascii=False), json.dumps(body.get("extra") or {}, ensure_ascii=False), 1 if body.get("enabled", True) else 0]


def direct_engine_device(body, checks):
    values = validate({**body, "checks": checks, "enabled": True}, True)
    hostname, ip, role, port, username, password, _, _, _ = values
    device = {"id": "direct", "hostname": hostname, "ip": ip, "role": role,
              "checks": checks, "conn_info": {"port": port, "user": username, "password": password}}
    platform = str(body.get("platform", "")).strip().lower()
    path = str(body.get("path", "")).strip()
    if "virtual" in checks:
        if platform not in ("esxi", "xenserver"):
            raise ValueError("가상화 점검은 ESXi 또는 XenServer Platform을 선택하세요.")
        device["virt_info"] = {"platform": platform}
    if "web_application" in checks:
        if not path:
            raise ValueError("Web Application 점검은 대상 경로가 필요합니다.")
        device["web_info"] = {"path": path}
    return device


def probe_ssh(target):
    if target["port"] != 22 and target["checks"] == ["virtual"]:
        try:
            with socket.create_connection((target["ip"], target["port"]), timeout=5):
                return "reachable", f"TCP {target['port']} 연결 성공 (SSH 대상 아님)"
        except OSError as exc:
            return "unreachable", f"TCP 연결 실패: {exc}"
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(target["ip"], port=target["port"], username=target["username"], password=target["password"], timeout=7, banner_timeout=7, auth_timeout=7)
        return "connected", "SSH 인증 성공"
    except paramiko.AuthenticationException:
        return "auth_failed", "SSH Port는 열렸지만 인증에 실패했습니다."
    except Exception as exc:
        return "unreachable", f"SSH 연결 실패: {exc.__class__.__name__}: {exc}"
    finally:
        client.close()
