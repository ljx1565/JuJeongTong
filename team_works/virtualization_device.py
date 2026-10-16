#!/usr/bin/env python3
"""ESXi 및 XenServer용 HV-01~HV-25 읽기 전용 보안 점검기.

ESXi는 HTTPS vSphere API로, XenServer는 SSH로 설정을 조회한다.
설정을 변경하거나 서비스를 재시작하지 않는다. 결과는 화면과 JSON 보고서로 남긴다.
"""

from __future__ import annotations

import argparse
import csv
import getpass
import io
import json
import os
import re
import shlex
import ssl
import sys
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import urlparse

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass

try:
    import paramiko
except ImportError:
    paramiko = None  # type: ignore[assignment]

try:
    import requests
except ImportError:
    requests = None  # type: ignore[assignment]

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None  # type: ignore[assignment,misc]

try:
    from pyVim.connect import Disconnect as VsphereDisconnect
    from pyVim.connect import SmartConnect
    from pyVmomi import vim
except ImportError:
    SmartConnect = None  # type: ignore[assignment]
    VsphereDisconnect = None  # type: ignore[assignment]
    vim = None  # type: ignore[assignment]


class Status(str, Enum):
    GOOD = "양호"
    VULNERABLE = "취약"
    REVIEW = "검토필요"
    ERROR = "오류"
    NOT_APPLICABLE = "해당없음"


@dataclass
class CheckResult:
    code: str
    title: str
    status: Status
    evidence: str
    recommendation: str = ""


SimpleResult = tuple[str, str]


@dataclass
class CommandResult:
    command: str
    exit_status: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.exit_status == 0


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _as_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {
        "1",
        "true",
        "yes",
        "y",
        "on",
        "enabled",
    }


def _first_int(text: str) -> int | None:
    match = re.search(r"-?\d+", text)
    return int(match.group(0)) if match else None


def _character_classes(value: str) -> int:
    return sum(
        bool(pattern.search(value))
        for pattern in (
            re.compile(r"[a-z]"),
            re.compile(r"[A-Z]"),
            re.compile(r"\d"),
            re.compile(r"[^A-Za-z0-9]"),
        )
    )


def _complexity_ok(value: str) -> bool:
    """2종 10자 또는 3종 8자 이상의 문자열 복잡도 기준을 적용한다."""
    classes = _character_classes(value)
    return (classes >= 3 and len(value) >= 8) or (
        classes >= 2 and len(value) >= 10
    )


class _BaseAuditor:
    """SSH/HTTP 연결, 읽기 전용 명령 실행 및 보고서 저장을 담당한다."""

    def __init__(self, connection_info: Mapping[str, Any] | None = None):
        self.info = self._connection_info(connection_info)
        self.ip = str(self.info["ip"])
        self.user_id = str(self.info["id"])
        self._password = str(self.info.get("pw", ""))
        self.ssh_port = int(self.info.get("ssh_port", 22))
        self.timeout = float(self.info.get("timeout", 10))
        self.verify_tls = _as_bool(self.info.get("verify_tls"), True)
        self.tls_verify: bool | str = (
            str(self.info["ca_bundle"])
            if self.info.get("ca_bundle")
            else self.verify_tls
        )
        self.strict_host_key = _as_bool(
            self.info.get("strict_host_key"), True
        )
        self.use_ssh = _as_bool(self.info.get("use_ssh"), True)
        self.use_http = _as_bool(self.info.get("use_http"), True)
        scheme = str(self.info.get("scheme", "https")).lower()
        raw_base_url = str(
            self.info.get("url") or f"{scheme}://{self.ip}"
        )
        parsed_base = urlparse(raw_base_url)
        self.base_url = (
            raw_base_url
            if parsed_base.path not in {"", "/"}
            and raw_base_url.endswith("/")
            else raw_base_url.rstrip("/")
        )
        self._ssh: Any = None
        self._http: Any = None
        self._home_response: Any = None
        self._connection_errors: list[str] = []
        self._command_cache: dict[str, CommandResult] = {}
        if _as_bool(self.info.get("auto_connect"), True):
            self.connect()

    @staticmethod
    def _connection_info(
        connection_info: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        if connection_info is None:
            return {
                "ip": input("IP 또는 호스트명: ").strip(),
                "id": input("접속 ID: ").strip(),
                "pw": getpass.getpass("접속 비밀번호: "),
            }

        info = dict(connection_info)
        aliases = {
            "host": "ip",
            "hostname": "ip",
            "username": "id",
            "user": "id",
            "password": "pw",
        }
        for old, new in aliases.items():
            if new not in info and old in info:
                info[new] = info[old]

        if "pw" not in info and info.get("pw_env"):
            info["pw"] = os.environ.get(str(info["pw_env"]), "")

        missing = [key for key in ("ip", "id") if key not in info]
        if missing:
            raise ValueError(
                "접속 정보에 다음 키가 필요합니다: " + ", ".join(missing)
            )
        if not str(info["ip"]).strip():
            raise ValueError("ip는 비어 있을 수 없습니다.")
        info.setdefault("pw", "")
        return info

    def connect(self) -> None:
        """SSH와 HTTP를 독립적으로 연결해 한쪽 실패 시에도 증적을 수집한다."""
        if self.use_ssh and self._ssh is None:
            self._connect_ssh()
        if self.use_http and self._http is None:
            self._connect_http()
        if (
            self.use_http
            and self._home_response is None
            and self._http is not None
        ):
            try:
                self._home_response = self._request("GET", self.base_url)
            except Exception as exc:
                self._connection_errors.append(
                    f"HTTP 연결 실패: {type(exc).__name__}: {exc}"
                )

    def _connect_ssh(self) -> None:
        if paramiko is None:
            self._connection_errors.append(
                "SSH 연결 실패: paramiko 패키지가 설치되지 않았습니다."
            )
            return

        client = paramiko.SSHClient()
        client.load_system_host_keys()
        known_hosts = self.info.get("known_hosts")
        if known_hosts:
            client.load_host_keys(str(known_hosts))
        if self.strict_host_key:
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.WarningPolicy())

        connect_options: dict[str, Any] = {
            "hostname": self.ip,
            "port": self.ssh_port,
            "username": self.user_id,
            "password": self._password or None,
            "timeout": self.timeout,
            "banner_timeout": self.timeout,
            "auth_timeout": self.timeout,
            "allow_agent": _as_bool(
                self.info.get("allow_agent"), True
            ),
            "look_for_keys": _as_bool(
                self.info.get("look_for_keys"), True
            ),
        }
        key_filename = self.info.get("key_filename")
        if key_filename:
            connect_options["key_filename"] = key_filename

        try:
            client.connect(**connect_options)
            self._ssh = client
        except Exception as exc:
            client.close()
            self._connection_errors.append(
                f"SSH 연결 실패: {type(exc).__name__}: {exc}"
            )

    def _connect_http(self) -> None:
        if requests is None:
            self._connection_errors.append(
                "HTTP 연결 실패: requests 패키지가 설치되지 않았습니다."
            )
            return

        session = requests.Session()
        session.headers.update(
            {
                "User-Agent": "HV-ReadOnly-Audit/1.0",
                "Accept": (
                    "text/html,application/xhtml+xml,"
                    "application/json;q=0.8,*/*;q=0.5"
                ),
            }
        )
        custom_headers = self.info.get("headers")
        if isinstance(custom_headers, Mapping):
            session.headers.update(
                {str(key): str(value) for key, value in custom_headers.items()}
            )
        if str(self.info.get("web_auth", "")).lower() == "basic":
            session.auth = (self.user_id, self._password)
        self._http = session

    def _request(self, method: str, url: str, **kwargs: Any) -> Any:
        if self._http is None:
            raise RuntimeError("HTTP 세션이 없습니다.")
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.tls_verify)
        kwargs.setdefault("allow_redirects", True)
        response = self._http.request(method, url, **kwargs)
        max_bytes = int(self.info.get("max_response_bytes", 2_000_000))
        if len(response.content) > max_bytes:
            raise RuntimeError(
                f"응답이 허용 크기({max_bytes} bytes)를 초과했습니다."
            )
        return response

    def _ssh_run(
        self, command: str, timeout: float | None = None
    ) -> CommandResult:
        if command in self._command_cache:
            return self._command_cache[command]
        if self._ssh is None:
            result = CommandResult(
                command, 255, "", "SSH 연결이 없습니다."
            )
            self._command_cache[command] = result
            return result

        try:
            _, stdout, stderr = self._ssh.exec_command(
                command,
                timeout=timeout or max(self.timeout, 20),
                get_pty=False,
            )
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            status = stdout.channel.recv_exit_status()
            limit = int(
                self.info.get("max_command_output", 500_000)
            )
            result = CommandResult(
                command, status, out[:limit], err[:limit]
            )
        except Exception as exc:
            result = CommandResult(
                command, 255, "", f"{type(exc).__name__}: {exc}"
            )
        self._command_cache[command] = result
        return result

    def _sanitize(self, text: Any, limit: int = 1200) -> str:
        value = (
            str(text).replace(self._password, "[REDACTED]")
            if self._password
            else str(text)
        )
        value = re.sub(
            (
                r"(?im)\b(password|passwd|community|secret|token|"
                r"authorization)\b\s*[:=]\s*[^\s,;]+"
            ),
            r"\1=[REDACTED]",
            value,
        )
        value = re.sub(r"[\r\n\t ]+", " ", value).strip()
        return value[:limit]

    def _result(
        self,
        code: str,
        title: str,
        status: Status,
        evidence: Any,
        recommendation: str = "",
    ) -> CheckResult:
        return CheckResult(
            code,
            title,
            status,
            self._sanitize(evidence),
            recommendation,
        )

    def _simple_result(self, result: CheckResult) -> SimpleResult:
        reason = f"{result.title}: {result.evidence}"
        if result.recommendation:
            reason += (
                " | 권고: " + self._sanitize(result.recommendation)
            )
        return result.status.value, reason

    def save_report(
        self, results: Sequence[CheckResult], path: str | Path
    ) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "generated_at": _now_iso(),
            "auditor": type(self).__name__,
            "target": {
                "ip": self.ip,
                "url": (
                    self.base_url
                    if getattr(self, "connection_mode", "")
                    == "https-vsphere-api"
                    else None
                ),
                "connection_mode": getattr(
                    self, "connection_mode", "unknown"
                ),
                "ssh_port": (
                    self.ssh_port
                    if getattr(self, "connection_mode", "") == "ssh"
                    else None
                ),
                "api_port": (
                    int(self.info.get("api_port", 443))
                    if getattr(self, "connection_mode", "")
                    == "https-vsphere-api"
                    else None
                ),
                "platform": getattr(self, "platform", "unknown"),
                "platform_detail": getattr(
                    self, "platform_detail", ""
                ),
            },
            "connection_errors": [
                self._sanitize(item) for item in self._connection_errors
            ],
            "summary": {
                status.value: sum(
                    result.status == status for result in results
                )
                for status in Status
            },
            "results": [
                {
                    **asdict(result),
                    "status": result.status.value,
                }
                for result in results
            ],
        }
        target.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return target.resolve()

    def close(self) -> None:
        if self._ssh is not None:
            self._ssh.close()
            self._ssh = None
        if self._http is not None:
            self._http.close()
            self._http = None

    def __enter__(self) -> _BaseAuditor:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class _LegacySshVirtualHost(_BaseAuditor):
    """XenServer SSH 점검 분기를 재사용하기 위한 내부 구현.

    이 클래스는 외부에 노출하지 않는다. 공개 Virtual_Host는 ESXi일 때 모든
    check_hv 메서드를 HTTPS API 구현으로 재정의하고 SSH 실행도 차단한다.
    """

    TITLES: ClassVar[dict[str, str]] = {
        "HV-01": "계정 로그오프/세션 관리",
        "HV-02": "가상화 장비 외부접속 차단",
        "HV-03": "가상화 장비 루트계정 관리",
        "HV-04": "가상화 장비 계정 권한 관리",
        "HV-05": "가상화 장비 사용자 인증 강화",
        "HV-06": "비밀번호 관리정책 설정",
        "HV-07": "계정 잠금 임계값 설정",
        "HV-08": "시스템 사용 주의사항 출력 설정",
        "HV-09": "NTP 및 시각 동기화 설정",
        "HV-10": "SNMP Community String 복잡성 적용",
        "HV-11": "MOB(Managed Object Browser) 서비스 비활성화",
        "HV-12": "ESXi Shell 비활성화",
        "HV-13": "ESXi Shell 세션 종료 시간 설정",
        "HV-14": "원격 로그 서버 이용",
        "HV-15": "시스템 주요 이벤트 로그 설정",
        "HV-16": "비휘발성 경로 내 로그 파일 저장",
        "HV-17": "코어덤프 수집 기능 활성화",
        "HV-18": "가상 머신의 장치 변경 제한 설정",
        "HV-19": "가상 머신의 불필요한 장치 제거",
        "HV-20": "가상 머신 콘솔 클립보드 복사&붙여넣기 기능 비활성화",
        "HV-21": "가상 머신 콘솔 드래그 앤 드롭 기능 비활성화",
        "HV-22": "가상 스위치 MAC 주소 변경 정책 비활성화",
        "HV-23": "가상 스위치 무차별(Promiscuous) 모드 정책 비활성화",
        "HV-24": "가상 스위치 위조전송(Forged Transmits) 모드 정책 비활성화",
        "HV-25": "주기적 보안 패치 및 벤더 권고사항 적용",
    }

    def __init__(self, connection_info: Mapping[str, Any] | None = None):
        super().__init__(connection_info)
        self.platform, self.platform_detail = self._detect_platform()
        self.console_snapshot = self._inspect_console_page()
        self._vm_cache: list[tuple[int, str]] | None = None
        self._vm_cache_truncated = False
        self._switch_cache: list[tuple[str, dict[str, bool | None]]] | None = None
        self._switch_has_dvs = False
        self._portgroup_parse_failed = False

    def _detect_platform(self) -> tuple[str, str]:
        probe = self._ssh_run(
            "if command -v vmware >/dev/null 2>&1; then vmware -vl; "
            "elif command -v vpxd >/dev/null 2>&1; then echo VCENTER; vpxd -v 2>/dev/null; "
            "elif command -v xe >/dev/null 2>&1; then echo XENSERVER; xe host-list params=software-version 2>/dev/null; "
            "elif command -v ncli >/dev/null 2>&1; then echo NUTANIX; ncli --version 2>/dev/null; "
            "elif command -v virsh >/dev/null 2>&1; then echo KVM; virsh --version 2>/dev/null; "
            "else uname -a 2>/dev/null; fi"
        )
        text = f"{probe.stdout}\n{probe.stderr}"
        lowered = text.lower()
        if "vmware esxi" in lowered:
            return "esxi", self._sanitize(text, 400)
        if "vcenter" in lowered:
            return "vcenter", self._sanitize(text, 400)
        if "xenserver" in lowered or "xenserver" in text:
            return "xenserver", self._sanitize(text, 400)
        if "nutanix" in lowered:
            return "nutanix", self._sanitize(text, 400)
        if "kvm" in text or ("virsh" in lowered and probe.ok):
            return "kvm", self._sanitize(text, 400)

        body = getattr(self._home_response, "text", "") or ""
        if re.search(
            r"VMware\s+(?:ESXi|Host Client)|/ui/(?:#|index)", body, re.IGNORECASE
        ):
            return "esxi-web-only", "VMware ESXi 웹 콘솔 HTML 패턴으로 탐지됨"
        if re.search(r"vCenter|vSphere Client", body, re.IGNORECASE):
            return "vcenter-web-only", "vCenter/vSphere 웹 콘솔 HTML 패턴으로 탐지됨"
        return "unknown", self._sanitize(text or "플랫폼을 식별하지 못했습니다.", 400)

    def _inspect_console_page(self) -> dict[str, Any]:
        response = self._home_response
        if response is None:
            return {"available": False, "error": "웹 콘솔 응답 없음"}
        body = response.text or ""
        title = ""
        if BeautifulSoup is not None:
            soup = BeautifulSoup(body, "html.parser")
            title = soup.title.get_text(" ", strip=True) if soup.title else ""
        markers = []
        for name, pattern in {
            "VMware ESXi": r"VMware\s+(?:ESXi|Host Client)|/ui/(?:#|index)",
            "vCenter/vSphere": r"vCenter|vSphere Client",
            "Nutanix": r"Nutanix|Prism",
            "XenServer": r"XenServer|Citrix Hypervisor",
        }.items():
            if re.search(pattern, body, re.IGNORECASE):
                markers.append(name)
        auth_form = bool(
            re.search(
                r"type=[\"']password[\"']|login|sign.?in|로그인",
                body[:500_000],
                re.IGNORECASE,
            )
        )
        return {
            "available": True,
            "status_code": response.status_code,
            "url": response.url,
            "title": title,
            "vendor_markers": markers,
            "authentication_page": auth_form,
            "html_length": len(body),
        }

    def get_console_html(self) -> str:
        """웹 콘솔에서 받은 원본 HTML을 메모리에서 반환한다."""
        return getattr(self._home_response, "text", "") or ""

    def save_console_html(self, path: str | Path) -> Path:
        """명시적으로 요청한 경우에만 웹 콘솔 HTML을 파일로 저장한다."""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self.get_console_html(), encoding="utf-8")
        return target.resolve()

    @staticmethod
    def _advanced_value(text: str) -> tuple[str | None, str | None]:
        for key in ("Int Value", "String Value", "Bool Value"):
            match = re.search(rf"(?im)^\s*{re.escape(key)}\s*:\s*(.*?)\s*$", text)
            if match:
                return match.group(1).strip(), key
        return None, None

    def _esxi_advanced(self, path: str) -> tuple[str | None, CommandResult]:
        result = self._ssh_run(
            "esxcli system settings advanced list -o "
            + shlex.quote(path)
            + " 2>/dev/null"
        )
        value, _ = self._advanced_value(result.stdout)
        return value, result

    def _unsupported(self, code: str, reason: str = "") -> CheckResult:
        detail = (
            reason
            or f"탐지 플랫폼 {self.platform}에는 가이드상 이 항목이 적용되지 않습니다."
        )
        return self._result(code, self.TITLES[code], Status.NOT_APPLICABLE, detail)

    def _review(
        self, code: str, evidence: str, recommendation: str = ""
    ) -> CheckResult:
        return self._result(
            code, self.TITLES[code], Status.REVIEW, evidence, recommendation
        )

    def _ssh_required(self, code: str) -> CheckResult | None:
        if self._ssh is not None:
            return None
        console = json.dumps(self.console_snapshot, ensure_ascii=False)
        return self._result(
            code,
            self.TITLES[code],
            Status.ERROR,
            f"SSH 조회 불가. 웹 콘솔 응답 증적: {console}. "
            "웹 로그인 초기 HTML만으로 내부 설정값을 확정할 수 없습니다.",
        )

    @staticmethod
    def _permissions(text: str) -> list[tuple[str, str]]:
        permissions: list[tuple[str, str]] = []
        for line in text.splitlines():
            match = re.match(
                r"^\s*(.+?)\s+(?:true|false)\s+(Admin|ReadOnly|NoAccess)\s+(?:.+?)\s*$",
                line,
                re.IGNORECASE,
            )
            if match and match.group(1).strip().lower() != "principal":
                permissions.append((match.group(1).strip(), match.group(2)))
        if permissions:
            return permissions

        # 구버전 환경에서 vim-cmd 형태가 반환될 때의 호환 파서.
        blocks = re.findall(
            r"\(vim\.AuthorizationManager\.Permission\)\s*\{(.*?)\n\s*\}",
            text,
            re.DOTALL,
        )
        for block in blocks:
            principal = re.search(r'principal\s*=\s*"([^"]+)"', block)
            role = re.search(r"roleId\s*=\s*(-?\d+)", block)
            if principal and role:
                role_name = {"-1": "Admin", "-2": "ReadOnly", "-3": "NoAccess"}.get(
                    role.group(1), role.group(1)
                )
                permissions.append((principal.group(1), role_name))
        return permissions

    def _account_names(self) -> list[str]:
        if self.platform.startswith("esxi"):
            result = self._ssh_run("esxcli system account list 2>/dev/null")
            names: list[str] = []
            for line in result.stdout.splitlines():
                match = re.match(r"^\s*([A-Za-z0-9_.@-]+)\s{2,}.*$", line)
                if match and match.group(1).lower() not in {
                    "user",
                    "userid",
                    "user-id",
                }:
                    names.append(match.group(1))
            return sorted(set(names))
        result = self._ssh_run(
            "awk -F: '$7 ~ /(bash|sh)$/ {print $1}' /etc/passwd 2>/dev/null"
        )
        return sorted(
            {line.strip() for line in result.stdout.splitlines() if line.strip()}
        )

    def check_hv01(self) -> CheckResult:
        code = "HV-01"
        missing = self._ssh_required(code)
        if missing:
            return missing
        if self.platform.startswith("esxi"):
            value, result = self._esxi_advanced("/UserVars/HostClientSessionTimeout")
            seconds = _first_int(value or "")
            if seconds is None:
                return self._result(
                    code,
                    self.TITLES[code],
                    Status.ERROR,
                    result.stderr or "설정값을 읽지 못했습니다.",
                )
            status = Status.GOOD if 1 <= seconds <= 600 else Status.VULNERABLE
            return self._result(
                code,
                self.TITLES[code],
                status,
                f"UserVars.HostClientSessionTimeout={seconds}초",
                "웹 콘솔/셸 세션 타임아웃을 1~600초로 설정하세요."
                if status == Status.VULNERABLE
                else "",
            )
        result = self._ssh_run(
            "grep -hE '^[[:space:]]*(readonly[[:space:]]+)?TMOUT[[:space:]]*=' "
            "/etc/profile /etc/profile.d/*.sh 2>/dev/null | tail -n 20"
        )
        values = [
            int(value) for value in re.findall(r"TMOUT\s*=\s*(\d+)", result.stdout)
        ]
        if not values:
            return self._result(
                code,
                self.TITLES[code],
                Status.VULNERABLE,
                "시스템 프로파일에서 TMOUT 설정을 찾지 못했습니다.",
            )
        highest = max(values)
        status = Status.GOOD if 1 <= highest <= 600 else Status.VULNERABLE
        return self._result(code, self.TITLES[code], status, f"탐지 TMOUT 값={values}")

    def check_hv02(self) -> CheckResult:
        code = "HV-02"
        missing = self._ssh_required(code)
        if missing:
            return missing
        if self.platform.startswith("esxi"):
            result = self._ssh_run(
                "esxcli network firewall ruleset allowedip list 2>/dev/null"
            )
            if not result.ok and not result.stdout:
                return self._result(
                    code, self.TITLES[code], Status.ERROR, result.stderr
                )
            rows: dict[str, str] = {}
            for line in result.stdout.splitlines():
                match = re.match(
                    r"^\s*(sshServer|webAccess|vSphereClient)\s+(.+?)\s*$",
                    line,
                    re.IGNORECASE,
                )
                if match:
                    rows[match.group(1)] = match.group(2)
            has_ssh = any(name.lower() == "sshserver" for name in rows)
            has_web = any(
                name.lower() in {"webaccess", "vsphereclient"} for name in rows
            )
            if (
                has_ssh
                and has_web
                and all(
                    not re.search(r"\bAll\b|0\.0\.0\.0/0|::/0", value, re.IGNORECASE)
                    for value in rows.values()
                )
            ):
                return self._result(
                    code,
                    self.TITLES[code],
                    Status.GOOD,
                    f"관리 ruleset {len(rows)}개가 허용 IP 목록으로 제한됨.",
                )
            if rows:
                # 검증필: ESXi 자체 허용 IP가 All이어도 상위 방화벽/VPN에서 제한할 수 있다.
                return self._review(
                    code,
                    "ESXi 관리 ruleset 중 전체 주소 허용 설정이 있습니다. 상위 방화벽/VPN 통제 증적을 함께 확인하세요.",
                    "ESXi 또는 상위 방화벽에서 관리 IP만 허용하세요.",
                )
            return self._review(
                code, "sshServer/webAccess 허용 IP 설정을 파싱하지 못했습니다."
            )
        firewall = self._ssh_run(
            "(nft list ruleset 2>/dev/null || iptables -S 2>/dev/null || firewall-cmd --list-all 2>/dev/null); "
            "printf '\nHOSTS_ALLOW\n'; grep -vE '^[[:space:]]*(#|$)' /etc/hosts.allow 2>/dev/null"
        )
        # 검증필: 로컬 방화벽만으로 외부 경계/VPN의 전체 접근 경로를 확정할 수 없다.
        return self._review(
            code,
            f"로컬 접근통제 설정 {len(firewall.stdout.splitlines())}줄 수집. 허용 관리망 정책과 대조가 필요합니다.",
        )

    def check_hv03(self) -> CheckResult:
        code = "HV-03"
        if self.platform not in {
            "esxi",
            "esxi-web-only",
            "vcenter",
            "vcenter-web-only",
        }:
            return self._unsupported(code)
        missing = self._ssh_required(code)
        if missing:
            return missing
        result = self._ssh_run("esxcli system permission list 2>/dev/null")
        permissions = self._permissions(result.stdout)
        if not permissions:
            return self._review(
                code,
                "권한 목록을 파싱하지 못했습니다. 웹 콘솔의 호스트 > 작업 > 사용 권한에서 확인하세요.",
            )
        root_admin = any(
            principal.lower() == "root" and role.lower() == "admin"
            for principal, role in permissions
        )
        alternate_admin = any(
            principal.lower() != "root" and role.lower() == "admin"
            for principal, role in permissions
        )
        if not root_admin and alternate_admin:
            return self._result(
                code,
                self.TITLES[code],
                Status.GOOD,
                "root 외 관리자 존재 및 root 최고관리자 권한 미탐지.",
            )
        if root_admin:
            return self._result(
                code,
                self.TITLES[code],
                Status.VULNERABLE,
                f"root 최고관리자 권한 탐지; 별도 최고관리자 존재={alternate_admin}.",
                "별도 관리자 계정을 만든 후 root 관리자 권한을 제거하세요.",
            )
        return self._review(
            code, "root 최고관리자 권한은 없으나 별도 최고관리자도 식별되지 않았습니다."
        )

    def check_hv04(self) -> CheckResult:
        code = "HV-04"
        missing = self._ssh_required(code)
        if missing:
            return missing
        accounts = self._account_names()
        expected = self.info.get("expected_accounts")
        if not isinstance(expected, Sequence) or isinstance(expected, (str, bytes)):
            # 검증필: 퇴사자·공용·서비스 계정 여부는 조직의 승인 계정 목록이 필요하다.
            return self._review(
                code,
                f"로그인 가능 계정 {len(accounts)}개 수집. expected_accounts 정책과 대조가 필요합니다.",
            )
        extras = sorted(set(accounts) - {str(item) for item in expected})
        if extras:
            return self._result(
                code,
                self.TITLES[code],
                Status.VULNERABLE,
                "승인 목록 외 계정: " + ", ".join(extras),
                "서비스 영향 확인 후 불필요 계정을 제거하세요.",
            )
        return self._result(
            code,
            self.TITLES[code],
            Status.GOOD,
            f"수집 계정 {len(accounts)}개가 승인 목록과 일치합니다.",
        )

    def check_hv05(self) -> CheckResult:
        code = "HV-05"
        missing = self._ssh_required(code)
        if missing:
            return missing
        expected = self.info.get("expected_admin_accounts")
        if not isinstance(expected, Sequence) or isinstance(expected, (str, bytes)):
            # 검증필: 최소권한 여부는 직무별 승인 관리자 목록이 필요하다.
            return self._review(
                code,
                "expected_admin_accounts가 없어 계정별 권한 적정성을 확정할 수 없습니다.",
            )
        allowed = {str(item) for item in expected}
        if self.platform.startswith("esxi"):
            result = self._ssh_run("esxcli system permission list 2>/dev/null")
            admins = {
                principal
                for principal, role in self._permissions(result.stdout)
                if role.lower() == "admin"
            }
            unexpected = sorted(admins - allowed)
            if unexpected:
                return self._result(
                    code,
                    self.TITLES[code],
                    Status.VULNERABLE,
                    "승인 목록 외 최고관리자: " + ", ".join(unexpected),
                )
            return self._result(
                code,
                self.TITLES[code],
                Status.GOOD,
                f"최고관리자 {len(admins)}개가 승인 목록 범위 내입니다.",
            )
        sudo = self._ssh_run(
            "getent group sudo 2>/dev/null; getent group wheel 2>/dev/null"
        )
        members: set[str] = set()
        for line in sudo.stdout.splitlines():
            parts = line.split(":")
            if len(parts) >= 4:
                members.update(filter(None, parts[3].split(",")))
        unexpected = sorted(members - allowed)
        if unexpected:
            return self._result(
                code,
                self.TITLES[code],
                Status.VULNERABLE,
                "승인 목록 외 sudo/wheel 계정: " + ", ".join(unexpected),
            )
        return self._result(
            code,
            self.TITLES[code],
            Status.GOOD,
            f"sudo/wheel 계정 {len(members)}개가 승인 목록 범위 내입니다.",
        )

    @staticmethod
    def _parse_password_minimums(value: str) -> list[int | None]:
        match = re.search(r"\bmin\s*=\s*([^\s]+)", value, re.IGNORECASE)
        if not match:
            return []
        values: list[int | None] = []
        for item in match.group(1).split(","):
            values.append(int(item) if item.isdigit() else None)
        return values

    def check_hv06(self) -> CheckResult:
        code = "HV-06"
        missing = self._ssh_required(code)
        if missing:
            return missing
        if self.platform.startswith("esxi"):
            quality, quality_result = self._esxi_advanced(
                "/Security/PasswordQualityControl"
            )
            max_days, days_result = self._esxi_advanced("/Security/PasswordMaxDays")
            minimums = self._parse_password_minimums(quality or "")
            days = _first_int(max_days or "")
            quality_ok = (
                len(minimums) >= 5
                and minimums[3] is not None
                and minimums[4] is not None
                and minimums[3] >= 8
                and minimums[4] >= 8
            )
            days_ok = days is not None and 1 <= days <= 90
            if quality is None or days is None:
                return self._result(
                    code,
                    self.TITLES[code],
                    Status.ERROR,
                    quality_result.stderr or days_result.stderr or "설정값 파싱 실패",
                )
            status = Status.GOOD if quality_ok and days_ok else Status.VULNERABLE
            evidence = (
                f"PasswordQualityControl 최소값={minimums}; PasswordMaxDays={days}"
            )
            return self._result(
                code,
                self.TITLES[code],
                status,
                evidence,
                "N3/N4를 8 이상, 최대 사용기간을 90일 이하로 설정하세요."
                if status == Status.VULNERABLE
                else "",
            )
        result = self._ssh_run(
            "grep -hE '^[[:space:]]*(PASS_MAX_DAYS|PASS_MIN_LEN)[[:space:]]+' /etc/login.defs 2>/dev/null; "
            "grep -hE '^[[:space:]]*(minlen|[ludoc]credit)[[:space:]]*=' /etc/security/pwquality.conf 2>/dev/null"
        )
        max_days = (
            _first_int(re.search(r"PASS_MAX_DAYS\s+(\d+)", result.stdout).group(1))
            if re.search(r"PASS_MAX_DAYS\s+(\d+)", result.stdout)
            else None
        )
        min_lengths = [
            int(value)
            for value in re.findall(
                r"(?:PASS_MIN_LEN\s+|minlen\s*=\s*)(\d+)", result.stdout
            )
        ]
        if max_days is None or not min_lengths:
            return self._result(
                code,
                self.TITLES[code],
                Status.VULNERABLE,
                "최대 사용기간 또는 최소 길이 정책을 찾지 못했습니다.",
            )
        status = (
            Status.GOOD
            if 1 <= max_days <= 90 and max(min_lengths) >= 8
            else Status.VULNERABLE
        )
        return self._result(
            code,
            self.TITLES[code],
            status,
            f"PASS_MAX_DAYS={max_days}, 최소길이 후보={min_lengths}",
        )

    def check_hv07(self) -> CheckResult:
        code = "HV-07"
        if self.platform == "xenserver" or self.platform == "nutanix":
            return self._unsupported(code)
        missing = self._ssh_required(code)
        if missing:
            return missing
        if self.platform.startswith("esxi"):
            failures_value, _ = self._esxi_advanced("/Security/AccountLockFailures")
            unlock_value, _ = self._esxi_advanced("/Security/AccountUnlockTime")
            failures = _first_int(failures_value or "")
            unlock = _first_int(unlock_value or "")
            if failures is None or unlock is None:
                return self._result(
                    code,
                    self.TITLES[code],
                    Status.ERROR,
                    "계정 잠금 설정값을 읽지 못했습니다.",
                )
            good = 1 <= failures <= 5 and unlock >= 600
            return self._result(
                code,
                self.TITLES[code],
                Status.GOOD if good else Status.VULNERABLE,
                f"AccountLockFailures={failures}, AccountUnlockTime={unlock}초",
            )
        result = self._ssh_run(
            "grep -hE '^[[:space:]]*(deny|unlock_time)[[:space:]]*=' /etc/security/faillock.conf 2>/dev/null; "
            "grep -hE 'pam_(faillock|tally)' /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/common-auth 2>/dev/null"
        )
        deny = (
            _first_int(re.search(r"\bdeny\s*=\s*(\d+)", result.stdout).group(1))
            if re.search(r"\bdeny\s*=\s*(\d+)", result.stdout)
            else None
        )
        if deny is None or deny <= 0:
            return self._result(
                code,
                self.TITLES[code],
                Status.VULNERABLE,
                "로그인 실패 횟수 제한을 찾지 못했습니다.",
            )
        return self._result(
            code,
            self.TITLES[code],
            Status.GOOD if deny <= 5 else Status.VULNERABLE,
            f"로그인 실패 임계값 deny={deny}",
        )

    def check_hv08(self) -> CheckResult:
        code = "HV-08"
        missing = self._ssh_required(code)
        if missing:
            return missing
        messages: list[str] = []
        if self.platform.startswith("esxi"):
            value, _ = self._esxi_advanced("/Annotations/WelcomeMessage")
            if value:
                messages.append(value)
        files = self._ssh_run(
            "cat /etc/motd /etc/issue /etc/issue.net 2>/dev/null; grep -iE '^[[:space:]]*Banner' /etc/ssh/sshd_config 2>/dev/null"
        )
        if files.stdout.strip():
            messages.append(files.stdout)
        combined = "\n".join(messages).strip()
        if not combined:
            return self._result(
                code,
                self.TITLES[code],
                Status.VULNERABLE,
                "웹/SSH 시스템 사용 주의사항 문구를 찾지 못했습니다.",
            )
        if re.search(
            r"VMware ESXi\s+\d|Linux\s+\S+\s+\d|kernel\s+\d", combined, re.IGNORECASE
        ):
            return self._result(
                code,
                self.TITLES[code],
                Status.VULNERABLE,
                "주의 문구에 제품/버전 정보가 포함된 것으로 탐지되었습니다.",
            )
        return self._result(
            code,
            self.TITLES[code],
            Status.GOOD,
            "웹 또는 SSH 사용 주의사항 문구가 설정되어 있고 대표 버전 패턴이 없습니다.",
        )

    def check_hv09(self) -> CheckResult:
        code = "HV-09"
        missing = self._ssh_required(code)
        if missing:
            return missing
        if self.platform.startswith("esxi"):
            result = self._ssh_run("esxcli system ntp get 2>/dev/null")
            enabled = bool(re.search(r"(?im)^\s*Enabled\s*:\s*true\s*$", result.stdout))
            servers = re.search(r"(?im)^\s*Servers\s*:\s*(.+?)\s*$", result.stdout)
            has_server = bool(
                servers and servers.group(1).strip() not in {"", "N/A", "None"}
            )
            status = Status.GOOD if enabled and has_server else Status.VULNERABLE
            return self._result(
                code,
                self.TITLES[code],
                status,
                f"NTP Enabled={enabled}, 서버 설정={has_server}",
            )
        result = self._ssh_run(
            "timedatectl show -p NTPSynchronized --value 2>/dev/null || chronyc tracking 2>/dev/null || ntpq -pn 2>/dev/null"
        )
        synchronized = bool(
            re.search(
                r"^yes$|Leap status\s*:\s*Normal|^\*",
                result.stdout,
                re.IGNORECASE | re.MULTILINE,
            )
        )
        return self._result(
            code,
            self.TITLES[code],
            Status.GOOD if synchronized else Status.VULNERABLE,
            f"시간 동기화 상태={synchronized}",
        )

    def check_hv10(self) -> CheckResult:
        code = "HV-10"
        missing = self._ssh_required(code)
        if missing:
            return missing
        if self.platform.startswith("esxi"):
            result = self._ssh_run("esxcli system snmp get 2>/dev/null")
            enabled = bool(re.search(r"(?im)^\s*Enabled\s*:\s*true\s*$", result.stdout))
            if not enabled:
                return self._result(
                    code,
                    self.TITLES[code],
                    Status.GOOD,
                    "SNMP가 비활성화되어 있습니다.",
                )
            match = re.search(r"(?im)^\s*Communities\s*:\s*(.*?)\s*$", result.stdout)
            values = [
                value.strip()
                for value in (match.group(1).split(",") if match else [])
                if value.strip()
            ]
            weak = [
                value
                for value in values
                if value.lower() in {"public", "private", "community"}
                or not _complexity_ok(value)
            ]
            if weak:
                return self._result(
                    code,
                    self.TITLES[code],
                    Status.VULNERABLE,
                    f"SNMP 활성; Community {len(values)}개 중 취약 복잡도 {len(weak)}개. 값은 저장하지 않았습니다.",
                )
            if values:
                return self._result(
                    code,
                    self.TITLES[code],
                    Status.GOOD,
                    f"SNMP 활성; Community {len(values)}개가 복잡도 기준을 만족합니다. 값은 저장하지 않았습니다.",
                )
            # 검증필: Community가 없으면 v3일 수 있으나 사용자/인증 설정 확인이 필요하다.
            return self._review(
                code,
                "SNMP가 활성화됐으나 Community가 비어 있습니다. SNMPv3 사용자/인증 설정을 확인하세요.",
            )
        result = self._ssh_run(
            "systemctl is-active snmpd 2>/dev/null; grep -hE '^[[:space:]]*(rocommunity|rwcommunity)[[:space:]]+' /etc/snmp/snmpd.conf 2>/dev/null"
        )
        lines = [
            line
            for line in result.stdout.splitlines()
            if re.match(r"\s*(rocommunity|rwcommunity)\s+", line)
        ]
        if "inactive" in result.stdout or "failed" in result.stdout:
            return self._result(
                code,
                self.TITLES[code],
                Status.GOOD,
                "SNMP 서비스가 비활성화되어 있습니다.",
            )
        values = [line.split()[1] for line in lines if len(line.split()) > 1]
        weak_count = sum(
            value.lower() in {"public", "private", "community"}
            or not _complexity_ok(value)
            for value in values
        )
        if weak_count:
            return self._result(
                code,
                self.TITLES[code],
                Status.VULNERABLE,
                f"Community {len(values)}개 중 취약 복잡도 {weak_count}개. 값은 저장하지 않았습니다.",
            )
        return self._review(
            code, "SNMP 활성 여부 또는 v3 설정을 완전히 확인하지 못했습니다."
        )

    def check_hv11(self) -> CheckResult:
        code = "HV-11"
        if self.platform not in {
            "esxi",
            "esxi-web-only",
            "vcenter",
            "vcenter-web-only",
        }:
            return self._unsupported(code)
        missing = self._ssh_required(code)
        if missing:
            return missing
        path = (
            "/Config/HostAgent/plugins/solo/enableMob"
            if self.platform.startswith("esxi")
            else "/Config/vpxd/enableDebugBrowse"
        )
        value, result = self._esxi_advanced(path)
        if value is None:
            return self._review(
                code,
                result.stderr
                or "MOB 설정값을 CLI에서 읽지 못했습니다. 웹 콘솔 고급 설정을 확인하세요.",
            )
        enabled = _as_bool(value)
        return self._result(
            code,
            self.TITLES[code],
            Status.VULNERABLE if enabled else Status.GOOD,
            f"MOB enabled={enabled}",
        )

    def check_hv12(self) -> CheckResult:
        code = "HV-12"
        if not self.platform.startswith("esxi"):
            return self._unsupported(code)
        missing = self._ssh_required(code)
        if missing:
            return missing
        result = self._ssh_run(
            "printf 'TSM\\n'; /etc/init.d/TSM status 2>&1; printf 'SSH\\n'; /etc/init.d/SSH status 2>&1"
        )
        text = result.stdout + result.stderr
        tsm_running = bool(
            re.search(
                r"TSM\s*\n(?![^\n]*not running)[^\n]*running", text, re.IGNORECASE
            )
        )
        ssh_running = bool(
            re.search(
                r"SSH\s*\n(?![^\n]*not running)[^\n]*running", text, re.IGNORECASE
            )
        )
        # SSH로 현재 점검 중이라면 TSM-SSH는 활성 상태이므로 가이드 기준상 취약이다.
        ssh_running = ssh_running or self._ssh is not None
        enabled = [
            name
            for name, state in (("TSM", tsm_running), ("TSM-SSH", ssh_running))
            if state
        ]
        if enabled:
            return self._result(
                code,
                self.TITLES[code],
                Status.VULNERABLE,
                "활성 서비스: " + ", ".join(enabled),
                "승인된 점검 종료 후 ESXi Shell/SSH 서비스를 중지하세요.",
            )
        return self._result(
            code,
            self.TITLES[code],
            Status.GOOD,
            "TSM 및 TSM-SSH가 비활성화되어 있습니다.",
        )

    def check_hv13(self) -> CheckResult:
        code = "HV-13"
        if not self.platform.startswith("esxi"):
            return self._unsupported(code)
        missing = self._ssh_required(code)
        if missing:
            return missing
        value, result = self._esxi_advanced("/UserVars/ESXiShellInteractiveTimeOut")
        seconds = _first_int(value or "")
        if seconds is None:
            return self._result(
                code,
                self.TITLES[code],
                Status.ERROR,
                result.stderr or "설정값 파싱 실패",
            )
        # PDF 조치 문구에는 900 이하가 있으나 판단 기준/Step 4의 600 이하를 우선 적용한다.
        good = 1 <= seconds <= 600
        return self._result(
            code,
            self.TITLES[code],
            Status.GOOD if good else Status.VULNERABLE,
            f"ESXiShellInteractiveTimeOut={seconds}초",
        )

    def check_hv14(self) -> CheckResult:
        code = "HV-14"
        missing = self._ssh_required(code)
        if missing:
            return missing
        if self.platform.startswith("esxi"):
            value, result = self._esxi_advanced("/Syslog/global/logHost")
            if value is None:
                return self._result(
                    code,
                    self.TITLES[code],
                    Status.ERROR,
                    result.stderr or "설정값 파싱 실패",
                )
            configured = bool(value.strip())
            return self._result(
                code,
                self.TITLES[code],
                Status.GOOD if configured else Status.VULNERABLE,
                f"원격 Syslog 대상 설정={configured}",
            )
        result = self._ssh_run(
            "grep -hE '^[[:space:]]*[^#].*(@@?|omfwd)' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null"
        )
        configured = bool(result.stdout.strip())
        return self._result(
            code,
            self.TITLES[code],
            Status.GOOD if configured else Status.VULNERABLE,
            f"원격 rsyslog 지시어 설정={configured}",
        )

    def check_hv15(self) -> CheckResult:
        code = "HV-15"
        if self.platform in {"xenserver", "nutanix"}:
            return self._unsupported(code)
        missing = self._ssh_required(code)
        if missing:
            return missing
        if self.platform.startswith("esxi"):
            value, result = self._esxi_advanced("/Config/HostAgent/log/level")
            if value is None:
                return self._result(
                    code,
                    self.TITLES[code],
                    Status.ERROR,
                    result.stderr or "설정값 파싱 실패",
                )
            lowered = value.strip().lower()
            if lowered in {"none", "quiet", ""}:
                return self._result(
                    code,
                    self.TITLES[code],
                    Status.VULNERABLE,
                    f"Config.HostAgent.log.level={value}",
                )
            expected = self.info.get("expected_log_levels")
            if isinstance(expected, Sequence) and not isinstance(
                expected, (str, bytes)
            ):
                allowed = {str(item).lower() for item in expected}
                return self._result(
                    code,
                    self.TITLES[code],
                    Status.GOOD if lowered in allowed else Status.VULNERABLE,
                    f"로그 레벨={value}; 승인 레벨 정책과 대조함.",
                )
            # 검증필: 가이드 기준이 '내부 정책 부합'이므로 정책값 없이는 확정할 수 없다.
            return self._review(
                code,
                f"로그 레벨={value}. expected_log_levels와의 정책 대조가 필요합니다.",
            )
        result = self._ssh_run(
            "grep -hE '^[[:space:]]*log_level[[:space:]]*=' /etc/libvirt/libvirtd.conf /etc/libvirt/virtqemud.conf 2>/dev/null"
        )
        return self._review(
            code,
            f"libvirt 로그 레벨 설정 수집={bool(result.stdout.strip())}; 내부 정책과 대조가 필요합니다.",
        )

    def check_hv16(self) -> CheckResult:
        code = "HV-16"
        if not self.platform.startswith("esxi"):
            return self._unsupported(code)
        missing = self._ssh_required(code)
        if missing:
            return missing
        value, result = self._esxi_advanced("/Syslog/global/logDir")
        if value is None:
            return self._result(
                code,
                self.TITLES[code],
                Status.ERROR,
                result.stderr or "설정값 파싱 실패",
            )
        path = value.strip()
        if not path:
            return self._result(
                code,
                self.TITLES[code],
                Status.VULNERABLE,
                "Syslog.global.logDir가 비어 있습니다.",
            )
        if re.match(r"^\[[^]]+\]", path) or path.startswith("/vmfs/volumes/"):
            return self._result(
                code,
                self.TITLES[code],
                Status.GOOD,
                "로그 경로가 데이터스토어/비휘발성 볼륨 형식입니다.",
            )
        if any(
            path == prefix or path.startswith(prefix + "/")
            for prefix in ("/tmp", "/var/tmp", "/run", "/dev/shm", "/dev/pts")
        ):
            return self._result(
                code, self.TITLES[code], Status.VULNERABLE, f"휘발성 로그 경로={path}"
            )
        if path.startswith(("/scratch", "[scratch]")):
            resolved = self._ssh_run("readlink -f /scratch 2>/dev/null")
            if resolved.stdout.strip().startswith("/vmfs/volumes/"):
                return self._result(
                    code,
                    self.TITLES[code],
                    Status.GOOD,
                    "scratch가 비휘발성 /vmfs/volumes 경로를 가리킵니다.",
                )
            # 검증필: /scratch의 영속성은 설치 방식/링크 대상에 따라 달라진다.
            return self._review(
                code,
                f"로그 경로={path}; /scratch 실제 대상의 비휘발성 여부를 확인하세요.",
            )
        return self._review(
            code, f"로그 경로={path}; 마운트의 비휘발성 여부를 확인하세요."
        )

    def check_hv17(self) -> CheckResult:
        code = "HV-17"
        if not self.platform.startswith("esxi"):
            return self._unsupported(code)
        missing = self._ssh_required(code)
        if missing:
            return missing
        get_result = self._ssh_run("esxcli system coredump network get 2>/dev/null")
        check_result = self._ssh_run("esxcli system coredump network check 2>/dev/null")
        enabled = bool(re.search(r"(?im)^\s*Enabled\s*:\s*true\s*$", get_result.stdout))
        healthy = check_result.ok and not re.search(
            r"failed|invalid|not configured",
            check_result.stdout + check_result.stderr,
            re.IGNORECASE,
        )
        status = Status.GOOD if enabled and healthy else Status.VULNERABLE
        return self._result(
            code,
            self.TITLES[code],
            status,
            f"네트워크 코어덤프 Enabled={enabled}, 구성 확인 성공={healthy}",
        )

    def _esxi_vm_configs(self) -> list[tuple[int, str]]:
        if self._vm_cache is not None:
            return self._vm_cache
        listing = self._ssh_run("vim-cmd vmsvc/getallvms 2>/dev/null")
        ids = [int(value) for value in re.findall(r"(?m)^\s*(\d+)\s+", listing.stdout)]
        maximum = int(self.info.get("max_vms", 200))
        self._vm_cache_truncated = len(ids) > maximum
        configs: list[tuple[int, str]] = []
        for vmid in ids[:maximum]:
            result = self._ssh_run(f"vim-cmd vmsvc/get.config {vmid} 2>/dev/null")
            configs.append((vmid, result.stdout))
        self._vm_cache = configs
        return configs

    @staticmethod
    def _vm_option_value(config: str, key: str) -> str | None:
        match = re.search(
            rf'key\s*=\s*"{re.escape(key)}".*?value\s*=\s*"([^"]*)"',
            config,
            re.IGNORECASE | re.DOTALL,
        )
        return match.group(1).strip() if match else None

    def _vm_option_check(self, code: str, expected: Mapping[str, str]) -> CheckResult:
        if not self.platform.startswith("esxi"):
            return self._unsupported(code)
        missing = self._ssh_required(code)
        if missing:
            return missing
        configs = self._esxi_vm_configs()
        if not configs:
            return self._review(
                code, "가상 머신이 없거나 구성 정보를 조회하지 못했습니다."
            )
        noncompliant: list[int] = []
        for vmid, config in configs:
            if any(
                (self._vm_option_value(config, key) or "").lower() != value.lower()
                for key, value in expected.items()
            ):
                noncompliant.append(vmid)
        if self._vm_cache_truncated:
            return self._review(
                code,
                f"최대 점검 개수까지만 확인했습니다. 비준수 VM ID 수={len(noncompliant)}",
            )
        if noncompliant:
            return self._result(
                code,
                self.TITLES[code],
                Status.VULNERABLE,
                f"점검 VM {len(configs)}개 중 설정 누락/불일치 {len(noncompliant)}개; VM ID={noncompliant[:30]}",
            )
        return self._result(
            code,
            self.TITLES[code],
            Status.GOOD,
            f"점검 VM {len(configs)}개가 요구 구성값을 만족합니다.",
        )

    def check_hv18(self) -> CheckResult:
        return self._vm_option_check(
            "HV-18",
            {
                "isolation.device.edit.disable": "true",
                "isolation.device.connectable.disable": "true",
            },
        )

    def check_hv19(self) -> CheckResult:
        code = "HV-19"
        if self.platform == "xenserver":
            # 검증필: XenServer 장치의 업무 필요성은 VM별 승인 장치 목록이 필요하다.
            return self._review(
                code,
                "XenServer는 VM별 승인 USB/CD/DVD/포트 목록과 xe 출력의 대조가 필요합니다.",
            )
        if not self.platform.startswith("esxi"):
            return self._unsupported(code)
        missing = self._ssh_required(code)
        if missing:
            return missing
        configs = self._esxi_vm_configs()
        labels = re.compile(
            r'(?:label|summary)\s*=\s*"([^"]*(?:CD/DVD|Floppy|USB|Serial|Parallel)[^"]*)"',
            re.IGNORECASE,
        )
        affected: dict[int, list[str]] = {}
        for vmid, config in configs:
            found = sorted(set(labels.findall(config)))
            if found:
                affected[vmid] = found
        if not affected:
            return self._result(
                code,
                self.TITLES[code],
                Status.GOOD,
                f"점검 VM {len(configs)}개에서 외부 장치 후보가 식별되지 않았습니다.",
            )
        # 검증필: 장치 존재/연결만으로 업무상 불필요 여부를 자동 확정할 수 없다.
        return self._review(
            code,
            f"외부 장치 후보가 있는 VM {len(affected)}개. VM별 승인 장치 목록과 연결 상태를 확인하세요.",
        )

    def check_hv20(self) -> CheckResult:
        return self._vm_option_check(
            "HV-20",
            {
                "isolation.tools.copy.disable": "true",
                "isolation.tools.paste.disable": "true",
                "isolation.tools.setGUIOptions.enable": "false",
            },
        )

    def check_hv21(self) -> CheckResult:
        return self._vm_option_check("HV-21", {"isolation.tools.dnd.disable": "true"})

    def _esxi_switch_security(self) -> list[tuple[str, dict[str, bool | None]]]:
        if self._switch_cache is not None:
            return self._switch_cache

        def parse_security(text: str) -> dict[str, bool | None]:
            aliases = {
                "Allow Promiscuous": ("Allow Promiscuous",),
                "Allow MAC Address Change": (
                    "Allow MAC Address Change",
                    "Allow MAC Address Changes",
                ),
                "Allow Forged Transmits": ("Allow Forged Transmits",),
            }
            values: dict[str, bool | None] = {}
            for canonical, candidates in aliases.items():
                match = None
                for candidate in candidates:
                    match = re.search(
                        rf"(?im)^\s*{re.escape(candidate)}\s*:\s*(true|false)\s*$",
                        text,
                    )
                    if match:
                        break
                values[canonical] = _as_bool(match.group(1)) if match else None
            return values

        listing = self._ssh_run("esxcli network vswitch standard list 2>/dev/null")
        names = [
            match.strip()
            for match in re.findall(r"(?im)^\s*Name\s*:\s*(.+?)\s*$", listing.stdout)
        ]
        switches: list[tuple[str, dict[str, bool | None]]] = []
        for name in names:
            result = self._ssh_run(
                "esxcli network vswitch standard policy security get -v "
                + shlex.quote(name)
                + " 2>/dev/null"
            )
            switches.append((f"vSwitch:{name}", parse_security(result.stdout)))

        portgroups = self._ssh_run(
            "esxcli --formatter=csv network vswitch standard portgroup list 2>/dev/null"
        )
        parsed_portgroups: list[str] = []
        if portgroups.stdout.strip():
            try:
                for row in csv.DictReader(io.StringIO(portgroups.stdout)):
                    name = ""
                    for key, value in row.items():
                        normalized = re.sub(r"[^a-z]", "", str(key).lower())
                        if normalized in {"name", "portgroupname"} and value:
                            name = str(value).strip()
                            break
                    if name:
                        parsed_portgroups.append(name)
            except (csv.Error, TypeError):
                self._portgroup_parse_failed = True
            if not parsed_portgroups and len(portgroups.stdout.splitlines()) > 1:
                self._portgroup_parse_failed = True
        for name in dict.fromkeys(parsed_portgroups):
            result = self._ssh_run(
                "esxcli network vswitch standard portgroup policy security get -p "
                + shlex.quote(name)
                + " 2>/dev/null"
            )
            switches.append((f"PortGroup:{name}", parse_security(result.stdout)))

        dvs = self._ssh_run("esxcli network vswitch dvs vmware list 2>/dev/null")
        self._switch_has_dvs = bool(dvs.stdout.strip())
        self._switch_cache = switches
        return switches

    def _switch_check(self, code: str, setting: str) -> CheckResult:
        if code == "HV-23" and self.platform == "xenserver":
            return self._review(
                code,
                "XenServer PIF/VIF의 other-config:promiscuous 값을 VM/네트워크별로 확인하세요.",
            )
        if not self.platform.startswith("esxi"):
            return self._unsupported(code)
        missing = self._ssh_required(code)
        if missing:
            return missing
        switches = self._esxi_switch_security()
        if not switches:
            if self._switch_has_dvs:
                # 검증필: 분산 스위치는 vCenter 정책/API로 별도 확인해야 한다.
                return self._review(
                    code,
                    "표준 스위치가 없고 분산 스위치가 탐지되었습니다. vCenter 정책을 확인하세요.",
                )
            return self._result(
                code,
                self.TITLES[code],
                Status.ERROR,
                "표준/분산 스위치 정보를 조회하지 못했습니다.",
            )
        vulnerable = [name for name, values in switches if values.get(setting) is True]
        unknown = [name for name, values in switches if values.get(setting) is None]
        if vulnerable:
            return self._result(
                code,
                self.TITLES[code],
                Status.VULNERABLE,
                f"허용 상태 스위치: {', '.join(vulnerable)}",
            )
        if unknown or self._portgroup_parse_failed or self._switch_has_dvs:
            details = []
            if unknown:
                details.append("설정 파싱 실패=" + ", ".join(unknown))
            if self._portgroup_parse_failed:
                details.append("포트그룹 목록 파싱 실패")
            if self._switch_has_dvs:
                details.append("분산 스위치 정책 미점검")
            return self._review(code, "; ".join(details))
        return self._result(
            code,
            self.TITLES[code],
            Status.GOOD,
            f"표준 스위치/포트그룹 {len(switches)}개의 {setting}이 모두 거부(false)입니다.",
        )

    def check_hv22(self) -> CheckResult:
        return self._switch_check("HV-22", "Allow MAC Address Change")

    def check_hv23(self) -> CheckResult:
        return self._switch_check("HV-23", "Allow Promiscuous")

    def check_hv24(self) -> CheckResult:
        return self._switch_check("HV-24", "Allow Forged Transmits")

    def check_hv25(self) -> CheckResult:
        code = "HV-25"
        missing = self._ssh_required(code)
        if missing:
            return missing
        if self.platform.startswith("esxi"):
            version = self._ssh_run(
                "vmware -vl 2>/dev/null; esxcli software profile get 2>/dev/null"
            )
        else:
            version = self._ssh_run(
                "cat /etc/os-release 2>/dev/null; uname -r 2>/dev/null"
            )
        # 검증필: '주기적 검토/적용'은 현재 버전만으로 입증되지 않으며 최신 권고와 변경기록이 필요하다.
        return self._review(
            code,
            "제품/빌드 정보는 수집했습니다: "
            + self._sanitize(version.stdout, 500)
            + ". 패치 절차와 최신 벤더 권고 대조가 필요합니다.",
            "승인된 패치 절차, 최근 검토일, 벤더 보안 권고 및 적용 이력을 증적으로 확인하세요.",
        )

    # PDF의 HV-01~HV-25 코드를 파이썬 함수명 hv_01~hv_25로 표현한다.
    def hv_01(self) -> SimpleResult:
        """HV-01 계정 로그오프/세션 관리."""
        return self._simple_result(self.check_hv01())

    def hv_02(self) -> SimpleResult:
        """HV-02 가상화 장비 외부접속 차단."""
        return self._simple_result(self.check_hv02())

    def hv_03(self) -> SimpleResult:
        """HV-03 가상화 장비 루트계정 관리."""
        return self._simple_result(self.check_hv03())

    def hv_04(self) -> SimpleResult:
        """HV-04 가상화 장비 계정 권한 관리."""
        return self._simple_result(self.check_hv04())

    def hv_05(self) -> SimpleResult:
        """HV-05 가상화 장비 사용자 인증 강화."""
        return self._simple_result(self.check_hv05())

    def hv_06(self) -> SimpleResult:
        """HV-06 비밀번호 관리정책 설정."""
        return self._simple_result(self.check_hv06())

    def hv_07(self) -> SimpleResult:
        """HV-07 계정 잠금 임계값 설정."""
        return self._simple_result(self.check_hv07())

    def hv_08(self) -> SimpleResult:
        """HV-08 시스템 사용 주의사항 출력 설정."""
        return self._simple_result(self.check_hv08())

    def hv_09(self) -> SimpleResult:
        """HV-09 NTP 및 시각 동기화 설정."""
        return self._simple_result(self.check_hv09())

    def hv_10(self) -> SimpleResult:
        """HV-10 SNMP Community String 복잡성 적용."""
        return self._simple_result(self.check_hv10())

    def hv_11(self) -> SimpleResult:
        """HV-11 MOB(Managed Object Browser) 서비스 비활성화."""
        return self._simple_result(self.check_hv11())

    def hv_12(self) -> SimpleResult:
        """HV-12 ESXi Shell 비활성화."""
        return self._simple_result(self.check_hv12())

    def hv_13(self) -> SimpleResult:
        """HV-13 ESXi Shell 세션 종료 시간 설정."""
        return self._simple_result(self.check_hv13())

    def hv_14(self) -> SimpleResult:
        """HV-14 원격 로그 서버 이용."""
        return self._simple_result(self.check_hv14())

    def hv_15(self) -> SimpleResult:
        """HV-15 시스템 주요 이벤트 로그 설정."""
        return self._simple_result(self.check_hv15())

    def hv_16(self) -> SimpleResult:
        """HV-16 비휘발성 경로 내 로그 파일 저장."""
        return self._simple_result(self.check_hv16())

    def hv_17(self) -> SimpleResult:
        """HV-17 코어덤프 수집 기능 활성화."""
        return self._simple_result(self.check_hv17())

    def hv_18(self) -> SimpleResult:
        """HV-18 가상 머신의 장치 변경 제한 설정."""
        return self._simple_result(self.check_hv18())

    def hv_19(self) -> SimpleResult:
        """HV-19 가상 머신의 불필요한 장치 제거."""
        return self._simple_result(self.check_hv19())

    def hv_20(self) -> SimpleResult:
        """HV-20 가상 머신 콘솔 클립보드 복사&붙여넣기 기능 비활성화."""
        return self._simple_result(self.check_hv20())

    def hv_21(self) -> SimpleResult:
        """HV-21 가상 머신 콘솔 드래그 앤 드롭 기능 비활성화."""
        return self._simple_result(self.check_hv21())

    def hv_22(self) -> SimpleResult:
        """HV-22 가상 스위치 MAC 주소 변경 정책 비활성화."""
        return self._simple_result(self.check_hv22())

    def hv_23(self) -> SimpleResult:
        """HV-23 가상 스위치 무차별(Promiscuous) 모드 정책 비활성화."""
        return self._simple_result(self.check_hv23())

    def hv_24(self) -> SimpleResult:
        """HV-24 가상 스위치 위조전송(Forged Transmits) 모드 정책 비활성화."""
        return self._simple_result(self.check_hv24())

    def hv_25(self) -> SimpleResult:
        """HV-25 주기적 보안 패치 및 벤더 권고사항 적용."""
        return self._simple_result(self.check_hv25())

    def run_all(self) -> dict[str, SimpleResult]:
        """가상화 점검코드를 키로 하여 간단한 튜플 결과를 반환한다."""
        return {
            "HV-01": self.hv_01(),
            "HV-02": self.hv_02(),
            "HV-03": self.hv_03(),
            "HV-04": self.hv_04(),
            "HV-05": self.hv_05(),
            "HV-06": self.hv_06(),
            "HV-07": self.hv_07(),
            "HV-08": self.hv_08(),
            "HV-09": self.hv_09(),
            "HV-10": self.hv_10(),
            "HV-11": self.hv_11(),
            "HV-12": self.hv_12(),
            "HV-13": self.hv_13(),
            "HV-14": self.hv_14(),
            "HV-15": self.hv_15(),
            "HV-16": self.hv_16(),
            "HV-17": self.hv_17(),
            "HV-18": self.hv_18(),
            "HV-19": self.hv_19(),
            "HV-20": self.hv_20(),
            "HV-21": self.hv_21(),
            "HV-22": self.hv_22(),
            "HV-23": self.hv_23(),
            "HV-24": self.hv_24(),
            "HV-25": self.hv_25(),
        }

    def run_all_detailed(self) -> list[CheckResult]:
        """JSON 보고서 저장용 상세 결과를 반환한다."""
        return [
            self.check_hv01(),
            self.check_hv02(),
            self.check_hv03(),
            self.check_hv04(),
            self.check_hv05(),
            self.check_hv06(),
            self.check_hv07(),
            self.check_hv08(),
            self.check_hv09(),
            self.check_hv10(),
            self.check_hv11(),
            self.check_hv12(),
            self.check_hv13(),
            self.check_hv14(),
            self.check_hv15(),
            self.check_hv16(),
            self.check_hv17(),
            self.check_hv18(),
            self.check_hv19(),
            self.check_hv20(),
            self.check_hv21(),
            self.check_hv22(),
            self.check_hv23(),
            self.check_hv24(),
            self.check_hv25(),
        ]


class Virtual_Host(_LegacySshVirtualHost):
    """ESXi는 HTTPS vSphere API, XenServer는 SSH로만 점검한다.

    ESXi 점검 중에는 Paramiko 연결을 만들거나 원격 셸 명령을 실행하지 않는다.
    XenServer 점검 중에는 vSphere API나 웹 콘솔에 접속하지 않는다.
    """

    _PLATFORM_ALIASES: ClassVar[dict[str, str]] = {
        "esx": "esxi",
        "vmware": "esxi",
        "vmware-esxi": "esxi",
        "xen": "xenserver",
        "citrix": "xenserver",
        "citrix-hypervisor": "xenserver",
    }

    def __init__(self, connection_info: Mapping[str, Any] | None = None):
        if connection_info is None:
            platform = input("플랫폼(esxi/xenserver): ").strip().lower()
            connection_info = {
                "platform": platform,
                "ip": input("IP 또는 호스트명: ").strip(),
                "id": input("접속 ID: ").strip(),
                "pw": getpass.getpass("접속 비밀번호: "),
            }

        info = dict(connection_info)
        requested = str(info.get("platform", "")).strip().lower()
        requested = self._PLATFORM_ALIASES.get(requested, requested)
        if requested not in {"esxi", "xenserver"}:
            raise ValueError(
                "platform은 'esxi' 또는 'xenserver'여야 합니다. "
                "접속 방식을 안전하게 분리하기 위해 자동 SSH 판별은 하지 않습니다."
            )

        auto_connect = _as_bool(info.get("auto_connect"), True)
        info["auto_connect"] = False
        if requested == "esxi":
            info["use_ssh"] = False
            info["use_http"] = False
        else:
            info["use_ssh"] = True
            info["use_http"] = False

        _BaseAuditor.__init__(self, info)
        self.platform = requested
        self.connection_mode = (
            "https-vsphere-api" if requested == "esxi" else "ssh"
        )
        self.platform_detail = ""
        self.console_snapshot: dict[str, Any] = {
            "available": False,
            "transport": self.connection_mode,
        }

        self._service_instance: Any = None
        self._api_content: Any = None
        self._esxi_host: Any = None
        self._esxi_manager: Any = None
        self._api_option_cache: dict[str, Any] = {}
        self._api_option_errors: dict[str, str] = {}
        self._api_vm_cache: list[dict[str, Any]] | None = None
        self._api_vm_truncated = False
        self._api_vm_inaccessible = 0
        self._api_switch_cache: list[tuple[str, dict[str, bool | None]]] | None = None
        self._api_has_dvs = False

        # XenServer용으로 상속한 기존 SSH 헬퍼의 캐시도 초기화한다.
        self._vm_cache = None
        self._vm_cache_truncated = False
        self._switch_cache = None
        self._switch_has_dvs = False
        self._portgroup_parse_failed = False

        if auto_connect:
            if requested == "esxi":
                self._connect_esxi_api()
            else:
                self._connect_ssh()
                self._describe_xenserver()

    def _connect_ssh(self) -> None:
        if getattr(self, "platform", None) == "esxi":
            self._connection_errors.append(
                "ESXi 모드에서는 정책상 SSH 연결이 차단됩니다."
            )
            return
        _BaseAuditor._connect_ssh(self)

    def _ssh_run(
        self, command: str, timeout: float | None = None
    ) -> CommandResult:
        if getattr(self, "platform", None) == "esxi":
            return CommandResult(
                command,
                126,
                "",
                "ESXi 모드에서는 정책상 SSH 명령 실행이 차단됩니다.",
            )
        return _BaseAuditor._ssh_run(self, command, timeout)

    def _connect_esxi_api(self) -> None:
        if getattr(self, "platform", None) != "esxi":
            self._connection_errors.append(
                "XenServer 모드에서는 vSphere API 연결이 차단됩니다."
            )
            return
        if SmartConnect is None or VsphereDisconnect is None or vim is None:
            self._connection_errors.append(
                "vSphere API 연결 실패: pyvmomi 패키지가 설치되지 않았습니다."
            )
            return

        try:
            if isinstance(self.tls_verify, str):
                ssl_context = ssl.create_default_context(cafile=self.tls_verify)
            else:
                ssl_context = ssl.create_default_context()
            if self.tls_verify is False:
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

            api_port = int(self.info.get("api_port", 443))
            self._service_instance = SmartConnect(
                host=self.ip,
                user=self.user_id,
                pwd=self._password,
                port=api_port,
                sslContext=ssl_context,
                httpConnectionTimeout=self.timeout,
            )
            self._api_content = self._service_instance.RetrieveContent()
            view = self._api_content.viewManager.CreateContainerView(
                self._api_content.rootFolder,
                [vim.HostSystem],
                True,
            )
            try:
                hosts = list(view.view)
            finally:
                view.Destroy()

            requested_name = str(
                self.info.get("esxi_host_name", "")
            ).strip().lower()
            if requested_name:
                hosts = [
                    host
                    for host in hosts
                    if str(getattr(host, "name", "")).lower()
                    == requested_name
                ]
            if not hosts:
                raise RuntimeError("vSphere API 인벤토리에서 ESXi 호스트를 찾지 못했습니다.")
            if len(hosts) > 1:
                raise RuntimeError(
                    "호스트가 여러 개입니다. esxi_host_name을 지정하거나 "
                    "개별 ESXi 주소로 직접 연결하세요."
                )

            self._esxi_host = hosts[0]
            self._esxi_manager = self._esxi_host.configManager
            product = getattr(
                getattr(self._esxi_host, "config", None), "product", None
            )
            full_name = str(getattr(product, "fullName", "")).strip()
            version = str(getattr(product, "version", "")).strip()
            build = str(getattr(product, "build", "")).strip()
            self.platform_detail = (
                full_name
                or " ".join(
                    value
                    for value in ("VMware ESXi", version, f"build-{build}" if build else "")
                    if value
                )
            )
            self.console_snapshot = {
                "available": True,
                "transport": "vSphere Web Services API over HTTPS",
                "port": api_port,
                "host_name": str(getattr(self._esxi_host, "name", "")),
            }
        except Exception as exc:
            if self._service_instance is not None:
                try:
                    VsphereDisconnect(self._service_instance)
                except Exception:
                    pass
            self._service_instance = None
            self._api_content = None
            self._esxi_host = None
            self._esxi_manager = None
            self._connection_errors.append(
                "vSphere API 연결 실패: "
                + self._sanitize(f"{type(exc).__name__}: {exc}")
            )

    def _describe_xenserver(self) -> None:
        if self._ssh is None:
            self.platform_detail = "XenServer/Citrix Hypervisor (SSH 연결 실패)"
            return
        probe = self._ssh_run(
            "if command -v xe >/dev/null 2>&1; then "
            "echo XENSERVER; xe host-list params=software-version 2>/dev/null; "
            "else echo XE_COMMAND_NOT_FOUND; fi"
        )
        text = self._sanitize(probe.stdout or probe.stderr, 500)
        self.platform_detail = text or "XenServer/Citrix Hypervisor"
        if "XE_COMMAND_NOT_FOUND" in probe.stdout:
            self._connection_errors.append(
                "XenServer 확인 경고: xe 명령을 찾지 못했습니다."
            )

    def close(self) -> None:
        _BaseAuditor.close(self)
        if self._service_instance is not None and VsphereDisconnect is not None:
            try:
                VsphereDisconnect(self._service_instance)
            except Exception as exc:
                self._connection_errors.append(
                    "vSphere API 로그아웃 경고: "
                    + self._sanitize(f"{type(exc).__name__}: {exc}")
                )
            finally:
                self._service_instance = None
                self._api_content = None
                self._esxi_host = None
                self._esxi_manager = None

    def _api_required(self, code: str) -> CheckResult | None:
        if self._esxi_host is not None and self._esxi_manager is not None:
            return None
        detail = "; ".join(self._connection_errors) or "vSphere API 세션이 없습니다."
        return self._result(
            code,
            self.TITLES[code],
            Status.ERROR,
            "HTTPS vSphere API 조회 불가: " + detail,
        )

    def _dispatch(self, number: int) -> CheckResult:
        if self.platform == "xenserver":
            method = getattr(super(), f"check_hv{number:02d}")
            return method()

        code = f"HV-{number:02d}"
        missing = self._api_required(code)
        if missing:
            return missing
        try:
            method = getattr(self, f"_api_hv{number:02d}")
            return method()
        except Exception as exc:
            return self._result(
                code,
                self.TITLES[code],
                Status.ERROR,
                "vSphere API 조회 실패: "
                + self._sanitize(f"{type(exc).__name__}: {exc}"),
            )

    def _api_option(self, path: str) -> Any:
        key = path.strip("/").replace("/", ".")
        if key in self._api_option_cache:
            return self._api_option_cache[key]
        try:
            values = self._esxi_manager.advancedOption.QueryOptions(key)
            value = None
            for item in values or []:
                if str(getattr(item, "key", "")) == key:
                    value = getattr(item, "value", None)
                    break
            if value is None:
                for item in (
                    getattr(
                        getattr(self._esxi_host, "config", None),
                        "option",
                        None,
                    )
                    or []
                ):
                    if str(getattr(item, "key", "")) == key:
                        value = getattr(item, "value", None)
                        break
            self._api_option_cache[key] = value
            return value
        except Exception as exc:
            self._api_option_errors[key] = (
                f"{type(exc).__name__}: {exc}"
            )
            self._api_option_cache[key] = None
            return None

    def _api_option_failure(self, path: str) -> str:
        key = path.strip("/").replace("/", ".")
        reason = self._api_option_errors.get(key)
        return (
            f"{key} 값을 API에서 읽지 못했습니다"
            + (f": {reason}" if reason else ".")
        )

    def _api_services(self) -> dict[str, Any]:
        service_system = getattr(self._esxi_manager, "serviceSystem", None)
        service_info = getattr(service_system, "serviceInfo", None)
        services = getattr(service_info, "service", None)
        if services is None:
            host_service = getattr(
                getattr(self._esxi_host, "config", None), "service", None
            )
            services = getattr(host_service, "service", None)
        return {
            str(getattr(item, "key", "")).lower(): item
            for item in (services or [])
            if getattr(item, "key", None)
        }

    @staticmethod
    def _principal_leaf(value: str) -> str:
        return re.split(r"[\\/]", value)[-1].lower()

    def _api_permissions(self) -> list[tuple[str, int, str]]:
        manager = self._api_content.authorizationManager
        role_names = {
            int(getattr(role, "roleId")): str(getattr(role, "name", ""))
            for role in (getattr(manager, "roleList", None) or [])
        }
        permissions = manager.RetrieveEntityPermissions(
            self._esxi_host, True
        )
        return [
            (
                str(getattr(item, "principal", "")),
                int(getattr(item, "roleId", 0)),
                role_names.get(int(getattr(item, "roleId", 0)), ""),
            )
            for item in (permissions or [])
            if getattr(item, "principal", None)
        ]

    @staticmethod
    def _is_admin_role(role_id: int, role_name: str) -> bool:
        return role_id == -1 or role_name.strip().lower() in {
            "admin",
            "administrator",
        }

    def _api_accounts(self) -> list[str]:
        directory = getattr(self._api_content, "userDirectory", None)
        if directory is None:
            directory = getattr(self._esxi_manager, "userDirectory", None)
        if directory is None:
            raise RuntimeError("UserDirectory API가 제공되지 않습니다.")
        users = directory.RetrieveUserGroups(
            domain="",
            searchStr="",
            belongsToGroup=None,
            belongsToUser=None,
            exactMatch=False,
            findUsers=True,
            findGroups=False,
        )
        return sorted(
            {
                str(getattr(item, "principal", "")).strip()
                for item in (users or [])
                if not bool(getattr(item, "group", False))
                and str(getattr(item, "principal", "")).strip()
            }
        )

    def _api_vms(self) -> list[dict[str, Any]]:
        if self._api_vm_cache is not None:
            return self._api_vm_cache
        all_vms = list(getattr(self._esxi_host, "vm", None) or [])
        maximum = max(1, int(self.info.get("max_vms", 200)))
        self._api_vm_truncated = len(all_vms) > maximum
        records: list[dict[str, Any]] = []
        for vm_object in all_vms[:maximum]:
            try:
                config = getattr(vm_object, "config", None)
                if config is None:
                    self._api_vm_inaccessible += 1
                    continue
                extra = {
                    str(getattr(item, "key", "")): str(
                        getattr(item, "value", "")
                    )
                    for item in (getattr(config, "extraConfig", None) or [])
                    if getattr(item, "key", None)
                }
                hardware = getattr(config, "hardware", None)
                records.append(
                    {
                        "name": str(
                            getattr(config, "name", "")
                            or getattr(vm_object, "name", "")
                        ),
                        "extra": extra,
                        "devices": list(
                            getattr(hardware, "device", None) or []
                        ),
                    }
                )
            except Exception:
                self._api_vm_inaccessible += 1
        self._api_vm_cache = records
        return records

    def _api_vm_option_check(
        self, code: str, expected: Mapping[str, str]
    ) -> CheckResult:
        records = self._api_vms()
        if not records:
            return self._review(
                code,
                "API에서 조회 가능한 가상 머신 구성이 없습니다.",
            )
        noncompliant = [
            record["name"]
            for record in records
            if any(
                str(record["extra"].get(key, "")).lower()
                != expected_value.lower()
                for key, expected_value in expected.items()
            )
        ]
        if noncompliant:
            return self._result(
                code,
                self.TITLES[code],
                Status.VULNERABLE,
                f"점검 VM {len(records)}개 중 설정 누락/불일치 "
                f"{len(noncompliant)}개; VM={noncompliant[:30]}",
            )
        if (
            self._api_vm_truncated
            or self._api_vm_inaccessible
        ):
            return self._review(
                code,
                "조회 범위 내 VM은 준수하지만 일부 VM 구성을 확인하지 못했습니다. "
                f"최대개수초과={self._api_vm_truncated}, "
                f"조회불가={self._api_vm_inaccessible}",
            )
        return self._result(
            code,
            self.TITLES[code],
            Status.GOOD,
            f"점검 VM {len(records)}개가 요구 구성값을 만족합니다.",
        )

    def _api_switch_security(
        self,
    ) -> list[tuple[str, dict[str, bool | None]]]:
        if self._api_switch_cache is not None:
            return self._api_switch_cache
        network_system = getattr(self._esxi_manager, "networkSystem", None)
        network_info = getattr(network_system, "networkInfo", None)
        if network_info is None:
            raise RuntimeError("HostNetworkSystem.networkInfo가 없습니다.")

        def values(policy: Any) -> dict[str, bool | None]:
            security = getattr(policy, "security", None)
            return {
                "macChanges": getattr(security, "macChanges", None),
                "allowPromiscuous": getattr(
                    security, "allowPromiscuous", None
                ),
                "forgedTransmits": getattr(
                    security, "forgedTransmits", None
                ),
            }

        result: list[tuple[str, dict[str, bool | None]]] = []
        for switch in (getattr(network_info, "vswitch", None) or []):
            spec = getattr(switch, "spec", None)
            result.append(
                (
                    "vSwitch:" + str(getattr(switch, "name", "")),
                    values(getattr(spec, "policy", None)),
                )
            )
        for portgroup in (
            getattr(network_info, "portgroup", None) or []
        ):
            spec = getattr(portgroup, "spec", None)
            result.append(
                (
                    "PortGroup:" + str(getattr(spec, "name", "")),
                    values(getattr(portgroup, "computedPolicy", None)),
                )
            )
        self._api_has_dvs = bool(
            getattr(network_info, "proxySwitch", None)
        )
        self._api_switch_cache = result
        return result

    def _api_switch_check(
        self, code: str, property_name: str, label: str
    ) -> CheckResult:
        switches = self._api_switch_security()
        vulnerable = [
            name
            for name, values in switches
            if values.get(property_name) is True
        ]
        unknown = [
            name
            for name, values in switches
            if values.get(property_name) is None
        ]
        if vulnerable:
            return self._result(
                code,
                self.TITLES[code],
                Status.VULNERABLE,
                "허용 상태: " + ", ".join(vulnerable[:50]),
            )
        if unknown or self._api_has_dvs:
            details = []
            if unknown:
                details.append("API 값 없음=" + ", ".join(unknown[:30]))
            if self._api_has_dvs:
                details.append(
                    "분산 스위치 정책은 직접 ESXi API에서 완전 조회 불가"
                )
            return self._review(code, "; ".join(details))
        if not switches:
            return self._review(
                code, "표준 스위치/포트그룹을 API에서 찾지 못했습니다."
            )
        return self._result(
            code,
            self.TITLES[code],
            Status.GOOD,
            f"표준 스위치/포트그룹 {len(switches)}개의 "
            f"{label} 정책이 모두 거부(false)입니다.",
        )

    def _api_hv01(self) -> CheckResult:
        code = "HV-01"
        value = self._api_option("/UserVars/HostClientSessionTimeout")
        seconds = _first_int(str(value)) if value is not None else None
        if seconds is None:
            return self._result(
                code,
                self.TITLES[code],
                Status.ERROR,
                self._api_option_failure(
                    "/UserVars/HostClientSessionTimeout"
                ),
            )
        status = Status.GOOD if 1 <= seconds <= 600 else Status.VULNERABLE
        return self._result(
            code,
            self.TITLES[code],
            status,
            f"UserVars.HostClientSessionTimeout={seconds}초",
        )

    def _api_hv02(self) -> CheckResult:
        code = "HV-02"
        firewall = self._esxi_manager.firewallSystem.firewallInfo
        targets = []
        target_keys = {
            "sshserver",
            "webaccess",
            "vsphereclient",
            "httpclient",
            "hostclient",
        }
        for ruleset in (getattr(firewall, "ruleset", None) or []):
            key = str(getattr(ruleset, "key", "")).lower()
            if key in target_keys and bool(
                getattr(ruleset, "enabled", False)
            ):
                targets.append(ruleset)
        if not targets:
            return self._review(
                code,
                "활성 관리 ruleset을 API 응답에서 식별하지 못했습니다.",
            )
        unrestricted = []
        for ruleset in targets:
            allowed = getattr(ruleset, "allowedHosts", None)
            if allowed is None or bool(getattr(allowed, "allIp", False)):
                unrestricted.append(str(getattr(ruleset, "key", "")))
        if unrestricted:
            return self._review(
                code,
                "전체 IP 허용 또는 허용 목록 미확인 ruleset: "
                + ", ".join(unrestricted)
                + ". 상위 방화벽/VPN 통제 증적과 대조하세요.",
                "ESXi 또는 상위 방화벽에서 관리 IP만 허용하세요.",
            )
        return self._result(
            code,
            self.TITLES[code],
            Status.GOOD,
            f"활성 관리 ruleset {len(targets)}개가 허용 IP 목록으로 제한됩니다.",
        )

    def _api_hv03(self) -> CheckResult:
        code = "HV-03"
        permissions = self._api_permissions()
        admins = [
            principal
            for principal, role_id, role_name in permissions
            if self._is_admin_role(role_id, role_name)
        ]
        root_admin = any(
            self._principal_leaf(item) == "root" for item in admins
        )
        alternate = any(
            self._principal_leaf(item) != "root" for item in admins
        )
        if root_admin:
            return self._result(
                code,
                self.TITLES[code],
                Status.VULNERABLE,
                f"root 관리자 권한 탐지; 별도 관리자 존재={alternate}",
            )
        if alternate:
            return self._result(
                code,
                self.TITLES[code],
                Status.GOOD,
                "root 외 관리자 존재 및 root 관리자 권한 미탐지.",
            )
        return self._review(
            code, "API 권한 목록에서 관리자 역할을 식별하지 못했습니다."
        )

    def _api_hv04(self) -> CheckResult:
        code = "HV-04"
        accounts = self._api_accounts()
        expected = self.info.get("expected_accounts")
        if not isinstance(expected, Sequence) or isinstance(
            expected, (str, bytes)
        ):
            return self._review(
                code,
                f"API로 사용자 계정 {len(accounts)}개 수집. "
                "expected_accounts 정책과 대조가 필요합니다.",
            )
        extras = sorted(
            set(accounts) - {str(item) for item in expected}
        )
        if extras:
            return self._result(
                code,
                self.TITLES[code],
                Status.VULNERABLE,
                "승인 목록 외 계정: " + ", ".join(extras),
            )
        return self._result(
            code,
            self.TITLES[code],
            Status.GOOD,
            f"API 수집 계정 {len(accounts)}개가 승인 목록 범위 내입니다.",
        )

    def _api_hv05(self) -> CheckResult:
        code = "HV-05"
        expected = self.info.get("expected_admin_accounts")
        if not isinstance(expected, Sequence) or isinstance(
            expected, (str, bytes)
        ):
            return self._review(
                code,
                "expected_admin_accounts가 없어 관리자 권한 적정성을 확정할 수 없습니다.",
            )
        allowed = {str(item).lower() for item in expected}
        admins = {
            principal
            for principal, role_id, role_name in self._api_permissions()
            if self._is_admin_role(role_id, role_name)
        }
        unexpected = sorted(
            principal
            for principal in admins
            if principal.lower() not in allowed
            and self._principal_leaf(principal) not in allowed
        )
        if unexpected:
            return self._result(
                code,
                self.TITLES[code],
                Status.VULNERABLE,
                "승인 목록 외 관리자: " + ", ".join(unexpected),
            )
        return self._result(
            code,
            self.TITLES[code],
            Status.GOOD,
            f"관리자 {len(admins)}개가 승인 목록 범위 내입니다.",
        )

    def _api_hv06(self) -> CheckResult:
        code = "HV-06"
        quality = self._api_option("/Security/PasswordQualityControl")
        max_days = self._api_option("/Security/PasswordMaxDays")
        minimums = self._parse_password_minimums(str(quality or ""))
        days = _first_int(str(max_days)) if max_days is not None else None
        if quality is None or days is None:
            return self._result(
                code,
                self.TITLES[code],
                Status.ERROR,
                "PasswordQualityControl 또는 PasswordMaxDays를 API에서 읽지 못했습니다.",
            )
        quality_ok = (
            len(minimums) >= 5
            and minimums[3] is not None
            and minimums[4] is not None
            and minimums[3] >= 8
            and minimums[4] >= 8
        )
        good = quality_ok and 1 <= days <= 90
        return self._result(
            code,
            self.TITLES[code],
            Status.GOOD if good else Status.VULNERABLE,
            f"PasswordQualityControl 최소값={minimums}; PasswordMaxDays={days}",
        )

    def _api_hv07(self) -> CheckResult:
        code = "HV-07"
        failures = _first_int(
            str(self._api_option("/Security/AccountLockFailures") or "")
        )
        unlock = _first_int(
            str(self._api_option("/Security/AccountUnlockTime") or "")
        )
        if failures is None or unlock is None:
            return self._result(
                code,
                self.TITLES[code],
                Status.ERROR,
                "계정 잠금 설정을 API에서 읽지 못했습니다.",
            )
        good = 1 <= failures <= 5 and unlock >= 600
        return self._result(
            code,
            self.TITLES[code],
            Status.GOOD if good else Status.VULNERABLE,
            f"AccountLockFailures={failures}, AccountUnlockTime={unlock}초",
        )

    def _api_hv08(self) -> CheckResult:
        code = "HV-08"
        value = self._api_option("/Annotations/WelcomeMessage")
        message = str(value or "").strip()
        if not message:
            return self._result(
                code,
                self.TITLES[code],
                Status.VULNERABLE,
                "Annotations.WelcomeMessage가 비어 있습니다.",
            )
        exposes_version = bool(
            re.search(
                r"VMware ESXi\s+\d|build[- ]?\d|version\s+\d",
                message,
                re.IGNORECASE,
            )
        )
        return self._result(
            code,
            self.TITLES[code],
            Status.VULNERABLE if exposes_version else Status.GOOD,
            "웹 사용 주의 문구가 설정되어 있으며 "
            + (
                "제품/버전 노출 패턴이 있습니다."
                if exposes_version
                else "대표 제품/버전 노출 패턴이 없습니다."
            ),
        )

    def _api_hv09(self) -> CheckResult:
        code = "HV-09"
        date_info = getattr(
            self._esxi_manager.dateTimeSystem, "dateTimeInfo", None
        )
        if date_info is None:
            date_info = getattr(
                getattr(self._esxi_host, "config", None),
                "dateTimeInfo",
                None,
            )
        ntp_config = getattr(date_info, "ntpConfig", None)
        servers = list(getattr(ntp_config, "server", None) or [])
        api_enabled = getattr(date_info, "enabled", None)
        service_sync = getattr(date_info, "serviceSync", None)
        ntpd = self._api_services().get("ntpd")
        service_running = (
            bool(getattr(ntpd, "running", False))
            if ntpd is not None
            else None
        )
        enabled = api_enabled is True or service_running is True
        good = bool(servers) and enabled
        return self._result(
            code,
            self.TITLES[code],
            Status.GOOD if good else Status.VULNERABLE,
            f"NTP 서버={len(servers)}개, 활성={enabled}, "
            f"동기화={service_sync}",
        )

    def _api_hv10(self) -> CheckResult:
        code = "HV-10"
        snmp_system = getattr(self._esxi_manager, "snmpSystem", None)
        if snmp_system is None:
            return self._review(code, "HostSnmpSystem API가 제공되지 않습니다.")
        configuration = snmp_system.configuration
        enabled = bool(getattr(configuration, "enabled", False))
        if not enabled:
            return self._result(
                code,
                self.TITLES[code],
                Status.GOOD,
                "SNMP가 비활성화되어 있습니다.",
            )
        communities = [
            str(value)
            for value in (
                getattr(configuration, "readOnlyCommunities", None) or []
            )
        ]
        weak = [
            value
            for value in communities
            if value.lower() in {"public", "private", "community"}
            or not _complexity_ok(value)
        ]
        if weak:
            return self._result(
                code,
                self.TITLES[code],
                Status.VULNERABLE,
                f"SNMP 활성; Community {len(communities)}개 중 "
                f"복잡도 미달 {len(weak)}개. 원문은 저장하지 않았습니다.",
            )
        if communities:
            return self._result(
                code,
                self.TITLES[code],
                Status.GOOD,
                f"SNMP 활성; Community {len(communities)}개가 "
                "복잡도 기준을 만족합니다. 원문은 저장하지 않았습니다.",
            )
        return self._review(
            code,
            "SNMP가 활성화됐으나 v1/v2c Community가 없습니다. "
            "별도 SNMP 구성 증적을 확인하세요.",
        )

    def _api_hv11(self) -> CheckResult:
        code = "HV-11"
        value = self._api_option(
            "/Config/HostAgent/plugins/solo/enableMob"
        )
        if value is None:
            return self._review(
                code,
                self._api_option_failure(
                    "/Config/HostAgent/plugins/solo/enableMob"
                ),
            )
        enabled = _as_bool(value)
        return self._result(
            code,
            self.TITLES[code],
            Status.VULNERABLE if enabled else Status.GOOD,
            f"MOB enabled={enabled}",
        )

    def _api_hv12(self) -> CheckResult:
        code = "HV-12"
        services = self._api_services()
        found = {
            key: bool(getattr(value, "running", False))
            for key, value in services.items()
            if key in {"tsm", "tsm-ssh"}
        }
        if not found:
            return self._review(
                code, "HostServiceSystem에서 TSM/TSM-SSH를 찾지 못했습니다."
            )
        enabled = [
            name.upper()
            for name, running in found.items()
            if running
        ]
        if enabled:
            return self._result(
                code,
                self.TITLES[code],
                Status.VULNERABLE,
                "활성 서비스: " + ", ".join(enabled),
            )
        return self._result(
            code,
            self.TITLES[code],
            Status.GOOD,
            "TSM 및 TSM-SSH가 비활성화되어 있습니다.",
        )

    def _api_hv13(self) -> CheckResult:
        code = "HV-13"
        value = self._api_option(
            "/UserVars/ESXiShellInteractiveTimeOut"
        )
        seconds = _first_int(str(value)) if value is not None else None
        if seconds is None:
            return self._result(
                code,
                self.TITLES[code],
                Status.ERROR,
                self._api_option_failure(
                    "/UserVars/ESXiShellInteractiveTimeOut"
                ),
            )
        good = 1 <= seconds <= 600
        return self._result(
            code,
            self.TITLES[code],
            Status.GOOD if good else Status.VULNERABLE,
            f"ESXiShellInteractiveTimeOut={seconds}초",
        )

    def _api_hv14(self) -> CheckResult:
        code = "HV-14"
        value = self._api_option("/Syslog/global/logHost")
        if value is None:
            return self._result(
                code,
                self.TITLES[code],
                Status.ERROR,
                self._api_option_failure("/Syslog/global/logHost"),
            )
        configured = bool(str(value).strip())
        return self._result(
            code,
            self.TITLES[code],
            Status.GOOD if configured else Status.VULNERABLE,
            f"원격 Syslog 대상 설정={configured}",
        )

    def _api_hv15(self) -> CheckResult:
        code = "HV-15"
        value = self._api_option("/Config/HostAgent/log/level")
        if value is None:
            return self._result(
                code,
                self.TITLES[code],
                Status.ERROR,
                self._api_option_failure("/Config/HostAgent/log/level"),
            )
        level = str(value).strip().lower()
        if level in {"", "none", "quiet"}:
            return self._result(
                code,
                self.TITLES[code],
                Status.VULNERABLE,
                f"로그 레벨={value}",
            )
        expected = self.info.get("expected_log_levels")
        if isinstance(expected, Sequence) and not isinstance(
            expected, (str, bytes)
        ):
            allowed = {str(item).lower() for item in expected}
            return self._result(
                code,
                self.TITLES[code],
                Status.GOOD if level in allowed else Status.VULNERABLE,
                f"로그 레벨={value}; 승인 정책과 대조함.",
            )
        return self._review(
            code,
            f"로그 레벨={value}. expected_log_levels 정책 대조가 필요합니다.",
        )

    def _api_hv16(self) -> CheckResult:
        code = "HV-16"
        value = self._api_option("/Syslog/global/logDir")
        if value is None:
            return self._result(
                code,
                self.TITLES[code],
                Status.ERROR,
                self._api_option_failure("/Syslog/global/logDir"),
            )
        path = str(value).strip()
        if not path:
            return self._result(
                code,
                self.TITLES[code],
                Status.VULNERABLE,
                "Syslog.global.logDir가 비어 있습니다.",
            )
        if re.match(r"^\[[^]]+\]", path) or path.startswith(
            "/vmfs/volumes/"
        ):
            return self._result(
                code,
                self.TITLES[code],
                Status.GOOD,
                "로그 경로가 데이터스토어/비휘발성 볼륨 형식입니다.",
            )
        if path.startswith(("/tmp", "/var/tmp", "/run", "/dev/shm")):
            return self._result(
                code,
                self.TITLES[code],
                Status.VULNERABLE,
                f"휘발성 로그 경로={path}",
            )
        return self._review(
            code,
            f"로그 경로={path}; API 값만으로 저장소 영속성을 확정할 수 없습니다.",
        )

    def _api_hv17(self) -> CheckResult:
        code = "HV-17"
        partition = getattr(
            getattr(self._esxi_host, "config", None),
            "activeDiagnosticPartition",
            None,
        )
        if partition is None:
            return self._result(
                code,
                self.TITLES[code],
                Status.VULNERABLE,
                "활성 진단/코어덤프 파티션이 없습니다.",
            )
        return self._result(
            code,
            self.TITLES[code],
            Status.GOOD,
            "활성 진단 파티션 존재; "
            f"유형={getattr(partition, 'diagnosticType', '')}, "
            f"저장소={getattr(partition, 'storageType', '')}",
        )

    def _api_hv18(self) -> CheckResult:
        return self._api_vm_option_check(
            "HV-18",
            {
                "isolation.device.edit.disable": "true",
                "isolation.device.connectable.disable": "true",
            },
        )

    def _api_hv19(self) -> CheckResult:
        code = "HV-19"
        records = self._api_vms()
        affected: dict[str, list[str]] = {}
        device_markers = (
            "virtualcdrom",
            "virtualfloppy",
            "virtualusb",
            "virtualserialport",
            "virtualparallelport",
        )
        for record in records:
            labels = []
            for device in record["devices"]:
                class_name = type(device).__name__.lower()
                if any(marker in class_name for marker in device_markers):
                    info = getattr(device, "deviceInfo", None)
                    labels.append(
                        str(
                            getattr(info, "label", "")
                            or type(device).__name__
                        )
                    )
            if labels:
                affected[record["name"]] = sorted(set(labels))
        if affected:
            return self._review(
                code,
                f"외부 장치 후보가 있는 VM {len(affected)}개. "
                "승인 장치 목록 및 실제 연결 필요성을 대조하세요.",
            )
        if self._api_vm_truncated or self._api_vm_inaccessible:
            return self._review(
                code,
                "조회 범위에서는 외부 장치 후보가 없으나 일부 VM 구성을 확인하지 못했습니다.",
            )
        return self._result(
            code,
            self.TITLES[code],
            Status.GOOD,
            f"점검 VM {len(records)}개에서 외부 장치 후보가 식별되지 않았습니다.",
        )

    def _api_hv20(self) -> CheckResult:
        return self._api_vm_option_check(
            "HV-20",
            {
                "isolation.tools.copy.disable": "true",
                "isolation.tools.paste.disable": "true",
                "isolation.tools.setGUIOptions.enable": "false",
            },
        )

    def _api_hv21(self) -> CheckResult:
        return self._api_vm_option_check(
            "HV-21", {"isolation.tools.dnd.disable": "true"}
        )

    def _api_hv22(self) -> CheckResult:
        return self._api_switch_check(
            "HV-22", "macChanges", "MAC 주소 변경"
        )

    def _api_hv23(self) -> CheckResult:
        return self._api_switch_check(
            "HV-23", "allowPromiscuous", "무차별 모드"
        )

    def _api_hv24(self) -> CheckResult:
        return self._api_switch_check(
            "HV-24", "forgedTransmits", "위조 전송"
        )

    def _api_hv25(self) -> CheckResult:
        code = "HV-25"
        product = getattr(
            getattr(self._esxi_host, "config", None), "product", None
        )
        parts = [
            str(getattr(product, "fullName", "")).strip(),
            (
                "version="
                + str(getattr(product, "version", "")).strip()
                if getattr(product, "version", None)
                else ""
            ),
            (
                "build="
                + str(getattr(product, "build", "")).strip()
                if getattr(product, "build", None)
                else ""
            ),
        ]
        image_manager = getattr(
            self._esxi_manager, "imageConfigManager", None
        )
        if image_manager is not None:
            try:
                profile = image_manager.HostImageConfigGetProfile()
                profile_name = str(getattr(profile, "name", "")).strip()
                if profile_name:
                    parts.append("image-profile=" + profile_name)
            except Exception:
                pass
        evidence = "; ".join(part for part in parts if part)
        return self._review(
            code,
            "HTTPS API로 제품/빌드 정보를 수집했습니다: "
            + (evidence or "세부 버전 없음")
            + ". 최신 벤더 권고 및 변경 이력 대조가 필요합니다.",
        )

    def check_hv01(self) -> CheckResult:
        return self._dispatch(1)

    def check_hv02(self) -> CheckResult:
        return self._dispatch(2)

    def check_hv03(self) -> CheckResult:
        return self._dispatch(3)

    def check_hv04(self) -> CheckResult:
        return self._dispatch(4)

    def check_hv05(self) -> CheckResult:
        return self._dispatch(5)

    def check_hv06(self) -> CheckResult:
        return self._dispatch(6)

    def check_hv07(self) -> CheckResult:
        return self._dispatch(7)

    def check_hv08(self) -> CheckResult:
        return self._dispatch(8)

    def check_hv09(self) -> CheckResult:
        return self._dispatch(9)

    def check_hv10(self) -> CheckResult:
        return self._dispatch(10)

    def check_hv11(self) -> CheckResult:
        return self._dispatch(11)

    def check_hv12(self) -> CheckResult:
        return self._dispatch(12)

    def check_hv13(self) -> CheckResult:
        return self._dispatch(13)

    def check_hv14(self) -> CheckResult:
        return self._dispatch(14)

    def check_hv15(self) -> CheckResult:
        return self._dispatch(15)

    def check_hv16(self) -> CheckResult:
        return self._dispatch(16)

    def check_hv17(self) -> CheckResult:
        return self._dispatch(17)

    def check_hv18(self) -> CheckResult:
        return self._dispatch(18)

    def check_hv19(self) -> CheckResult:
        return self._dispatch(19)

    def check_hv20(self) -> CheckResult:
        return self._dispatch(20)

    def check_hv21(self) -> CheckResult:
        return self._dispatch(21)

    def check_hv22(self) -> CheckResult:
        return self._dispatch(22)

    def check_hv23(self) -> CheckResult:
        return self._dispatch(23)

    def check_hv24(self) -> CheckResult:
        return self._dispatch(24)

    def check_hv25(self) -> CheckResult:
        return self._dispatch(25)


# 새 코드에서는 PEP 8 이름을 사용할 수 있고, 기존 이름도 호환된다.
VirtualHostAuditor = Virtual_Host


def _load_config(path: Path) -> dict[str, Any]:
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, Mapping):
        raise ValueError("설정 JSON의 최상위 값은 객체여야 합니다.")
    return dict(loaded)


def _require_platform_dependency(platform: str) -> None:
    """CLI 실행에 필요한 플랫폼별 모듈을 자격 증명 입력 전에 확인한다."""
    if platform == "esxi" and (
        SmartConnect is None or VsphereDisconnect is None or vim is None
    ):
        raise ValueError(
            "ESXi HTTPS vSphere API 점검에는 'pyvmomi' 패키지가 필요합니다. "
            "현재 실행 중인 Python에 다음 명령으로 설치하세요: "
            "python3 -m pip install pyvmomi "
            "('pyvomomi'가 아니라 'pyvmomi'입니다)."
        )
    if platform == "xenserver" and paramiko is None:
        raise ValueError(
            "XenServer SSH 점검에는 'paramiko' 패키지가 필요합니다. "
            "현재 실행 중인 Python에 다음 명령으로 설치하세요: "
            "python3 -m pip install paramiko"
        )


def _build_connection_info(args: argparse.Namespace) -> dict[str, Any]:
    info = _load_config(args.config) if args.config else {}

    if args.platform:
        info["platform"] = args.platform
    if args.host:
        info["ip"] = args.host
    if args.user:
        info["id"] = args.user
    if args.password_env:
        info["pw_env"] = args.password_env
        info.pop("pw", None)
    if args.ssh_port is not None:
        info["ssh_port"] = args.ssh_port
    if args.api_port is not None:
        info["api_port"] = args.api_port
    if args.timeout is not None:
        info["timeout"] = args.timeout
    if args.insecure_tls:
        info["verify_tls"] = False
    if args.accept_unknown_host_key:
        info["strict_host_key"] = False

    for alias in ("host", "hostname"):
        if "ip" not in info and alias in info:
            info["ip"] = info[alias]
    for alias in ("username", "user"):
        if "id" not in info and alias in info:
            info["id"] = info[alias]

    platform = str(info.get("platform", "")).strip().lower()
    platform = Virtual_Host._PLATFORM_ALIASES.get(platform, platform)
    if not platform:
        platform = input("플랫폼(esxi/xenserver): ").strip().lower()
        platform = Virtual_Host._PLATFORM_ALIASES.get(platform, platform)
    if platform not in {"esxi", "xenserver"}:
        raise ValueError("platform은 esxi 또는 xenserver여야 합니다.")
    info["platform"] = platform
    if platform == "esxi":
        if args.ssh_port is not None:
            raise ValueError("--ssh-port는 XenServer에서만 사용할 수 있습니다.")
        if args.accept_unknown_host_key:
            raise ValueError(
                "--accept-unknown-host-key는 XenServer에서만 사용할 수 있습니다."
            )
    else:
        if args.api_port is not None:
            raise ValueError("--api-port는 ESXi에서만 사용할 수 있습니다.")
        if args.insecure_tls:
            raise ValueError("--insecure-tls는 ESXi에서만 사용할 수 있습니다.")

    _require_platform_dependency(platform)

    if not str(info.get("ip", "")).strip():
        info["ip"] = input("IP 또는 호스트명: ").strip()
    if not str(info.get("id", "")).strip():
        info["id"] = input("접속 ID: ").strip()

    pw_env = str(info.get("pw_env", "")).strip()
    if pw_env:
        if pw_env not in os.environ:
            raise ValueError(
                f"환경 변수 {pw_env!r}가 설정되지 않았습니다."
            )
    elif (
        "pw" not in info
        and not (
            platform == "xenserver" and info.get("key_filename")
        )
    ):
        info["pw"] = getpass.getpass("접속 비밀번호: ")

    return info


def _parse_check_codes(raw: str | None) -> list[str]:
    if not raw:
        return [f"HV-{number:02d}" for number in range(1, 26)]

    codes: list[str] = []
    for token in re.split(r"[\s,]+", raw.upper().strip()):
        if not token:
            continue
        match = re.fullmatch(r"(?:HV-?)?(\d{1,2})", token)
        if not match:
            raise ValueError(f"올바르지 않은 점검 코드: {token}")
        number = int(match.group(1))
        if not 1 <= number <= 25:
            raise ValueError(
                f"점검 코드 범위는 HV-01~HV-25입니다: {token}"
            )
        code = f"HV-{number:02d}"
        if code not in codes:
            codes.append(code)
    if not codes:
        raise ValueError("점검 코드를 하나 이상 지정하세요.")
    return codes


def _run_selected(
    auditor: Virtual_Host, codes: Sequence[str]
) -> list[CheckResult]:
    results: list[CheckResult] = []
    for code in codes:
        number = code.split("-")[1]
        method = getattr(auditor, f"check_hv{number}")
        results.append(method())
    return results


def _print_results(results: Sequence[CheckResult]) -> None:
    print("\n점검 결과")
    print("-" * 90)
    for result in results:
        print(
            f"{result.code:<6} [{result.status.value}] "
            f"{result.title}\n"
            f"       근거: {result.evidence}"
        )
        if result.recommendation:
            print(f"       권고: {result.recommendation}")
    print("-" * 90)
    summary = {
        status.value: sum(item.status == status for item in results)
        for status in Status
    }
    print(
        " / ".join(
            f"{name} {count}" for name, count in summary.items()
        )
    )


def _make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "ESXi/XenServer HV-01~HV-25 읽기 전용 보안 점검기"
        )
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="접속 및 정책 정보 JSON 파일",
    )
    parser.add_argument(
        "--platform",
        choices=("esxi", "xenserver"),
        help="esxi는 HTTPS API, xenserver는 SSH 사용",
    )
    parser.add_argument("--host", help="IP 또는 호스트명")
    parser.add_argument("--user", help="점검 접속 계정")
    parser.add_argument(
        "--password-env",
        help="접속 비밀번호가 들어 있는 환경 변수 이름",
    )
    parser.add_argument(
        "--ssh-port", type=int, help="XenServer SSH 포트"
    )
    parser.add_argument(
        "--api-port", type=int, help="ESXi vSphere API HTTPS 포트"
    )
    parser.add_argument("--timeout", type=float, help="연결 제한 시간(초)")
    parser.add_argument(
        "--insecure-tls",
        action="store_true",
        help="TLS 인증서 검증을 끔(격리된 시험망에서만 사용)",
    )
    parser.add_argument(
        "--accept-unknown-host-key",
        action="store_true",
        help="미등록 SSH 호스트 키를 허용(격리된 시험망에서만 사용)",
    )
    parser.add_argument(
        "--checks",
        help="실행할 항목. 예: HV-01,HV-09,HV-25",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="JSON 보고서 경로",
    )
    parser.add_argument(
        "--fail-on-vulnerable",
        action="store_true",
        help="취약 또는 오류가 있으면 종료 코드 1 반환",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _make_parser()
    args = parser.parse_args(argv)

    try:
        info = _build_connection_info(args)
        codes = _parse_check_codes(args.checks)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))

    try:
        with Virtual_Host(info) as auditor:
            if auditor._connection_errors:
                print("연결 경고:")
                for item in auditor._connection_errors:
                    print("-", auditor._sanitize(item))

            print(f"플랫폼: {auditor.platform}")
            print(f"접속 방식: {auditor.connection_mode}")
            print(f"제품 정보: {auditor.platform_detail}")
            results = _run_selected(auditor, codes)
            _print_results(results)

            output = args.output or Path(
                "audit-report-virtual-"
                + datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
                + ".json"
            )
            saved_report = auditor.save_report(results, output)
            print("JSON 보고서:", saved_report)

            if args.fail_on_vulnerable and any(
                item.status in {
                    Status.VULNERABLE,
                    Status.ERROR,
                }
                for item in results
            ):
                return 1
            return 0
    except KeyboardInterrupt:
        print("\n점검이 취소되었습니다.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(
            f"실행할 수 없습니다: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())



# ============================================================================
# main.py 연동용 래퍼 (기존 코드는 수정하지 않고 아래에 덧붙임)
#
#   device_list.json 스키마
#     {
#       "ip": "172.16.14.31",
#       "hostname": "esxi_host",
#       "type": "virtual",
#       "conn_info": { "port": 443, "user": "root", "password": "..." },
#       "virt_info": { "platform": "esxi" }
#     }
#
#   platform 은 필수(esxi | xenserver)다.
#   ESXi 는 HTTPS vSphere API 로만, XenServer 는 SSH 로만 점검하므로
#   자동 판별하지 않는다.
#
#   requires_ssh = False :
#     Virtual_Host 가 자체적으로 연결을 관리하므로
#     main.py 는 SSHConnection.connect() 를 호출하지 않는다.
# ============================================================================
class VirtualDevice:
    """가상화 장비 점검 항목을 main.py 규격으로 노출하는 래퍼."""

    requires_ssh = False

    check_list = {
        "hv_01": {"code": "HV-01", "title": "계정 로그오프/세션 관리"},
        "hv_02": {"code": "HV-02", "title": "가상화 장비 외부접속 차단"},
        "hv_03": {"code": "HV-03", "title": "가상화 장비 루트계정 관리"},
        "hv_04": {"code": "HV-04", "title": "가상화 장비 계정 권한 관리"},
        "hv_05": {"code": "HV-05", "title": "가상화 장비 사용자 인증 강화"},
        "hv_06": {"code": "HV-06", "title": "비밀번호 관리정책 설정"},
        "hv_07": {"code": "HV-07", "title": "계정 잠금 임계값 설정"},
        "hv_08": {"code": "HV-08", "title": "시스템 사용 주의사항 출력 설정"},
        "hv_09": {"code": "HV-09", "title": "NTP 및 시각 동기화 설정"},
        "hv_10": {"code": "HV-10", "title": "SNMP Community String 복잡성 적용"},
        "hv_11": {"code": "HV-11", "title": "MOB(Managed Object Browser) 서비스 비활성화"},
        "hv_12": {"code": "HV-12", "title": "ESXi Shell 비활성화"},
        "hv_13": {"code": "HV-13", "title": "ESXi Shell 세션 종료 시간 설정"},
        "hv_14": {"code": "HV-14", "title": "원격 로그 서버 이용"},
        "hv_15": {"code": "HV-15", "title": "시스템 주요 이벤트 로그 설정"},
        "hv_16": {"code": "HV-16", "title": "비휘발성 경로 내 로그 파일 저장"},
        "hv_17": {"code": "HV-17", "title": "코어덤프 수집 기능 활성화"},
        "hv_18": {"code": "HV-18", "title": "가상 머신의 장치 변경 제한 설정"},
        "hv_19": {"code": "HV-19", "title": "가상 머신의 불필요한 장치 제거"},
        "hv_20": {"code": "HV-20", "title": "가상 머신 콘솔 클립보드 복사&붙여넣기 기능 비활성화"},
        "hv_21": {"code": "HV-21", "title": "가상 머신 콘솔 드래그 앤 드롭 기능 비활성화"},
        "hv_22": {"code": "HV-22", "title": "가상 스위치 MAC 주소 변경 정책 비활성화"},
        "hv_23": {"code": "HV-23", "title": "가상 스위치 무차별(Promiscuous) 모드 정책 비활성화"},
        "hv_24": {"code": "HV-24", "title": "가상 스위치 위조전송(Forged Transmits) 모드 정책 비활성화"},
        "hv_25": {"code": "HV-25", "title": "주기적 보안 패치 및 벤더 권고사항 적용"},
    }

    def __init__(self, conn):
        self.conn = conn

        device = dict(getattr(conn, "device", None) or {})
        virt_info = dict(device.get("virt_info") or {})
        conn_info = dict(device.get("conn_info") or {})

        platform = str(virt_info.get("platform", "")).strip().lower()
        if not platform:
            raise ValueError(
                "device_list.json 의 virt_info.platform 이 필요합니다 "
                "(esxi 또는 xenserver)."
            )

        connection_info = {
            "platform": platform,
            "ip": getattr(conn, "hostname", ""),
            "id": conn_info.get("user", getattr(conn, "username", "")),
            "pw": conn_info.get("password", getattr(conn, "password", "")),
        }
        for key, value in virt_info.items():
            if key != "platform":
                connection_info[key] = value

        self.platform = platform
        self._host = Virtual_Host(connection_info)

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)

        host = self.__dict__.get("_host")
        if host is not None:
            func = getattr(host, name, None)
            if func is not None:
                return func

        raise AttributeError(
            f"{type(self).__name__} 에 '{name}' 점검 항목이 없습니다."
        )
