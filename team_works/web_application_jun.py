#!/usr/bin/env python3
"""SSH/SFTP 기반 웹 애플리케이션 정적 취약점 점검기.

2026 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드의
EP, IA, PR, IS, CC 항목을 보조적으로 점검한다. 원격 파일은 읽기만 하며,
서비스에 요청을 반복하거나 파일/설정을 변경하지 않는다.

이 파일 하나만 복사해 실행할 수 있다. SSH 모듈이 없으면 최초 실행 시
인터넷을 통해 사용자 전용 캐시에 자동 설치하며 이후 실행에서는 캐시를 사용한다.
"""

from __future__ import annotations

import argparse
import getpass
import importlib
import json
import os
import posixpath
import re
import stat
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Sequence

try:
    import paramiko  # type: ignore
except ImportError:  # 정적 규칙 단위 테스트는 paramiko 없이도 실행 가능하다.
    paramiko = None  # type: ignore[assignment]


PARAMIKO_REQUIREMENT = "paramiko>=3.4,<5"


def _dependency_cache_path() -> Path:
    """자동 설치 패키지를 현재 Python 환경과 분리된 사용자 캐시에 둔다."""
    override = os.environ.get("WEB_SCANNER_DEPENDENCY_DIR")
    if override:
        return Path(override).expanduser().resolve()

    if os.name == "nt" and os.environ.get("LOCALAPPDATA"):
        base = Path(os.environ["LOCALAPPDATA"])
    elif os.environ.get("XDG_CACHE_HOME"):
        base = Path(os.environ["XDG_CACHE_HOME"])
    else:
        base = Path.home() / ".cache"
    return base / "web-ssh-scanner" / "python-packages"


def _import_cached_paramiko(cache_dir: Path) -> Any:
    cache_text = str(cache_dir)
    if cache_text not in sys.path:
        sys.path.insert(0, cache_text)
    importlib.invalidate_caches()
    return importlib.import_module("paramiko")


def _ensure_paramiko() -> Any:
    """paramiko가 없으면 전용 캐시에 자동 설치한 뒤 모듈을 반환한다."""
    global paramiko
    if paramiko is not None:
        return paramiko

    cache_dir = _dependency_cache_path()
    if cache_dir.is_dir():
        try:
            paramiko = _import_cached_paramiko(cache_dir)
            return paramiko
        except (ImportError, OSError):
            pass

    print(
        f"SSH 기능에 필요한 {PARAMIKO_REQUIREMENT}을(를) 최초 1회 설치합니다.\n"
        f"설치 위치: {cache_dir}",
        file=sys.stderr,
    )
    cache_dir.mkdir(parents=True, exist_ok=True)

    pip_check = subprocess.run(
        [sys.executable, "-m", "pip", "--version"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if pip_check.returncode != 0:
        ensure = subprocess.run(
            [sys.executable, "-m", "ensurepip", "--upgrade"],
            check=False,
        )
        if ensure.returncode != 0:
            raise RuntimeError(
                "자동 설치에 필요한 pip를 준비하지 못했습니다. pip가 포함된 Python 3.10 이상을 사용하세요."
            )

    install = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-warn-script-location",
            "--upgrade",
            "--target",
            str(cache_dir),
            PARAMIKO_REQUIREMENT,
        ],
        check=False,
    )
    if install.returncode != 0:
        raise RuntimeError(
            "SSH 모듈 자동 설치에 실패했습니다. 최초 실행 시 인터넷 연결과 사용자 캐시 쓰기 권한이 필요합니다."
        )

    try:
        paramiko = _import_cached_paramiko(cache_dir)
    except (ImportError, OSError) as exc:
        raise RuntimeError(f"설치된 SSH 모듈을 불러오지 못했습니다: {exc}") from exc
    return paramiko


class Status(str, Enum):
    VULNERABLE = "취약"
    REVIEW = "점검 필요"
    PASS = "양호 추정"
    NOT_APPLICABLE = "해당 없음"
    ERROR = "오류"


STATUS_RANK = {
    Status.NOT_APPLICABLE: 0,
    Status.PASS: 1,
    Status.REVIEW: 2,
    Status.VULNERABLE: 3,
    Status.ERROR: 4,
}


ITEMS = {
    "EP": {
        "title": "에러 페이지 적용 미흡",
        "guide_pages": "703-707",
    },
    "IA": {
        "title": "불충분한 인증 절차",
        "guide_pages": "729-732",
    },
    "PR": {
        "title": "취약한 비밀번호 복구 절차",
        "guide_pages": "735-738",
    },
    "IS": {
        "title": "불충분한 세션 관리",
        "guide_pages": "759-765",
    },
    "CC": {
        "title": "자동화 공격",
        "guide_pages": "777-778",
    },
}


HTML_EXTENSIONS = {".html", ".htm", ".xhtml", ".shtml"}
SOURCE_EXTENSIONS = {
    ".php",
    ".phtml",
    ".jsp",
    ".jspx",
    ".java",
    ".kt",
    ".cs",
    ".cshtml",
    ".vb",
    ".aspx",
    ".py",
    ".rb",
    ".go",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
}
CONFIG_EXTENSIONS = {".conf", ".ini", ".config", ".properties", ".yml", ".yaml", ".toml"}
CONFIG_NAMES = {
    ".htaccess",
    "apache2.conf",
    "httpd.conf",
    "nginx.conf",
    "server.xml",
    "web.xml",
    "web.config",
    "php.ini",
    "application.properties",
    "application.yml",
    "application.yaml",
    "appsettings.json",
    "settings.py",
}
IGNORED_DIRECTORIES = {
    ".git",
    ".svn",
    ".hg",
    ".idea",
    ".vscode",
    "node_modules",
    "vendor",
    ".venv",
    "venv",
    "__pycache__",
    "logs",
}
COMMON_CONFIG_PATHS = (
    "/etc/httpd/conf/httpd.conf",
    "/etc/httpd/conf.d",
    "/etc/apache2/apache2.conf",
    "/etc/apache2/conf-available",
    "/etc/apache2/sites-available",
    "/etc/nginx/nginx.conf",
    "/etc/nginx/conf.d",
    "/etc/nginx/sites-available",
    "/etc/php.ini",
    "/etc/tomcat/server.xml",
    "/etc/tomcat/web.xml",
    "/opt/tomcat/conf/server.xml",
    "/opt/tomcat/conf/web.xml",
)


@dataclass(frozen=True)
class Evidence:
    line: int | None
    rule: str
    excerpt: str

    def to_dict(self) -> dict[str, Any]:
        return {"line": self.line, "rule": self.rule, "excerpt": self.excerpt}


@dataclass(frozen=True)
class RemoteFile:
    path: str
    kind: str
    text: str
    encoding: str = "utf-8"
    size: int = 0


@dataclass
class Finding:
    code: str
    title: str
    guide_pages: str
    status: Status
    confidence: str
    path: str
    file_kind: str
    summary: str
    recommendation: str
    evidence: list[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "title": self.title,
            "guide_pages": self.guide_pages,
            "status": self.status.value,
            "confidence": self.confidence,
            "path": self.path,
            "file_kind": self.file_kind,
            "summary": self.summary,
            "recommendation": self.recommendation,
            "evidence": [item.to_dict() for item in self.evidence],
        }


@dataclass
class ScanReport:
    target: dict[str, Any]
    started_at: str
    finished_at: str = ""
    scanned_files: dict[str, int] = field(default_factory=dict)
    skipped_files: int = 0
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def _assessment(self) -> dict[str, Any]:
        grouped: dict[str, list[Finding]] = defaultdict(list)
        for finding in self.findings:
            grouped[finding.code].append(finding)

        result: dict[str, Any] = {}
        for code, metadata in ITEMS.items():
            values = grouped.get(code, [])
            counts = Counter(item.status.value for item in values)
            meaningful = [item.status for item in values if item.status != Status.NOT_APPLICABLE]
            overall = max(meaningful, key=lambda item: STATUS_RANK[item]) if meaningful else Status.NOT_APPLICABLE
            binary_vulnerable = any(
                item.status in {Status.VULNERABLE, Status.REVIEW, Status.ERROR}
                for item in values
            )
            result[code] = {
                "title": metadata["title"],
                "status": "취약" if binary_vulnerable else "양호",
                "detailed_status": overall.value,
                "counts": dict(counts),
            }
        return result

    def to_dict(self, include_not_applicable: bool = True) -> dict[str, Any]:
        findings = self.findings
        if not include_not_applicable:
            findings = [item for item in findings if item.status != Status.NOT_APPLICABLE]
        return {
            "scanner": "Web SSH Static Scanner",
            "mode": "read-only static analysis",
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "scanned_files": self.scanned_files,
            "skipped_files": self.skipped_files,
            "item_assessment": self._assessment(),
            "findings": [item.to_dict() for item in findings],
            "errors": self.errors,
            "limitations": [
                "정적 분석 결과이며 런타임 동작과 외부 WAF/프록시 정책을 완전히 확인하지 못합니다.",
                "점검 필요 항목은 승인된 환경에서 수동 또는 동적 검증이 필요합니다.",
                "화면의 이진 판정에서는 점검 필요 또는 검사 오류가 하나라도 있으면 보수적으로 취약으로 표시합니다.",
                "CC 검사는 서비스 장애를 유발할 수 있는 반복 요청을 전송하지 않습니다.",
            ],
        }


Rule = tuple[str, str]


def _redact(text: str) -> str:
    """보고서 증적에 비밀번호, 토큰 및 키 원문이 남지 않도록 마스킹한다."""
    text = re.sub(
        r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|authorization)\b"
        r"(\s*[:=]\s*)(['\"]?)[^\s,'\";<>]{3,}\3",
        r"\1\2<redacted>",
        text,
    )
    text = re.sub(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*", "<redacted-jwt>", text)
    return text.strip()[:260]


def _line_excerpt(text: str, position: int) -> tuple[int, str]:
    line = text.count("\n", 0, position) + 1
    start = text.rfind("\n", 0, position) + 1
    end = text.find("\n", position)
    if end < 0:
        end = len(text)
    return line, _redact(text[start:end])


def _collect_evidence(text: str, rules: Sequence[Rule], limit: int = 6) -> list[Evidence]:
    found: list[Evidence] = []
    seen: set[tuple[str, int]] = set()
    for rule_name, pattern in rules:
        try:
            matches = re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE)
        except re.error as exc:
            raise ValueError(f"잘못된 정규식 규칙 {rule_name}: {exc}") from exc
        for match in matches:
            line, excerpt = _line_excerpt(text, match.start())
            key = (rule_name, line)
            if key in seen:
                continue
            seen.add(key)
            found.append(Evidence(line=line, rule=rule_name, excerpt=excerpt))
            if len(found) >= limit:
                return found
    return found


def _feature_evidence(remote_file: RemoteFile, rule: str, message: str) -> Evidence:
    return Evidence(line=None, rule=rule, excerpt=_redact(f"{message}: {remote_file.path}"))


def _contains(text: str, pattern: str) -> bool:
    return re.search(pattern, text, re.IGNORECASE | re.MULTILINE) is not None


def _is_non_runtime_path(path: str) -> bool:
    """도움말·문서·CI·테스트 파일을 실행 코드 판정에서 제외한다."""
    normalized = path.replace("\\", "/").lower()
    segments = {segment for segment in normalized.split("/") if segment}
    excluded_segments = {
        ".github",
        ".gitlab",
        "docs",
        "doc",
        "documentation",
        "help",
        "tests",
        "test",
        "examples",
        "example",
        "samples",
        "sample",
    }
    name = PurePosixPath(normalized).name
    return bool(segments & excluded_segments) or name.startswith(
        ("readme", "changelog", "contributing", "license")
    )


class Web:
    """원격 웹 루트를 읽기 전용으로 검사하는 SSH/SFTP 스캐너.

    공개 메서드 ``EP``, ``IA``, ``PR``, ``IS``, ``CC``가 각각 가이드의
    항목 코드에 대응한다. 모든 HTML 파일은 다섯 메서드를 모두 거치고,
    서버 소스 및 설정 파일은 적용 가능한 메서드만 별도로 거친다.
    """

    CHECK_METHODS = ("EP", "IA", "PR", "IS", "CC")
    CONFIG_CHECK_METHODS = ("EP", "IS", "CC")

    def __init__(
        self,
        server_ip: str,
        username: str,
        password: str,
        html_path: str,
        *,
        port: int = 22,
        config_paths: Sequence[str] | None = None,
        known_hosts: str | None = None,
        accept_new_host_key: bool = False,
        auto_config_discovery: bool = True,
        connect_timeout: float = 15.0,
        max_files: int = 10_000,
        max_file_bytes: int = 2 * 1024 * 1024,
        max_depth: int = 40,
    ) -> None:
        if not server_ip.strip():
            raise ValueError("server_ip가 비어 있습니다.")
        if not username.strip():
            raise ValueError("username이 비어 있습니다.")
        if not html_path.strip():
            raise ValueError("html_path가 비어 있습니다.")
        if not (1 <= port <= 65535):
            raise ValueError("port는 1~65535 범위여야 합니다.")
        if max_files < 1 or max_file_bytes < 1 or max_depth < 0:
            raise ValueError("max_files/max_file_bytes는 양수이고 max_depth는 0 이상이어야 합니다.")

        self.server_ip = server_ip.strip()
        self.username = username.strip()
        self.password = password
        self.html_path = self._normalize_remote_path(html_path)
        self.port = port
        self.config_paths = [self._normalize_remote_path(item) for item in (config_paths or [])]
        self.known_hosts = known_hosts
        self.accept_new_host_key = accept_new_host_key
        self.auto_config_discovery = auto_config_discovery
        self.connect_timeout = connect_timeout
        self.max_files = max_files
        self.max_file_bytes = max_file_bytes
        self.max_depth = max_depth

        self._ssh: Any = None
        self._sftp: Any = None

    @staticmethod
    def _normalize_remote_path(path: str) -> str:
        normalized = path.strip().replace("\\", "/")
        if not normalized:
            raise ValueError("원격 경로가 비어 있습니다.")
        return posixpath.normpath(normalized)

    def __enter__(self) -> "Web":
        self.connect()
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    def connect(self) -> None:
        if self._sftp is not None:
            return
        ssh_module = _ensure_paramiko()

        client = ssh_module.SSHClient()
        client.load_system_host_keys()
        if self.known_hosts:
            expanded = os.path.expanduser(self.known_hosts)
            if not os.path.isfile(expanded):
                raise FileNotFoundError(f"known_hosts 파일을 찾을 수 없습니다: {expanded}")
            client.load_host_keys(expanded)

        if self.accept_new_host_key:
            client.set_missing_host_key_policy(ssh_module.AutoAddPolicy())
        else:
            client.set_missing_host_key_policy(ssh_module.RejectPolicy())

        try:
            client.connect(
                hostname=self.server_ip,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=self.connect_timeout,
                banner_timeout=self.connect_timeout,
                auth_timeout=self.connect_timeout,
                allow_agent=False,
                look_for_keys=False,
            )
            self._sftp = client.open_sftp()
            self._ssh = client
        except Exception:
            client.close()
            raise

    def close(self) -> None:
        if self._sftp is not None:
            try:
                self._sftp.close()
            finally:
                self._sftp = None
        if self._ssh is not None:
            self._ssh.close()
            self._ssh = None

    def _discover_common_config_paths(self) -> list[str]:
        if not self.auto_config_discovery or self._sftp is None:
            return []
        discovered: list[str] = []
        for path in COMMON_CONFIG_PATHS:
            try:
                self._sftp.stat(path)
            except OSError:
                continue
            discovered.append(path)
        return discovered

    @staticmethod
    def _classify(path: str, *, explicit_config: bool = False) -> str | None:
        name = PurePosixPath(path).name.lower()
        suffix = PurePosixPath(name).suffix.lower()
        if suffix in HTML_EXTENSIONS:
            return "html"
        if name in CONFIG_NAMES or suffix in CONFIG_EXTENSIONS:
            return "config"
        if suffix == ".xml" and name in {"server.xml", "web.xml"}:
            return "config"
        if suffix == ".json" and (name == "appsettings.json" or name.startswith("appsettings.")):
            return "config"
        if suffix in SOURCE_EXTENSIONS:
            return "source"
        if explicit_config:
            return "config"
        return None

    def _iter_remote_files(self, root: str, *, explicit_config: bool = False) -> Iterable[tuple[str, str, Any]]:
        if self._sftp is None:
            raise RuntimeError("SSH 연결이 설정되지 않았습니다.")

        root_attr = self._sftp.stat(root)
        if stat.S_ISREG(root_attr.st_mode):
            kind = self._classify(root, explicit_config=explicit_config)
            if kind:
                yield root, kind, root_attr
            return
        if not stat.S_ISDIR(root_attr.st_mode):
            return

        stack: list[tuple[str, int]] = [(root, 0)]
        yielded = 0
        while stack:
            directory, depth = stack.pop()
            if depth > self.max_depth:
                continue
            entries = self._sftp.listdir_attr(directory)
            for entry in entries:
                child = posixpath.join(directory, entry.filename)
                mode = entry.st_mode
                if stat.S_ISLNK(mode):
                    continue
                if stat.S_ISDIR(mode):
                    if entry.filename.lower() not in IGNORED_DIRECTORIES and depth < self.max_depth:
                        stack.append((child, depth + 1))
                    continue
                if not stat.S_ISREG(mode):
                    continue
                kind = self._classify(child, explicit_config=explicit_config)
                if kind is None:
                    continue
                yield child, kind, entry
                yielded += 1
                if yielded >= self.max_files:
                    return

    @staticmethod
    def _decode(data: bytes) -> tuple[str, str]:
        if b"\x00" in data[:4096]:
            raise ValueError("바이너리 파일로 판단되어 건너뜁니다.")
        for encoding in ("utf-8-sig", "utf-8", "cp949", "euc-kr"):
            try:
                return data.decode(encoding), encoding
            except UnicodeDecodeError:
                continue
        return data.decode("latin-1"), "latin-1"

    def _read_remote_file(self, path: str, kind: str, attr: Any) -> RemoteFile:
        if self._sftp is None:
            raise RuntimeError("SSH 연결이 설정되지 않았습니다.")
        declared_size = int(getattr(attr, "st_size", 0) or 0)
        if declared_size > self.max_file_bytes:
            raise ValueError(f"파일 크기 제한 초과({declared_size} > {self.max_file_bytes} bytes)")
        with self._sftp.open(path, "rb") as stream:
            data = stream.read(self.max_file_bytes + 1)
        if len(data) > self.max_file_bytes:
            raise ValueError(f"파일 크기 제한 초과(>{self.max_file_bytes} bytes)")
        text, encoding = self._decode(data)
        return RemoteFile(path=path, kind=kind, text=text, encoding=encoding, size=len(data))

    def _result(
        self,
        code: str,
        remote_file: RemoteFile,
        status: Status,
        confidence: str,
        summary: str,
        recommendation: str,
        evidence: Sequence[Evidence] = (),
    ) -> Finding:
        metadata = ITEMS[code]
        return Finding(
            code=code,
            title=metadata["title"],
            guide_pages=metadata["guide_pages"],
            status=status,
            confidence=confidence,
            path=remote_file.path,
            file_kind=remote_file.kind,
            summary=summary,
            recommendation=recommendation,
            evidence=list(evidence),
        )

    # ------------------------------------------------------------------ EP
    def EP(self, remote_file: RemoteFile) -> Finding:
        """EP: 에러 페이지의 상세 정보 노출 및 사용자 정의 오류 설정을 점검한다."""
        if remote_file.kind == "config":
            return self._EP_config(remote_file)

        if remote_file.kind == "html":
            sensitive_rules: list[Rule] = [
                ("EP-SERVER-VERSION", r"\b(?:Apache|nginx|Microsoft-IIS|Tomcat|Jetty)/\d+(?:\.\d+)+"),
                ("EP-STACKTRACE", r"\b(?:Traceback \(most recent call last\)|Stack trace:|Exception in thread|System\.Web\.HttpException)\b"),
                ("EP-JAVA-TRACE", r"\bat\s+[a-z_$][\w$]*(?:\.[\w$]+){2,}\([^\n)]*\.java:\d+\)"),
                ("EP-PHP-ERROR", r"\b(?:Fatal error|Warning|Parse error):[^\n<]{0,180}\bon line\s+\d+"),
                ("EP-SQL-DETAIL", r"\b(?:SQLSTATE\[[^\]]+\]|ORA-\d{4,5}|Unclosed quotation mark|syntax error at or near)\b"),
                ("EP-ABSOLUTE-PATH", r"(?:[A-Za-z]:\\(?:inetpub|xampp|wamp|Users|Program Files)\\|/(?:var/www|srv/www|home/[^/\s]+|opt/[^/\s]+)/(?:[^\s<'\"]+/)*)"),
                ("EP-SERVER-SIGNATURE", r"\bServer at\s+[^<\n]+\s+Port\s+\d+"),
            ]
            sensitive = _collect_evidence(remote_file.text, sensitive_rules)
            if sensitive:
                return self._result(
                    "EP",
                    remote_file,
                    Status.VULNERABLE,
                    "높음",
                    "HTML 응답 템플릿에서 서버 버전, 경로, 스택 트레이스 또는 DB 오류로 보이는 상세 정보가 발견되었습니다.",
                    "사용자 정의 오류 페이지에는 일반화된 메시지만 표시하고 상세 오류는 접근 통제된 서버 로그에만 기록하세요.",
                    sensitive,
                )

            error_hint = _contains(
                f"{remote_file.path}\n{remote_file.text[:8000]}",
                r"(?:^|[/_.-])(?:error|errors|404|405|500|50x)(?:[/_.-]|$)|<title>[^<]*(?:error|not found|오류|에러)",
            )
            if error_hint:
                generic = _collect_evidence(
                    remote_file.text,
                    [("EP-CUSTOM-PAGE", r"(?:요청하신 페이지를 찾을 수 없습니다|문제가 발생했습니다|not found|something went wrong|try again later)")],
                    limit=2,
                )
                if generic:
                    return self._result(
                        "EP",
                        remote_file,
                        Status.PASS,
                        "중간",
                        "사용자 정의 오류 페이지로 보이며 정적 파일 안에서 상세 오류 노출 징후가 발견되지 않았습니다.",
                        "실제 4xx/5xx 응답에도 이 페이지가 매핑되는지 승인된 동적 점검으로 확인하세요.",
                        generic,
                    )
                return self._result(
                    "EP",
                    remote_file,
                    Status.REVIEW,
                    "중간",
                    "오류 페이지로 보이지만 일반화된 메시지와 서버 측 매핑 여부를 정적 HTML만으로 확정할 수 없습니다.",
                    "4xx/5xx 사용자 정의 매핑과 서버 버전/스택 트레이스 비노출을 확인하세요.",
                    [_feature_evidence(remote_file, "EP-ERROR-PAGE-HINT", "오류 페이지 후보")],
                )
            return self._result(
                "EP",
                remote_file,
                Status.NOT_APPLICABLE,
                "낮음",
                "일반 HTML에서 오류 페이지 또는 상세 오류 노출 징후가 발견되지 않았습니다.",
                "서버 설정 파일 및 실제 4xx/5xx 응답을 별도로 확인하세요.",
            )

        if _is_non_runtime_path(remote_file.path):
            return self._result(
                "EP",
                remote_file,
                Status.NOT_APPLICABLE,
                "높음",
                "도움말·문서·CI·테스트 경로이므로 실행 코드 판정에서 제외했습니다.",
                "실제 운영 응답을 생성하는 소스와 서버 설정을 검사하세요.",
            )

        bad_source = _collect_evidence(
            remote_file.text,
            [
                ("EP-DEBUG-ENABLED", r"\b(?:DEBUG\s*=\s*True|debug\s*[:=]\s*true|display_errors\s*=\s*(?:On|1)|IncludeExceptionDetails\s*[:=]\s*true)\b"),
                ("EP-STACKTRACE-TO-RESPONSE", r"(?:printStackTrace\s*\(\s*(?:response|getWriter)|response\.(?:write|send)\s*\([^\n]*(?:exception|stackTrace))"),
                ("EP-RAW-EXCEPTION", r"(?:res\.(?:send|json)|Response\.Write|echo)\s*\([^\n]*(?:exception|stack[_-]?trace|error\.stack)"),
            ],
        )
        if bad_source:
            return self._result(
                "EP",
                remote_file,
                Status.VULNERABLE,
                "높음",
                "디버그 활성화 또는 예외 상세를 응답으로 보내는 코드 징후가 발견되었습니다.",
                "운영 환경 디버그를 끄고 공통 예외 처리기로 일반화된 오류만 응답하세요.",
                bad_source,
            )

        good_source = _collect_evidence(
            remote_file.text,
            [
                ("EP-GLOBAL-HANDLER", r"(?:@ControllerAdvice|@ExceptionHandler|@app\.errorhandler|UseExceptionHandler\s*\(|handler404\s*=|handler500\s*=)"),
                ("EP-GENERIC-RESPONSE", r"(?:status\s*\(\s*500\s*\)|HttpStatus\.INTERNAL_SERVER_ERROR)[^\n]{0,160}(?:generic|unexpected|문제가|오류가)"),
            ],
        )
        if good_source:
            return self._result(
                "EP",
                remote_file,
                Status.PASS,
                "중간",
                "공통 예외 처리 또는 일반화된 오류 응답 구현 징후가 발견되었습니다.",
                "운영 응답에서 상세 정보가 실제로 제거되는지 확인하세요.",
                good_source,
            )
        return self._result(
            "EP",
            remote_file,
            Status.NOT_APPLICABLE,
            "낮음",
            "이 소스 파일에서 오류 처리 관련 징후가 발견되지 않았습니다.",
            "공통 예외 처리기와 서버 오류 설정을 함께 검토하세요.",
        )

    def _EP_config(self, remote_file: RemoteFile) -> Finding:
        text = remote_file.text
        bad = _collect_evidence(
            text,
            [
                ("EP-APACHE-SIGNATURE-ON", r"^\s*ServerSignature\s+On\b"),
                ("EP-APACHE-TOKENS-VERBOSE", r"^\s*ServerTokens\s+(?:Full|OS|Min|Major|Minor)\b"),
                ("EP-NGINX-TOKENS-ON", r"^\s*server_tokens\s+on\s*;"),
                ("EP-TOMCAT-REPORT-ON", r"\b(?:showReport|showServerInfo)\s*=\s*['\"]true['\"]"),
                ("EP-IIS-DETAILED", r"\b(?:customErrors\s+mode\s*=\s*['\"]Off|httpErrors[^>]+errorMode\s*=\s*['\"]Detailed['\"])") ,
                ("EP-DEBUG-ENABLED", r"\b(?:DEBUG\s*=\s*True|debug\s*[:=]\s*true|display_errors\s*=\s*(?:On|1)|include-stacktrace\s*=\s*always)\b"),
            ],
        )
        if bad:
            return self._result(
                "EP",
                remote_file,
                Status.VULNERABLE,
                "높음",
                "상세 오류 또는 서버 식별 정보 노출을 허용하는 설정이 발견되었습니다.",
                "운영 환경에서 상세 오류를 끄고 서버 서명 제거 및 사용자 정의 4xx/5xx 페이지를 설정하세요.",
                bad,
            )

        positive = _collect_evidence(
            text,
            [
                ("EP-APACHE-HARDENING", r"^\s*(?:ServerTokens\s+Prod|ServerSignature\s+Off)\b"),
                ("EP-APACHE-CUSTOM", r"^\s*ErrorDocument\s+(?:4\d\d|5\d\d)\s+\S+"),
                ("EP-NGINX-HARDENING", r"^\s*server_tokens\s+off\s*;"),
                ("EP-NGINX-CUSTOM", r"^\s*error_page\s+[^;]*(?:4\d\d|5\d\d)[^;]*;"),
                ("EP-TOMCAT-HARDENING", r"<Valve\b[^>]*ErrorReportValve[^>]*showReport\s*=\s*['\"]false['\"][^>]*showServerInfo\s*=\s*['\"]false['\"]"),
                ("EP-JAVA-CUSTOM", r"<error-page>[\s\S]{0,500}<(?:error-code|exception-type)>[\s\S]{0,300}<location>"),
                ("EP-IIS-CUSTOM", r"<(?:customErrors|httpErrors)\b[^>]*(?:mode\s*=\s*['\"](?:On|RemoteOnly)|errorMode\s*=\s*['\"](?:Custom|DetailedLocalOnly))"),
                ("EP-SPRING-HARDENING", r"^\s*server\.error\.(?:include-stacktrace\s*=\s*never|whitelabel\.enabled\s*=\s*false)"),
                ("EP-DEBUG-DISABLED", r"\b(?:DEBUG\s*=\s*False|debug\s*[:=]\s*false|display_errors\s*=\s*(?:Off|0))\b"),
            ],
            limit=10,
        )
        platform_hint = _contains(
            f"{remote_file.path}\n{text}",
            r"(?:apache|httpd|ServerTokens|nginx|server_tokens|tomcat|ErrorReportValve|<error-page>|customErrors|httpErrors|server\.error\.|display_errors|DEBUG\s*=)",
        )
        if positive:
            return self._result(
                "EP",
                remote_file,
                Status.PASS,
                "중간",
                "서버 정보 억제, 상세 오류 비활성화 또는 사용자 정의 오류 매핑 설정이 발견되었습니다.",
                "분리된 다른 설정 파일과 실제 4xx/5xx 응답에서도 정책이 일관되게 적용되는지 확인하세요.",
                positive,
            )
        if platform_hint:
            return self._result(
                "EP",
                remote_file,
                Status.REVIEW,
                "중간",
                "웹 서버/애플리케이션 오류 관련 설정 파일이지만 명시적인 보호 설정을 찾지 못했습니다.",
                "포함(include)된 설정까지 확인하고 서버 서명 제거와 사용자 정의 오류 매핑을 명시하세요.",
                [_feature_evidence(remote_file, "EP-CONFIG-HINT", "오류 관련 설정 후보")],
            )
        return self._result(
            "EP",
            remote_file,
            Status.NOT_APPLICABLE,
            "낮음",
            "이 설정 파일에서 EP 관련 지시자를 찾지 못했습니다.",
            "실제 웹 서버 설정 파일을 --config-path로 추가하세요.",
        )

    # ------------------------------------------------------------------ IA
    def IA(self, remote_file: RemoteFile) -> Finding:
        """IA: 중요 기능의 추가 인증 및 서버 측 검증 징후를 점검한다."""
        feature_pattern = (
            r"(?:edit[-_/ ]?(?:profile|account)|update[-_/ ]?(?:profile|account)|change[-_/ ]?"
            r"(?:email|phone|mobile|password)|personal[-_/ ]?info|delete[-_/ ]?account|withdraw|"
            r"회원\s*정보|개인\s*정보|비밀번호\s*변경|회원\s*탈퇴)"
        )
        combined = f"{remote_file.path}\n{remote_file.text}"
        feature = _contains(combined, feature_pattern)

        if remote_file.kind == "html":
            bad = _collect_evidence(
                remote_file.text,
                [
                    ("IA-CLIENT-AUTH-STATE", r"if\s*\([^\n]{0,180}(?:localStorage|sessionStorage)\.getItem\s*\(\s*['\"](?:isAuthenticated|isVerified|role|auth)['\"][^\n]{0,180}(?:location|redirect)"),
                    ("IA-CLIENT-VERIFIED-FIELD", r"<input\b[^>]*type\s*=\s*['\"]hidden['\"][^>]*name\s*=\s*['\"](?:isVerified|authenticated|role)['\"][^>]*>"),
                    ("IA-HARDCODED-OTP", r"(?:expected|valid|correct)[_-]?(?:otp|code)\s*=\s*['\"]\d{4,8}['\"]"),
                ],
            )
            if feature and bad:
                return self._result(
                    "IA",
                    remote_file,
                    Status.VULNERABLE,
                    "높음",
                    "중요 페이지 접근 여부를 클라이언트 저장값, 숨김 필드 또는 하드코딩된 인증값으로 판단하는 징후가 발견되었습니다.",
                    "추가 인증 성공 상태를 서버 세션에 저장하고 모든 중요 요청마다 서버 측에서 검증하세요.",
                    bad,
                )
            if feature:
                auth_ui = _collect_evidence(
                    remote_file.text,
                    [("IA-REAUTH-UI", r"(?:current[_-]?password|otp|verification[_-]?code|auth[_-]?code|re-?auth|본인\s*인증|인증\s*번호|현재\s*비밀번호)")],
                    limit=3,
                )
                message = "중요 기능과 추가 인증 UI가 발견되었으나 서버 측 검증 여부는 HTML만으로 확인할 수 없습니다."
                if not auth_ui:
                    message = "중요 기능으로 보이는 HTML에 명시적인 재인증 UI가 확인되지 않았습니다."
                return self._result(
                    "IA",
                    remote_file,
                    Status.REVIEW,
                    "중간",
                    message,
                    "서버 핸들러에서 최근 재인증/OTP 성공 상태를 검증하고 URL 직접 접근 및 파라미터 변조를 수동 확인하세요.",
                    auth_ui or [_feature_evidence(remote_file, "IA-SENSITIVE-PAGE", "중요 기능 후보")],
                )
            return self._result(
                "IA",
                remote_file,
                Status.NOT_APPLICABLE,
                "낮음",
                "중요 정보 변경 기능으로 식별되는 징후가 없습니다.",
                "실제 중요 페이지와 서버 측 핸들러가 다른 경로에 있으면 해당 경로를 함께 검사하세요.",
            )

        if remote_file.kind == "config":
            return self._result(
                "IA",
                remote_file,
                Status.NOT_APPLICABLE,
                "낮음",
                "IA는 일반적으로 서버 소스와 동적 우회 검증 대상이므로 이 설정 파일에는 적용하지 않았습니다.",
                "인증 미들웨어와 중요 기능 서버 소스를 점검하세요.",
            )

        if _is_non_runtime_path(remote_file.path):
            return self._result(
                "IA",
                remote_file,
                Status.NOT_APPLICABLE,
                "높음",
                "도움말·문서·CI·테스트 경로이므로 인증 구현 판정에서 제외했습니다.",
                "실제 중요 기능의 서버 핸들러를 검사하세요.",
            )

        bad_server = _collect_evidence(
            remote_file.text,
            [
                ("IA-TRUST-REQUEST-FLAG", r"if\s*\([^\n]{0,220}(?:req\.(?:body|query)|request\.getParameter|\$_(?:POST|GET)|Request\[(?:[^\]]+)\])[^\n]{0,100}(?:isVerified|authenticated|authSuccess)"),
                ("IA-CLIENT-STORAGE-GATE", r"(?:localStorage|sessionStorage)\.getItem\s*\(\s*['\"](?:isAuthenticated|isVerified|role|auth)['\"]"),
            ],
        )
        if feature and bad_server:
            return self._result(
                "IA",
                remote_file,
                Status.VULNERABLE,
                "높음",
                "중요 기능의 인증 상태를 요청 파라미터 또는 클라이언트 저장값에서 신뢰하는 징후가 발견되었습니다.",
                "서버 세션/서명된 서버 토큰의 인증 상태만 신뢰하고 중요 요청마다 공통 서버 미들웨어로 검증하세요.",
                bad_server,
            )

        good_server = _collect_evidence(
            remote_file.text,
            [
                ("IA-SERVER-SESSION", r"(?:session\.getAttribute\s*\(\s*['\"]isVerified['\"]|session\[['\"]is_verified['\"]\]|req\.session\.(?:isVerified|reauthenticated)|HttpContext\.Session\.Get\w*\s*\(\s*['\"](?:isVerified|Reauthenticated))"),
                ("IA-AUTH-DECORATOR", r"(?:@PreAuthorize|@Authorize|\[Authorize(?:Attribute)?\]|@login_required|@permission_required|LoginRequiredMixin)"),
                ("IA-OTP-SERVER", r"(?:verify|validate|check)[A-Za-z_]*(?:Otp|OTP|VerificationCode|AuthCode)\s*\("),
            ],
        )
        if feature and good_server:
            return self._result(
                "IA",
                remote_file,
                Status.PASS,
                "중간",
                "중요 기능 근처에서 서버 세션, 권한 데코레이터 또는 OTP 검증 구현 징후가 발견되었습니다.",
                "모든 중요 경로에 공통 적용되는지와 직접 URL/파라미터 변조 우회가 불가능한지 확인하세요.",
                good_server,
            )
        if feature:
            return self._result(
                "IA",
                remote_file,
                Status.REVIEW,
                "중간",
                "중요 기능 핸들러 후보가 있으나 이 파일에서 명시적인 서버 측 추가 인증 검증을 찾지 못했습니다.",
                "외부 미들웨어 적용 여부를 확인하고 없다면 재인증 상태를 서버 측에서 검증하세요.",
                [_feature_evidence(remote_file, "IA-SENSITIVE-HANDLER", "중요 서버 기능 후보")],
            )
        return self._result(
            "IA",
            remote_file,
            Status.NOT_APPLICABLE,
            "낮음",
            "이 소스 파일에서 중요 정보 변경 기능을 식별하지 못했습니다.",
            "중요 페이지의 실제 서버 핸들러를 검사 범위에 포함하세요.",
        )

    # ------------------------------------------------------------------ PR
    def PR(self, remote_file: RemoteFile) -> Finding:
        """PR: 비밀번호 복구의 난수, 전달 채널 및 직접 노출 징후를 점검한다."""
        feature_pattern = (
            r"(?:forgot[-_/ ]?(?:password|passwd)|reset[-_/ ]?(?:password|passwd)|recover[-_/ ]?"
            r"(?:password|passwd)|password[-_/ ]?reset|temporary[-_ ]?password|temp[-_ ]?password|"
            r"비밀번호\s*(?:찾기|복구|재설정|초기화|임시))"
        )
        combined = f"{remote_file.path}\n{remote_file.text}"
        feature = _contains(combined, feature_pattern)

        if remote_file.kind == "html":
            direct_display = _collect_evidence(
                remote_file.text,
                [
                    ("PR-DISPLAY-PASSWORD", r"(?:innerHTML|textContent|document\.write|alert)\s*(?:=|\()[^\n]{0,180}(?:temporaryPassword|temp[_-]?password|newPassword|resetPassword)"),
                    ("PR-HARDCODED-TEMP", r"(?:temporaryPassword|temp[_-]?password|newPassword)\s*=\s*['\"][^'\"]{1,40}['\"]"),
                    ("PR-PASSWORD-IN-VALUE", r"<input\b[^>]*name\s*=\s*['\"](?:temporaryPassword|temp_password|newPassword)['\"][^>]*value\s*=\s*['\"][^'\"]+['\"]"),
                ],
            )
            if feature and direct_display:
                return self._result(
                    "PR",
                    remote_file,
                    Status.VULNERABLE,
                    "높음",
                    "임시/재설정 비밀번호를 화면 또는 HTML 값으로 직접 노출하는 징후가 발견되었습니다.",
                    "일회용 난수 토큰을 등록된 이메일/SMS로만 전송하고 화면에는 비밀번호를 표시하지 마세요.",
                    direct_display,
                )
            if feature:
                weak_question = _collect_evidence(
                    remote_file.text,
                    [
                        ("PR-GUESSABLE-QUESTION", r"(?:birth(?:day|date)|employee[_-]?id|student[_-]?id|mother['’]?s maiden|생년월일|사번|학번|고향|졸업한 학교)"),
                        ("PR-USER-DESTINATION", r"<input\b[^>]*(?:name|id)\s*=\s*['\"](?:email|phone|mobile|recipient)['\"][^>]*>"),
                    ],
                    limit=4,
                )
                return self._result(
                    "PR",
                    remote_file,
                    Status.REVIEW,
                    "중간",
                    "비밀번호 복구 UI가 발견되었습니다. 난수 생성, 등록된 연락처 사용, 토큰 만료 및 화면 비노출은 서버 소스 확인이 필요합니다.",
                    "복구 대상 계정에 저장된 이메일/SMS로만 만료되는 일회용 링크 또는 임시 비밀번호를 보내고 실패 횟수를 제한하세요.",
                    weak_question or [_feature_evidence(remote_file, "PR-RECOVERY-UI", "비밀번호 복구 UI")],
                )
            return self._result(
                "PR",
                remote_file,
                Status.NOT_APPLICABLE,
                "낮음",
                "비밀번호 복구 기능으로 식별되는 징후가 없습니다.",
                "복구 기능이 별도 애플리케이션에 있다면 해당 경로를 추가 검사하세요.",
            )

        if remote_file.kind == "config":
            return self._result(
                "PR",
                remote_file,
                Status.NOT_APPLICABLE,
                "낮음",
                "PR은 서버 복구 로직과 동적 절차가 주 대상이므로 이 설정 파일에는 적용하지 않았습니다.",
                "비밀번호 복구 서버 소스를 검사하세요.",
            )

        if _is_non_runtime_path(remote_file.path):
            return self._result(
                "PR",
                remote_file,
                Status.NOT_APPLICABLE,
                "높음",
                "도움말·문서·CI·테스트 경로이므로 복구 로직 판정에서 제외했습니다.",
                "실제 비밀번호 복구 핸들러를 검사하세요.",
            )

        weak_rng = _collect_evidence(
            remote_file.text,
            [
                ("PR-JAVA-WEAK-RNG", r"\b(?:new\s+Random\s*\(|Math\.random\s*\()"),
                ("PR-PHP-WEAK-RNG", r"\b(?:rand|mt_rand)\s*\("),
                ("PR-PYTHON-WEAK-RNG", r"\brandom\.(?:random|randint|choice|choices)\s*\("),
                ("PR-DOTNET-WEAK-RNG", r"\bnew\s+(?:System\.)?Random\s*\("),
                ("PR-FIXED-PASSWORD", r"(?:temporaryPassword|temp[_-]?password|resetPassword|newPassword)\s*=\s*['\"][^'\"]{1,40}['\"]"),
            ],
        )
        direct_output = _collect_evidence(
            remote_file.text,
            [
                ("PR-DIRECT-OUTPUT", r"(?:echo|print|Response\.Write|res\.(?:send|json)|model\.addAttribute)\s*\([^\n]{0,180}(?:temporaryPassword|temp[_-]?password|newPassword|resetPassword)"),
                ("PR-JSON-PASSWORD", r"(?:password|temporaryPassword|temp_password)\s*[:=]>?\s*(?:temporaryPassword|temp[_-]?password|newPassword)"),
            ],
        )
        if feature and (weak_rng or direct_output):
            return self._result(
                "PR",
                remote_file,
                Status.VULNERABLE,
                "높음",
                "비밀번호 복구 코드에서 약한 난수/고정값 또는 응답 직접 노출 징후가 발견되었습니다.",
                "암호학적으로 안전한 난수를 사용하고, 만료되는 일회용 값을 계정에 등록된 이메일/SMS로만 전달하세요.",
                [*weak_rng, *direct_output][:8],
            )

        secure_rng = _collect_evidence(
            remote_file.text,
            [
                ("PR-JAVA-SECURE-RNG", r"\bSecureRandom\b"),
                ("PR-PHP-SECURE-RNG", r"\brandom_(?:int|bytes)\s*\("),
                ("PR-PYTHON-SECURE-RNG", r"\bsecrets\.(?:token_|choice|randbelow)"),
                ("PR-DOTNET-SECURE-RNG", r"\b(?:RandomNumberGenerator|RNGCryptoServiceProvider)\b"),
                ("PR-NODE-SECURE-RNG", r"\b(?:crypto\.)?randomBytes\s*\("),
                ("PR-GO-SECURE-RNG", r"\bcrypto/rand\b"),
            ],
        )
        secure_delivery = _collect_evidence(
            remote_file.text,
            [
                ("PR-REGISTERED-DELIVERY", r"(?:send|mail|sms)[A-Za-z_]*(?:Password|Reset|Token|Code|Email|Sms)\s*\("),
                ("PR-EXPIRING-TOKEN", r"(?:expiresAt|expiry|expiration|tokenExpiry|validUntil|setExpiration)\s*[:=(]"),
                ("PR-TOKEN-HASH", r"(?:password_hash|bcrypt|argon2|MessageDigest|sha256|createHash)\s*\("),
            ],
        )
        if feature and secure_rng and secure_delivery:
            return self._result(
                "PR",
                remote_file,
                Status.PASS,
                "중간",
                "암호학적으로 안전한 난수와 외부 전달/만료 처리로 보이는 구현 징후가 발견되었습니다.",
                "수신지가 요청값이 아니라 계정에 등록된 연락처인지, 토큰이 1회 사용 후 폐기되는지 동적으로 확인하세요.",
                [*secure_rng, *secure_delivery][:8],
            )
        if feature:
            return self._result(
                "PR",
                remote_file,
                Status.REVIEW,
                "중간",
                "비밀번호 복구 로직 후보가 있으나 안전한 난수와 등록 연락처 전달/만료 통제를 충분히 확인하지 못했습니다.",
                "난수, 만료, 1회성, 등록 연락처 무결성, 실패 횟수 제한을 함께 검토하세요.",
                [*secure_rng, *secure_delivery][:6] or [_feature_evidence(remote_file, "PR-RECOVERY-HANDLER", "비밀번호 복구 핸들러")],
            )
        return self._result(
            "PR",
            remote_file,
            Status.NOT_APPLICABLE,
            "낮음",
            "이 소스 파일에서 비밀번호 복구 기능을 식별하지 못했습니다.",
            "실제 복구 핸들러가 있는 경로를 검사 범위에 포함하세요.",
        )

    # ------------------------------------------------------------------ IS
    @staticmethod
    def _timeout_evidence(text: str) -> tuple[list[Evidence], list[Evidence], list[Evidence]]:
        """세션 제한값을 초 단위로 환산해 양호/장기/무제한 증적을 반환한다."""
        specs = [
            ("IS-JAVA-WEBXML-TIMEOUT", r"<session-timeout>\s*(\d+)\s*</session-timeout>", 60),
            ("IS-SPRING-TIMEOUT", r"server\.servlet\.session\.timeout\s*=\s*(\d+)\s*([smhd]?)", None),
            ("IS-JAVA-CODE-TIMEOUT", r"setMaxInactiveInterval\s*\(\s*(\d+)\s*\)", 1),
            ("IS-DOTNET-TIMEOUT", r"(?:sessionState[^>]*timeout\s*=\s*['\"]|Session\.Timeout\s*=\s*)(\d+)", 60),
            ("IS-PHP-GC-TIMEOUT", r"session\.gc_maxlifetime\s*['\"]?\s*[,=]\s*['\"]?(\d+)", 1),
            ("IS-EXPRESS-MAXAGE", r"maxAge\s*:\s*(\d+)", 0.001),
        ]
        good: list[Evidence] = []
        long_value: list[Evidence] = []
        unlimited: list[Evidence] = []
        for rule, pattern, multiplier in specs:
            for match in re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE):
                value = int(match.group(1))
                factor = multiplier
                if factor is None:
                    unit = (match.group(2) or "s").lower()
                    factor = {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
                seconds = value * factor
                line, excerpt = _line_excerpt(text, match.start())
                evidence = Evidence(line=line, rule=rule, excerpt=f"{excerpt} [환산: {seconds:g}초]")
                if seconds <= 0:
                    unlimited.append(evidence)
                elif seconds <= 3600:
                    good.append(evidence)
                else:
                    long_value.append(evidence)
        return good[:4], long_value[:4], unlimited[:4]

    def IS(self, remote_file: RemoteFile) -> Finding:
        """IS: 세션 회전/만료와 JWT 서명·만료 설정을 점검한다."""
        html_feature_pattern = r"(?:(?:localStorage|sessionStorage)\.(?:getItem|setItem)\s*\(\s*['\"][^'\"]*(?:auth|token|session|jwt)|document\.cookie[^\n]{0,120}(?:session|token|auth)|jsonwebtoken|\bjwt\b|setTimeout\s*\([^\n]{0,120}(?:logout|session))"
        general_feature_pattern = r"(?:session_start\s*\(|session_set_cookie_params\s*\(|session_regenerate_id\s*\(|HttpSession\b|(?:request|req)\.session\b|Session\s*\[|sessionState\b|express-session|server\.servlet\.session|(?:jwt|jsonwebtoken)\.(?:encode|decode|sign|verify)\s*\(|JsonWebToken|Authorization[^\n]{0,80}Bearer)"

        if remote_file.kind != "html" and _is_non_runtime_path(remote_file.path):
            return self._result(
                "IS",
                remote_file,
                Status.NOT_APPLICABLE,
                "높음",
                "도움말·문서·CI·테스트 경로이므로 세션 구현 판정에서 제외했습니다.",
                "실제 로그인·세션 초기화 소스와 서버 설정을 검사하세요.",
            )

        jwt_bad = _collect_evidence(
            remote_file.text,
            [
                ("IS-JWT-NONE", r"(?:algorithms?\s*[:=]\s*\[[^\]]*['\"]none['\"]|algorithm\s*[:=]\s*['\"]none['\"]|SignatureAlgorithm\.NONE)"),
                ("IS-JWT-NO-VERIFY", r"(?:verify_signature\s*['\"]?\s*[:=]\s*false|verify\s*[:=]\s*false|ignoreExpiration\s*[:=]\s*true)"),
                ("IS-JWT-WEAK-ALG", r"(?:algorithm|alg)\s*[:=]\s*['\"](?:HS1|RS1|plaintext)['\"]"),
                ("IS-WEAK-SECRET", r"(?:jwt[_-]?(?:secret|key)|secret[_-]?key)\s*[:=]\s*['\"](?:secret|password|test|changeme|123456|jwtsecret)['\"]"),
                ("IS-PREDICTABLE-ID", r"(?:\$?(?:sessionId|session_id|session_value|sid|cookie_value)|dvwaSession)\s*=\s*(?:Date\.now\s*\(|time\s*\(|microtime\s*\(|Math\.random\s*\(|new\s+Random\s*\(|\$_COOKIE[^;\n]*\+\s*1|\d+\s*;)"),
                ("IS-PREDICTABLE-HASH", r"(?:md5|sha1)\s*\(\s*(?:time|microtime|Date\.now|\$?(?:counter|cookie_value|session_value))"),
                ("IS-PHP-STRICT-OFF", r"session\.use_strict_mode\s*=\s*0"),
            ],
        )
        timeout_good, timeout_long, timeout_unlimited = self._timeout_evidence(remote_file.text)
        if jwt_bad or timeout_unlimited:
            return self._result(
                "IS",
                remote_file,
                Status.VULNERABLE,
                "높음",
                "서명 검증 우회, 약한 비밀값, 예측 가능한 세션 ID 또는 무제한 세션 설정 징후가 발견되었습니다.",
                "프레임워크의 안전한 세션 ID를 사용하고 로그인 시 회전시키며, 60분 이하 만료와 명시적인 JWT 알고리즘/서명/exp 검증을 적용하세요.",
                [*jwt_bad, *timeout_unlimited][:8],
            )

        if remote_file.kind == "html":
            feature = _contains(remote_file.text, html_feature_pattern)
            jwt_literal = _collect_evidence(
                remote_file.text,
                [("IS-EMBEDDED-JWT", r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")],
                limit=2,
            )
            if jwt_literal:
                return self._result(
                    "IS",
                    remote_file,
                    Status.VULNERABLE,
                    "높음",
                    "HTML 원문에 JWT 형태의 값이 직접 포함되어 있습니다.",
                    "토큰을 정적 파일에 포함하지 말고 서버 발급·만료·회수 정책과 안전한 쿠키 사용을 검토하세요.",
                    jwt_literal,
                )
            if feature:
                feature_ev = _collect_evidence(
                    remote_file.text,
                    [("IS-CLIENT-SESSION", html_feature_pattern)],
                    limit=4,
                )
                return self._result(
                    "IS",
                    remote_file,
                    Status.REVIEW,
                    "중간",
                    "클라이언트 측 세션/JWT 처리 징후가 있습니다. 세션 ID 난수성, 로그인 시 회전, 서버 만료는 HTML만으로 확인할 수 없습니다.",
                    "서버 설정과 인증 핸들러에서 세션 회전·만료 및 JWT 서명/exp 검증을 확인하세요.",
                    feature_ev,
                )
            return self._result(
                "IS",
                remote_file,
                Status.NOT_APPLICABLE,
                "낮음",
                "HTML에서 세션/JWT를 직접 처리하는 징후가 없습니다.",
                "세션 정책은 서버 소스와 설정 파일에서 별도 확인하세요.",
            )

        feature = _contains(f"{remote_file.path}\n{remote_file.text}", general_feature_pattern)
        rotation = _collect_evidence(
            remote_file.text,
            [
                ("IS-JAVA-ROTATION", r"(?:changeSessionId\s*\(|sessionFixation\s*\(\)\.migrateSession\s*\()"),
                ("IS-PHP-ROTATION", r"session_regenerate_id\s*\(\s*true\s*\)"),
                ("IS-DOTNET-ROTATION", r"regenerateExpiredSessionId\s*=\s*['\"]true['\"]"),
                ("IS-EXPRESS-ROTATION", r"req\.session\.regenerate\s*\("),
            ],
        )
        jwt_safe_alg = _collect_evidence(
            remote_file.text,
            [("IS-JWT-SAFE-ALG", r"(?:algorithm|algorithms?|signWith)[^\n]{0,120}(?:HS(?:256|384|512)|RS(?:256|384|512)|ES(?:256|384|512))")],
        )
        jwt_exp = _collect_evidence(
            remote_file.text,
            [("IS-JWT-EXPIRATION", r"(?:setExpiration\s*\(|expiresIn\s*[:=]|expiration\s*[:=]|\bexp\s*[:=])")],
        )

        if timeout_long:
            return self._result(
                "IS",
                remote_file,
                Status.REVIEW,
                "높음",
                "세션 만료가 가이드 권고 상한인 60분보다 길게 설정된 징후가 있습니다.",
                "서비스 특성을 검토하여 세션 만료를 10~60분 범위로 조정하고 자동 로그아웃을 적용하세요.",
                timeout_long,
            )
        if (jwt_safe_alg and jwt_exp) or (timeout_good and (rotation or remote_file.kind == "config")):
            evidence = [*timeout_good, *rotation, *jwt_safe_alg, *jwt_exp][:10]
            return self._result(
                "IS",
                remote_file,
                Status.PASS,
                "중간",
                "세션 만료/회전 또는 안전한 JWT 알고리즘과 만료 설정 징후가 발견되었습니다.",
                "실제 로그인 전후 세션 ID 변경, 로그아웃 후 폐기, JWT 변조 거부를 승인된 테스트로 확인하세요.",
                evidence,
            )
        if feature:
            partial = [*timeout_good, *rotation, *jwt_safe_alg, *jwt_exp][:8]
            return self._result(
                "IS",
                remote_file,
                Status.REVIEW,
                "중간",
                "세션/JWT 사용 징후는 있으나 난수성·회전·만료·서명 검증 통제를 이 파일에서 모두 확인하지 못했습니다.",
                "로그인 시 세션 ID 회전, 60분 이하 만료, 안전한 JWT 알고리즘·비밀 키·exp 검증을 함께 확인하세요.",
                partial or [_feature_evidence(remote_file, "IS-SESSION-HINT", "세션/JWT 구현 후보")],
            )
        return self._result(
            "IS",
            remote_file,
            Status.NOT_APPLICABLE,
            "낮음",
            "이 파일에서 세션 또는 JWT 설정을 식별하지 못했습니다.",
            "실제 세션 설정 파일을 --config-path로 추가하세요.",
        )

    # ------------------------------------------------------------------ CC
    def CC(self, remote_file: RemoteFile) -> Finding:
        """CC: 반복 요청 제한, 계정 잠금 및 CAPTCHA 적용 징후를 점검한다."""
        repeatable_pattern = (
            r"(?:login|sign[-_ ]?in|forgot[-_ ]?password|reset[-_ ]?password|send[-_ ]?(?:sms|code)|"
            r"verify[-_ ]?(?:otp|code)|comment|create[-_ ]?post|register|로그인|비밀번호\s*찾기|"
            r"문자\s*발송|인증\s*번호|게시글\s*등록)"
        )
        combined = f"{remote_file.path}\n{remote_file.text}"
        feature_evidence: list[Evidence] = []
        if remote_file.kind == "html":
            feature = _contains(combined, repeatable_pattern)
        elif remote_file.kind == "source":
            feature_evidence = _collect_evidence(
                remote_file.text,
                [
                    ("CC-AUTH-HANDLER", r"(?:function|def|class|route|@\w*(?:Mapping|route))[^\n]{0,160}(?:login|signin|register|signup|forgotPassword|resetPassword)"),
                    ("CC-CREDENTIAL-REQUEST", r"(?:\$_(?:POST|REQUEST)|req\.(?:body|query)|request\.(?:form|POST)|@RequestParam|Request\.Form)[^\n]{0,180}(?:username|user|password|passwd|otp|verification[_-]?code)"),
                    ("CC-MESSAGE-HANDLER", r"(?:INSERT\s+INTO\s+(?:guestbook|comments?|posts?)|(?:create|save|add)(?:Post|Comment|Message)\s*\()"),
                    ("CC-SMS-OTP-HANDLER", r"(?:send|issue|verify|validate)[A-Za-z_]*(?:Sms|SMS|Otp|OTP|VerificationCode)\s*\("),
                ],
                limit=6,
            )
            path_feature = _contains(
                remote_file.path.replace("\\", "/"),
                r"(?:^|/)(?:login(?:controller)?|signin|register|signup|forgot[-_]?password|reset[-_]?password|brute|captcha|sms|otp)(?:[/_.-]|$)",
            )
            if path_feature:
                feature_evidence.insert(
                    0,
                    _feature_evidence(remote_file, "CC-HANDLER-PATH", "반복 요청 가능 기능 경로"),
                )
            feature = bool(feature_evidence)
        else:
            # 일반 애플리케이션 설정에 login 등의 문자열이 있다는 이유만으로
            # 반복 요청 처리기로 판정하지 않는다. 방어 지시자는 아래에서 별도 확인한다.
            feature = False

        if remote_file.kind != "html" and _is_non_runtime_path(remote_file.path):
            return self._result(
                "CC",
                remote_file,
                Status.NOT_APPLICABLE,
                "높음",
                "도움말·문서·CI·테스트 경로이므로 자동화 공격 대상 판정에서 제외했습니다.",
                "실제 로그인·게시·SMS/OTP 처리 핸들러와 WAF 설정을 검사하세요.",
            )

        if remote_file.kind == "html":
            has_form = _contains(remote_file.text, r"<form\b")
            if feature and has_form:
                captcha = _collect_evidence(
                    remote_file.text,
                    [("CC-CAPTCHA-UI", r"(?:g-recaptcha|h-captcha|cf-turnstile|turnstile|captcha)")],
                    limit=3,
                )
                summary = "반복 가능한 중요 폼이 발견되었으나 서버 측 횟수 제한/잠금은 HTML만으로 확인할 수 없습니다."
                if captcha:
                    summary = "반복 가능한 중요 폼에 CAPTCHA UI가 있으나 토큰의 서버 검증 및 요청 횟수 제한을 추가 확인해야 합니다."
                return self._result(
                    "CC",
                    remote_file,
                    Status.REVIEW,
                    "중간",
                    summary,
                    "IP·계정·기능 단위 속도 제한, 실패 횟수 잠금, 서버 측 CAPTCHA 검증 및 우회 방지를 확인하세요.",
                    captcha or [_feature_evidence(remote_file, "CC-REPEATABLE-FORM", "반복 요청 가능 폼")],
                )
            return self._result(
                "CC",
                remote_file,
                Status.NOT_APPLICABLE,
                "낮음",
                "반복 공격 대상이 될 수 있는 폼을 식별하지 못했습니다.",
                "API 전용 엔드포인트와 외부 WAF 정책은 서버 소스/설정에서 별도 확인하세요.",
            )

        disabled = _collect_evidence(
            remote_file.text,
            [
                ("CC-RATE-LIMIT-DISABLED", r"(?:rate[_-]?limit(?:ing)?|captcha[_-]?enabled)\s*[:=]\s*(?:false|0|off)\b"),
                ("CC-LOCKOUT-DISABLED", r"lockoutOnFailure\s*[:=]\s*false\b"),
                ("CC-UNLIMITED-ATTEMPTS", r"(?:MaxFailedAccessAttempts|maximumAttempts|loginAttemptLimit)\s*[:=]\s*(?:0|int\.MaxValue|Integer\.MAX_VALUE)\b"),
            ],
        )
        if disabled and (feature or remote_file.kind == "config"):
            return self._result(
                "CC",
                remote_file,
                Status.VULNERABLE,
                "높음",
                "로그인/인증 등 반복 가능 기능에서 속도 제한, 계정 잠금 또는 CAPTCHA를 비활성화한 설정 징후가 발견되었습니다.",
                "기능·계정·IP 단위 제한과 지수 백오프/잠금, 서버 측 CAPTCHA 검증을 적용하세요.",
                disabled,
            )

        controls = _collect_evidence(
            remote_file.text,
            [
                ("CC-NGINX-RATE-LIMIT", r"^\s*(?:limit_req_zone|limit_req)\b"),
                ("CC-APACHE-EVASIVE", r"\b(?:mod_evasive|DOSPageCount|DOSSiteCount|DOSBlockingPeriod)\b"),
                ("CC-EXPRESS-RATE-LIMIT", r"\b(?:express-rate-limit|rateLimit\s*\()"),
                ("CC-PYTHON-RATE-LIMIT", r"\b(?:Flask-Limiter|@limiter\.limit|django[_-]?ratelimit|@ratelimit)\b"),
                ("CC-JAVA-RATE-LIMIT", r"\b(?:Bucket4j|@RateLimiter|RateLimiter\.create|resilience4j\.ratelimiter)\b"),
                ("CC-DOTNET-RATE-LIMIT", r"\b(?:AddRateLimiter|UseRateLimiter|EnableRateLimiting)\b"),
                ("CC-ACCOUNT-LOCKOUT", r"(?:MaxFailedAccessAttempts\s*[:=]\s*[1-9]\d*|lockoutOnFailure\s*[:=]\s*true|(?:failedAttempts|failed[_-]?login|login[_-]?attempts)\s*(?:>=|>)\s*[1-9]\d*)"),
                ("CC-REQUEST-DELAY", r"\b(?:sleep|usleep)\s*\("),
                ("CC-SERVER-CAPTCHA", r"(?:siteverify|verifyRecaptcha|verifyCaptcha|captchaService\.verify|recaptcha_check_answer)"),
                ("CC-REDIS-COUNTER", r"(?:redis\.|RedisTemplate)[^\n]{0,100}(?:incr|increment)[^\n]{0,120}(?:expire|ttl)"),
            ],
            limit=10,
        )
        if controls:
            return self._result(
                "CC",
                remote_file,
                Status.PASS,
                "중간",
                "속도 제한, 계정 잠금, CAPTCHA 서버 검증 또는 WAF 통제 징후가 발견되었습니다.",
                "모든 로그인·게시·SMS/OTP 엔드포인트에 적용되는지와 분산/헤더 위조 우회를 승인된 환경에서 확인하세요.",
                controls,
            )
        if feature:
            return self._result(
                "CC",
                remote_file,
                Status.REVIEW,
                "중간",
                "반복 요청 가능한 서버 기능 후보가 있으나 이 파일에서 명시적인 속도 제한/잠금/CAPTCHA 통제를 찾지 못했습니다.",
                "외부 WAF·게이트웨이 정책을 확인하고 없다면 기능·계정·IP 단위 제한을 서버 측에 구현하세요.",
                feature_evidence or [_feature_evidence(remote_file, "CC-REPEATABLE-HANDLER", "반복 요청 가능 기능")],
            )
        return self._result(
            "CC",
            remote_file,
            Status.NOT_APPLICABLE,
            "낮음",
            "이 파일에서 반복 요청 대상 기능 또는 방어 설정을 식별하지 못했습니다.",
            "WAF/리버스 프록시 설정이 다른 경로에 있으면 --config-path로 추가하세요.",
        )

    # --------------------------------------------------------------- runner
    def scan(self) -> ScanReport:
        """원격 경로를 순회하고 결과를 반환한다. 비밀번호는 보고서에 포함하지 않는다."""
        self.connect()
        auto_config_paths = self._discover_common_config_paths()
        all_config_paths = list(dict.fromkeys([*self.config_paths, *auto_config_paths]))
        report = ScanReport(
            target={
                "server_ip": self.server_ip,
                "ssh_port": self.port,
                "username": self.username,
                "html_path": self.html_path,
                "config_paths": self.config_paths,
                "auto_config_paths": auto_config_paths,
            },
            started_at=datetime.now(timezone.utc).isoformat(),
        )
        counts: Counter[str] = Counter()
        seen: set[str] = set()

        roots = [(self.html_path, False), *[(item, True) for item in all_config_paths]]
        for root, explicit_config in roots:
            try:
                candidates = self._iter_remote_files(root, explicit_config=explicit_config)
                for path, kind, attr in candidates:
                    if path in seen:
                        continue
                    seen.add(path)
                    try:
                        remote_file = self._read_remote_file(path, kind, attr)
                    except Exception as exc:
                        report.skipped_files += 1
                        report.errors.append(f"{path}: {exc}")
                        continue

                    counts[kind] += 1
                    method_names = self.CHECK_METHODS
                    if kind == "config":
                        method_names = self.CONFIG_CHECK_METHODS
                    for method_name in method_names:
                        try:
                            checker = getattr(self, method_name)
                            report.findings.append(checker(remote_file))
                        except Exception as exc:
                            report.errors.append(f"{path} [{method_name}]: {exc}")
                            report.findings.append(
                                self._result(
                                    method_name,
                                    remote_file,
                                    Status.ERROR,
                                    "낮음",
                                    f"검사 중 오류가 발생했습니다: {exc}",
                                    "파일 인코딩과 검사 규칙을 확인하세요.",
                                )
                            )
            except Exception as exc:
                report.errors.append(f"{root}: 경로를 검사할 수 없습니다: {exc}")

        report.scanned_files = {kind: counts.get(kind, 0) for kind in ("html", "source", "config")}
        if counts.get("html", 0) == 0:
            report.errors.append(f"HTML 파일을 찾지 못했습니다: {self.html_path}")
        report.finished_at = datetime.now(timezone.utc).isoformat()
        return report


def _print_human_summary(report: ScanReport) -> None:
    """파일별 내역을 숨기고 항목 코드별 최종 이진 판정만 출력한다."""
    data = report.to_dict(include_not_applicable=False)
    print("\n=== 최종 검증 결과 ===")
    for code, item in data["item_assessment"].items():
        print(f"{code} : {item['status']}")


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SSH/SFTP로 원격 웹 파일을 읽어 EP/IA/PR/IS/CC 항목을 정적으로 점검합니다.",
        epilog="SSH 모듈이 없으면 최초 실행 시 사용자 전용 캐시에 자동 설치합니다(인터넷 연결 필요).",
    )
    parser.add_argument("--host", required=True, help="SSH 서버 IP 또는 호스트명")
    parser.add_argument("--port", type=int, default=22, help="SSH 포트(기본값: 22)")
    parser.add_argument("--username", required=True, help="SSH 사용자 ID")
    parser.add_argument(
        "--password",
        help="SSH 비밀번호. 생략하면 안전하게 프롬프트로 입력받습니다(명령행 노출 방지를 위해 생략 권장).",
    )
    parser.add_argument("--path", required=True, help="원격 HTML/웹 애플리케이션 루트 경로")
    parser.add_argument(
        "--config-path",
        action="append",
        default=[],
        help="추가 원격 설정 파일 또는 디렉터리. 여러 번 지정할 수 있습니다.",
    )
    parser.add_argument(
        "--no-auto-config",
        action="store_true",
        help="Apache/Nginx/Tomcat/PHP의 표준 원격 설정 경로 자동 탐색을 끕니다.",
    )
    parser.add_argument("--known-hosts", help="추가로 사용할 로컬 known_hosts 파일")
    parser.add_argument(
        "--accept-new-host-key",
        action="store_true",
        help="알 수 없는 SSH 호스트 키를 이번 실행에서 허용합니다. 최초 지문을 별도 확인한 경우에만 사용하세요.",
    )
    parser.add_argument("--output", help="전체 JSON 보고서 저장 경로. 생략하면 요약만 출력합니다.")
    parser.add_argument(
        "--include-not-applicable",
        action="store_true",
        help="JSON 보고서에 '해당 없음' 결과도 포함합니다.",
    )
    parser.add_argument("--max-files", type=int, default=10_000, help="루트별 최대 후보 파일 수")
    parser.add_argument("--max-file-bytes", type=int, default=2 * 1024 * 1024, help="파일당 최대 읽기 크기")
    parser.add_argument("--max-depth", type=int, default=40, help="원격 디렉터리 최대 재귀 깊이")
    return parser.parse_args(argv)


def _configure_console_encoding() -> None:
    """비 UTF-8 기본 로캘에서도 한글 도움말과 결과를 안전하게 출력한다."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (OSError, ValueError):
                pass


def main(argv: Sequence[str] | None = None) -> int:
    _configure_console_encoding()
    args = _parse_args(argv)
    password = args.password
    if password is None:
        password = getpass.getpass("SSH 비밀번호: ")

    scanner = Web(
        server_ip=args.host,
        username=args.username,
        password=password,
        html_path=args.path,
        port=args.port,
        config_paths=args.config_path,
        known_hosts=args.known_hosts,
        accept_new_host_key=args.accept_new_host_key,
        auto_config_discovery=not args.no_auto_config,
        max_files=args.max_files,
        max_file_bytes=args.max_file_bytes,
        max_depth=args.max_depth,
    )

    try:
        with scanner:
            report = scanner.scan()
    except Exception as exc:
        print(f"검사를 시작할 수 없습니다: {exc}", file=sys.stderr)
        if "known_hosts" in str(exc).lower() or "not found in known_hosts" in str(exc).lower():
            print("SSH 호스트 키 지문을 확인해 known_hosts에 등록하거나 --accept-new-host-key를 사용하세요.", file=sys.stderr)
        return 2

    if report.scanned_files.get("html", 0) == 0:
        print("검사를 완료할 수 없습니다: HTML 파일을 찾지 못했습니다.", file=sys.stderr)
        return 2

    _print_human_summary(report)
    if args.output:
        output_path = os.path.abspath(os.path.expanduser(args.output))
        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as stream:
            json.dump(
                report.to_dict(include_not_applicable=args.include_not_applicable),
                stream,
                ensure_ascii=False,
                indent=2,
            )
        print(f"\nJSON 보고서 저장: {output_path}")

    if any(
        item.status in {Status.ERROR, Status.VULNERABLE, Status.REVIEW}
        for item in report.findings
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())



# ============================================================================
# main.py 연동용 래퍼 (기존 코드는 수정하지 않고 아래에 덧붙임)
#
#   CLI 사용법과의 대응
#     python3 web_application_jun.py \
#         --host 172.16.14.41 --username root \
#         --path /var/www/html --accept-new-host-key
#
#   device_list.json 스키마
#     {
#       "ip": "172.16.14.41",
#       "hostname": "web_app",
#       "type": "web_application",
#       "conn_info": { "port": 22, "user": "root", "password": "..." },
#       "web_info": {
#         "path": "/var/www/html",          // --path            (필수)
#         "accept_new_host_key": true,      // --accept-new-host-key
#         "known_hosts": null,              // --known-hosts
#         "config_paths": [],               // --config-path (여러 개)
#         "auto_config_discovery": true,    // --no-auto-config 의 반대
#         "max_files": 10000,               // --max-files
#         "max_file_bytes": 2097152,        // --max-file-bytes
#         "max_depth": 40                   // --max-depth
#       }
#     }
#
#   requires_ssh = False :
#     Web 클래스가 자체적으로 SSH/SFTP 세션을 열고 닫으므로
#     main.py 는 SSHConnection.connect() 를 호출하지 않는다.
#
#   다른 모듈과 다른 점 :
#     이 스캐너는 항목별로 따로 점검하지 않고 scan() 한 번에 전부 판정한다.
#     따라서 첫 항목 호출 시 1회만 스캔하고 결과를 캐시해 나눠 준다.
# ============================================================================
class WebApplication:
    """웹 애플리케이션 점검 결과를 main.py 규격으로 노출하는 래퍼."""

    requires_ssh = False

    check_list = {
        "wa_ep": {"code": "EP", "title": "에러 페이지 적용 미흡"},
        "wa_ia": {"code": "IA", "title": "불충분한 인증 절차"},
        "wa_pr": {"code": "PR", "title": "취약한 비밀번호 복구 절차"},
        "wa_is": {"code": "IS", "title": "불충분한 세션 관리"},
        "wa_cc": {"code": "CC", "title": "자동화 공격"},
    }

    def __init__(self, conn):
        self.conn = conn

        device = dict(getattr(conn, "device", None) or {})
        conn_info = dict(device.get("conn_info") or {})
        web_info = dict(device.get("web_info") or {})

        html_path = str(web_info.get("path", "")).strip()
        if not html_path:
            raise ValueError(
                "device_list.json 의 web_info.path 가 필요합니다 "
                "(CLI 의 --path 에 해당)."
            )

        self._scanner_args = dict(
            server_ip=getattr(conn, "hostname", ""),
            username=conn_info.get("user", getattr(conn, "username", "")),
            password=conn_info.get("password", getattr(conn, "password", "")),
            html_path=html_path,
            port=conn_info.get("port", 22),
            config_paths=web_info.get("config_paths") or [],
            known_hosts=web_info.get("known_hosts"),
            accept_new_host_key=bool(web_info.get("accept_new_host_key", False)),
            auto_config_discovery=bool(web_info.get("auto_config_discovery", True)),
            max_files=int(web_info.get("max_files", 10_000)),
            max_file_bytes=int(web_info.get("max_file_bytes", 2 * 1024 * 1024)),
            max_depth=int(web_info.get("max_depth", 40)),
        )

        self._assessment = None
        self._scan_error = None

    # -- scan() 은 무거우므로 최초 1회만 실행하고 결과를 캐시한다 --------------
    def _ensure_scanned(self):
        if self._assessment is not None or self._scan_error is not None:
            return

        try:
            scanner = Web(**self._scanner_args)
            with scanner:
                report = scanner.scan()
            self._assessment = report._assessment()
        except Exception as exc:
            self._scan_error = f"{exc.__class__.__name__}: {exc}"

    def _result_for(self, code):
        self._ensure_scanned()

        if self._scan_error is not None:
            return "오류", f"웹 애플리케이션 스캔 실패: {self._scan_error}"

        entry = self._assessment.get(code)
        if not entry:
            return "해당없음", f"{code} 항목에 대한 판정 결과가 없습니다."

        # detailed_status: 취약 / 점검 필요 / 양호 추정 / 해당 없음 / 오류
        detailed = str(entry.get("detailed_status", "")).strip()
        status = {
            "취약": "취약",
            "점검 필요": "검토필요",
            "양호 추정": "양호",
            "해당 없음": "해당없음",
            "오류": "오류",
        }.get(detailed, entry.get("status", "오류"))

        counts = entry.get("counts") or {}
        detail = ", ".join(f"{k} {v}건" for k, v in counts.items())
        reason = f"{entry.get('title', code)}: {detailed or status}"
        if detail:
            reason += f" ({detail})"

        return status, reason

    def wa_ep(self):
        return self._result_for("EP")

    def wa_ia(self):
        return self._result_for("IA")

    def wa_pr(self):
        return self._result_for("PR")

    def wa_is(self):
        return self._result_for("IS")

    def wa_cc(self):
        return self._result_for("CC")
