from __future__ import annotations

import argparse
import csv
import io
import os
import re
import shlex
from functools import wraps
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

import pymysql
from pymysql.cursors import DictCursor

import sys

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.append(ROOT_DIR)

from ssh_connection import SSHConnection
from sql_manager import SqlManager


CheckResult = Tuple[str, str]

STATUS_GOOD = "양호"
STATUS_BAD = "취약"
STATUS_MANUAL = "추가 점검 필요함"
STATUS_NA = "해당 없음"


def safe_check(func: Callable[..., CheckResult]) -> Callable[..., CheckResult]:
    """모든 점검 메서드가 반드시 (상태, 사유) 튜플을 반환하도록 보장한다."""

    @wraps(func)
    def wrapper(self: "DBMS", *args: Any, **kwargs: Any) -> CheckResult:
        try:
            result = func(self, *args, **kwargs)
            if (
                not isinstance(result, tuple)
                or len(result) != 2
                or not all(isinstance(item, str) for item in result)
            ):
                raise TypeError("점검 함수는 (status, reason) 문자열 튜플을 반환해야 합니다.")
            return result
        except Exception as exc:  # 개별 항목 오류가 전체 점검을 중단시키지 않도록 처리
            message = str(exc).strip() or "상세 오류 메시지 없음"
            return (
                STATUS_MANUAL,
                f"{func.__name__.upper()} 자동 점검 오류: {exc.__class__.__name__}: {message}",
            )

    return wrapper


class DBMS:
    """
    MySQL/MariaDB용 D-01 ~ D-26 취약점 점검 클래스.

    - OS 점검은 ssh_connection.py의 SSHConnection을 사용한다.
    - DB 점검은 PyMySQL 직접 접속 또는 SSH 원격 mysql/mariadb CLI를 사용한다.
    - 결과 저장은 sql_manager.py의 SqlManager를 사용한다.
    - 모든 d_XX 메서드는 (status, reason) 형식의 튜플을 반환한다.
    """

    CHECK_TITLES: Dict[str, str] = {
        "D-01": "기본 계정의 비밀번호, 정책 등을 변경하여 사용",
        "D-02": "데이터베이스의 불필요 계정을 제거하거나, 잠금설정 후 사용",
        "D-03": "비밀번호의 사용기간 및 복잡도를 기관의 정책에 맞도록 설정",
        "D-04": "데이터베이스 관리자 권한을 꼭 필요한 계정 및 그룹에 대해서만 허용",
        "D-05": "비밀번호 재사용에 대한 제약 설정",
        "D-06": "DB 사용자 계정을 개별적으로 부여하여 사용",
        "D-07": "root 권한으로 서비스 구동 제한",
        "D-08": "안전한 암호화 알고리즘 사용",
        "D-09": "일정 횟수의 로그인 실패 시 이에 대한 잠금정책 설정",
        "D-10": "원격에서 DB 서버로의 접속 제한",
        "D-11": "DBA 이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정",
        "D-12": "안전한 리스너 비밀번호 설정 및 사용",
        "D-13": "불필요한 ODBC/OLE-DB 데이터 소스와 드라이브를 제거하여 사용",
        "D-14": "데이터베이스 주요 설정파일 등의 접근 권한 적절성",
        "D-15": "오라클 리스너 로그 및 trace 파일 변경 제한",
        "D-16": "Windows 인증 모드 사용",
        "D-17": "Audit Table은 데이터베이스 관리자 계정으로 접근하도록 제한",
        "D-18": "응용프로그램 또는 DBA 계정의 Role이 Public으로 설정되지 않도록 조정",
        "D-19": "OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES를 FALSE로 설정",
        "D-20": "인가되지 않은 Object Owner의 제한",
        "D-21": "인가되지 않은 GRANT OPTION 사용 제한",
        "D-22": "데이터베이스의 자원 제한 기능을 TRUE로 설정",
        "D-23": "xp_cmdshell 사용 제한",
        "D-24": "Registry Procedure 권한 제한",
        "D-25": "주기적 보안 패치 및 벤더 권고 사항 적용",
        "D-26": "데이터베이스 감사 기록 정책 설정",
    }

    DEFAULT_INTERNAL_ACCOUNTS: Set[str] = {
        "root",
        "mysql",
        "mysql.sys",
        "mysql.session",
        "mysql.infoschema",
        "mariadb.sys",
    }

    DEFAULT_UNNECESSARY_ACCOUNTS: Set[str] = {
        "",
        "anonymous",
        "guest",
        "test",
        "demo",
        "sample",
        "scott",
        "pm",
        "adams",
        "clark",
        "blake",
        "jones",
    }

    SAFE_PASSWORD_PLUGINS: Set[str] = {
        "caching_sha2_password",
        "sha256_password",
        "ed25519",
        "unix_socket",
        "auth_socket",
    }

    WEAK_PASSWORD_PLUGINS: Set[str] = {
        "mysql_old_password",
        "mysql_native_password",
        "mysql_password",
    }

    EXTERNAL_AUTH_PLUGINS: Set[str] = {
        "pam",
        "gssapi",
        "dialog",
        "named_pipe",
        "socket",
    }

    def __init__(
        self,
        ip: str,
        dbms: SSHConnection,
        sql_manager: Optional[SqlManager] = None,
        target_db_config: Optional[Mapping[str, Any]] = None,
        result_db_config: Optional[Mapping[str, Any]] = None,
        query_mode: str = "pymysql",
        mysql_cli_sudo: bool = False,
        mysql_cli_bin: str = "mysql",
        allowed_admin_accounts: Optional[Iterable[str]] = None,
        allowed_grant_accounts: Optional[Iterable[str]] = None,
        allowed_system_table_accounts: Optional[Iterable[str]] = None,
        unnecessary_account_names: Optional[Iterable[str]] = None,
        password_min_length: int = 8,
        password_lifetime_days: int = 90,
        command_executor: Optional[Callable[[str], str]] = None,
        query_executor: Optional[Callable[[str], Sequence[Mapping[str, Any]]]] = None,
    ):
        self.ip = ip
        self.dbms = dbms
        self.sql_manager = sql_manager
        self.result_db_config = dict(result_db_config or {})

        self.target_db_config: Dict[str, Any] = dict(target_db_config or {})
        self.target_db_config.setdefault("host", ip)
        self.target_db_config.setdefault("port", 3306)
        self.target_db_config.setdefault("user", "root")
        self.target_db_config.setdefault("password", "")
        self.target_db_config.setdefault("charset", "utf8mb4")
        self.target_db_config.setdefault("connect_timeout", 10)
        self.target_db_config.setdefault("read_timeout", 15)
        self.target_db_config.setdefault("write_timeout", 15)

        if query_mode not in {"pymysql", "ssh-cli"}:
            raise ValueError("query_mode는 'pymysql' 또는 'ssh-cli'만 지원합니다.")
        self.query_mode = query_mode
        self.mysql_cli_sudo = mysql_cli_sudo
        self.mysql_cli_bin = mysql_cli_bin

        internal = set(self.DEFAULT_INTERNAL_ACCOUNTS)
        self.allowed_admin_accounts = internal | set(allowed_admin_accounts or ())
        self.allowed_grant_accounts = internal | set(allowed_grant_accounts or ())
        self.allowed_system_table_accounts = internal | set(
            allowed_system_table_accounts or ()
        )
        self.unnecessary_account_names = {
            name.lower() for name in (
                set(self.DEFAULT_UNNECESSARY_ACCOUNTS)
                | set(unnecessary_account_names or ())
            )
        }

        self.password_min_length = int(password_min_length)
        self.password_lifetime_days = int(password_lifetime_days)

        self.command_executor = command_executor
        self.query_executor = query_executor

        self._target_conn: Optional[pymysql.connections.Connection] = None
        self._user_column_cache: Optional[Dict[str, str]] = None
        self._server_version_cache: Optional[str] = None

    # ------------------------------------------------------------------
    # 연결 및 공통 실행
    # ------------------------------------------------------------------

    def connect_target_db(self) -> None:
        """PyMySQL 직접 접속 모드에서 대상 DB 연결을 생성한다."""
        if self.query_executor is not None or self.query_mode != "pymysql":
            return
        if self._target_conn is not None:
            self._target_conn.ping(reconnect=True)
            return

        config = dict(self.target_db_config)
        config["cursorclass"] = DictCursor
        config["autocommit"] = True
        self._target_conn = pymysql.connect(**config)

    def close(self) -> None:
        if self._target_conn is not None:
            try:
                self._target_conn.close()
            finally:
                self._target_conn = None

    def _execute_cmd(self, command: str) -> str:
        if self.command_executor is not None:
            return str(self.command_executor(command)).strip()
        return str(self.dbms.execute_cmd(command)).strip()

    def _query(self, query: str) -> List[Dict[str, Any]]:
        if self.query_executor is not None:
            return [dict(row) for row in self.query_executor(query)]

        if self.query_mode == "ssh-cli":
            return self._query_via_ssh_cli(query)

        self.connect_target_db()
        if self._target_conn is None:
            raise RuntimeError("대상 DB 연결이 생성되지 않았습니다.")

        self._target_conn.ping(reconnect=True)
        with self._target_conn.cursor() as cursor:
            cursor.execute(query)
            if cursor.description is None:
                return []
            return [dict(row) for row in cursor.fetchall()]

    def _query_via_ssh_cli(self, query: str) -> List[Dict[str, Any]]:
        """
        SSH로 대상 서버의 mysql/mariadb CLI를 실행한다.

        비밀번호가 없고 mysql_cli_sudo=True이면 `sudo -n mysql` 방식으로
        unix_socket 인증을 사용할 수 있다.
        """
        config = self.target_db_config
        cli_parts: List[str] = [
            self.mysql_cli_bin,
            "--batch",
            "--raw",
            "--column-names",
            f"--connect-timeout={int(config.get('connect_timeout', 10))}",
        ]

        user = str(config.get("user", "")).strip()
        host = str(config.get("host", "")).strip()
        port = config.get("port")
        unix_socket = str(config.get("unix_socket", "")).strip()

        if user:
            cli_parts.extend(["--user", user])
        if unix_socket:
            cli_parts.extend(["--socket", unix_socket])
        else:
            # SSH 원격 CLI에서는 localhost/socket 사용이 일반적이다.
            remote_host = str(config.get("cli_host", "localhost"))
            cli_parts.extend(["--host", remote_host])
            if port:
                cli_parts.extend(["--port", str(port)])

        cli_parts.extend(["--execute", query])
        command = " ".join(shlex.quote(part) for part in cli_parts)

        password = config.get("password")
        if password not in (None, ""):
            command = f"MYSQL_PWD={shlex.quote(str(password))} {command}"
        elif self.mysql_cli_sudo:
            command = f"sudo -n {command}"

        marker = "__DBMS_QUERY_RC__"
        command = (
            f"{command} 2>&1; "
            f"rc=$?; printf '\\n{marker}=%s\\n' \"$rc\""
        )
        output = self._execute_cmd(command)
        body, separator, rc_text = output.rpartition(f"{marker}=")
        if not separator:
            raise RuntimeError(f"원격 DB 명령 종료코드를 확인할 수 없습니다: {output[:500]}")

        try:
            return_code = int(rc_text.strip().splitlines()[0])
        except (ValueError, IndexError) as exc:
            raise RuntimeError(f"원격 DB 명령 종료코드 파싱 실패: {rc_text!r}") from exc

        body = body.rstrip()
        if return_code != 0:
            raise RuntimeError(body or f"mysql CLI 종료코드 {return_code}")

        if not body:
            return []

        reader = csv.DictReader(io.StringIO(body), delimiter="\t")
        return [dict(row) for row in reader]

    # ------------------------------------------------------------------
    # 공통 데이터 처리
    # ------------------------------------------------------------------

    @staticmethod
    def _row_get(row: Mapping[str, Any], *names: str, default: Any = None) -> Any:
        lowered = {str(key).lower(): value for key, value in row.items()}
        for name in names:
            if name.lower() in lowered:
                return lowered[name.lower()]
        return default

    @staticmethod
    def _as_int(value: Any, default: Optional[int] = None) -> Optional[int]:
        if value is None:
            return default
        text = str(value).strip()
        match = re.search(r"-?\d+", text)
        if not match:
            return default
        try:
            return int(match.group(0))
        except ValueError:
            return default

    @staticmethod
    def _normalize_grantee(value: Any) -> str:
        text = str(value or "").strip()
        # INFORMATION_SCHEMA의 GRANTEE 형식: 'user'@'host'
        return text.replace("'", "").replace("`", "")

    @staticmethod
    def _account_identity(row: Mapping[str, Any]) -> str:
        user = str(DBMS._row_get(row, "user", default="") or "")
        host = str(DBMS._row_get(row, "host", default="") or "")
        return f"{user}@{host}"

    @staticmethod
    def _is_yes(value: Any) -> bool:
        return str(value or "").strip().upper() in {"Y", "YES", "ON", "TRUE", "1"}

    @staticmethod
    def _is_local_host(host: str) -> bool:
        return host.lower() in {"localhost", "127.0.0.1", "::1"}

    @staticmethod
    def _summarize(values: Iterable[str], limit: int = 10) -> str:
        unique = sorted({str(value) for value in values if str(value)})
        if not unique:
            return "없음"
        if len(unique) <= limit:
            return ", ".join(unique)
        return f"{', '.join(unique[:limit])} 외 {len(unique) - limit}건"

    @staticmethod
    def _allowed(identity: str, allowlist: Set[str]) -> bool:
        user = identity.split("@", 1)[0]
        return identity in allowlist or user in allowlist

    def _get_user_columns(self) -> Dict[str, str]:
        if self._user_column_cache is not None:
            return self._user_column_cache

        rows = self._query(
            """
            SELECT COLUMN_NAME AS column_name
              FROM INFORMATION_SCHEMA.COLUMNS
             WHERE TABLE_SCHEMA = 'mysql'
               AND TABLE_NAME = 'user'
            """
        )
        columns: Dict[str, str] = {}
        for row in rows:
            column = str(self._row_get(row, "column_name", default="") or "")
            if column:
                columns[column.lower()] = column

        if not columns:
            raise RuntimeError("mysql.user 컬럼 정보를 조회하지 못했습니다.")

        self._user_column_cache = columns
        return columns

    def _get_user_accounts(self) -> List[Dict[str, Any]]:
        columns = self._get_user_columns()

        def column_expr(name: str, alias: str, default_sql: str = "''") -> str:
            actual = columns.get(name.lower())
            if actual:
                return f"`{actual}` AS `{alias}`"
            return f"{default_sql} AS `{alias}`"

        auth_column = "authentication_string"
        if auth_column not in columns and "password" in columns:
            auth_column = "password"

        expressions = [
            column_expr("user", "user"),
            column_expr("host", "host"),
            column_expr("plugin", "plugin"),
            column_expr(auth_column, "authentication_string"),
            column_expr("account_locked", "account_locked"),
            column_expr("password_expired", "password_expired"),
            column_expr("password_last_changed", "password_last_changed", "NULL"),
            column_expr("failed_login_attempts", "failed_login_attempts", "NULL"),
            column_expr("password_lock_time", "password_lock_time", "NULL"),
            column_expr("max_questions", "max_questions", "0"),
            column_expr("max_updates", "max_updates", "0"),
            column_expr("max_connections", "max_connections", "0"),
            column_expr("max_user_connections", "max_user_connections", "0"),
            column_expr("file_priv", "file_priv"),
        ]
        return self._query(f"SELECT {', '.join(expressions)} FROM mysql.user")

    def _get_variables(self, pattern: str) -> Dict[str, str]:
        escaped = pattern.replace("\\", "\\\\").replace("'", "''")
        rows = self._query(f"SHOW VARIABLES LIKE '{escaped}'")
        variables: Dict[str, str] = {}
        for row in rows:
            name = str(
                self._row_get(row, "Variable_name", "variable_name", default="") or ""
            ).lower()
            value = str(self._row_get(row, "Value", "value", default="") or "")
            if name:
                variables[name] = value
        return variables

    def _get_plugins(self) -> Dict[str, str]:
        rows = self._query(
            """
            SELECT PLUGIN_NAME AS plugin_name, PLUGIN_STATUS AS plugin_status
              FROM INFORMATION_SCHEMA.PLUGINS
            """
        )
        return {
            str(self._row_get(row, "plugin_name", default="") or "").lower():
            str(self._row_get(row, "plugin_status", default="") or "").upper()
            for row in rows
            if self._row_get(row, "plugin_name", default="")
        }

    def _get_server_version(self) -> str:
        if self._server_version_cache is not None:
            return self._server_version_cache
        rows = self._query("SELECT VERSION() AS version")
        version = (
            str(self._row_get(rows[0], "version", default="") or "")
            if rows
            else ""
        )
        self._server_version_cache = version
        return version

    # ------------------------------------------------------------------
    # D-01 ~ D-26
    # ------------------------------------------------------------------

    @safe_check
    def d_01(self, ip: Optional[str] = None, dbms: Optional[SSHConnection] = None) -> CheckResult:
        """D-01: 기본 계정의 초기 비밀번호 또는 인증 정책 변경 여부."""
        roots = [
            row
            for row in self._get_user_accounts()
            if str(self._row_get(row, "user", default="")).lower() == "root"
        ]
        if not roots:
            return (
                STATUS_MANUAL,
                "root 기본 계정이 조회되지 않았습니다. 대체 관리자 계정의 초기 인증정보 변경 여부를 확인해야 합니다.",
            )

        vulnerable: List[str] = []
        protected: List[str] = []
        unverifiable: List[str] = []

        for row in roots:
            identity = self._account_identity(row)
            host = str(self._row_get(row, "host", default="") or "")
            plugin = str(self._row_get(row, "plugin", default="") or "").lower()
            auth = str(
                self._row_get(row, "authentication_string", default="") or ""
            ).strip()
            locked = self._is_yes(self._row_get(row, "account_locked", default=""))

            if locked:
                protected.append(f"{identity}(잠금)")
            elif plugin in {"unix_socket", "auth_socket"} and self._is_local_host(host):
                protected.append(f"{identity}({plugin})")
            elif not auth and plugin not in self.EXTERNAL_AUTH_PLUGINS:
                vulnerable.append(f"{identity}(빈 인증정보, plugin={plugin or '미설정'})")
            else:
                unverifiable.append(
                    f"{identity}(plugin={plugin or '미설정'}, 인증정보 존재)"
                )

        if vulnerable:
            return (
                STATUS_BAD,
                f"기본 관리자 계정의 인증정보가 비어 있거나 보호되지 않았습니다: {self._summarize(vulnerable)}",
            )
        if unverifiable:
            return (
                STATUS_MANUAL,
                "비밀번호 해시 존재 여부는 확인했으나 초기 비밀번호가 실제로 변경되었는지는 해시만으로 판별할 수 없습니다. "
                f"확인 대상: {self._summarize(unverifiable)}; 자동 확인된 보호 계정: {self._summarize(protected)}",
            )
        return (
            STATUS_GOOD,
            f"root 기본 계정이 잠금 또는 로컬 소켓 인증으로 보호되어 있습니다: {self._summarize(protected)}",
        )

    @safe_check
    def d_02(self, ip: Optional[str] = None, dbms: Optional[SSHConnection] = None) -> CheckResult:
        """D-02: 불필요 계정 존재 여부."""
        accounts = self._get_user_accounts()
        obvious: List[str] = []
        review: List[str] = []

        for row in accounts:
            user = str(self._row_get(row, "user", default="") or "")
            identity = self._account_identity(row)
            locked = self._is_yes(self._row_get(row, "account_locked", default=""))
            if user.lower() in self.unnecessary_account_names and not locked:
                obvious.append(identity)
            elif user not in self.DEFAULT_INTERNAL_ACCOUNTS:
                review.append(f"{identity}{'(잠금)' if locked else ''}")

        if obvious:
            return (
                STATUS_BAD,
                f"익명·테스트·샘플 계정 등 불필요 가능성이 높은 활성 계정이 존재합니다: {self._summarize(obvious)}",
            )
        if review:
            return (
                STATUS_MANUAL,
                "퇴직자·직무변경·장기 미사용 계정 여부는 DB 계정 목록만으로 판별할 수 없습니다. "
                f"용도 확인 대상: {self._summarize(review)}",
            )
        return (
            STATUS_GOOD,
            "기본 내부 계정 외 별도 사용자 계정이 없고, 명백한 익명·테스트 계정도 확인되지 않았습니다.",
        )

    @safe_check
    def d_03(self, ip: Optional[str] = None, dbms: Optional[SSHConnection] = None) -> CheckResult:
        """D-03: 비밀번호 복잡도와 사용기간 정책."""
        variables: Dict[str, str] = {}
        for pattern in (
            "validate_password%",
            "simple_password_check%",
            "cracklib_password_check%",
            "default_password_lifetime",
            "strict_password_validation",
        ):
            variables.update(self._get_variables(pattern))

        plugins = self._get_plugins()

        # MySQL validate_password 컴포넌트/플러그인
        validate_policy = (
            variables.get("validate_password.policy")
            or variables.get("validate_password_policy")
            or ""
        ).upper()
        validate_length = self._as_int(
            variables.get("validate_password.length")
            or variables.get("validate_password_length")
        )
        validate_mixed = self._as_int(
            variables.get("validate_password.mixed_case_count")
            or variables.get("validate_password_mixed_case_count")
        )
        validate_number = self._as_int(
            variables.get("validate_password.number_count")
            or variables.get("validate_password_number_count")
        )
        validate_special = self._as_int(
            variables.get("validate_password.special_char_count")
            or variables.get("validate_password_special_char_count")
        )

        policy_strength_ok = validate_policy in {
            "MEDIUM",
            "STRONG",
            "1",
            "2",
        }
        validate_complexity_ok = bool(
            policy_strength_ok
            and validate_length is not None
            and validate_length >= self.password_min_length
            and (validate_mixed or 0) >= 1
            and (validate_number or 0) >= 1
            and (validate_special or 0) >= 1
        )

        # MariaDB simple_password_check 또는 cracklib_password_check
        simple_active = plugins.get("simple_password_check") == "ACTIVE"
        simple_length = self._as_int(
            variables.get("simple_password_check_minimal_length")
        )
        simple_digits = self._as_int(variables.get("simple_password_check_digits"))
        simple_letters = self._as_int(
            variables.get("simple_password_check_letters_same_case")
        )
        simple_other = self._as_int(
            variables.get("simple_password_check_other_characters")
        )
        simple_complexity_ok = bool(
            simple_active
            and simple_length is not None
            and simple_length >= self.password_min_length
            and (simple_digits or 0) >= 1
            and (simple_letters or 0) >= 1
            and (simple_other or 0) >= 1
        )

        cracklib_active = plugins.get("cracklib_password_check") == "ACTIVE"
        cracklib_length = self._as_int(
            variables.get("cracklib_password_check_min_length"),
            self.password_min_length if cracklib_active else None,
        )
        cracklib_complexity_ok = bool(
            cracklib_active
            and cracklib_length is not None
            and cracklib_length >= self.password_min_length
        )

        complexity_ok = (
            validate_complexity_ok
            or simple_complexity_ok
            or cracklib_complexity_ok
        )

        lifetime = self._as_int(variables.get("default_password_lifetime"))
        lifetime_ok = bool(
            lifetime is not None
            and 1 <= lifetime <= self.password_lifetime_days
        )

        problems: List[str] = []
        if not complexity_ok:
            problems.append(
                f"복잡도 정책 미흡(최소 {self.password_min_length}자, 대/소문자·숫자·특수문자 기준 확인 필요)"
            )
        if not lifetime_ok:
            problems.append(
                f"default_password_lifetime이 1~{self.password_lifetime_days}일 범위로 설정되지 않음"
            )

        if problems:
            return STATUS_BAD, "; ".join(problems)

        method = (
            "validate_password"
            if validate_complexity_ok
            else "simple_password_check"
            if simple_complexity_ok
            else "cracklib_password_check"
        )
        return (
            STATUS_GOOD,
            f"{method} 복잡도 정책과 비밀번호 최대 사용기간 {lifetime}일이 설정되어 있습니다.",
        )

    @safe_check
    def d_04(self, ip: Optional[str] = None, dbms: Optional[SSHConnection] = None) -> CheckResult:
        """D-04: 불필요한 관리자 권한 계정 확인."""
        rows = self._query(
            """
            SELECT GRANTEE AS grantee, PRIVILEGE_TYPE AS privilege_type
              FROM INFORMATION_SCHEMA.USER_PRIVILEGES
             WHERE PRIVILEGE_TYPE IN (
                   'SUPER', 'SYSTEM_USER', 'SYSTEM_VARIABLES_ADMIN',
                   'BINLOG_ADMIN', 'CONNECTION_ADMIN', 'ROLE_ADMIN',
                   'CREATE USER'
             )
            """
        )

        privileged: Dict[str, Set[str]] = {}
        for row in rows:
            identity = self._normalize_grantee(
                self._row_get(row, "grantee", default="")
            )
            privilege = str(
                self._row_get(row, "privilege_type", default="") or ""
            )
            if identity:
                privileged.setdefault(identity, set()).add(privilege)

        unauthorized = {
            identity: privileges
            for identity, privileges in privileged.items()
            if not self._allowed(identity, self.allowed_admin_accounts)
        }
        if unauthorized:
            details = [
                f"{identity}({','.join(sorted(privileges))})"
                for identity, privileges in unauthorized.items()
            ]
            return (
                STATUS_BAD,
                "허용 목록 밖의 계정에 관리자급 권한이 부여되어 있습니다: "
                f"{self._summarize(details)}",
            )
        return (
            STATUS_GOOD,
            "관리자급 권한 보유 계정이 설정된 허용 목록 이내입니다.",
        )

    @safe_check
    def d_05(self, ip: Optional[str] = None, dbms: Optional[SSHConnection] = None) -> CheckResult:
        """D-05: MySQL 8/MariaDB 확장 기능을 이용한 비밀번호 재사용 제한 대체 점검."""
        variables: Dict[str, str] = {}
        for pattern in (
            "password_history",
            "password_reuse_interval",
            "password_reuse_check%",
        ):
            variables.update(self._get_variables(pattern))
        plugins = self._get_plugins()

        history = self._as_int(variables.get("password_history"))
        reuse_interval = self._as_int(variables.get("password_reuse_interval"))
        mariadb_interval = self._as_int(
            variables.get("password_reuse_check_interval")
            or variables.get("password_reuse_check_interval_days")
        )
        mariadb_plugin_active = (
            plugins.get("password_reuse_check") == "ACTIVE"
        )

        configured_values = [
            value
            for value in (history, reuse_interval, mariadb_interval)
            if value is not None
        ]
        if configured_values and any(value > 0 for value in configured_values):
            return (
                STATUS_GOOD,
                "비밀번호 재사용 제한 기능이 설정되어 있습니다. "
                f"password_history={history}, password_reuse_interval={reuse_interval}, "
                f"password_reuse_check_interval={mariadb_interval}, "
                f"plugin_active={mariadb_plugin_active}",
            )
        if configured_values:
            return (
                STATUS_BAD,
                "비밀번호 재사용 제한 관련 변수가 존재하지만 모두 0 또는 비활성 상태입니다. "
                f"password_history={history}, password_reuse_interval={reuse_interval}, "
                f"password_reuse_check_interval={mariadb_interval}",
            )
        return (
            STATUS_MANUAL,
            "MySQL/MariaDB 버전에서 비밀번호 재사용 제한 변수를 확인하지 못했습니다. "
            "DBMS 미지원 여부와 기관의 절차적 비밀번호 이력 통제를 추가 확인해야 합니다.",
        )

    @safe_check
    def d_06(self, ip: Optional[str] = None, dbms: Optional[SSHConnection] = None) -> CheckResult:
        accounts = [
            self._account_identity(row)
            for row in self._get_user_accounts()
            if str(self._row_get(row, "user", default="") or "")
            not in self.DEFAULT_INTERNAL_ACCOUNTS
        ]
        return (
            STATUS_MANUAL,
            "계정 목록만으로 실제 공용 계정 공유 사용 여부를 판별할 수 없습니다. "
            f"사용자·응용프로그램별 계정 매핑 및 접속 로그를 확인하십시오. 현재 검토 대상: {self._summarize(accounts)}",
        )

    @safe_check
    def d_07(self, ip: Optional[str] = None, dbms: Optional[SSHConnection] = None) -> CheckResult:
        command = (
            "ps -eo user=,pid=,comm=,args= 2>/dev/null | "
            "awk '$3==\"mysqld\" || $3==\"mariadbd\" {print}'"
        )
        output = self._execute_cmd(command)
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        if not lines:
            return (
                STATUS_MANUAL,
                "mysqld/mariadbd 실행 프로세스를 확인하지 못했습니다. 서비스 중지 상태 또는 프로세스 명칭을 추가 확인해야 합니다.",
            )

        owners = {line.split()[0] for line in lines if line.split()}
        return (
            (STATUS_GOOD, f"DBMS 프로세스가 비-root 계정으로 구동 중입니다: {self._summarize(owners)}")
            if "root" not in owners
            else (STATUS_BAD, f"root 권한으로 구동되는 DBMS 프로세스가 존재합니다: {self._summarize(lines)}")
        )

    @safe_check
    def d_08(self, ip: Optional[str] = None, dbms: Optional[SSHConnection] = None) -> CheckResult:
        weak: List[str] = []
        unknown: List[str] = []
        safe: List[str] = []

        for row in self._get_user_accounts():
            identity = self._account_identity(row)
            plugin = str(self._row_get(row, "plugin", default="") or "").lower()
            locked = self._is_yes(self._row_get(row, "account_locked", default=""))
            if locked:
                continue

            if plugin in self.SAFE_PASSWORD_PLUGINS:
                safe.append(f"{identity}({plugin})")
            elif plugin in self.WEAK_PASSWORD_PLUGINS or not plugin:
                weak.append(f"{identity}({plugin or '미설정'})")
            elif plugin in self.EXTERNAL_AUTH_PLUGINS:
                unknown.append(f"{identity}({plugin}, 외부 인증정책 확인 필요)")
            else:
                unknown.append(f"{identity}({plugin})")

        if weak:
            return (
                STATUS_BAD,
                "SHA-256 미만 또는 취약한 인증 플러그인을 사용하는 활성 계정이 존재합니다: "
                f"{self._summarize(weak)}",
            )
        if unknown:
            return (
                STATUS_MANUAL,
                "외부/비표준 인증 플러그인의 실제 해시 알고리즘을 자동 판별할 수 없습니다: "
                f"{self._summarize(unknown)}; 자동 확인된 안전 계정: {self._summarize(safe)}",
            )
        return (
            STATUS_GOOD,
            f"활성 계정이 SHA-256 이상 또는 안전한 소켓/ed25519 인증을 사용합니다: {self._summarize(safe)}",
        )

    @safe_check
    def d_09(self, ip: Optional[str] = None, dbms: Optional[SSHConnection] = None) -> CheckResult:
        """D-09: MariaDB max_password_errors 또는 MySQL 계정 잠금 기능 점검."""
        variables: Dict[str, str] = {}
        for pattern in ("max_password_errors", "connection_control%"):
            variables.update(self._get_variables(pattern))
        plugins = self._get_plugins()

        max_password_errors = self._as_int(
            variables.get("max_password_errors")
        )
        connection_threshold = self._as_int(
            variables.get("connection_control_failed_connections_threshold")
        )
        connection_plugin_active = any(
            name.startswith("connection_control") and status == "ACTIVE"
            for name, status in plugins.items()
        )

        account_lock_candidates: List[str] = []
        account_lock_missing: List[str] = []
        account_columns_available = {
            "failed_login_attempts",
            "password_lock_time",
        }.issubset(self._get_user_columns())

        if account_columns_available:
            for row in self._get_user_accounts():
                user = str(self._row_get(row, "user", default="") or "")
                if user in self.DEFAULT_INTERNAL_ACCOUNTS:
                    continue
                failed = self._as_int(
                    self._row_get(row, "failed_login_attempts", default=None)
                )
                lock_time = self._as_int(
                    self._row_get(row, "password_lock_time", default=None)
                )
                identity = self._account_identity(row)
                if (failed or 0) > 0 and (lock_time or 0) > 0:
                    account_lock_candidates.append(
                        f"{identity}(실패 {failed}회, 잠금 {lock_time}일)"
                    )
                else:
                    account_lock_missing.append(identity)

        if account_lock_missing:
            return (
                STATUS_BAD,
                "계정별 로그인 실패 잠금 설정이 없는 활성 일반 계정이 존재합니다: "
                f"{self._summarize(account_lock_missing)}",
            )
        if account_lock_candidates:
            return (
                STATUS_GOOD,
                "계정별 로그인 실패 횟수 및 잠금 시간이 설정되어 있습니다: "
                f"{self._summarize(account_lock_candidates)}",
            )
        if max_password_errors is not None:
            return (
                (STATUS_GOOD, f"MariaDB max_password_errors={max_password_errors}로 로그인 실패 제한이 설정되어 있습니다.")
                if max_password_errors > 0
                else (STATUS_BAD, "MariaDB max_password_errors=0으로 로그인 실패 차단 기능이 비활성화되어 있습니다.")
            )
        if connection_threshold is not None or connection_plugin_active:
            return (
                (STATUS_GOOD, f"Connection Control 로그인 실패 임계값이 설정되어 있습니다: threshold={connection_threshold}")
                if (connection_threshold or 0) > 0 and connection_plugin_active
                else (
                    STATUS_BAD,
                    "Connection Control 플러그인 또는 실패 임계값 설정이 불완전합니다. "
                    f"plugin_active={connection_plugin_active}, threshold={connection_threshold}",
                )
            )
        return (
            STATUS_BAD,
            "로그인 실패 횟수 제한 또는 계정 잠금 기능을 확인하지 못했습니다.",
        )

    @safe_check
    def d_10(self, ip: Optional[str] = None, dbms: Optional[SSHConnection] = None) -> CheckResult:
        wildcard_accounts: List[str] = []
        for row in self._get_user_accounts():
            host = str(self._row_get(row, "host", default="") or "").strip()
            locked = self._is_yes(self._row_get(row, "account_locked", default=""))
            if not locked and host in {"%", "", "0.0.0.0", "::"}:
                wildcard_accounts.append(self._account_identity(row))

        listen_info = self._execute_cmd(
            "(ss -lnt 2>/dev/null || netstat -lnt 2>/dev/null) | "
            "grep -E '(:3306|:33060)[[:space:]]' || true"
        )

        if wildcard_accounts:
            return (
                STATUS_BAD,
                "모든 호스트에서 접속 가능한 DB 계정이 존재합니다: "
                f"{self._summarize(wildcard_accounts)}. "
                f"리스닝 정보: {listen_info or '확인되지 않음'}",
            )
        return (
            STATUS_GOOD,
            "Host='%' 등 전역 접속 계정이 없으며 계정별 접속 호스트 제한이 설정되어 있습니다. "
            f"리스닝 정보: {listen_info or '확인되지 않음'}",
        )

    @safe_check
    def d_11(self, ip: Optional[str] = None, dbms: Optional[SSHConnection] = None) -> CheckResult:
        queries = [
            """
            SELECT GRANTEE AS grantee, PRIVILEGE_TYPE AS privilege_type, 'GLOBAL' AS scope
              FROM INFORMATION_SCHEMA.USER_PRIVILEGES
             WHERE PRIVILEGE_TYPE IN (
                   'SELECT','INSERT','UPDATE','DELETE','CREATE','DROP',
                   'ALTER','INDEX','REFERENCES','EXECUTE','CREATE VIEW',
                   'SHOW VIEW','TRIGGER'
             )
            """,
            """
            SELECT GRANTEE AS grantee, PRIVILEGE_TYPE AS privilege_type, 'SCHEMA' AS scope
              FROM INFORMATION_SCHEMA.SCHEMA_PRIVILEGES
             WHERE TABLE_SCHEMA = 'mysql'
            """,
            """
            SELECT GRANTEE AS grantee, PRIVILEGE_TYPE AS privilege_type, 'TABLE' AS scope
              FROM INFORMATION_SCHEMA.TABLE_PRIVILEGES
             WHERE TABLE_SCHEMA = 'mysql'
            """,
        ]

        grants: Dict[str, Set[str]] = {}
        for query in queries:
            for row in self._query(query):
                identity = self._normalize_grantee(
                    self._row_get(row, "grantee", default="")
                )
                privilege = str(
                    self._row_get(row, "privilege_type", default="") or ""
                )
                scope = str(self._row_get(row, "scope", default="") or "")
                if identity:
                    grants.setdefault(identity, set()).add(f"{scope}:{privilege}")

        unauthorized = {
            identity: privileges
            for identity, privileges in grants.items()
            if not self._allowed(identity, self.allowed_system_table_accounts)
        }
        if unauthorized:
            details = [
                f"{identity}({','.join(sorted(privileges))})"
                for identity, privileges in unauthorized.items()
            ]
            return (
                STATUS_BAD,
                "허용 목록 밖의 계정이 mysql 시스템 스키마에 접근 가능한 권한을 보유합니다: "
                f"{self._summarize(details)}",
            )
        return (
            STATUS_GOOD,
            "mysql 시스템 스키마 접근 가능 계정이 설정된 DBA/내부 계정 허용 목록 이내입니다.",
        )

    @safe_check
    def d_12(self, ip: Optional[str] = None, dbms: Optional[SSHConnection] = None) -> CheckResult:
        return STATUS_NA, "Oracle Listener 전용 항목으로 MySQL/MariaDB에는 해당하지 않습니다."

    @safe_check
    def d_13(self, ip: Optional[str] = None, dbms: Optional[SSHConnection] = None) -> CheckResult:
        """D-13: Linux unixODBC 설정 파일의 데이터 소스/드라이버 등록 여부 보완 점검."""
        output = self._execute_cmd(
            """
            found=0
            for f in /etc/odbc.ini /etc/odbcinst.ini /usr/local/etc/odbc.ini /usr/local/etc/odbcinst.ini; do
                [ -f "$f" ] || continue
                active=$(grep -Ev '^[[:space:]]*($|#|;)' "$f" 2>/dev/null || true)
                if [ -n "$active" ]; then
                    found=1
                    printf '### %s\n%s\n' "$f" "$active"
                fi
            done
            [ "$found" -eq 0 ] && printf 'NO_ACTIVE_ODBC_ENTRY\n'
            """.strip()
        )
        if "NO_ACTIVE_ODBC_ENTRY" in output:
            return (
                STATUS_GOOD,
                "Linux ODBC 설정 파일에 활성 데이터 소스 또는 드라이버 등록이 확인되지 않았습니다.",
            )
        return (
            STATUS_MANUAL,
            "ODBC 데이터 소스/드라이버 등록은 확인되었으나 업무상 필요 여부는 자동 판별할 수 없습니다. "
            f"등록 내용: {output[:1500]}",
        )

    @safe_check
    def d_14(self, ip: Optional[str] = None, dbms: Optional[SSHConnection] = None) -> CheckResult:
        """D-14: MySQL/MariaDB 주요 파일 권한 보완 점검."""
        datadir_rows = self._query("SHOW VARIABLES LIKE 'datadir'")
        datadir = (
            str(self._row_get(datadir_rows[0], "Value", "value", default="") or "")
            if datadir_rows
            else ""
        )
        paths = [
            "/etc/my.cnf",
            "/etc/mysql/my.cnf",
            "/etc/mysql/mariadb.cnf",
        ]
        if datadir:
            paths.append(datadir)
        path_args = " ".join(shlex.quote(path) for path in paths)

        command = f"""
        for p in {path_args}; do
            [ -e "$p" ] || continue
            stat -Lc '%n|%F|%U|%G|%a' "$p" 2>/dev/null
        done
        for d in /etc/mysql/mariadb.conf.d /etc/mysql/mysql.conf.d /etc/my.cnf.d; do
            [ -d "$d" ] || continue
            find "$d" -maxdepth 1 -type f -name '*.cnf' -exec stat -Lc '%n|%F|%U|%G|%a' {{}} \\; 2>/dev/null
        done
        """.strip()
        output = self._execute_cmd(command)
        records = [line for line in output.splitlines() if line.count("|") >= 4]
        if not records:
            return (
                STATUS_MANUAL,
                "주요 설정 파일과 데이터 디렉터리의 stat 정보를 수집하지 못했습니다.",
            )

        bad: List[str] = []
        checked: List[str] = []
        allowed_owners = {"root", "mysql", "mariadb"}
        allowed_groups = {"root", "mysql", "mariadb"}

        for record in records:
            path, file_type, owner, group, mode_text = record.split("|", 4)
            try:
                mode = int(mode_text, 8)
            except ValueError:
                bad.append(f"{path}(권한 파싱 실패:{mode_text})")
                continue

            checked.append(f"{path}({owner}:{group},{mode_text})")
            reasons: List[str] = []
            if owner not in allowed_owners:
                reasons.append(f"소유자={owner}")
            if mode & 0o002:
                reasons.append("other 쓰기 권한")
            if mode & 0o020 and group not in allowed_groups:
                reasons.append(f"비인가 그룹 쓰기 권한({group})")
            if "regular file" in file_type.lower() and mode & 0o022:
                # 설정 파일은 일반적으로 소유자 외 쓰기 권한이 없어야 한다.
                reasons.append("소유자 외 쓰기 권한")
            if reasons:
                bad.append(f"{path}({'; '.join(sorted(set(reasons)))})")

        if bad:
            return (
                STATUS_BAD,
                f"주요 DB 파일/디렉터리의 소유자 또는 쓰기 권한이 부적절합니다: {self._summarize(bad)}",
            )
        return (
            STATUS_GOOD,
            f"확인된 주요 DB 파일/디렉터리에 일반 사용자 쓰기 권한이 없습니다: {self._summarize(checked)}",
        )

    @safe_check
    def d_15(self, ip: Optional[str] = None, dbms: Optional[SSHConnection] = None) -> CheckResult:
        return STATUS_NA, "Oracle Listener 전용 항목으로 MySQL/MariaDB에는 해당하지 않습니다."

    @safe_check
    def d_16(self, ip: Optional[str] = None, dbms: Optional[SSHConnection] = None) -> CheckResult:
        return STATUS_NA, "MSSQL Windows 인증 모드 전용 항목으로 MySQL/MariaDB에는 해당하지 않습니다."

    @safe_check
    def d_17(self, ip: Optional[str] = None, dbms: Optional[SSHConnection] = None) -> CheckResult:
        """D-17: MySQL 로그/감사 테이블에 대한 일반 계정 권한 보완 점검."""
        audit_tables = self._query(
            """
            SELECT TABLE_NAME AS table_name
              FROM INFORMATION_SCHEMA.TABLES
             WHERE TABLE_SCHEMA = 'mysql'
               AND (
                    TABLE_NAME IN ('general_log', 'slow_log')
                    OR LOWER(TABLE_NAME) LIKE '%audit%'
               )
            """
        )
        table_names = {
            str(self._row_get(row, "table_name", default="") or "")
            for row in audit_tables
            if self._row_get(row, "table_name", default="")
        }
        if not table_names:
            return (
                STATUS_MANUAL,
                "DB 내부 Audit/로그 테이블이 확인되지 않았습니다. 파일 또는 플러그인 기반 감사 로그 접근권한은 D-26과 함께 확인해야 합니다.",
            )

        grants = self._query(
            """
            SELECT GRANTEE AS grantee, TABLE_NAME AS table_name,
                   PRIVILEGE_TYPE AS privilege_type
              FROM INFORMATION_SCHEMA.TABLE_PRIVILEGES
             WHERE TABLE_SCHEMA = 'mysql'
               AND (
                    TABLE_NAME IN ('general_log', 'slow_log')
                    OR LOWER(TABLE_NAME) LIKE '%audit%'
               )
            """
        )
        unauthorized: List[str] = []
        for row in grants:
            identity = self._normalize_grantee(
                self._row_get(row, "grantee", default="")
            )
            if identity and not self._allowed(
                identity, self.allowed_system_table_accounts
            ):
                unauthorized.append(
                    f"{identity}:{self._row_get(row, 'table_name', default='')}="
                    f"{self._row_get(row, 'privilege_type', default='')}"
                )

        if unauthorized:
            return (
                STATUS_BAD,
                "일반 계정에 Audit/로그 테이블 접근 권한이 부여되어 있습니다: "
                f"{self._summarize(unauthorized)}",
            )
        return (
            STATUS_GOOD,
            f"Audit/로그 테이블({self._summarize(table_names)})에 비인가 일반 계정 권한이 확인되지 않았습니다.",
        )

    @safe_check
    def d_18(self, ip: Optional[str] = None, dbms: Optional[SSHConnection] = None) -> CheckResult:
        """D-18: MariaDB/MySQL의 PUBLIC Role 대체 확인으로 익명 계정 및 PUBLIC 명칭 Role을 점검."""
        anonymous = [
            self._account_identity(row)
            for row in self._get_user_accounts()
            if not str(self._row_get(row, "user", default="") or "")
            and not self._is_yes(self._row_get(row, "account_locked", default=""))
        ]

        public_roles: List[str] = []
        try:
            rows = self._query(
                """
                SELECT User AS user, Host AS host
                  FROM mysql.user
                 WHERE LOWER(User) = 'public'
                """
            )
            public_roles = [self._account_identity(row) for row in rows]
        except Exception:
            # mysql.user 조회는 위에서 이미 수행되므로 역할 메타데이터 차이는 수동 보완 대상으로 둔다.
            public_roles = []

        findings = anonymous + public_roles
        return (
            (STATUS_GOOD, "활성 익명 계정과 PUBLIC 명칭 계정/Role이 확인되지 않았습니다.")
            if not findings
            else (
                STATUS_BAD,
                f"PUBLIC 수준의 광범위 접근으로 악용될 수 있는 익명/PUBLIC 계정이 존재합니다: {self._summarize(findings)}",
            )
        )

    @safe_check
    def d_19(self, ip: Optional[str] = None, dbms: Optional[SSHConnection] = None) -> CheckResult:
        return STATUS_NA, "Oracle OS_ROLES/REMOTE_OS_* 전용 항목으로 MySQL/MariaDB에는 해당하지 않습니다."

    @safe_check
    def d_20(self, ip: Optional[str] = None, dbms: Optional[SSHConnection] = None) -> CheckResult:
        """D-20: MySQL/MariaDB Object DEFINER와 FEDERATED 사용 여부 보완 점검."""
        rows = self._query(
            """
            SELECT DEFINER AS definer, 'VIEW' AS object_type,
                   CONCAT(TABLE_SCHEMA, '.', TABLE_NAME) AS object_name
              FROM INFORMATION_SCHEMA.VIEWS
            UNION ALL
            SELECT DEFINER AS definer, 'ROUTINE' AS object_type,
                   CONCAT(ROUTINE_SCHEMA, '.', ROUTINE_NAME) AS object_name
              FROM INFORMATION_SCHEMA.ROUTINES
            UNION ALL
            SELECT DEFINER AS definer, 'TRIGGER' AS object_type,
                   CONCAT(TRIGGER_SCHEMA, '.', TRIGGER_NAME) AS object_name
              FROM INFORMATION_SCHEMA.TRIGGERS
            UNION ALL
            SELECT DEFINER AS definer, 'EVENT' AS object_type,
                   CONCAT(EVENT_SCHEMA, '.', EVENT_NAME) AS object_name
              FROM INFORMATION_SCHEMA.EVENTS
            """
        )

        review: List[str] = []
        for row in rows:
            identity = self._normalize_grantee(
                self._row_get(row, "definer", default="")
            )
            if identity and not self._allowed(identity, self.allowed_admin_accounts):
                review.append(
                    f"{self._row_get(row, 'object_type', default='OBJECT')} "
                    f"{self._row_get(row, 'object_name', default='')} -> {identity}"
                )

        engine_rows = self._query("SHOW ENGINES")
        federated_enabled = False
        for row in engine_rows:
            engine = str(self._row_get(row, "Engine", "engine", default="") or "")
            support = str(
                self._row_get(row, "Support", "support", default="") or ""
            ).upper()
            if engine.upper() == "FEDERATED" and support in {"YES", "DEFAULT"}:
                federated_enabled = True
                break

        if review or federated_enabled:
            notes: List[str] = []
            if review:
                notes.append(
                    f"비관리자 DEFINER의 인가 여부 확인 필요: {self._summarize(review)}"
                )
            if federated_enabled:
                notes.append("FEDERATED 엔진 활성화: 외부 연결 Object 소유자/권한 확인 필요")
            return STATUS_MANUAL, "; ".join(notes)
        return (
            STATUS_GOOD,
            "비관리자 DEFINER Object와 활성 FEDERATED 엔진이 확인되지 않았습니다.",
        )

    @safe_check
    def d_21(self, ip: Optional[str] = None, dbms: Optional[SSHConnection] = None) -> CheckResult:
        queries = [
            """
            SELECT GRANTEE AS grantee, PRIVILEGE_TYPE AS privilege_type, 'GLOBAL' AS scope
              FROM INFORMATION_SCHEMA.USER_PRIVILEGES
             WHERE IS_GRANTABLE = 'YES'
            """,
            """
            SELECT GRANTEE AS grantee, PRIVILEGE_TYPE AS privilege_type, 'SCHEMA' AS scope
              FROM INFORMATION_SCHEMA.SCHEMA_PRIVILEGES
             WHERE IS_GRANTABLE = 'YES'
            """,
            """
            SELECT GRANTEE AS grantee, PRIVILEGE_TYPE AS privilege_type, 'TABLE' AS scope
              FROM INFORMATION_SCHEMA.TABLE_PRIVILEGES
             WHERE IS_GRANTABLE = 'YES'
            """,
            """
            SELECT GRANTEE AS grantee, PRIVILEGE_TYPE AS privilege_type, 'ROUTINE' AS scope
              FROM INFORMATION_SCHEMA.ROUTINE_PRIVILEGES
             WHERE IS_GRANTABLE = 'YES'
            """,
        ]

        grants: Dict[str, Set[str]] = {}
        for query in queries:
            for row in self._query(query):
                identity = self._normalize_grantee(
                    self._row_get(row, "grantee", default="")
                )
                privilege = str(
                    self._row_get(row, "privilege_type", default="") or ""
                )
                scope = str(self._row_get(row, "scope", default="") or "")
                if identity:
                    grants.setdefault(identity, set()).add(f"{scope}:{privilege}")

        unauthorized = {
            identity: privileges
            for identity, privileges in grants.items()
            if not self._allowed(identity, self.allowed_grant_accounts)
        }
        if unauthorized:
            details = [
                f"{identity}({','.join(sorted(privileges))})"
                for identity, privileges in unauthorized.items()
            ]
            return (
                STATUS_BAD,
                "허용 목록 밖의 일반 계정에 GRANT OPTION이 부여되어 있습니다: "
                f"{self._summarize(details)}",
            )
        return STATUS_GOOD, "GRANT OPTION 보유 계정이 설정된 관리자 허용 목록 이내입니다."

    @safe_check
    def d_22(self, ip: Optional[str] = None, dbms: Optional[SSHConnection] = None) -> CheckResult:
        """D-22: MySQL/MariaDB 계정별 자원 제한 대체 점검."""
        unrestricted: List[str] = []
        restricted: List[str] = []

        for row in self._get_user_accounts():
            user = str(self._row_get(row, "user", default="") or "")
            if user in self.DEFAULT_INTERNAL_ACCOUNTS:
                continue

            limits = {
                "questions": self._as_int(
                    self._row_get(row, "max_questions", default=0), 0
                )
                or 0,
                "updates": self._as_int(
                    self._row_get(row, "max_updates", default=0), 0
                )
                or 0,
                "connections": self._as_int(
                    self._row_get(row, "max_connections", default=0), 0
                )
                or 0,
                "user_connections": self._as_int(
                    self._row_get(row, "max_user_connections", default=0), 0
                )
                or 0,
            }
            identity = self._account_identity(row)
            if any(value > 0 for value in limits.values()):
                restricted.append(
                    f"{identity}({','.join(f'{key}={value}' for key, value in limits.items())})"
                )
            else:
                unrestricted.append(identity)

        if unrestricted:
            return (
                STATUS_MANUAL,
                "계정별 자원 제한값이 모두 0인 일반 계정이 존재합니다. "
                "업무 특성상 제한이 필요한 계정인지 추가 검토하십시오: "
                f"{self._summarize(unrestricted)}; 제한 설정 계정: {self._summarize(restricted)}",
            )
        return (
            STATUS_GOOD,
            f"일반 계정에 하나 이상의 자원 제한이 설정되어 있습니다: {self._summarize(restricted)}",
        )

    @safe_check
    def d_23(self, ip: Optional[str] = None, dbms: Optional[SSHConnection] = None) -> CheckResult:
        """D-23: MSSQL xp_cmdshell의 MariaDB 대체 점검으로 FILE 권한을 확인."""
        file_priv_accounts: List[str] = []
        for row in self._get_user_accounts():
            if not self._is_yes(self._row_get(row, "file_priv", default="")):
                continue
            identity = self._account_identity(row)
            if not self._allowed(identity, self.allowed_admin_accounts):
                file_priv_accounts.append(identity)

        return (
            (STATUS_GOOD, "허용 목록 밖의 일반 계정에 FILE 권한이 부여되지 않았습니다.")
            if not file_priv_accounts
            else (
                STATUS_BAD,
                "OS 파일 읽기/쓰기 악용 가능성이 있는 FILE 권한이 일반 계정에 부여되어 있습니다: "
                f"{self._summarize(file_priv_accounts)}",
            )
        )

    @safe_check
    def d_24(self, ip: Optional[str] = None, dbms: Optional[SSHConnection] = None) -> CheckResult:
        return STATUS_NA, "MSSQL Registry Procedure 전용 항목으로 MySQL/MariaDB에는 해당하지 않습니다."

    @safe_check
    def d_25(self, ip: Optional[str] = None, dbms: Optional[SSHConnection] = None) -> CheckResult:
        version = self._get_server_version()
        package_info = self._execute_cmd(
            """
            if command -v dpkg-query >/dev/null 2>&1; then
                dpkg-query -W -f='${Package}\\t${Version}\\n' 2>/dev/null |
                grep -E '^(mariadb|mysql)(-server|-client|-common|[0-9])' | head -20
            elif command -v rpm >/dev/null 2>&1; then
                rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\n' 2>/dev/null |
                grep -Ei '^(mariadb|mysql)' | head -20
            else
                (mariadb --version || mysql --version) 2>/dev/null
            fi
            """.strip()
        )
        return (
            STATUS_MANUAL,
            "설치 버전 수집은 완료했으나 최신 보안 패치 여부는 점검 시점의 벤더 권고·EOL 정보와 비교해야 합니다. "
            f"DB 버전: {version or '조회 실패'}; 패키지: {package_info or '조회 실패'}",
        )

    @safe_check
    def d_26(self, ip: Optional[str] = None, dbms: Optional[SSHConnection] = None) -> CheckResult:
        """D-26: MariaDB server_audit 또는 MySQL audit_log 플러그인 보완 점검."""
        plugins = self._get_plugins()
        active_plugins = {
            name
            for name, status in plugins.items()
            if status == "ACTIVE"
            and (
                "audit" in name
                or name in {"server_audit", "audit_log"}
            )
        }
        if not active_plugins:
            return (
                STATUS_BAD,
                "Audit 관련 플러그인이 활성화되어 있지 않아 DB 접근·변경·삭제 감사 기록 설정을 확인할 수 없습니다.",
            )

        variables: Dict[str, str] = {}
        for pattern in ("server_audit%", "audit_log%"):
            variables.update(self._get_variables(pattern))

        server_logging = str(
            variables.get("server_audit_logging", "")
        ).upper()
        audit_policy = str(
            variables.get("audit_log_policy")
            or variables.get("audit_log_filter_id")
            or ""
        ).upper()
        events = str(variables.get("server_audit_events", "")).upper()

        logging_on = server_logging in {"ON", "1", "TRUE"} or (
            audit_policy not in {"", "OFF", "NONE", "0"}
        )
        if not logging_on:
            return (
                STATUS_BAD,
                "Audit 플러그인은 활성화되어 있으나 감사 로깅 또는 정책이 비활성 상태입니다. "
                f"plugins={self._summarize(active_plugins)}, "
                f"server_audit_logging={server_logging or '미설정'}, "
                f"audit_log_policy={audit_policy or '미설정'}",
            )

        # server_audit_events가 비어 있으면 MariaDB에서는 전체 이벤트가 대상이 될 수 있다.
        if events and events not in {"ALL", "*"}:
            required = {"CONNECT", "QUERY"}
            configured = {
                item.strip()
                for item in re.split(r"[,; ]+", events)
                if item.strip()
            }
            if not required.issubset(configured):
                return (
                    STATUS_MANUAL,
                    "감사 로깅은 활성화되어 있으나 기관 정책에 필요한 이벤트 범위인지 추가 확인해야 합니다. "
                    f"plugins={self._summarize(active_plugins)}, events={events}",
                )

        return (
            STATUS_GOOD,
            "Audit 플러그인과 감사 로깅 정책이 활성화되어 있습니다. "
            f"plugins={self._summarize(active_plugins)}, "
            f"events={events or '전체/기본 정책'}",
        )

    # ------------------------------------------------------------------
    # 전체 실행 및 결과 저장
    # ------------------------------------------------------------------

    def run_all(self, push_to_db: bool = False) -> List[Dict[str, str]]:
        results: List[Dict[str, str]] = []

        print("\n" + "=" * 100)
        print(f"DBMS 취약점 점검 시작: {self.ip} (D-01 ~ D-26)")
        print("=" * 100)

        for number in range(1, 27):
            method_name = f"d_{number:02d}"
            code = f"D-{number:02d}"
            title = self.CHECK_TITLES[code]
            method = getattr(self, method_name)
            status, reason = method()

            result = {
                "code": code,
                "title": title,
                "status": status,
                "reason": reason,
            }
            results.append(result)

            print(f"[{code}] {status} | {title}")
            print(f"       {reason}")

            if self.sql_manager is not None:
                self.sql_manager.record_result(code, title, status, reason)

        if push_to_db:
            if self.sql_manager is None:
                raise RuntimeError("push_to_db=True이지만 SqlManager가 설정되지 않았습니다.")
            if not self.result_db_config:
                raise RuntimeError("결과 저장 DB 설정(result_db_config)이 없습니다.")
            self.sql_manager.push_to_db(self.result_db_config)

        return results


def _comma_set(value: Optional[str]) -> Set[str]:
    if not value:
        return set()
    return {item.strip() for item in value.split(",") if item.strip()}


def _validate_table_name(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
        raise argparse.ArgumentTypeError(
            "테이블명은 영문자/밑줄로 시작하고 영문자, 숫자, 밑줄만 포함해야 합니다."
        )
    return value


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="MySQL/MariaDB 주요정보통신기반시설 D-01~D-26 점검"
    )
    parser.add_argument("--ip", required=True, help="SSH 대상 서버 IP 또는 호스트명")
    parser.add_argument("--ssh-port", type=int, default=22)
    parser.add_argument("--ssh-user", required=True)
    parser.add_argument(
        "--ssh-password",
        default=os.getenv("SSH_PASSWORD"),
        help="미지정 시 SSH_PASSWORD 환경변수 사용",
    )

    parser.add_argument(
        "--query-mode",
        choices=("pymysql", "ssh-cli"),
        default="pymysql",
        help="대상 DB 조회 방식",
    )
    parser.add_argument("--db-host", default=None, help="기본값: --ip")
    parser.add_argument("--db-port", type=int, default=3306)
    parser.add_argument("--db-user", default="root")
    parser.add_argument(
        "--db-password",
        default=os.getenv("TARGET_DB_PASSWORD", ""),
        help="미지정 시 TARGET_DB_PASSWORD 환경변수 사용",
    )
    parser.add_argument(
        "--db-unix-socket",
        default=None,
        help="PyMySQL 로컬 소켓 또는 SSH CLI 소켓 경로",
    )
    parser.add_argument(
        "--mysql-cli-bin",
        default="mysql",
        help="ssh-cli 모드에서 사용할 mysql 또는 mariadb 실행 파일",
    )
    parser.add_argument(
        "--mysql-cli-sudo",
        action="store_true",
        help="ssh-cli 모드에서 비밀번호 없이 sudo -n mysql 사용",
    )

    parser.add_argument(
        "--allowed-admin",
        default="",
        help="추가 관리자 허용 계정. 쉼표 구분(user 또는 user@host)",
    )
    parser.add_argument(
        "--allowed-grant",
        default="",
        help="추가 GRANT OPTION 허용 계정. 쉼표 구분",
    )
    parser.add_argument(
        "--allowed-system-table",
        default="",
        help="추가 mysql 시스템 스키마 접근 허용 계정. 쉼표 구분",
    )
    parser.add_argument(
        "--password-min-length",
        type=int,
        default=8,
    )
    parser.add_argument(
        "--password-lifetime-days",
        type=int,
        default=90,
    )

    parser.add_argument(
        "--save-results",
        action="store_true",
        help="SqlManager를 이용해 결과 DB에 저장",
    )
    parser.add_argument("--setup-result-db", action="store_true")
    parser.add_argument("--result-db-host", default="127.0.0.1")
    parser.add_argument("--result-db-port", type=int, default=3306)
    parser.add_argument("--result-db-user", default="root")
    parser.add_argument(
        "--result-db-password",
        default=os.getenv("RESULT_DB_PASSWORD", ""),
    )
    parser.add_argument("--result-db-name", default="vulnerability")
    parser.add_argument(
        "--result-table",
        type=_validate_table_name,
        default="dbms_table",
    )
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()

    if not args.ssh_password:
        raise SystemExit(
            "--ssh-password 또는 SSH_PASSWORD 환경변수가 필요합니다."
        )

    target_db_config: Dict[str, Any] = {
        "host": args.db_host or args.ip,
        "port": args.db_port,
        "user": args.db_user,
        "password": args.db_password,
    }
    if args.db_unix_socket:
        target_db_config["unix_socket"] = args.db_unix_socket

    result_db_config: Dict[str, Any] = {
        "host": args.result_db_host,
        "port": args.result_db_port,
        "user": args.result_db_user,
        "password": args.result_db_password,
        "database": args.result_db_name,
        "charset": "utf8mb4",
    }

    ssh = SSHConnection(
        hostname=args.ip,
        port=args.ssh_port,
        username=args.ssh_user,
        password=args.ssh_password,
        device_type="server",
    )
    manager = (
        SqlManager(target_ip=args.ip, table_name=args.result_table)
        if args.save_results
        else None
    )

    scanner = DBMS(
        ip=args.ip,
        dbms=ssh,
        sql_manager=manager,
        target_db_config=target_db_config,
        result_db_config=result_db_config if args.save_results else None,
        query_mode=args.query_mode,
        mysql_cli_sudo=args.mysql_cli_sudo,
        mysql_cli_bin=args.mysql_cli_bin,
        allowed_admin_accounts=_comma_set(args.allowed_admin),
        allowed_grant_accounts=_comma_set(args.allowed_grant),
        allowed_system_table_accounts=_comma_set(args.allowed_system_table),
        password_min_length=args.password_min_length,
        password_lifetime_days=args.password_lifetime_days,
    )

    ssh_connected = False
    try:
        ssh.connect()
        ssh_connected = True

        if args.query_mode == "pymysql":
            scanner.connect_target_db()

        if args.save_results and args.setup_result_db:
            if manager is None:
                raise RuntimeError("SqlManager 초기화 실패")
            manager.setup_db(result_db_config)

        scanner.run_all(push_to_db=args.save_results)
        return 0
    except Exception as exc:
        print(f"\n[ERROR] 점검 실행 실패: {exc.__class__.__name__}: {exc}")
        return 1
    finally:
        scanner.close()
        if ssh_connected:
            ssh.disconnect()


if __name__ == "__main__":
    raise SystemExit(main())
