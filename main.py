import _bootstrap  # noqa: F401  필요한 패키지가 없으면 .venv 에 설치하고 다시 실행 (점검 로직과 무관)
import json
import random
import threading
import time
import warnings
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from ssh_connection import SSHConnection
from sql_manager import SqlManager

from team_works.unix_server import UnixServer
from team_works.windows_server import WindowsServer
#from team_works.web_service import Webservice
from team_works.network_device import NetworkDevice
from team_works.PC import PC
from team_works.DBMS import DBMSServer
from team_works.web_application_jun import WebApplication
from team_works.virtualization_device import VirtualDevice

VALIDATOR_MAP = {
    "unix": UnixServer,
    "windows": WindowsServer,
    "network": NetworkDevice,
    "pc": PC,
    "dbms": DBMSServer,
    "virtual": VirtualDevice,
    "web_application": WebApplication
}

TABLE_MAP = {
    "unix": "unix_table",
    "windows": "windows_table",
    "network": "network_table",
    "pc": "pc_table",
    "dbms": "dbms_table",
    "virtual": "virtual_table",
    "web_application": "webapp_table"
}

DB_CONFIG = {'host': '', 'user': 'jjt_app', 'password': '',
             'database': 'jjt_db', 'charset': 'utf8mb4'}

# 동시에 붙일 호스트 수. sshd 기본값 MaxStartups 10:30:100 을 감안해 보수적으로 잡는다.
MAX_WORKERS = 8

# 호스트 1대 전체 점검의 상한. 넘으면 해당 호스트만 포기하고 나머지는 계속 진행한다.
HOST_DEADLINE = 1800  # 초

# strict_host_key 를 false 로 둔 장비는 '미등록 호스트 키 허용'을 이미 명시한 것이므로
# paramiko 의 WarningPolicy 경고를 매번 찍지 않는다.
# (보안 검증을 끄는 게 아니라, 이미 내린 결정에 대한 중복 경고만 숨긴다)
warnings.filterwarnings("ignore", message="Unknown .* host key", module="paramiko")

_print_lock = threading.Lock()
_progress_lock = threading.Lock()
_progress = {"done": 0, "total": 0}


def log(message):
    """스레드 출력이 섞이지 않도록 락을 걸고 한 번에 찍는다."""
    with _print_lock:
        print(message, flush=True)


def get_checks(device):
    """
    한 호스트가 받을 점검 종류 목록.
    checks: ["unix", "web_application"] 형식을 기본으로 하되,
    예전 형식(type: "unix")도 그대로 읽는다.
    """
    checks = device.get('checks')
    if isinstance(checks, str):
        return [checks]
    if checks:
        return list(checks)
    if device.get('type'):
        return [device['type']]
    return []


def select_targets(device_list):
    """전체를 점검할지, 특정 호스트 하나만 점검할지 고른다."""
    print("\n--- 점검할 장비를 선택하세요 ---")
    print("0. 전체 장비 점검")
    for idx, device in enumerate(device_list):
        checks = ", ".join(get_checks(device))
        print(f"{idx + 1}. {device['hostname']} ({device['ip']}) [{checks}]")

    while True:
        answer = input("번호 선택 (0=전체): ").strip()
        if not answer.isdigit():
            print("  숫자를 입력하세요.")
            continue

        choice = int(answer)
        if choice == 0:
            jobs = sum(len(get_checks(d)) for d in device_list)
            print(f"[알림] 전체 {len(device_list)}대 / 점검 {jobs}건을 실행합니다.")
            return device_list
        if 1 <= choice <= len(device_list):
            target = device_list[choice - 1]
            checks = ", ".join(get_checks(target))
            print(f"[알림] {target['hostname']} ({target['ip']}) 만 점검합니다. [{checks}]")
            return [target]

        print(f"  0 ~ {len(device_list)} 사이로 입력하세요.")


def validate_devices(device_list):
    """
    스레드를 만들기 전에 필수 항목을 미리 검증한다.
    스레드 안에서 input()/getpass() 가 호출되면 그대로 멈춰버리므로,
    누락된 값은 여기서 걸러 낸다.
    """
    valid, skipped = [], []

    for device in device_list:
        problems = []
        checks = get_checks(device)

        if not checks:
            problems.append("checks 가 비어 있음")

        for check in checks:
            if check not in VALIDATOR_MAP:
                problems.append(f"지원하지 않는 점검 종류: {check}")

        conn_info = device.get('conn_info') or {}
        for key in ('port', 'user', 'password'):
            if conn_info.get(key) in (None, ""):
                problems.append(f"conn_info.{key} 누락")

        if 'virtual' in checks:
            platform = (device.get('virt_info') or {}).get('platform', '')
            if str(platform).lower() not in ('esxi', 'xenserver'):
                problems.append("virt_info.platform 이 esxi/xenserver 가 아님")

        if 'web_application' in checks:
            if not (device.get('web_info') or {}).get('path'):
                problems.append("web_info.path 누락")

        if problems:
            skipped.append((device, problems))
        else:
            valid.append(device)

    return valid, skipped


def run_check(device, check_type, lines):
    """호스트 하나에 점검 종류 하나를 수행한다."""
    ip = device['ip']
    validator_class = VALIDATOR_MAP[check_type]
    requires_ssh = getattr(validator_class, 'requires_ssh', True)
    sql_mgr = SqlManager(ip, TABLE_MAP.get(check_type, "other_table"))
    counts = defaultdict(int)
    conn = None

    try:
        conn = SSHConnection(ip, device['conn_info']['port'],
                             device['conn_info']['user'],
                             device['conn_info']['password'],
                             check_type, device)

        if requires_ssh:
            conn.connect()
            lines.append(f"    [{check_type}] SSH 접속 성공")
        else:
            lines.append(f"    [{check_type}] 점검 모듈이 자체 연결 관리")

        validator = validator_class(conn)

        for code, meta in validator.check_list.items():
            func = getattr(validator, code, None)
            if func is None:
                continue

            try:
                status, reason = func()
            except Exception as exc:
                status = "오류"
                reason = f"{code} 실행 중 예외: {exc.__class__.__name__}: {exc}"

            # DB 에는 메서드명(u_01)이 아니라 점검 코드(U-01)를 넣는다
            item_code = meta.get('code', code.upper().replace('_', '-'))
            sql_mgr.record_result(item_code, meta['title'], status, reason)
            counts[status] += 1

        saved = sql_mgr.push_to_db(DB_CONFIG)
        summary = ", ".join(f"{k} {v}" for k, v in sorted(counts.items()))
        lines.append(f"    [{check_type}] 점검 {sum(counts.values())}건 ({summary}) "
                     f"-> {TABLE_MAP.get(check_type)} {saved}건 저장")
        return True, dict(counts)

    except Exception as exc:
        lines.append(f"    [{check_type}] 실패: {exc.__class__.__name__}: {exc}")
        return False, dict(counts)

    finally:
        if conn is not None and requires_ssh:
            try:
                conn.disconnect()
            except Exception:
                pass


def check_host(device):
    """
    호스트 1대를 점검한다. 스레드 1개가 이 함수 하나를 통째로 담당한다.
    한 호스트에 점검 종류가 여러 개면 순차로 돌린다
    (같은 장비에 동시에 여러 세션을 붙이지 않기 위해).
    출력은 모아뒀다가 끝날 때 한 번에 찍는다.
    """
    hostname, ip = device['hostname'], device['ip']
    checks = get_checks(device)

    lines = [f"\n>>> {hostname} ({ip})  점검 {len(checks)}건: {', '.join(checks)}"]
    started = time.time()
    total_counts = defaultdict(int)
    failed = []

    # 동시 접속이 몰려 sshd MaxStartups 에 걸리는 것을 피하려 살짝 흩뜨린다
    time.sleep(random.uniform(0, 1.0))

    for check_type in checks:
        ok, counts = run_check(device, check_type, lines)
        if not ok:
            failed.append(check_type)
        for status, n in counts.items():
            total_counts[status] += n

    elapsed = time.time() - started
    with _progress_lock:
        _progress["done"] += 1
        position = f"{_progress['done']}/{_progress['total']}"

    lines.append(f"    소요 {elapsed:.1f}초  (완료 {position})")
    log("\n".join(lines))

    return {"hostname": hostname, "ip": ip, "checks": checks,
            "failed": failed, "ok": not failed,
            "counts": dict(total_counts), "elapsed": elapsed,
            "log": lines}


def main():
    with open('device_list.json', 'r', encoding='utf-8') as f:
        all_devices = json.load(f)

    device_list = select_targets(all_devices)

    db_servers = [d for d in all_devices if 'db' in d['hostname'].lower()]
    print("\n--- 결과 저장할 DB 서버를 선택하세요 ---")
    for idx, db in enumerate(db_servers):
        print(f"{idx + 1}. {db['hostname']} ({db['ip']})")

    db_choice = int(input("번호 선택: ")) - 1
    DB_CONFIG['host'] = db_servers[db_choice]['ip']
    print(f"[알림] 모든 결과는 {db_servers[db_choice]['hostname']} "
          f"({db_servers[db_choice]['ip']}) 로 저장됩니다.")

    # --- 여기까지가 대화형 구간. 이후로는 입력을 받지 않는다 ---

    device_list, skipped = validate_devices(device_list)
    for device, problems in skipped:
        print(f"[건너뜀] {device.get('hostname')}: {', '.join(problems)}")

    if not device_list:
        print("점검할 장비가 없습니다.")
        return

    # 스키마 준비는 스레드 시작 전에 테이블 종류마다 한 번씩만
    tables = {TABLE_MAP.get(c, "other_table")
              for d in device_list for c in get_checks(d)}
    print(f"\n[스키마] 테이블 {len(tables)}종 준비: {', '.join(sorted(tables))}")
    SqlManager.setup_schema(DB_CONFIG, tables)

    _progress["total"] = len(device_list)
    workers = min(MAX_WORKERS, len(device_list))
    jobs = sum(len(get_checks(d)) for d in device_list)
    print(f"[실행] 호스트 {len(device_list)}대 / 점검 {jobs}건을 "
          f"스레드 {workers}개로 병렬 처리합니다.")

    started = time.time()
    results = []

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(check_host, d): d for d in device_list}
        try:
            for future in as_completed(futures, timeout=HOST_DEADLINE):
                device = futures[future]
                try:
                    results.append(future.result())
                except Exception as exc:
                    log(f"\n>>> {device['hostname']} 처리 실패: "
                        f"{exc.__class__.__name__}: {exc}")
                    results.append({"hostname": device['hostname'], "ip": device['ip'],
                                    "checks": get_checks(device), "failed": get_checks(device),
                                    "ok": False, "counts": {}, "elapsed": 0})
        except KeyboardInterrupt:
            print("\n[중단] 사용자 요청으로 중단합니다. 실행 중인 호스트는 마무리됩니다.")
        except TimeoutError:
            print(f"\n[시간초과] {HOST_DEADLINE}초를 넘겨 미완료 호스트를 남기고 종료합니다.")

    elapsed = time.time() - started
    success = [r for r in results if r['ok']]
    failed = [r for r in results if not r['ok']]

    print("\n" + "=" * 60)
    print(f"완료: {len(success)}대 성공 / {len(failed)}대 실패 / 전체 {elapsed:.1f}초")
    for r in failed:
        print(f"  실패 {r['hostname']}({r['ip']}): {', '.join(r['failed'])}")
    total_items = sum(sum(r['counts'].values()) for r in results)
    vulnerable = sum(r['counts'].get('취약', 0) for r in results)
    print(f"점검 항목 {total_items}건 중 취약 {vulnerable}건")
    print("=" * 60)


if __name__ == "__main__":
    main()
