"""
automation_module.py
====================

Cisco 라우터/스위치 자동화와 Linux 서버 초기 설정/웹 서버 설정을 한 파일로
정리한 모듈입니다.

정리 원칙
---------
1. 노트북 셀에 흩어져 있던 함수들을 기능별 섹션으로 묶었습니다.
2. 같은 이름으로 서로 덮어쓰던 함수는 충돌하지 않도록 정리했습니다.
   - Cisco 장비 명령 실행: run_cmd(), run_conf()
   - Linux 서버 SSH 명령 실행: run_ssh_commands()
3. import 시 바로 실행되던 메뉴/테스트 코드는 제거하고, 파일을 직접 실행할 때만
   `if __name__ == "__main__":` 분기 아래의 메뉴가 뜨도록 구성했습니다.
4. JSON 백업/복구 로직은 공통 helper를 사용하여 빈 파일/없는 파일 처리 오류를 줄였습니다.

필요 패키지
-----------
- Cisco 장비 자동화: netmiko
- Linux 서버 자동화: paramiko

주의
----
이 모듈은 네트워크 장비와 서버에 실제 설정 명령을 전송합니다.
실습 환경이 아닌 운영 환경에서는 명령어와 대상 IP를 반드시 검토한 뒤 실행하세요.
"""

from __future__ import annotations

import base64
import json
import os
import re
import shlex
from pathlib import Path
from pprint import pprint
from typing import Any, Sequence

# -----------------------------------------------------------------------------
# 선택 의존성 import
# -----------------------------------------------------------------------------
# netmiko와 paramiko는 실행 환경에 설치되어 있지 않을 수 있습니다.
# 모듈 import 자체가 실패하지 않도록 try/except로 감싸고, 실제 기능 호출 시점에
# 명확한 에러 메시지를 내도록 구성했습니다.
try:
    from netmiko import BaseConnection, ConnectHandler
except ImportError:  # pragma: no cover - 의존성이 없는 환경에서도 파일 검사용으로 import 가능하게 함
    ConnectHandler = None  # type: ignore[assignment]

    class BaseConnection:  # type: ignore[no-redef]
        """netmiko가 없을 때 타입 힌트용으로만 사용하는 대체 클래스입니다."""

        pass

try:
    import paramiko
except ImportError:  # pragma: no cover - 의존성이 없는 환경에서도 파일 검사용으로 import 가능하게 함
    paramiko = None  # type: ignore[assignment]


# -----------------------------------------------------------------------------
# 공통 타입/상수
# -----------------------------------------------------------------------------
CommandList = Sequence[tuple[str, str]]

# Rocky Linux 초기 설정에서 사용할 명령 목록입니다.
# 각 원소는 (설명, 실제 명령어) 구조입니다.
ROCKY_INIT_COMMANDS: CommandList = [
    ("필수 패키지 설치", "dnf -y install epel-release wget vim libstdc++ tar gzip"),
    ("expect 설치", "dnf makecache && dnf install -y expect"),
    ("CRB 레포지토리 활성화", "dnf config-manager --set-enabled crb"),
    ("시스템 업데이트 및 업그레이드", "dnf -y update && dnf -y upgrade"),
    ("SELinux 비활성화", "sed -i 's/^SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config && setenforce 0"),
    ("방화벽 중지", "systemctl disable --now firewalld"),
    ("Miniconda 다운로드", "wget https://www.ubiedu.co.kr/Miniconda3-latest-Linux-x86_64.sh -O /tmp/miniconda.sh"),
    ("Miniconda 무인 설치", "chmod u+x /tmp/miniconda.sh && /tmp/miniconda.sh -b -u -p /root/miniconda3"),
    ("Conda 초기화", "/root/miniconda3/bin/conda init bash"),
    ("환경변수 등록", "sed -i '$ a export PATH=$PATH:/root/miniconda3/bin' /etc/bashrc"),
    ("Conda 자동활성화 방지", "/root/miniconda3/bin/conda config --set auto_activate false"),
    ("Conda 약관 동의(Main)", "/root/miniconda3/bin/conda tos accept --override-channels --channel https://repo.anaconda.com/pkgs/main"),
    ("Conda 약관 동의(R)", "/root/miniconda3/bin/conda tos accept --override-channels --channel https://repo.anaconda.com/pkgs/r"),
    ("주피터 패키지 설치", "/root/miniconda3/bin/conda install jupyter notebook -y"),
    ("주피터 엔진 최종 확인", "/root/miniconda3/bin/pip install notebook"),
    (
        "주피터 비밀번호 설정(expect)",
        'expect -c "spawn /root/miniconda3/bin/jupyter notebook password; '
        'expect \\"Enter password:\\"; send \\"asd123!@\\r\\"; '
        'expect \\"Verify password:\\"; send \\"asd123!@\\r\\"; expect eof"',
    ),
    (
        "주피터 systemd 서비스 등록",
        """
cat > /etc/systemd/system/jupyter.service <<'EOF'
[Unit]
Description=Jupyter Notebook Service
After=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/root
ExecStart=/root/miniconda3/bin/jupyter notebook --allow-root --ip=0.0.0.0 --port=80 --no-browser
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
""".strip(),
    ),
    ("주피터 서비스 시작", "systemctl daemon-reload && systemctl enable --now jupyter"),
    (
        "Pip 및 라이브러리 설치",
        "/root/miniconda3/bin/conda install pip -y && "
        "/root/miniconda3/bin/pip install --upgrade pip && "
        "/root/miniconda3/bin/pip install paramiko",
    ),
    (
        "커널 등록",
        "/root/miniconda3/bin/python3 -m pip install ipykernel && "
        "/root/miniconda3/bin/python3 -m ipykernel install --user --name system-python --display-name 'Python 3 (System)'",
    ),
    ("임시 파일 삭제", "rm -f /tmp/miniconda.sh"),
]


# =============================================================================
# 1. 공통 유틸리티
# =============================================================================

def _ensure_netmiko() -> None:
    """netmiko가 설치되어 있는지 확인합니다."""
    if ConnectHandler is None:
        raise RuntimeError("netmiko가 설치되어 있지 않습니다. `pip install netmiko` 후 다시 실행하세요.")


def _ensure_paramiko() -> None:
    """paramiko가 설치되어 있는지 확인합니다."""
    if paramiko is None:
        raise RuntimeError("paramiko가 설치되어 있지 않습니다. `pip install paramiko` 후 다시 실행하세요.")


def _load_json_file(json_path: str | os.PathLike[str]) -> dict[str, Any]:
    """
    JSON 파일을 dict로 읽어옵니다.

    - 파일이 없으면 빈 dict를 반환합니다.
    - 파일은 있지만 0 byte이면 빈 dict를 반환합니다.
    - 내용이 깨진 JSON이면 json.JSONDecodeError가 발생하므로 호출부에서 원인을 확인할 수 있습니다.
    """
    path = Path(json_path)
    if not path.exists() or path.stat().st_size == 0:
        return {}

    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError(f"JSON 최상위 구조는 dict여야 합니다: {path}")

    return data


def _save_json_file(json_path: str | os.PathLike[str], data: dict[str, Any]) -> None:
    """
    dict 데이터를 JSON 파일로 저장합니다.

    상위 디렉터리가 없으면 자동으로 생성하여, 백업 경로를 새로 지정해도 오류가
    덜 나도록 했습니다.
    """
    path = Path(json_path)
    if path.parent and str(path.parent) != ".":
        path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


def _prefix_to_wildcard(ip_prefix: str) -> str:
    """
    `IP/Prefix` 형식을 Cisco ACL용 `IP wildcard-mask` 형식으로 변환합니다.

    예)
    - 입력:  `192.168.10.0/24`
    - 반환: `192.168.10.0 0.0.0.255`
    """
    ip, prefix_text = ip_prefix.split("/", maxsplit=1)
    prefix = int(prefix_text)

    if prefix < 0 or prefix > 32:
        raise ValueError("prefix는 0 이상 32 이하의 값이어야 합니다.")

    subnet = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    subnet_mask_octets = [
        (subnet >> 24) & 255,
        (subnet >> 16) & 255,
        (subnet >> 8) & 255,
        subnet & 255,
    ]
    wildcard_octets = [255 - octet for octet in subnet_mask_octets]
    return f"{ip} {'.'.join(map(str, wildcard_octets))}"


def _wildcard_(ip_prefix: str) -> str:
    """
    기존 노트북 코드와의 호환성을 위한 별칭입니다.

    새 코드에서는 의미가 더 분명한 _prefix_to_wildcard() 사용을 권장합니다.
    """
    return _prefix_to_wildcard(ip_prefix)


def _wildcard_to_prefix(wildcard_mask: str) -> int:
    """Cisco wildcard mask를 prefix 길이로 변환합니다."""
    host_bits = 0
    for octet in wildcard_mask.split("."):
        host_bits += bin(int(octet)).count("1")
    return 32 - host_bits


def _shell_quote(value: str) -> str:
    """리눅스 쉘 명령어에 들어갈 문자열을 안전하게 감쌉니다."""
    return shlex.quote(value)


def _remote_write_file_command(content: str, remote_path: str) -> str:
    """
    원격 서버에 파일 내용을 안전하게 쓰는 쉘 명령을 생성합니다.

    단순 echo는 따옴표, 줄바꿈, 특수문자가 포함된 HTML을 깨뜨릴 수 있습니다.
    그래서 내용을 base64로 인코딩한 뒤 원격에서 디코딩하여 파일로 저장합니다.
    """
    encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
    return f"printf %s {_shell_quote(encoded)} | base64 -d > {_shell_quote(remote_path)}"


# =============================================================================
# 2. Cisco 장비 공통 연결/명령 실행 함수
# =============================================================================

def get_con(
    ip: str,
    username: str = "root",
    password: str = "cisco",
    port: int = 22,
    device_type: str = "cisco_ios",
) -> BaseConnection:
    """
    Cisco 라우터/스위치에 SSH로 접속하고 enable 모드까지 진입합니다.

    Parameters
    ----------
    ip:
        접속할 Cisco 장비 IP 주소입니다.
    username, password:
        장비에 설정된 로컬 로그인 계정입니다.
    port:
        SSH 포트입니다. 기본값은 22입니다.
    device_type:
        netmiko 장비 타입입니다. Cisco IOS 장비는 보통 `cisco_ios`를 사용합니다.
    """
    _ensure_netmiko()

    con = ConnectHandler(  # type: ignore[misc]
        **{
            "device_type": device_type,
            "host": ip,
            "username": username,
            "password": password,
            "port": port,
        }
    )
    con.enable()
    return con


def run_cmd(con: BaseConnection, cmd: str) -> str:
    """Cisco 장비의 일반 EXEC 모드에서 명령어 1개를 실행하고 결과 문자열을 반환합니다."""
    return con.send_command(cmd)


def run_conf(con: BaseConnection, cmds: str | Sequence[str]) -> str:
    """
    Cisco 장비의 configure terminal 모드에서 설정 명령을 실행합니다.

    netmiko의 send_config_set()은 문자열 1개 또는 문자열 리스트를 받을 수 있으므로
    그대로 전달합니다.
    """
    return con.send_config_set(cmds)


def run_vlan(con: BaseConnection, cmds: Sequence[str]) -> str:
    """
    Cisco 구형 IOS의 `vlan database` 모드에서 VLAN/VTP 관련 명령을 실행합니다.

    일부 실습 장비(c3745 + EtherSwitch 모듈 등)는 VLAN 설정을 `vlan database` 모드에서
    처리하는 경우가 있어 원본 노트북의 동작을 유지했습니다.
    """
    output = ""

    # vlan database 모드 진입 후 프롬프트가 `(vlan)#` 형태가 될 때까지 대기합니다.
    output += con.send_command("vlan database", expect_string=r"vlan\)")

    for cmd in cmds:
        output += con.send_command(cmd, expect_string=r"vlan\)")

    # exit 시 VLAN database 변경사항이 반영됩니다.
    output += con.send_command("exit", expect_string=r"#")
    return output


# =============================================================================
# 3. Cisco 장비 정보/인터페이스 조회 함수
# =============================================================================

def get_device_role(con: BaseConnection) -> str:
    """
    장비 모델/모듈 정보를 확인하여 `SWITCH`, `ROUTER`, `UNKNOWN` 중 하나를 반환합니다.

    원본 노트북의 판정 기준을 유지했습니다.
    - c3745 + EtherSwitch/ESW 모듈: SWITCH
    - c3745 단독: ROUTER
    - c7200: ROUTER
    """
    version_out = run_cmd(con, "show version")
    inventory_out = run_cmd(con, "show inventory")

    if "3745" in version_out:
        if "ESW" in inventory_out or "EtherSwitch" in inventory_out:
            return "SWITCH"
        return "ROUTER"

    if "7200" in version_out:
        return "ROUTER"

    return "UNKNOWN"


def get_host_name(con: BaseConnection) -> str:
    """netmiko 연결 객체의 base_prompt 값을 장비 이름으로 반환합니다."""
    return con.base_prompt


def get_interface_brief(con: BaseConnection) -> dict[str, dict[str, str]]:
    """
    `show ip interface brief` 결과를 인터페이스명 기준 dict로 변환합니다.

    반환 예시
    --------
    {
        "FastEthernet0/0": {
            "ip_address": "192.168.1.1",
            "ok": "YES",
            "method": "manual",
            "status": "up",
            "protocol": "up"
        }
    }
    """
    txt = run_cmd(con, "show ip interface brief")
    interface_dict: dict[str, dict[str, str]] = {}

    for line in txt.strip().splitlines():
        if line.startswith("Interface") or not line.strip():
            continue

        parts = line.split()
        if len(parts) < 6:
            continue

        interface_name = parts[0]
        interface_dict[interface_name] = {
            "ip_address": parts[1],
            "ok": parts[2],
            "method": parts[3],
            "status": " ".join(parts[4:-1]),
            "protocol": parts[-1],
        }

    return interface_dict


# =============================================================================
# 4. Cisco STP 함수
# =============================================================================

def switch_stp_config(con: BaseConnection, vlan: str | int, priority: str | int) -> str:
    """
    특정 VLAN의 STP priority를 설정합니다.

    Cisco STP priority는 4096 단위 값이어야 하므로 함수 내부에서 검증합니다.
    일반적인 범위는 0~61440입니다.
    """
    priority_value = int(priority)
    if priority_value < 0 or priority_value > 61440 or priority_value % 4096 != 0:
        return "STP 설정 실패: priority는 0~61440 범위의 4096 배수여야 합니다."

    cmds = [f"spanning-tree vlan {vlan} priority {priority_value}"]
    return run_conf(con, cmds)


def get_stp_info(con: BaseConnection) -> str:
    """스위치의 STP 요약 정보를 문자열로 반환합니다."""
    return run_cmd(con, "show spanning-tree brief")


# =============================================================================
# 5. Cisco VTP 함수
# =============================================================================

def switch_vtp_config(
    con: BaseConnection,
    domain_name: str,
    password: str,
    vtp_mode: str = "server",
) -> str:
    """
    VTP mode/domain/password를 설정합니다.

    원본 노트북은 `vlan database` 모드에서 VTP 명령을 실행했으므로 run_vlan()을 사용합니다.
    실습 IOS 버전에 따라 global config 모드가 필요한 경우에는 명령 실행 방식을 조정하세요.
    """
    cmds = [
        f"vtp {vtp_mode}",
        f"vtp domain {domain_name}",
        f"vtp password {password}",
    ]
    return run_vlan(con, cmds)


def get_vtp_status(con: BaseConnection) -> str:
    """`show vtp status` 결과를 문자열로 반환합니다."""
    return run_cmd(con, "show vtp status")


def get_vtp_config(con: BaseConnection) -> dict[str, str]:
    """
    VTP 상태 출력에서 domain/mode를 파싱해 dict로 반환합니다.

    Cisco 장비는 VTP password를 평문으로 보여주지 않으므로 password 값은 기본적으로
    `"null"`로 저장합니다. 백업 시 실제 비밀번호를 알고 있으면 store_vtp_config()의
    custom_password 인자로 넘겨 저장할 수 있습니다.
    """
    vtp_status = get_vtp_status(con)
    vtp_domain = "Unknown"
    vtp_mode = "server"

    for line in vtp_status.splitlines():
        line = line.strip()
        if "VTP Domain Name" in line:
            parts = line.split(":", maxsplit=1)
            if len(parts) > 1:
                vtp_domain = parts[1].strip()
        elif "VTP Operating Mode" in line:
            parts = line.split(":", maxsplit=1)
            if len(parts) > 1:
                vtp_mode = parts[1].strip().lower()

    return {"domain": vtp_domain, "mode": vtp_mode, "password": "null"}


def store_vtp_config(
    con: BaseConnection,
    vtp_json_path: str,
    custom_password: str | None = None,
) -> dict[str, Any]:
    """
    현재 스위치의 VTP 설정 정보를 JSON 파일에 백업합니다.

    저장 구조
    --------
    {
        "SW1": {
            "domain": "example",
            "mode": "server",
            "password": "실제비밀번호 또는 null"
        }
    }
    """
    vtp_info = get_vtp_config(con)
    if custom_password:
        vtp_info["password"] = custom_password

    data = _load_json_file(vtp_json_path)
    data[get_host_name(con)] = vtp_info
    _save_json_file(vtp_json_path, data)
    return data


def restore_vtp_config(con: BaseConnection, vtp_json_path: str) -> str:
    """
    JSON 파일에 백업된 VTP 설정을 현재 스위치에 복구합니다.

    password가 `"null"`이거나 비어 있으면 password 명령은 생략합니다.
    """
    data = _load_json_file(vtp_json_path)
    device_name = get_host_name(con)
    config = data.get(device_name)

    if not config:
        return f"VTP 복구 실패: {device_name} 항목이 JSON 파일에 없습니다."

    cmds = [
        f"vtp {config.get('mode', 'server')}",
        f"vtp domain {config.get('domain', 'Unknown')}",
    ]
    password = config.get("password")
    if password and password != "null":
        cmds.append(f"vtp password {password}")

    return run_vlan(con, cmds)


# =============================================================================
# 6. Cisco Inter-VLAN 함수
# =============================================================================

def inter_vlan_config(
    con: BaseConnection,
    interface: str,
    vlan: str | int,
    ip: str,
    netmask: str,
) -> str:
    """
    라우터 서브인터페이스 기반 Router-on-a-stick Inter-VLAN 설정을 적용합니다.

    예)
    - interface: FastEthernet0/0
    - vlan: 10
    - 결과: FastEthernet0/0.10 서브인터페이스 생성 후 dot1Q 10 설정
    """
    cmds = [
        f"interface {interface}.{vlan}",
        f"encapsulation dot1Q {vlan}",
        f"ip address {ip} {netmask}",
        "exit",
        f"interface {interface}",
        "no shutdown",
    ]
    return run_conf(con, cmds)


def get_vlan_interfaces(con: BaseConnection) -> dict[str, list[dict[str, str]]]:
    """
    running-config에서 서브인터페이스(VLAN 인터페이스) 정보를 추출합니다.

    반환 구조
    --------
    {
        "R1": [
            {
                "interface": "FastEthernet0/0.10",
                "vlan": "10",
                "ip": "10.0.10.1",
                "netmask": "255.255.255.0"
            }
        ]
    }
    """
    raw_config = run_cmd(con, "show running-config")
    router_name = get_host_name(con) or "Unknown_Router"
    router_backup: dict[str, list[dict[str, str]]] = {router_name: []}

    current_iface: str | None = None

    for raw_line in raw_config.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        if line.startswith("hostname "):
            # base_prompt와 running-config의 hostname이 다를 때 running-config 값을 우선합니다.
            router_name = line.split()[1]
            router_backup.setdefault(router_name, router_backup.pop(next(iter(router_backup))))
            continue

        # 서브인터페이스 구역 진입 예: interface FastEthernet0/0.10
        if line.startswith("interface ") and "." in line:
            current_iface = line.split()[1]
            vlan_id = current_iface.split(".")[-1]
            router_backup[router_name].append(
                {"interface": current_iface, "vlan": vlan_id, "ip": "", "netmask": ""}
            )
            continue

        # 물리 인터페이스 또는 다른 interface 구역이 나오면 서브인터페이스 추적을 중단합니다.
        if line.startswith("interface ") and "." not in line:
            current_iface = None
            continue

        if current_iface and line.startswith("ip address "):
            parts = line.split()
            if len(parts) >= 4:
                router_backup[router_name][-1]["ip"] = parts[2]
                router_backup[router_name][-1]["netmask"] = parts[3]

    return router_backup


def store_vlan_interfaces(con: BaseConnection, vlan_int_setting_json_path: str) -> dict[str, list[dict[str, str]]]:
    """현재 라우터의 Inter-VLAN 서브인터페이스 정보를 JSON 파일에 백업합니다."""
    vlan_int_config = get_vlan_interfaces(con)
    data = _load_json_file(vlan_int_setting_json_path)
    data.update(vlan_int_config)
    _save_json_file(vlan_int_setting_json_path, data)
    return vlan_int_config


def restore_vlan_interfaces(con: BaseConnection, vlan_int_setting_json_path: str) -> list[dict[str, str]]:
    """
    JSON 파일에 백업된 Inter-VLAN 서브인터페이스 정보를 현재 라우터에 복구합니다.

    원본 노트북에는 백업 함수만 있었지만, 백업/복구 흐름을 맞추기 위해 복구 함수도
    함께 정리했습니다.
    """
    data = _load_json_file(vlan_int_setting_json_path)
    device_name = get_host_name(con)
    configs = data.get(device_name, [])

    if not configs:
        return []

    cmds: list[str] = []
    for info in configs:
        interface = info.get("interface", "")
        vlan = info.get("vlan", "")
        ip = info.get("ip", "")
        netmask = info.get("netmask", "")

        if not all([interface, vlan, ip, netmask]):
            continue

        # 백업에는 FastEthernet0/0.10처럼 서브인터페이스명이 저장되어 있으므로 그대로 사용합니다.
        cmds.extend(
            [
                f"interface {interface}",
                f"encapsulation dot1Q {vlan}",
                f"ip address {ip} {netmask}",
                "no shutdown",
            ]
        )

    if cmds:
        run_conf(con, cmds)

    return configs


# =============================================================================
# 7. Cisco 라우팅 테이블 함수
# =============================================================================

def get_routing_table(con: BaseConnection) -> list[dict[str, str]]:
    """
    running-config에 설정된 정적 라우팅 정보를 리스트로 반환합니다.

    `show run | include ^ip route` 결과를 대상으로 하므로 동적 라우팅 프로토콜로
    학습된 경로는 포함하지 않습니다.
    """
    table_raw = run_cmd(con, "show run | include ^ip route")
    route_list: list[dict[str, str]] = []

    # 기본 형식: ip route <NID> <Netmask> <Gateway>
    pattern = r"ip route\s+(\S+)\s+(\S+)\s+(\S+)"
    for nid, netmask, gateway in re.findall(pattern, table_raw):
        route_list.append({"NID": nid, "Netmask": netmask, "Gateway": gateway})

    return route_list


def add_route_info(con: BaseConnection, nid: str, netmask: str, gateway: str) -> str:
    """정적 라우팅 경로 1개를 추가합니다."""
    return run_conf(con, f"ip route {nid} {netmask} {gateway}")


def add_rotue_info(con: BaseConnection, nid: str, netmask: str, gateway: str) -> str:
    """
    기존 노트북의 오타 함수명(add_rotue_info)을 위한 호환성 wrapper입니다.

    새 코드에서는 add_route_info()를 사용하세요.
    """
    return add_route_info(con, nid, netmask, gateway)


def store_routing_table(con: BaseConnection, routing_table_json_path: str) -> list[dict[str, str]]:
    """현재 라우터의 정적 라우팅 테이블을 JSON 파일에 백업합니다."""
    routing_table = get_routing_table(con)
    data = _load_json_file(routing_table_json_path)
    data[get_host_name(con)] = routing_table
    _save_json_file(routing_table_json_path, data)
    return routing_table


def restore_routing_table(con: BaseConnection, routing_table_json_path: str) -> list[dict[str, str]]:
    """JSON 파일에서 현재 장비 이름에 해당하는 정적 라우팅 정보를 복구합니다."""
    data = _load_json_file(routing_table_json_path)
    device_name = get_host_name(con)
    route_infos = data.get(device_name, [])

    cmds = [
        f"ip route {info['NID']} {info['Netmask']} {info['Gateway']}"
        for info in route_infos
        if all(key in info for key in ("NID", "Netmask", "Gateway"))
    ]

    if cmds:
        run_conf(con, cmds)

    return route_infos


# =============================================================================
# 8. Cisco DHCP 함수
# =============================================================================

def router_dhcp_config(
    con: BaseConnection,
    pool_name: str,
    nid: str,
    subnet_mask: str,
    gateway_ip: str,
    exclude_ip_start: str,
    exclude_ip_end: str,
    dns_server_ip: str = "8.8.8.8",
) -> str:
    """라우터를 DHCP 서버로 설정합니다."""
    cmds = [
        f"ip dhcp excluded-address {exclude_ip_start} {exclude_ip_end}",
        f"ip dhcp pool {pool_name}",
        f"network {nid} {subnet_mask}",
        f"dns-server {dns_server_ip}",
        f"default-router {gateway_ip}",
    ]
    return run_conf(con, cmds)


def switch_dhcp_config(
    con: BaseConnection,
    pool_name: str,
    nid: str,
    subnet_mask: str,
    gateway_ip: str,
    exclude_ip_start: str,
    exclude_ip_end: str,
    dns_server_ip: str = "8.8.8.8",
) -> str:
    """스위치를 DHCP 서버로 설정합니다. 스위치이므로 service dhcp 명령을 포함합니다."""
    cmds = [
        f"ip dhcp excluded-address {exclude_ip_start} {exclude_ip_end}",
        "service dhcp",
        f"ip dhcp pool {pool_name}",
        f"network {nid} {subnet_mask}",
        f"dns-server {dns_server_ip}",
        f"default-router {gateway_ip}",
    ]
    return run_conf(con, cmds)


def get_dhcp_info(con: BaseConnection) -> list[dict[str, Any]]:
    """
    running-config의 DHCP 설정을 파싱하여 리스트로 반환합니다.

    제외 주소(excluded-address)는 pool 바깥에 정의되므로, 설정에 나타난 모든 제외
    주소를 각 pool 정보에 포함시키는 원본 노트북 방식을 유지했습니다.
    """
    output = run_cmd(con, "show run | section dhcp").splitlines()
    all_pools: list[dict[str, Any]] = []
    current_pool: dict[str, Any] = {}
    excluded_list: list[dict[str, str]] = []

    for raw_line in output:
        line = raw_line.strip()
        if not line:
            continue

        if "excluded-address" in line:
            parts = line.split()
            if len(parts) >= 4:
                start = parts[3]
                end = parts[4] if len(parts) >= 5 else parts[3]
                excluded_list.append({"start": start, "end": end})
            continue

        if line.startswith("ip dhcp pool"):
            if current_pool:
                all_pools.append(current_pool)

            current_pool = {
                "Poolname": line.split()[-1],
                "NID": None,
                "Netmask": None,
                "Gateway": None,
                "Excluded_Addresses": list(excluded_list),
                "DNS_Server_IP": None,
            }
            continue

        if line.startswith("network") and current_pool:
            parts = line.split()
            if len(parts) >= 3:
                current_pool["NID"] = parts[1]
                current_pool["Netmask"] = parts[2]
        elif line.startswith("default-router") and current_pool:
            current_pool["Gateway"] = line.split()[-1]
        elif line.startswith("dns-server") and current_pool:
            current_pool["DNS_Server_IP"] = line.split()[-1]

    if current_pool:
        all_pools.append(current_pool)

    return all_pools


def store_dhcp_setting(con: BaseConnection, dhcp_setting_json_path: str) -> list[dict[str, Any]]:
    """현재 장비의 DHCP 설정을 JSON 파일에 백업합니다."""
    dhcp_info = get_dhcp_info(con)
    data = _load_json_file(dhcp_setting_json_path)
    data[get_host_name(con)] = dhcp_info
    _save_json_file(dhcp_setting_json_path, data)
    return dhcp_info


def restore_dhcp_setting(con: BaseConnection, dhcp_setting_json_path: str) -> list[dict[str, Any]]:
    """JSON 파일에서 현재 장비 이름에 해당하는 DHCP 설정을 복구합니다."""
    data = _load_json_file(dhcp_setting_json_path)
    device_name = get_host_name(con)
    dhcp_pools = data.get(device_name, [])

    if not dhcp_pools:
        return []

    role = get_device_role(con)
    cmds: list[str] = []

    # 스위치라면 DHCP 서비스 활성화가 필요합니다.
    if role == "SWITCH":
        cmds.append("service dhcp")

    # 제외 주소는 여러 pool에 중복 저장될 수 있으므로 set으로 중복 제거합니다.
    processed_excluded: set[tuple[str, str]] = set()
    for pool in dhcp_pools:
        for excluded in pool.get("Excluded_Addresses", []):
            start = excluded.get("start")
            end = excluded.get("end")
            if not start or not end:
                continue

            key = (start, end)
            if key not in processed_excluded:
                cmds.append(f"ip dhcp excluded-address {start} {end}")
                processed_excluded.add(key)

    for pool in dhcp_pools:
        pool_name = pool.get("Poolname")
        if not pool_name:
            continue

        cmds.append(f"ip dhcp pool {pool_name}")
        if pool.get("NID") and pool.get("Netmask"):
            cmds.append(f"network {pool['NID']} {pool['Netmask']}")
        if pool.get("Gateway"):
            cmds.append(f"default-router {pool['Gateway']}")
        if pool.get("DNS_Server_IP"):
            cmds.append(f"dns-server {pool['DNS_Server_IP']}")

    if cmds:
        run_conf(con, cmds)

    return dhcp_pools


# =============================================================================
# 9. Cisco NAT 함수
# =============================================================================

def router_pat_nat_config(
    con: BaseConnection,
    in_interface: str,
    out_interface: str,
    ip_and_netmask_prefix: str,
) -> str:
    """
    라우터에 PAT 방식 NAT를 설정합니다.

    ip_and_netmask_prefix는 `192.168.10.0/24`처럼 IP/Prefix 형식으로 입력합니다.
    내부에서 ACL wildcard mask로 변환합니다.
    """
    cmds = [
        f"interface {in_interface}",
        "ip nat inside",
        f"interface {out_interface}",
        "ip nat outside",
        f"access-list 1 permit {_prefix_to_wildcard(ip_and_netmask_prefix)}",
        f"ip nat inside source list 1 interface {out_interface} overload",
    ]
    return run_conf(con, cmds)


def router_static_nat_config(
    con: BaseConnection,
    in_interface: str,
    out_interface: str,
    in_addr: str,
    out_addr: str,
) -> str:
    """라우터에 static NAT를 설정합니다."""
    cmds = [
        f"interface {in_interface}",
        "ip nat inside",
        f"interface {out_interface}",
        "ip nat outside",
        f"ip nat inside source static {in_addr} {out_addr}",
    ]
    return run_conf(con, cmds)


def router_dynamic_nat_config(
    con: BaseConnection,
    in_interface: str,
    out_interface: str,
    ip_and_netmask_prefix: str,
    nat_ip_pool_name: str,
    nat_ip_pool_start_ip: str,
    nat_ip_pool_end_ip: str,
    nat_ip_pool_netmask: str,
) -> str:
    """라우터에 pool 기반 dynamic NAT를 설정합니다."""
    cmds = [
        f"interface {in_interface}",
        "ip nat inside",
        f"interface {out_interface}",
        "ip nat outside",
        f"ip nat pool {nat_ip_pool_name} {nat_ip_pool_start_ip} {nat_ip_pool_end_ip} netmask {nat_ip_pool_netmask}",
        f"access-list 1 permit {_prefix_to_wildcard(ip_and_netmask_prefix)}",
        f"ip nat inside source list 1 pool {nat_ip_pool_name}",
    ]
    return run_conf(con, cmds)


def get_nat_pat_config(con: BaseConnection) -> dict[str, str]:
    """
    현재 라우터의 PAT NAT 설정 정보를 조회합니다.

    반환 값은 백업/복구에 맞춰 다음 키를 사용합니다.
    - IN_Interface
    - OUT_Interface
    - IP_Netmask_Prefix
    """
    nat_stats = run_cmd(con, "show ip nat statistics")
    acl_output = run_cmd(con, "show access-lists")

    in_interface = ""
    out_interface = ""

    nat_lines = nat_stats.splitlines()
    for index, raw_line in enumerate(nat_lines):
        line = raw_line.strip()
        if "Inside interfaces:" in line and index + 1 < len(nat_lines):
            in_interface = nat_lines[index + 1].strip()
        elif "Outside interfaces:" in line and index + 1 < len(nat_lines):
            out_interface = nat_lines[index + 1].strip()

    ip_and_prefix = ""

    # Cisco 출력 예: permit 192.168.1.0, wildcard bits 0.0.0.255
    acl_pattern = re.compile(r"permit\s+(\d+\.\d+\.\d+\.\d+).*?wildcard bits\s+(\d+\.\d+\.\d+\.\d+)")
    match = acl_pattern.search(acl_output)
    if match:
        ip = match.group(1)
        wildcard = match.group(2)
        prefix = _wildcard_to_prefix(wildcard)
        ip_and_prefix = f"{ip}/{prefix}"

    return {
        "IN_Interface": in_interface,
        "OUT_Interface": out_interface,
        "IP_Netmask_Prefix": ip_and_prefix,
    }


def store_nat_pat_setting(con: BaseConnection, nat_setting_json_path: str) -> dict[str, str]:
    """현재 라우터의 PAT NAT 설정 정보를 JSON 파일에 백업합니다."""
    nat_config = get_nat_pat_config(con)
    data = _load_json_file(nat_setting_json_path)
    data[get_host_name(con)] = nat_config
    _save_json_file(nat_setting_json_path, data)
    return nat_config


def restore_nat_pat_setting(con: BaseConnection, nat_setting_json_path: str) -> str:
    """
    JSON 파일에 백업된 PAT NAT 설정을 현재 라우터에 복구합니다.

    원본 노트북의 restore_nat_pat_setting()에는 data/device_name 사용 순서 오류가 있었고,
    여기서는 해당 오류를 수정했습니다.
    """
    data = _load_json_file(nat_setting_json_path)
    device_name = get_host_name(con)
    config = data.get(device_name)

    if not config:
        return f"NAT 복구 실패: {device_name} 항목이 JSON 파일에 없습니다."

    required_keys = ("IN_Interface", "OUT_Interface", "IP_Netmask_Prefix")
    if not all(config.get(key) for key in required_keys):
        return f"NAT 복구 실패: {device_name} 항목의 필수 값이 비어 있습니다."

    return router_pat_nat_config(
        con,
        in_interface=config["IN_Interface"],
        out_interface=config["OUT_Interface"],
        ip_and_netmask_prefix=config["IP_Netmask_Prefix"],
    )


# =============================================================================
# 10. Linux 서버 공통 SSH 함수
# =============================================================================

def get_ssh_client(
    ip: str,
    password: str,
    username: str = "root",
    port: int = 22,
    timeout: int = 10,
) -> paramiko.SSHClient:
    """
    paramiko SSHClient를 생성하고 대상 서버에 접속합니다.

    Cisco 장비 접속 함수 get_con()과 구분하기 위해 이 함수는 Linux 서버 자동화
    섹션에서만 사용합니다.
    """
    _ensure_paramiko()

    client = paramiko.SSHClient()  # type: ignore[union-attr]
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # type: ignore[union-attr]
    print(f"\n{username}@{ip}:{port}에 SSH 접속 시도 중...")
    client.connect(hostname=ip, port=port, username=username, password=password, timeout=timeout)
    return client


def run_ssh_commands(client: paramiko.SSHClient, commands: CommandList) -> list[dict[str, str]]:
    """
    원격 Linux 서버에서 여러 쉘 명령을 순서대로 실행합니다.

    반환값은 각 명령의 설명/표준출력/표준에러를 담은 리스트입니다.
    출력은 원본 노트북처럼 콘솔에도 표시합니다.
    """
    results: list[dict[str, str]] = []

    for description, command in commands:
        print(f"\n[{description}] 시작...")
        _stdin, stdout, stderr = client.exec_command(command)

        stdout_text_parts: list[str] = []
        for line in iter(stdout.readline, ""):
            line = line.rstrip("\n")
            stdout_text_parts.append(line)
            print(f"  {line}")

        stderr_text = stderr.read().decode("utf-8", errors="replace")
        if stderr_text:
            # 많은 Linux 명령은 경고/진행 메시지도 stderr로 출력하므로 "시스템 메시지"로 표시합니다.
            print(f"\n[시스템 메시지]:\n{stderr_text}")

        results.append(
            {
                "description": description,
                "command": command,
                "stdout": "\n".join(stdout_text_parts),
                "stderr": stderr_text,
            }
        )

    return results


def _run_ssh_command_list(
    ip: str,
    password: str,
    commands: CommandList,
    username: str = "root",
    port: int = 22,
) -> list[dict[str, str]]:
    """SSH 접속부터 명령 실행, 연결 종료까지 한 번에 처리하는 내부 helper입니다."""
    client = get_ssh_client(ip=ip, password=password, username=username, port=port)
    try:
        return run_ssh_commands(client, commands)
    finally:
        client.close()
        print("\nSSH 연결이 종료되었습니다.")


# =============================================================================
# 11. Ubuntu 초기 설정/Jupyter 설치 함수
# =============================================================================

def init_ubuntu_package(
    ip: str,
    username: str = "root",
    password: str = "asd123!@",
    port: int = 22,
) -> list[dict[str, str]]:
    """
    Ubuntu 서버에 기본 패키지, Miniconda, Jupyter Notebook을 설치/설정합니다.

    원본 노트북의 두 번째 setup_commands 블록을 기준으로 정리했습니다.
    기본 비밀번호는 실습용 값이므로 실제 사용 시 반드시 password 인자로 명시하세요.
    """
    setup_script = r"""
add-apt-repository universe -y
apt update -y && apt upgrade -y
apt install -y openssh-server wget vim libstdc++6 tar gzip build-essential iputils-ping ufw expect

systemctl enable --now ssh
ufw allow ssh
ufw allow 80
ufw allow 8888
ufw disable

wget https://www.ubiedu.co.kr/Miniconda3-latest-Linux-x86_64.sh -O /tmp/miniconda.sh
chmod u+x /tmp/miniconda.sh
/tmp/miniconda.sh -b -u -p /root/miniconda3
rm -f /tmp/miniconda.sh

/root/miniconda3/bin/conda init bash
sed -i '$ a export PATH=$PATH:/root/miniconda3/bin' ~/.bashrc
/root/miniconda3/bin/conda config --set auto_activate false
/root/miniconda3/bin/conda tos accept --override-channels --channel https://repo.anaconda.com/pkgs/main
/root/miniconda3/bin/conda tos accept --override-channels --channel https://repo.anaconda.com/pkgs/r

/root/miniconda3/bin/conda install jupyter notebook -y
/root/miniconda3/bin/pip install notebook paramiko ipykernel

expect -c '
spawn /root/miniconda3/bin/jupyter notebook password
expect "Enter password:"
send "1234\r"
expect "Verify password:"
send "1234\r"
expect eof
'

cat > /etc/systemd/system/jupyter.service <<'EOF'
[Unit]
Description=Jupyter Notebook Service
After=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/root
ExecStart=/root/miniconda3/bin/jupyter notebook --allow-root --ip=0.0.0.0 --port=8888 --no-browser
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now jupyter
/root/miniconda3/bin/python3 -m ipykernel install --user --name system-python --display-name 'Python 3 (System)'
""".strip()

    return _run_ssh_command_list(
        ip=ip,
        password=password,
        username=username,
        port=port,
        commands=[("Ubuntu 초기 패키지/Jupyter 설정", setup_script)],
    )


# =============================================================================
# 12. Rocky Linux 초기 설정/Jupyter 설치 함수
# =============================================================================

def setup_rocky(client: paramiko.SSHClient) -> list[dict[str, str]]:
    """이미 연결된 SSHClient를 사용해 Rocky Linux 초기 설정 명령을 실행합니다."""
    return run_ssh_commands(client, ROCKY_INIT_COMMANDS)




def setup(
    client: paramiko.SSHClient,
) -> list[dict[str, str]]:
    """
    기존 노트북의 setup() 함수명을 유지하기 위한 Rocky 초기 설정 wrapper입니다.

    새 코드에서는 함수명이 더 명확한 setup_rocky() 사용을 권장하지만,
    기존 코드에서 setup(client)를 호출하던 경우도 깨지지 않도록 남겨 두었습니다.
    """
    return setup_rocky(client)

def init_rocky_package(
    ip: str,
    user: str = "root",
    pw: str = "asd123!@",
    port: int = 22,
) -> list[dict[str, str]]:
    """
    Rocky Linux 서버에 기본 패키지, Miniconda, Jupyter Notebook을 설치/설정합니다.

    원본 노트북의 init_rocky_package()와 동일하게 user/pw 인자명을 유지했습니다.
    """
    client = get_ssh_client(ip=ip, password=pw, username=user, port=port)
    try:
        return setup_rocky(client)
    finally:
        client.close()
        print("\nSSH 연결이 종료되었습니다.")


# =============================================================================
# 13. Linux 사용자/웹 서버 설정 함수
# =============================================================================

def adduser_to_host(
    ip: str,
    root_password: str,
    new_user_name: str,
    new_user_passwd: str,
) -> list[dict[str, str]]:
    """원격 Linux 서버에 신규 사용자를 만들고 비밀번호를 설정합니다."""
    user = _shell_quote(new_user_name)
    password_pair = _shell_quote(f"{new_user_name}:{new_user_passwd}")

    commands: CommandList = [
        ("유저 만들기", f"useradd -m {user}"),
        ("유저 비밀번호 설정", f"echo {password_pair} | chpasswd"),
    ]
    return _run_ssh_command_list(ip=ip, password=root_password, commands=commands)


def install_rocky_httpd(
    ip: str,
    root_password: str,
    user_name: str,
    new_user_passwd: str,
    is_user: bool,
    index_html_path: str | None = None,
) -> list[dict[str, str]]:
    """
    Rocky Linux 서버에 httpd를 설치하고 DocumentRoot를 /home/{user_name}으로 변경합니다.

    is_user가 False이면 user_name 사용자를 먼저 생성합니다.
    index_html_path가 있으면 해당 HTML 파일 내용을 /home/{user_name}/index.html로 복사합니다.
    """
    user = _shell_quote(user_name)
    home_dir = f"/home/{user_name}"
    home_dir_q = _shell_quote(home_dir)
    password_pair = _shell_quote(f"{user_name}:{new_user_passwd}")

    new_user_commands: list[tuple[str, str]] = [
        ("유저 만들기", f"useradd -m {user}"),
        ("유저 비밀번호 설정", f"echo {password_pair} | chpasswd"),
    ]

    commands: list[tuple[str, str]] = [
        ("유저 홈 디렉터리 권한 변경", f"chmod -R 777 {home_dir_q}"),
        ("httpd 설치", "dnf install -y httpd"),
        ("httpd 실행", "systemctl enable --now httpd"),
        (
            "기존 DocumentRoot 주석 처리",
            "sed -i 's|^DocumentRoot \"/var/www/html\"|#DocumentRoot \"/var/www/html\"|' /etc/httpd/conf/httpd.conf",
        ),
        (
            "새 DocumentRoot 추가",
            f"sed -i '/#DocumentRoot \\\"\\/var\\/www\\/html\\\"/a DocumentRoot \\\"{home_dir}\\\"' /etc/httpd/conf/httpd.conf",
        ),
        (
            "Directory 설정 블록 추가",
            (
                f"cat >> /etc/httpd/conf/httpd.conf <<'EOF'\n"
                f"\n<Directory \"{home_dir}\">\n"
                "    Options Indexes FollowSymLinks\n"
                "    AllowOverride None\n"
                "    Require all granted\n"
                "</Directory>\n"
                "EOF"
            ),
        ),
        ("httpd 설정 재적용", "systemctl restart httpd"),
    ]

    if not is_user:
        commands = new_user_commands + commands

    if index_html_path is not None:
        with open(index_html_path, "r", encoding="utf-8") as f:
            index_html = f.read()
        commands.append(("index.html 파일 작성", _remote_write_file_command(index_html, f"{home_dir}/index.html")))

    return _run_ssh_command_list(ip=ip, password=root_password, commands=commands)


def add_virtual_host_to_httpd(
    ip: str,
    root_password: str,
    vhostip: str,
    vhostport: str,
    vhostfolderpath: str,
) -> list[dict[str, str]]:
    """Rocky/httpd 서버에 Apache VirtualHost 설정을 추가합니다."""
    vhost_folder_q = _shell_quote(vhostfolderpath)
    vhost_config = (
        f"\n<VirtualHost {vhostip}:{vhostport}>\n"
        f"    DocumentRoot \"{vhostfolderpath}\"\n"
        f"    <Directory \"{vhostfolderpath}\">\n"
        "        Require all granted\n"
        "    </Directory>\n"
        "</VirtualHost>\n"
    )

    commands: CommandList = [
        ("디렉터리 만들기", f"mkdir -p {vhost_folder_q}"),
        ("디렉터리 권한 설정", f"chmod -R 777 {vhost_folder_q}"),
        ("vhost.conf 세팅", _remote_write_file_command(vhost_config, "/tmp/vhost_append.conf")),
        ("vhost.conf 반영", "cat /tmp/vhost_append.conf >> /etc/httpd/conf.d/vhost.conf"),
        ("httpd 설정 검사", "httpd -t"),
        ("httpd 설정 재시작", "systemctl restart httpd"),
    ]
    return _run_ssh_command_list(ip=ip, password=root_password, commands=commands)


def install_ubuntu_nginx(
    ip: str,
    root_password: str,
    user_name: str,
    new_user_passwd: str,
    is_user: bool,
    index_html_path: str | None = None,
) -> list[dict[str, str]]:
    """
    Ubuntu 서버에 nginx를 설치하고 기본 root 경로를 /home/{user_name}으로 변경합니다.

    is_user가 False이면 user_name 사용자를 먼저 생성합니다.
    index_html_path가 없으면 기본 index.html 내용으로 `test`를 작성합니다.
    """
    user = _shell_quote(user_name)
    home_dir = f"/home/{user_name}"
    home_dir_q = _shell_quote(home_dir)
    password_pair = _shell_quote(f"{user_name}:{new_user_passwd}")

    new_user_commands: list[tuple[str, str]] = [
        ("유저 만들기", f"useradd -m {user}"),
        ("유저 비밀번호 설정", f"echo {password_pair} | chpasswd"),
        ("유저 홈 디렉터리 강제 생성", f"mkdir -p {home_dir_q}"),
    ]

    if index_html_path is not None:
        with open(index_html_path, "r", encoding="utf-8") as f:
            index_html = f.read()
    else:
        index_html = "test"

    commands: list[tuple[str, str]] = [
        ("패키지 업데이트", "apt update"),
        ("dpkg 잠금 및 오류 강제 복구", "dpkg --configure -a"),
        ("nginx 설치", "DEBIAN_FRONTEND=noninteractive apt -y install nginx"),
        ("nginx 실행", "systemctl enable --now nginx"),
        ("방화벽 비활성화", "ufw disable"),
        (
            "Nginx DocumentRoot 경로 수정",
            f"sed -i 's|root /var/www/html;|root {home_dir};|' /etc/nginx/sites-available/default",
        ),
        ("index.html 파일 작성", _remote_write_file_command(index_html, f"{home_dir}/index.html")),
        ("모든 권한 설정", f"chmod -R 777 {home_dir_q}"),
        ("소유권 이동", f"chown -R {user}:{user} {home_dir_q}"),
        ("nginx 설정 검사", "nginx -t"),
        ("nginx 설정 재적용", "systemctl restart nginx"),
    ]

    if not is_user:
        commands = new_user_commands + commands

    return _run_ssh_command_list(ip=ip, password=root_password, commands=commands)


def add_virtual_host_to_nginx(
    ip: str,
    root_password: str,
    vhostip: str,
    vhostport: str,
    vhostfolderpath: str,
    domain_name: str = "_",
) -> list[dict[str, str]]:
    """
    Ubuntu/nginx 서버에 Server Block 설정을 추가합니다.

    vhostip는 원본 노트북 함수 시그니처와의 호환성을 위해 유지했지만, nginx 설정에서는
    listen 포트와 server_name 중심으로 구성합니다.
    """
    del vhostip  # nginx 설정에서는 직접 사용하지 않지만 기존 함수 시그니처 유지를 위해 남겨둡니다.

    vhost_folder_q = _shell_quote(vhostfolderpath)
    config_filename = f"vhost_{vhostport}.conf"
    nginx_config = (
        "server {\n"
        f"    listen {vhostport};\n"
        f"    server_name {domain_name};\n\n"
        f"    root {vhostfolderpath};\n"
        "    index index.html index.htm;\n\n"
        "    location / {\n"
        "        try_files $uri $uri/ =404;\n"
        "    }\n"
        "}\n"
    )

    commands: CommandList = [
        ("디렉터리 만들기", f"mkdir -p {vhost_folder_q}"),
        ("디렉터리 권한 설정", f"chmod -R 777 {vhost_folder_q}"),
        ("index.html 생성", f"touch {vhost_folder_q}/index.html"),
        (
            "Nginx 블록 세팅",
            _remote_write_file_command(nginx_config, f"/etc/nginx/conf.d/{config_filename}"),
        ),
        ("Nginx 문법 검사", "nginx -t"),
        ("Nginx 설정 리로드", "nginx -s reload"),
    ]
    return _run_ssh_command_list(ip=ip, password=root_password, commands=commands)

# =============================================================================
# 14. 메인 분기점
# =============================================================================
# 아래 분기점은 이 파일을 직접 실행했을 때만 동작합니다.
# 즉, 다른 파이썬 파일에서 `import automation_module`로 가져다 쓰면 메뉴가 자동으로
# 뜨지 않고, 위에 정의한 함수들만 재사용할 수 있습니다.
#
# 요구사항에 맞게 실제 선택지와 해당 선택지가 호출하는 함수명을 메뉴에 함께 표시했습니다.
# 노트북에 있던 개별 테스트 호출은 모두 제거했고, 실행 진입점은 이 if 블록 하나뿐입니다.
if __name__ == "__main__":
    while True:
        print("\n========== 메인 메뉴 ==========")
        print("1. 서버 자동화 함수 실행")
        print("2. Cisco 네트워크 장비 자동화 함수 실행")
        print("0. 종료")
        print("================================")

        main_choice = input("작업 선택: ").strip()

        # ------------------------------------------------------------------
        # 서버 자동화 메뉴
        # ------------------------------------------------------------------
        if main_choice == "1":
            while True:
                print("\n========== 서버 자동화 메뉴 ==========")
                print("1. Rocky 초기 설정/Jupyter 설치        - init_rocky_package()")
                print("2. Rocky httpd 설치/DocumentRoot 설정  - install_rocky_httpd()")
                print("3. Rocky httpd VirtualHost 추가        - add_virtual_host_to_httpd()")
                print("4. Ubuntu 초기 설정/Jupyter 설치       - init_ubuntu_package()")
                print("5. Ubuntu nginx 설치/DocumentRoot 설정 - install_ubuntu_nginx()")
                print("6. Ubuntu nginx Server Block 추가      - add_virtual_host_to_nginx()")
                print("7. Linux 사용자 추가                   - adduser_to_host()")
                print("0. 메인 메뉴로 돌아가기")
                print("=======================================")

                server_choice = input("서버 작업 선택: ").strip()

                if server_choice == "0":
                    break

                try:
                    if server_choice == "1":
                        # Rocky Linux 서버에 SSH 접속 후 패키지, Miniconda, Jupyter를 설치합니다.
                        ip = input("서버 IP: ").strip()
                        user = input("SSH 사용자명(기본 root): ").strip() or "root"
                        pw = input("SSH 비밀번호: ").strip()
                        port_text = input("SSH 포트(기본 22): ").strip()
                        port = int(port_text) if port_text else 22
                        pprint(init_rocky_package(ip=ip, user=user, pw=pw, port=port))

                    elif server_choice == "2":
                        # Rocky Linux에 Apache httpd를 설치하고 /home/{user_name}을 웹 루트로 설정합니다.
                        ip = input("서버 IP: ").strip()
                        root_password = input("root 비밀번호: ").strip()
                        user_name = input("웹 루트로 사용할 사용자명: ").strip()
                        user_password = input("사용자 비밀번호: ").strip()
                        is_user = input("해당 사용자가 이미 존재합니까? (y/n): ").strip().lower() == "y"
                        index_html_path = input("index.html 파일 경로(없으면 n): ").strip()
                        if index_html_path.lower() == "n":
                            index_html_path = None
                        pprint(
                            install_rocky_httpd(
                                ip=ip,
                                root_password=root_password,
                                user_name=user_name,
                                new_user_passwd=user_password,
                                is_user=is_user,
                                index_html_path=index_html_path,
                            )
                        )

                    elif server_choice == "3":
                        # Apache VirtualHost 블록을 /etc/httpd/conf.d/vhost.conf에 추가합니다.
                        ip = input("서버 IP: ").strip()
                        root_password = input("root 비밀번호: ").strip()
                        vhost_ip = input("VirtualHost IP: ").strip()
                        vhost_port = input("VirtualHost Port: ").strip()
                        vhost_folder = input("DocumentRoot 디렉터리 경로: ").strip()
                        pprint(add_virtual_host_to_httpd(ip, root_password, vhost_ip, vhost_port, vhost_folder))

                    elif server_choice == "4":
                        # Ubuntu 서버에 SSH 접속 후 패키지, Miniconda, Jupyter를 설치합니다.
                        ip = input("서버 IP: ").strip()
                        username = input("SSH 사용자명(기본 root): ").strip() or "root"
                        password = input("SSH 비밀번호: ").strip()
                        port_text = input("SSH 포트(기본 22): ").strip()
                        port = int(port_text) if port_text else 22
                        pprint(init_ubuntu_package(ip=ip, username=username, password=password, port=port))

                    elif server_choice == "5":
                        # Ubuntu에 nginx를 설치하고 /home/{user_name}을 웹 루트로 설정합니다.
                        ip = input("서버 IP: ").strip()
                        root_password = input("root 비밀번호: ").strip()
                        user_name = input("웹 루트로 사용할 사용자명: ").strip()
                        user_password = input("사용자 비밀번호: ").strip()
                        is_user = input("해당 사용자가 이미 존재합니까? (y/n): ").strip().lower() == "y"
                        index_html_path = input("index.html 파일 경로(없으면 n): ").strip()
                        if index_html_path.lower() == "n":
                            index_html_path = None
                        pprint(
                            install_ubuntu_nginx(
                                ip=ip,
                                root_password=root_password,
                                user_name=user_name,
                                new_user_passwd=user_password,
                                is_user=is_user,
                                index_html_path=index_html_path,
                            )
                        )

                    elif server_choice == "6":
                        # nginx Server Block 설정 파일을 /etc/nginx/conf.d/ 아래에 생성합니다.
                        ip = input("서버 IP: ").strip()
                        root_password = input("root 비밀번호: ").strip()
                        vhost_ip = input("Server Block IP(호환용 입력값): ").strip()
                        vhost_port = input("Listen Port: ").strip()
                        vhost_folder = input("Root 디렉터리 경로: ").strip()
                        domain_name = input("server_name(기본 _): ").strip() or "_"
                        pprint(add_virtual_host_to_nginx(ip, root_password, vhost_ip, vhost_port, vhost_folder, domain_name))

                    elif server_choice == "7":
                        # 원격 Linux 서버에 신규 사용자를 생성합니다.
                        ip = input("서버 IP: ").strip()
                        root_password = input("root 비밀번호: ").strip()
                        new_user_name = input("새 사용자명: ").strip()
                        new_user_passwd = input("새 사용자 비밀번호: ").strip()
                        pprint(adduser_to_host(ip, root_password, new_user_name, new_user_passwd))

                    else:
                        print("알 수 없는 선택지입니다. 다시 선택하세요.")

                except Exception as exc:
                    # 자동화 명령은 원격 장비/서버 상태에 영향을 받기 때문에, 예외를 숨기지 않고 표시합니다.
                    print(f"[오류] 서버 자동화 작업 중 문제가 발생했습니다: {exc}")

        # ------------------------------------------------------------------
        # Cisco 네트워크 장비 자동화 메뉴
        # ------------------------------------------------------------------
        elif main_choice == "2":
            print("\n========== Cisco 장비 선택 ==========")
            print("1. 라우터 작업")
            print("2. 스위치 작업")
            print("0. 메인 메뉴로 돌아가기")
            print("=====================================")

            device_choice = input("장비 종류 선택: ").strip()
            if device_choice == "0":
                continue
            if device_choice not in {"1", "2"}:
                print("알 수 없는 장비 선택지입니다.")
                continue

            ip = input("Cisco 장비 IP: ").strip()
            username = input("Cisco 사용자명(기본 root): ").strip() or "root"
            password = input("Cisco 비밀번호(기본 cisco): ").strip() or "cisco"
            port_text = input("SSH 포트(기본 22): ").strip()
            port = int(port_text) if port_text else 22

            try:
                # 메뉴 하나의 작업 세션 동안 SSH 연결 하나를 재사용합니다.
                con = get_con(ip=ip, username=username, password=password, port=port, device_type="cisco_ios")
                try:
                    role = get_device_role(con)
                    host_name = get_host_name(con)
                    print(f"\n접속 장비: {role} {host_name}")

                    # ------------------------------------------------------
                    # 라우터 작업 메뉴
                    # ------------------------------------------------------
                    if device_choice == "1":
                        while True:
                            print("\n========== 라우터 작업 메뉴 ==========")
                            print("1. 인터페이스 요약 조회      - get_interface_brief()")
                            print("2. 라우팅 테이블 작업        - add_route_info(), get/store/restore_routing_table()")
                            print("3. DHCP 작업                 - router_dhcp_config(), get/store/restore_dhcp_setting()")
                            print("4. NAT 작업                  - router_pat/static/dynamic_nat_config(), get/store/restore_nat_pat_setting()")
                            print("5. Inter-VLAN 작업           - inter_vlan_config(), get/store/restore_vlan_interfaces()")
                            print("0. 메인 메뉴로 돌아가기")
                            print("======================================")

                            router_choice = input(f"{role} {host_name} 작업 선택: ").strip()
                            if router_choice == "0":
                                break

                            try:
                                if router_choice == "1":
                                    pprint(get_interface_brief(con))

                                elif router_choice == "2":
                                    print("\n--- 라우팅 테이블 작업 ---")
                                    print("1. 정적 라우팅 추가      - add_route_info()")
                                    print("2. 정적 라우팅 조회      - get_routing_table()")
                                    print("3. 정적 라우팅 백업      - store_routing_table()")
                                    print("4. 정적 라우팅 복구      - restore_routing_table()")
                                    print("0. 이전")
                                    sub_choice = input("라우팅 작업 선택: ").strip()

                                    if sub_choice == "1":
                                        nid = input("NID: ").strip()
                                        netmask = input("Netmask: ").strip()
                                        gateway = input("Gateway: ").strip()
                                        pprint(add_route_info(con, nid, netmask, gateway))
                                    elif sub_choice == "2":
                                        pprint(get_routing_table(con))
                                    elif sub_choice == "3":
                                        json_path = input("백업 JSON 경로: ").strip()
                                        pprint(store_routing_table(con, json_path))
                                    elif sub_choice == "4":
                                        json_path = input("복구 JSON 경로: ").strip()
                                        pprint(restore_routing_table(con, json_path))

                                elif router_choice == "3":
                                    print("\n--- 라우터 DHCP 작업 ---")
                                    print("1. DHCP 정보 조회        - get_dhcp_info()")
                                    print("2. DHCP 서버 설정        - router_dhcp_config()")
                                    print("3. DHCP 설정 백업        - store_dhcp_setting()")
                                    print("4. DHCP 설정 복구        - restore_dhcp_setting()")
                                    print("0. 이전")
                                    sub_choice = input("DHCP 작업 선택: ").strip()

                                    if sub_choice == "1":
                                        pprint(get_dhcp_info(con))
                                    elif sub_choice == "2":
                                        pool_name = input("Pool Name: ").strip()
                                        nid = input("NID: ").strip()
                                        subnet_mask = input("Netmask: ").strip()
                                        gateway_ip = input("Gateway: ").strip()
                                        exclude_start = input("Exclude IP Start: ").strip()
                                        exclude_end = input("Exclude IP End: ").strip()
                                        dns_server = input("DNS(기본 8.8.8.8): ").strip() or "8.8.8.8"
                                        pprint(router_dhcp_config(con, pool_name, nid, subnet_mask, gateway_ip, exclude_start, exclude_end, dns_server))
                                    elif sub_choice == "3":
                                        json_path = input("백업 JSON 경로: ").strip()
                                        pprint(store_dhcp_setting(con, json_path))
                                    elif sub_choice == "4":
                                        json_path = input("복구 JSON 경로: ").strip()
                                        pprint(restore_dhcp_setting(con, json_path))

                                elif router_choice == "4":
                                    print("\n--- NAT 작업 ---")
                                    print("1. PAT 정보 조회         - get_nat_pat_config()")
                                    print("2. PAT 설정              - router_pat_nat_config()")
                                    print("3. Static NAT 설정       - router_static_nat_config()")
                                    print("4. Dynamic NAT 설정      - router_dynamic_nat_config()")
                                    print("5. PAT 설정 백업         - store_nat_pat_setting()")
                                    print("6. PAT 설정 복구         - restore_nat_pat_setting()")
                                    print("0. 이전")
                                    sub_choice = input("NAT 작업 선택: ").strip()

                                    if sub_choice == "1":
                                        pprint(get_nat_pat_config(con))
                                    elif sub_choice == "2":
                                        in_interface = input("Inside Interface: ").strip()
                                        out_interface = input("Outside Interface: ").strip()
                                        ip_prefix = input("내부망 IP/Prefix 예: 192.168.10.0/24: ").strip()
                                        pprint(router_pat_nat_config(con, in_interface, out_interface, ip_prefix))
                                    elif sub_choice == "3":
                                        in_interface = input("Inside Interface: ").strip()
                                        out_interface = input("Outside Interface: ").strip()
                                        in_addr = input("Inside Local IP: ").strip()
                                        out_addr = input("Inside Global IP: ").strip()
                                        pprint(router_static_nat_config(con, in_interface, out_interface, in_addr, out_addr))
                                    elif sub_choice == "4":
                                        in_interface = input("Inside Interface: ").strip()
                                        out_interface = input("Outside Interface: ").strip()
                                        ip_prefix = input("내부망 IP/Prefix 예: 192.168.10.0/24: ").strip()
                                        pool_name = input("NAT Pool Name: ").strip()
                                        pool_start = input("Pool Start IP: ").strip()
                                        pool_end = input("Pool End IP: ").strip()
                                        pool_netmask = input("Pool Netmask: ").strip()
                                        pprint(router_dynamic_nat_config(con, in_interface, out_interface, ip_prefix, pool_name, pool_start, pool_end, pool_netmask))
                                    elif sub_choice == "5":
                                        json_path = input("백업 JSON 경로: ").strip()
                                        pprint(store_nat_pat_setting(con, json_path))
                                    elif sub_choice == "6":
                                        json_path = input("복구 JSON 경로: ").strip()
                                        pprint(restore_nat_pat_setting(con, json_path))

                                elif router_choice == "5":
                                    print("\n--- Inter-VLAN 작업 ---")
                                    print("1. 서브인터페이스 설정   - inter_vlan_config()")
                                    print("2. 서브인터페이스 조회   - get_vlan_interfaces()")
                                    print("3. 서브인터페이스 백업   - store_vlan_interfaces()")
                                    print("4. 서브인터페이스 복구   - restore_vlan_interfaces()")
                                    print("0. 이전")
                                    sub_choice = input("Inter-VLAN 작업 선택: ").strip()

                                    if sub_choice == "1":
                                        interface = input("물리 Interface 예: FastEthernet0/0: ").strip()
                                        vlan = input("VLAN ID: ").strip()
                                        ip_addr = input("서브인터페이스 IP: ").strip()
                                        netmask = input("Netmask: ").strip()
                                        pprint(inter_vlan_config(con, interface, vlan, ip_addr, netmask))
                                    elif sub_choice == "2":
                                        pprint(get_vlan_interfaces(con))
                                    elif sub_choice == "3":
                                        json_path = input("백업 JSON 경로: ").strip()
                                        pprint(store_vlan_interfaces(con, json_path))
                                    elif sub_choice == "4":
                                        json_path = input("복구 JSON 경로: ").strip()
                                        pprint(restore_vlan_interfaces(con, json_path))

                                else:
                                    print("알 수 없는 선택지입니다. 다시 선택하세요.")

                            except Exception as exc:
                                print(f"[오류] 라우터 작업 중 문제가 발생했습니다: {exc}")

                    # ------------------------------------------------------
                    # 스위치 작업 메뉴
                    # ------------------------------------------------------
                    elif device_choice == "2":
                        while True:
                            print("\n========== 스위치 작업 메뉴 ==========")
                            print("1. 인터페이스 요약 조회      - get_interface_brief()")
                            print("2. DHCP 작업                 - switch_dhcp_config(), get/store/restore_dhcp_setting()")
                            print("3. STP 작업                  - switch_stp_config(), get_stp_info()")
                            print("4. VTP 작업                  - switch_vtp_config(), get/store/restore_vtp_config()")
                            print("0. 메인 메뉴로 돌아가기")
                            print("======================================")

                            switch_choice = input(f"{role} {host_name} 작업 선택: ").strip()
                            if switch_choice == "0":
                                break

                            try:
                                if switch_choice == "1":
                                    pprint(get_interface_brief(con))

                                elif switch_choice == "2":
                                    print("\n--- 스위치 DHCP 작업 ---")
                                    print("1. DHCP 정보 조회        - get_dhcp_info()")
                                    print("2. DHCP 서버 설정        - switch_dhcp_config()")
                                    print("3. DHCP 설정 백업        - store_dhcp_setting()")
                                    print("4. DHCP 설정 복구        - restore_dhcp_setting()")
                                    print("0. 이전")
                                    sub_choice = input("DHCP 작업 선택: ").strip()

                                    if sub_choice == "1":
                                        pprint(get_dhcp_info(con))
                                    elif sub_choice == "2":
                                        pool_name = input("Pool Name: ").strip()
                                        nid = input("NID: ").strip()
                                        subnet_mask = input("Netmask: ").strip()
                                        gateway_ip = input("Gateway: ").strip()
                                        exclude_start = input("Exclude IP Start: ").strip()
                                        exclude_end = input("Exclude IP End: ").strip()
                                        dns_server = input("DNS(기본 8.8.8.8): ").strip() or "8.8.8.8"
                                        pprint(switch_dhcp_config(con, pool_name, nid, subnet_mask, gateway_ip, exclude_start, exclude_end, dns_server))
                                    elif sub_choice == "3":
                                        json_path = input("백업 JSON 경로: ").strip()
                                        pprint(store_dhcp_setting(con, json_path))
                                    elif sub_choice == "4":
                                        json_path = input("복구 JSON 경로: ").strip()
                                        pprint(restore_dhcp_setting(con, json_path))

                                elif switch_choice == "3":
                                    print("\n--- STP 작업 ---")
                                    print("1. STP Priority 설정     - switch_stp_config()")
                                    print("2. STP 정보 조회         - get_stp_info()")
                                    print("0. 이전")
                                    sub_choice = input("STP 작업 선택: ").strip()

                                    if sub_choice == "1":
                                        vlan = input("VLAN ID: ").strip()
                                        priority = input("Priority(0~61440, 4096 단위): ").strip()
                                        pprint(switch_stp_config(con, vlan, priority))
                                    elif sub_choice == "2":
                                        pprint(get_stp_info(con))

                                elif switch_choice == "4":
                                    print("\n--- VTP 작업 ---")
                                    print("1. VTP 설정              - switch_vtp_config()")
                                    print("2. VTP 상태 조회         - get_vtp_status()")
                                    print("3. VTP 설정 백업         - store_vtp_config()")
                                    print("4. VTP 설정 복구         - restore_vtp_config()")
                                    print("0. 이전")
                                    sub_choice = input("VTP 작업 선택: ").strip()

                                    if sub_choice == "1":
                                        domain_name = input("VTP Domain: ").strip()
                                        password_text = input("VTP Password: ").strip()
                                        vtp_mode = input("VTP Mode(기본 server): ").strip() or "server"
                                        pprint(switch_vtp_config(con, domain_name, password_text, vtp_mode))
                                    elif sub_choice == "2":
                                        pprint(get_vtp_status(con))
                                    elif sub_choice == "3":
                                        json_path = input("백업 JSON 경로: ").strip()
                                        custom_password = input("백업에 저장할 VTP Password(모르면 Enter): ").strip() or None
                                        pprint(store_vtp_config(con, json_path, custom_password))
                                    elif sub_choice == "4":
                                        json_path = input("복구 JSON 경로: ").strip()
                                        pprint(restore_vtp_config(con, json_path))

                                else:
                                    print("알 수 없는 선택지입니다. 다시 선택하세요.")

                            except Exception as exc:
                                print(f"[오류] 스위치 작업 중 문제가 발생했습니다: {exc}")

                finally:
                    # netmiko 연결을 명시적으로 종료합니다. 연결 종료 자체의 오류는 메뉴 종료를 막지 않도록 처리합니다.
                    try:
                        con.disconnect()
                        print("\nCisco 장비 SSH 연결이 종료되었습니다.")
                    except Exception:
                        pass

            except Exception as exc:
                print(f"[오류] Cisco 장비 접속 또는 작업 중 문제가 발생했습니다: {exc}")

        elif main_choice == "0":
            print("프로그램을 종료합니다.")
            break

        else:
            print("알 수 없는 선택지입니다. 다시 선택하세요.")

