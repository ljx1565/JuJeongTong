import re

class NetworkDevice:
    check_list = {
        "n_1": { "title": "비밀번호 설정" },
        "n_11": { "title": "로그 서버 설정" },
        "n_13": { "title": "로그 버퍼 사이즈 설정" },
        "n_16": { "title": "타임스탬프 및 시간대 설정" },
        "n_17": { "title": "SNMP Community 설정 확인" },
        "n_18": { "title": "SNMP Community 문자열 복잡도" },
        "n_20": { "title": "SNMP RW 권한 설정 확인" },
        "n_21": { "title": "자동 설정 기능(Service config) 비활성화" },
        "n_25": { "title": "TCP Keepalive 설정" },
        "n_26": { "title": "Finger 서비스 비활성화" },
        "n_27": { "title": "HTTP/HTTPS 서버 비활성화" },
        "n_28": { "title": "Small Server 서비스 비활성화" },
        "n_29": { "title": "BOOTP 설정 확인" },
        "n_30": { "title": "CDP(Cisco Discovery Protocol) 비활성화" },
        "n_31": { "title": "Directed-broadcast 비활성화" },
        "n_32": { "title": "Source-route 비활성화" },
        "n_34": { "title": "인터페이스 Unreachables/Redirects 설정" },
        "n_35": { "title": "Identd 서비스 비활성화" },
        "n_36": { "title": "DNS 룩업 비활성화" },
        "n_37": { "title": "PAD 서비스 비활성화" },
        "n_38": { "title": "Mask-reply 비활성화" }
    }    

   
    def __init__(self, conn):
        self.conn = conn
        self.show_run = self.conn.send_command("show run")
        self.show_logging = self.conn.send_command("show logging")

    def _get_l3_int(self):
        l3_int = []
        current = []
        for line in self.show_run.splitlines():
            line = line.strip()
            if line.startswith("interface "):
                if current and any(x.startswith("ip address ") for x in current):
                    l3_int.append(current)
                current = [line]
            elif current:
                current.append(line)
        if current and any(x.startswith("ip address ") for x in current):
            l3_int.append(current)
        return l3_int

def n_1(self):
    enable_ok = False

    for line in self.show_run.splitlines():
        line = line.strip()
        if re.match( r"^enable\s+(?:secret|password)(?:\s+\d+)?\s+\S+", line ):
            enable_ok = True
            break

    local_user_ok = False
    username_pattern = (
        r"^username\s+\S+"
        r"(?:\s+privilege\s+\d+)?"
        r"\s+(?:secret|password)"
        r"(?:\s+\d+)?"
        r"\s+\S+"
    )
    for line in self.show_run.splitlines():
        line = line.strip()
        if re.match(username_pattern, line):
            local_user_ok = True
            break
            
    aaa_login_methods = set()
    for line in self.show_run.splitlines():
        line = line.strip()
        m = re.match( r"^aaa authentication login\s+(\S+)\s+.+", line )
        if m:
            aaa_login_methods.add(m.group(1))
    line_blocks = {
        "vty": [],
        "console": [],
        "aux": []
    }
    current_block = None
    for raw_line in self.show_run.splitlines():
        line = raw_line.strip()
        if line.startswith("line vty "):
            current_block = [line]
            line_blocks["vty"].append(current_block)
            continue
        if line.startswith("line con "):
            current_block = [line]
            line_blocks["console"].append(current_block)
            continue
        if line.startswith("line aux "):
            current_block = [line]
            line_blocks["aux"].append(current_block)
            continue
        if current_block is not None:
            # line 내부 설정은 show run에서 들여쓰기되어 출력됨
            if raw_line.startswith(" "):
                current_block.append(line)
            else:
                current_block = None
    vty_ok = len(line_blocks["vty"]) > 0
    console_ok = len(line_blocks["console"]) > 0
    aux_ok = len(line_blocks["aux"]) == 0
    weak_reasons = []

    if not line_blocks["vty"]:
        weak_reasons.append("VTY 라인 설정이 존재하지 않음")

    for block in line_blocks["vty"]:
        block_ok = False
        block_name = block[0]
        if "no login" in block:
            weak_reasons.append(f"{block_name}: no login 설정")
        elif "login local" in block:
            if local_user_ok:
                block_ok = True
            else:
                weak_reasons.append(
                    f"{block_name}: login local이 설정되었으나 "
                    "비밀번호가 설정된 로컬 사용자 계정이 없음"
                )
        else:
            aaa_found = False
            for line in block:
                m = re.match( r"^login authentication\s+(\S+)$",line )
                if m:
                    aaa_found = True
                    method_name = m.group(1)
                    if method_name in aaa_login_methods:
                        block_ok = True
                    else:
                        weak_reasons.append(
                            f"{block_name}: login authentication "
                            f"{method_name}에 대응하는 AAA 설정이 없음"
                        )
                    break

            if not aaa_found and "login" in block:
                line_password_ok = any(
                    re.match( r"^password(?:\s+\d+)?\s+\S+", line)
                    for line in block
                )
                if line_password_ok:
                    block_ok = True
                else:
                    weak_reasons.append(
                        f"{block_name}: login이 설정되었으나 "
                        "라인 password가 없음"
                    )
            elif not aaa_found and "login" not in block:
                weak_reasons.append(
                    f"{block_name}: 로그인 인증 방식이 설정되지 않음"
                )
        if not block_ok:
            vty_ok = False

    if not line_blocks["console"]:
        weak_reasons.append("Console 라인 설정이 존재하지 않음")

    for block in line_blocks["console"]:
        block_ok = False
        block_name = block[0]

        if "no login" in block:
            weak_reasons.append(f"{block_name}: no login 설정")

        elif "login local" in block:
            if local_user_ok:
                block_ok = True
            else:
                weak_reasons.append(
                    f"{block_name}: login local이 설정되었으나 "
                    "비밀번호가 설정된 로컬 사용자 계정이 없음"
                )

        else:
            aaa_found = False

            for line in block:
                m = re.match(
                    r"^login authentication\s+(\S+)$",
                    line
                )

                if m:
                    aaa_found = True
                    method_name = m.group(1)

                    if method_name in aaa_login_methods:
                        block_ok = True
                    else:
                        weak_reasons.append(
                            f"{block_name}: login authentication "
                            f"{method_name}에 대응하는 AAA 설정이 없음"
                        )

                    break

            if not aaa_found and "login" in block:
                line_password_ok = any(
                    re.match(
                        r"^password(?:\s+\d+)?\s+\S+",
                        line
                    )
                    for line in block
                )

                if line_password_ok:
                    block_ok = True
                else:
                    weak_reasons.append(
                        f"{block_name}: login이 설정되었으나 "
                        "라인 password가 없음"
                    )
            elif not aaa_found and "login" not in block:
                weak_reasons.append(
                    f"{block_name}: 로그인 인증 방식이 설정되지 않음"
                )
        if not block_ok:
            console_ok = False
            
    if line_blocks["aux"]:
        aux_ok = True

        for block in line_blocks["aux"]:
            block_ok = False
            block_name = block[0]

            if "no exec" in block:
                block_ok = True

            elif "no login" in block:
                weak_reasons.append(f"{block_name}: no login 설정")

            elif "login local" in block:
                if local_user_ok:
                    block_ok = True
                else:
                    weak_reasons.append(
                        f"{block_name}: login local이 설정되었으나 "
                        "비밀번호가 설정된 로컬 사용자 계정이 없음"
                    )

            else:
                aaa_found = False

                for line in block:
                    m = re.match(
                        r"^login authentication\s+(\S+)$",
                        line
                    )

                    if m:
                        aaa_found = True
                        method_name = m.group(1)

                        if method_name in aaa_login_methods:
                            block_ok = True
                        else:
                            weak_reasons.append(
                                f"{block_name}: login authentication "
                                f"{method_name}에 대응하는 AAA 설정이 없음"
                            )

                        break

                if not aaa_found and "login" in block:
                    line_password_ok = any(
                        re.match(
                            r"^password(?:\s+\d+)?\s+\S+",
                            line
                        )
                        for line in block
                    )

                    if line_password_ok:
                        block_ok = True
                    else:
                        weak_reasons.append(
                            f"{block_name}: login이 설정되었으나 "
                            "라인 password가 없음"
                        )

                elif not aaa_found and "login" not in block:
                    weak_reasons.append(
                        f"{block_name}: 인증 설정 또는 no exec 설정이 없음"
                    )

            if not block_ok:
                aux_ok = False

    if not enable_ok:
        weak_reasons.insert(
            0,
            "enable secret 또는 enable password가 설정되지 않음"
        )

    if enable_ok and vty_ok and console_ok and aux_ok:
        return (
            "양호",
            "Enable 인증과 VTY·Console·AUX 로그인 인증이 모두 설정되어 있습니다."
        )
    return (
        "취약",
        "; ".join(weak_reasons)
    )

def n_3(self):
    service_encryption_ok = False
    enable_secret_ok = False
    weak_settings = []

    for raw_line in self.show_run.splitlines():
        line = raw_line.strip()

        # 비밀번호 암호화 서비스 확인
        if line == "service password-encryption":
            service_encryption_ok = True

        # enable secret 존재 여부
        if re.match(
            r"^enable\s+secret(?:\s+\d+)?\s+\S+",
            line
        ):
            enable_secret_ok = True

        # enable password 사용 시 취약
        if re.match(
            r"^enable\s+password(?:\s+\d+)?\s+\S+",
            line
        ):
            weak_settings.append("enable password 사용")

        # username ... password 방식 사용 시 취약
        if re.match(
            r"^username\s+\S+"
            r"(?:\s+privilege\s+\d+)?"
            r"\s+password(?:\s+\d+)?\s+\S+",
            line
        ):
            weak_settings.append(
                "로컬 계정에 username password 방식 사용"
            )

        # 라인 평문 비밀번호
        # password cisco
        if re.match(
            r"^password\s+\S+$",
            line
        ):
            weak_settings.append(
                "라인에 평문 password 사용"
            )

        # password 0 cisco
        if re.match(
            r"^password\s+0\s+\S+$",
            line
        ):
            weak_settings.append(
                "라인에 Type 0 평문 password 사용"
            )

    if (
        service_encryption_ok
        and enable_secret_ok
        and not weak_settings
    ):
        return (
            "양호",
            "비밀번호 암호화 설정과 enable secret이 적용되어 있으며 "
            "평문 또는 password 방식의 취약한 비밀번호가 없습니다."
        )

    reasons = []

    if not service_encryption_ok:
        reasons.append(
            "service password-encryption 설정 없음"
        )

    if not enable_secret_ok:
        reasons.append(
            "enable secret 설정 없음"
        )

    reasons.extend(weak_settings)

    return (
        "취약",
        "; ".join(reasons)
    )


def n_4(self):
    pattern = (
        r"^login\s+block-for\s+(\d+)"
        r"\s+attempts\s+(\d+)"
        r"\s+within\s+(\d+)$"
    )

    for raw_line in self.show_run.splitlines():
        line = raw_line.strip()
        m = re.match(pattern, line)

        if not m:
            continue

        block_time = int(m.group(1))
        attempts = int(m.group(2))
        within_time = int(m.group(3))

        if (
            block_time > 0
            and 1 <= attempts <= 5
            and within_time > 0
        ):
            return (
                "양호",
                "계정 잠금 정책이 설정되어 있으며 "
                f"로그인 실패 임계값이 {attempts}회입니다."
            )

        reasons = []

        if block_time <= 0:
            reasons.append("잠금시간이 0 이하")

        if attempts <= 0:
            reasons.append("실패횟수가 0 이하")

        elif attempts > 5:
            reasons.append(
                f"실패횟수가 기준 초과: {attempts}회"
            )

        if within_time <= 0:
            reasons.append("감시시간이 0 이하")

        return (
            "취약",
            "; ".join(reasons)
        )

    return (
        "취약",
        "login block-for 계정 잠금 정책이 설정되어 있지 않습니다."
    )


def n_6(self):
    vty_blocks = []
    numbered_acls = {}
    named_acls = {}

    current_vty = None
    current_named_acl = None

    for raw_line in self.show_run.splitlines():
        line = raw_line.strip()

        # VTY 블록 시작
        if line.startswith("line vty "):
            current_vty = [line]
            vty_blocks.append(current_vty)
            current_named_acl = None
            continue

        # 이름 기반 ACL 시작
        named_match = re.match(
            r"^ip access-list\s+(?:standard|extended)\s+(\S+)$",
            line
        )

        if named_match:
            acl_name = named_match.group(1)
            current_named_acl = acl_name
            named_acls.setdefault(acl_name, [])
            current_vty = None
            continue

        # 숫자 기반 ACL
        numbered_match = re.match(
            r"^access-list\s+(\S+)\s+(.+)$",
            line
        )

        if numbered_match:
            acl_number = numbered_match.group(1)
            acl_rule = numbered_match.group(2).strip()

            numbered_acls.setdefault(
                acl_number, []
            ).append(acl_rule)

            current_vty = None
            current_named_acl = None
            continue

        # 블록 내부 설정
        if raw_line.startswith(" "):
            if current_vty is not None:
                current_vty.append(line)

            elif current_named_acl is not None:
                named_acls[current_named_acl].append(line)

        else:
            current_vty = None
            current_named_acl = None

    if not vty_blocks:
        return (
            "취약",
            "VTY 라인 블록이 존재하지 않습니다."
        )

    weak_reasons = []

    for block in vty_blocks:
        block_name = block[0]
        acl_name = None

        # VTY에 적용된 inbound ACL 확인
        for line in block:
            m = re.match(
                r"^access-class\s+(\S+)\s+in$",
                line
            )

            if m:
                acl_name = m.group(1)
                break

        if acl_name is None:
            weak_reasons.append(
                f"{block_name}: access-class inbound 설정 없음"
            )
            continue

        # 실제 ACL 규칙 조회
        if acl_name in numbered_acls:
            acl_rules = numbered_acls[acl_name]

        elif acl_name in named_acls:
            acl_rules = named_acls[acl_name]

        else:
            weak_reasons.append(
                f"{block_name}: 참조 ACL {acl_name} 정의 없음"
            )
            continue

        permit_found = False
        unrestricted_permit = False

        for rule in acl_rules:
            normalized = " ".join(
                rule.lower().split()
            )

            # Named ACL의 sequence 번호 제거
            normalized = re.sub(
                r"^\d+\s+",
                "",
                normalized
            )

            if normalized.startswith("permit "):
                permit_found = True

            # 표준 ACL의 전체 허용
            if re.match(
                r"^permit\s+any$",
                normalized
            ):
                unrestricted_permit = True

            if re.match(
                r"^permit\s+0\.0\.0\.0\s+255\.255\.255\.255$",
                normalized
            ):
                unrestricted_permit = True

            # 확장 ACL의 전체 출발지 허용
            if re.match(
                r"^permit\s+\S+\s+any(?:\s+|$)",
                normalized
            ):
                unrestricted_permit = True

            if normalized == "permit ip any any":
                unrestricted_permit = True

        if not permit_found:
            weak_reasons.append(
                f"ACL {acl_name}: permit 규칙 없음"
            )

        if unrestricted_permit:
            weak_reasons.append(
                f"ACL {acl_name}: 전체 출발지 허용"
            )

    if weak_reasons:
        return (
            "취약",
            "; ".join(weak_reasons)
        )

    return (
        "양호",
        "모든 VTY 라인에 제한된 관리 출발지만 허용하는 "
        "inbound ACL이 적용되어 있습니다."
    )


def n_7(self):
    line_blocks = []
    current_block = None

    for raw_line in self.show_run.splitlines():
        line = raw_line.strip()

        if (
            line.startswith("line vty ")
            or line.startswith("line con ")
            or line.startswith("line aux ")
        ):
            current_block = [line]
            line_blocks.append(current_block)
            continue

        if current_block is not None:
            if raw_line.startswith(" "):
                current_block.append(line)
            else:
                current_block = None

    if not line_blocks:
        return (
            "취약",
            "VTY, Console, AUX 라인 설정이 존재하지 않습니다."
        )

    weak_reasons = []

    for block in line_blocks:
        block_name = block[0]

        # no exec로 비활성화된 AUX는 예외
        if (
            block_name.startswith("line aux ")
            and "no exec" in block
        ):
            continue

        timeout_found = False
        timeout_ok = False
        total_seconds = None

        for line in block:
            m = re.match(
                r"^exec-timeout\s+(\d+)\s+(\d+)$",
                line
            )

            if not m:
                continue

            timeout_found = True

            minutes = int(m.group(1))
            seconds = int(m.group(2))
            total_seconds = minutes * 60 + seconds

            if 0 < total_seconds <= 600:
                timeout_ok = True

            break

        if not timeout_found:
            weak_reasons.append(
                f"{block_name}: exec-timeout 설정 없음"
            )

        elif not timeout_ok:
            weak_reasons.append(
                f"{block_name}: 세션 종료 시간 부적절 "
                f"({total_seconds}초)"
            )

    if weak_reasons:
        return (
            "취약",
            "; ".join(weak_reasons)
        )

    return (
        "양호",
        "모든 활성 관리 라인의 세션 종료 시간이 "
        "10분 이하로 설정되어 있습니다."
    )


def n_8(self):
    ssh_version_2 = False
    vty_blocks = []
    current_block = None

    for raw_line in self.show_run.splitlines():
        line = raw_line.strip()

        if line == "ip ssh version 2":
            ssh_version_2 = True

        if line.startswith("line vty "):
            current_block = [line]
            vty_blocks.append(current_block)
            continue

        if current_block is not None:
            if raw_line.startswith(" "):
                current_block.append(line)
            else:
                current_block = None

    if not vty_blocks:
        return (
            "취약",
            "VTY 라인 블록이 존재하지 않습니다."
        )

    weak_reasons = []

    if not ssh_version_2:
        weak_reasons.append(
            "ip ssh version 2 설정 없음"
        )

    for block in vty_blocks:
        block_name = block[0]
        protocols = None

        for line in block:
            m = re.match(
                r"^transport\s+input\s+(.+)$",
                line
            )

            if m:
                protocols = m.group(1).lower().split()
                break

        if protocols is None:
            weak_reasons.append(
                f"{block_name}: transport input 설정 없음"
            )
            continue

        if protocols != ["ssh"]:
            weak_reasons.append(
                f"{block_name}: SSH 이외의 프로토콜 허용 "
                f"({', '.join(protocols)})"
            )

    if weak_reasons:
        return (
            "취약",
            "; ".join(weak_reasons)
        )

    return (
        "양호",
        "SSHv2가 설정되어 있으며 모든 VTY 라인이 "
        "SSH 접속만 허용합니다."
    )


def n_9(self):
    aux_blocks = []
    current_block = None

    for raw_line in self.show_run.splitlines():
        line = raw_line.strip()

        if line.startswith("line aux "):
            current_block = [line]
            aux_blocks.append(current_block)
            continue

        if current_block is not None:
            if raw_line.startswith(" "):
                current_block.append(line)
            else:
                current_block = None

    # AUX 라인이 없는 장비
    if not aux_blocks:
        return (
            "양호",
            "AUX 라인이 존재하지 않아 적용 대상에서 제외됩니다."
        )

    weak_reasons = []

    for block in aux_blocks:
        block_name = block[0]

        no_password_ok = "no password" in block
        transport_none_ok = "transport input none" in block
        no_exec_ok = "no exec" in block
        timeout_ok = "exec-timeout 0 1" in block

        auth_enabled = any(
            line == "login"
            or line == "login local"
            or line.startswith("login authentication ")
            for line in block
        )

        password_enabled = any(
            re.match(
                r"^password(?:\s+\d+)?\s+\S+",
                line
            )
            for line in block
        )

        if not no_password_ok:
            weak_reasons.append(
                f"{block_name}: no password 설정 없음"
            )

        if not transport_none_ok:
            weak_reasons.append(
                f"{block_name}: transport input none 설정 없음"
            )

        if not no_exec_ok:
            weak_reasons.append(
                f"{block_name}: no exec 설정 없음"
            )

        if not timeout_ok:
            weak_reasons.append(
                f"{block_name}: exec-timeout 0 1 설정 없음"
            )

        if auth_enabled:
            weak_reasons.append(
                f"{block_name}: 로그인 인증 활성화"
            )

        if password_enabled:
            weak_reasons.append(
                f"{block_name}: 일반 password 설정 존재"
            )

    if weak_reasons:
        return (
            "취약",
            "; ".join(weak_reasons)
        )

    return (
        "양호",
        "모든 AUX 라인이 접속 및 명령 실행 불가 상태로 "
        "비활성화되어 있습니다."
    )
    
    def n_11(self):
        syslog_enable = False
        remote_logging = False
        trap_level_ok = False
        ok_trap_levels = ["informational", "notifications"]
        for line in self.show_logging.splitlines():
            line = line.strip()
            if re.match(r"^Syslog logging:\s+enabled", line): syslog_enable = True
            if re.match(r"^Logging to\s+\d{1,3}(\.\d{1,3}){3}", line): remote_logging = True
            m = re.match(r"^Trap logging:\s+level\s+(\S+)", line)
            if m:
                trap_level = m.group(1).lower().rstrip(",")
                if trap_level in ok_trap_levels: trap_level_ok = True
        
        if syslog_enable and remote_logging and trap_level_ok:
            return ("양호", "Syslog, Remote Logging 및 적절한 Trap level이 설정됨")
        return ("취약", "Syslog, Remote Logging 또는 Trap level 설정 확인 필요")

    def n_13(self):
        pattern = r"^Log Buffer.*?\((\d+)\s+bytes\)"
        for line in self.show_logging.splitlines():
            m = re.match(pattern, line.strip())
            if m:
                log_size = int(m.group(1))
                if 16384 <= log_size <= 32768:
                    return ("양호", f"Log Buffer 사이즈 적정: {log_size} bytes")
        return ("취약", "Log Buffer 사이즈 미설정 또는 범위를 벗어남")

    def n_16(self):
        if ("clock timezone KST 9" in self.show_run and 
            "service timestamps debug datetime msec localtime show-timezone" in self.show_run and 
            "service timestamps log datetime msec localtime show-timezone" in self.show_run):
            return ("양호", "시간대 및 타임스탬프 설정이 정상입니다.")
        return ("취약", "시간대 또는 타임스탬프 설정이 미흡합니다.")
    
    def n_17(self):
        if "snmp-server community" in self.show_run:
            return ("취약", "SNMP community 설정이 존재함")
        return ("양호", "SNMP community 설정이 없음")

    def n_18(self):
        pattern = r"^snmp-server community\s+(\S+)\s+\S+.*"
        for line in self.show_run.splitlines():
            line = line.strip()
            m = re.match(pattern, line)
            if m:
                community_string = m.group(1)
                combined_count = 0
                if re.search(r"[A-Za-z]", community_string): combined_count += 1
                if re.search(r"[0-9]", community_string): combined_count += 1
                if re.search(r"[^A-Za-z0-9]", community_string): combined_count += 1
                
                if len(community_string) < 8 or combined_count < 2:
                    return ("취약", f"SNMP 커뮤니티 문자열 복잡도 미흡: {community_string}")
        return ("양호", "모든 SNMP 커뮤니티 문자열이 복잡도를 만족합니다.")

    def n_20(self):
        pattern = r"^snmp-server community\s+\S+\s+(RO|RW).*"
        for line in self.show_run.splitlines():
            m = re.match(pattern, line.strip())
            if m and m.group(1) == "RW":
                return ("취약", "SNMP RW(Write) 권한이 설정되어 있습니다.")
        return ("양호", "SNMP RW 권한이 없습니다.")

    def n_21(self):
        if "service config" in self.show_run:
            return ("취약", "자동 설정(service config) 기능이 활성화되어 있습니다.")
        return ("양호", "자동 설정 기능이 비활성화되어 있습니다.")

    def n_25(self):
        if "service tcp-keepalives-in" in self.show_run and "service tcp-keepalives-out" in self.show_run:
            return ("양호", "TCP Keepalive 설정이 활성화되어 있습니다.")
        return ("취약", "TCP Keepalive 설정이 미흡합니다.")

    def n_26(self):
        if "ip finger" in self.show_run:
            return ("취약", "Finger 서비스가 활성화되어 있습니다.")
        return ("양호", "Finger 서비스가 비활성화되어 있습니다.")

    def n_27(self):
        if "no ip http server" in self.show_run and "no ip http secure-server" in self.show_run:
            return ("양호", "HTTP/HTTPS 서버가 비활성화되어 있습니다.")
        return ("취약", "HTTP/HTTPS 서버 설정 확인이 필요합니다.")

    def n_28(self):
        if "service tcp-small-servers" in self.show_run or "service udp-small-servers" in self.show_run:
            return ("취약", "불필요한 Small Server 서비스가 활성화되어 있습니다.")
        return ("양호", "Small Server 서비스가 비활성화되어 있습니다.")

    def n_29(self):
        if "no ip bootp server" in self.show_run and "ip dhcp bootp ignore" in self.show_run:
            return ("양호", "BOOTP 설정이 안전합니다.")
        return ("취약", "BOOTP 설정이 미흡합니다.")

    def n_30(self):
        if "no cdp run" in self.show_run:
            return ("양호", "CDP가 비활성화되어 있습니다.")
        return ("취약", "CDP가 활성화되어 있습니다.")

    def n_31(self):
        if "ip directed-broadcast" in self.show_run:
            return ("취약", "Directed-broadcast가 활성화되어 있습니다.")
        return ("양호", "Directed-broadcast가 비활성화되어 있습니다.")

    def n_32(self):
        if "no ip source-route" in self.show_run:
            return ("양호", "Source-route가 비활성화되어 있습니다.")
        return ("취약", "Source-route가 활성화되어 있습니다.")

    def n_34(self):
        for intf in self._get_l3_int():
            if "no ip unreachables" not in intf or "no ip redirects" not in intf:
                return ("취약", "인터페이스에 Unreachables/Redirects 설정이 미흡합니다.")
        return ("양호", "모든 인터페이스 설정이 양호합니다.")

    def n_35(self):
        if "ip identd" in self.show_run:
            return ("취약", "Identd 서비스가 활성화되어 있습니다.")
        return ("양호", "Identd 서비스가 비활성화되어 있습니다.")
    
    def n_36(self):
        if "no ip domain lookup" in self.show_run:
            return ("양호", "DNS 룩업 비활성화됨")
        return ("취약", "DNS 룩업 활성화됨")

    def n_37(self):
        if "no service pad" in self.show_run:
            return ("양호", "PAD 서비스가 비활성화되어 있습니다.")
        return ("취약", "PAD 서비스가 활성화되어 있습니다.")

    def n_38(self):
        for intf in self._get_l3_int():
            if "ip mask-reply" in intf:
                return ("취약", "일부 인터페이스에 Mask-reply가 활성화되어 있습니다.")
        return ("양호", "모든 인터페이스에서 Mask-reply가 비활성화되어 있습니다.")
