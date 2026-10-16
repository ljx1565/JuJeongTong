"""
PC 취약점 점검 (PC-01 ~ PC-18)
2026 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 Chapter 07 기준.

대상: Windows 10, Windows 11
접속: SSH + PowerShell (windows_server.py 와 동일한 방식)

반환 규격은 team_works/result_spec.py 를 따른다.
    return (status, reason)
    status: 양호 / 취약 / 해당없음 / 검토필요 / 오류
"""

# ReportManager 는 windows_server.py 의 것을 재사용한다 (표 출력 형식 통일).
try:
    from .windows_server import ReportManager
except Exception:  # 단독 실행 등으로 import 가 안 되는 경우
    try:
        from windows_server import ReportManager
    except Exception:
        class ReportManager:
            def __init__(self, target_ip=""):
                self.target_ip = target_ip
                self.json_data = []

            def print_result(self, code, title, status):
                print(f"| {code:<8} | {title:<48} | {status:<6} |")
                self.json_data.append(
                    {"항목코드": code, "점검항목": title, "진단결과": status}
                )


# PC-05 판단 기준이 되는 '일반적으로 불필요한 서비스' 목록 (가이드 567~568p)
UNNECESSARY_SERVICES = {
    "Alerter": "관리용 경고 메시지 전송",
    "ClipSrv": "Clipbook 공유",
    "Browser": "네트워크 컴퓨터 목록 관리",
    "Dhcp": "고정 IP 사용 시 불필요",
    "TrkWks": "Distributed Link Tracking Client",
    "ErrSvc": "오류 보고 서비스",
    "hidserv": "Human Interface Device Access",
    "ImapiService": "IMAPI CD-Burning COM Service",
    "Messenger": "netsend 및 경고 서비스 메시지 전송",
    "WMPNetworkSvc": "미디어 공유",
    "Spooler": "프린터 미연결 시 불필요",
    "RemoteRegistry": "원격 레지스트리 수정 허용",
    "SimpTcp": "Simple TCP/IP Services",
    "upnphost": "Universal Plug and Play Device Host",
    "WZCSVC": "Wireless Zero Configuration",
}

# PC-06 판단 기준이 되는 상용 메신저 (가이드 570p)
COMMERCIAL_MESSENGERS = ["카카오톡", "KakaoTalk", "네이트온", "NateOn",
                         "Skype", "Telegram", "Discord", "Line"]


class PC:
    """PC 취약점 점검 항목을 main.py 규격으로 노출한다."""

    requires_ssh = True

    check_list = {
        # 1. 계정 관리
        "pc_01": {"code": "PC-01", "title": "비밀번호의 주기적 변경"},
        "pc_02": {"code": "PC-02", "title": "비밀번호 관리정책 설정"},
        "pc_03": {"code": "PC-03", "title": "복구 콘솔에서 자동 로그온을 금지하도록 설정"},
        # 2. 서비스 관리
        "pc_04": {"code": "PC-04", "title": "공유 폴더 제거"},
        "pc_05": {"code": "PC-05", "title": "항목의 불필요한 서비스 제거"},
        "pc_06": {"code": "PC-06", "title": "비인가 상용 메신저 사용 금지"},
        "pc_07": {"code": "PC-07", "title": "파일 시스템이 NTFS 포맷으로 설정"},
        "pc_08": {"code": "PC-08", "title": "다른 OS로 멀티 부팅이 가능하지 않도록 설정"},
        "pc_09": {"code": "PC-09", "title": "브라우저 종료 시 임시 인터넷 파일 폴더의 내용을 삭제하도록 설정"},
        # 3. 패치 관리
        "pc_10": {"code": "PC-10", "title": "주기적 보안 패치 및 벤더 권고사항 적용"},
        "pc_11": {"code": "PC-11", "title": "지원이 종료되지 않은 Windows OS Build 적용"},
        # 4. 보안 관리
        "pc_12": {"code": "PC-12", "title": "Windows 자동 로그인 점검"},
        "pc_13": {"code": "PC-13", "title": "바이러스 백신 프로그램 설치 및 주기적 업데이트"},
        "pc_14": {"code": "PC-14", "title": "바이러스 백신 프로그램에서 제공하는 실시간 감시 기능 활성화"},
        "pc_15": {"code": "PC-15", "title": "OS에서 제공하는 침입차단 기능 활성화"},
        "pc_16": {"code": "PC-16", "title": "화면보호기 대기 시간 설정 및 재시작 시 암호 보호 설정"},
        "pc_17": {"code": "PC-17", "title": "이동식 미디어의 자동 실행 방지 등 보안대책 수립"},
        "pc_18": {"code": "PC-18", "title": "원격 지원을 금지하도록 정책을 설정"},
    }

    def __init__(self, conn, report_mgr=None):
        self.conn = conn
        self.report = report_mgr or ReportManager(getattr(conn, "hostname", ""))

    # ------------------------------------------------------------------
    # 공통 헬퍼
    # ------------------------------------------------------------------
    def _run(self, ps_script):
        """PowerShell 실행 결과를 문자열로 반환한다."""
        output = self.conn.execute_cmd(ps_script)
        return (output or "").strip()

    def _failed(self, output):
        """명령 실행 자체가 실패했는지 판단한다."""
        return (not output) or output.startswith("ERROR:")

    def _finish(self, key, status, issues, good_reason=None):
        """판정 결과를 표에 출력하고 (status, reason) 규격으로 돌려준다."""
        meta = self.check_list[key]
        self.report.print_result(meta["code"], meta["title"], status)

        if issues:
            reason = "; ".join(issues)
        elif good_reason:
            reason = good_reason
        else:
            reason = "점검 기준을 충족합니다."

        return status, reason

    def _net_accounts_value(self, *keywords):
        """`net accounts` 출력에서 지정한 키워드가 있는 줄의 값을 뽑는다."""
        conditions = " -or ".join(f"$_ -match '{kw}'" for kw in keywords)
        ps_script = (
            "$acc = net accounts; "
            f"$line = $acc | Where-Object {{ {conditions} }}; "
            "if ($line) { ($line -split ':')[-1].Trim() } else { '' }"
        )
        return self._run(ps_script)

    # ==================================================================
    # 1. 계정 관리
    # ==================================================================
    def pc_01(self):  # PC-01: 비밀번호의 주기적 변경
        issues = []

        raw = self._net_accounts_value("Maximum password age", "최대 암호 사용 기간")

        if self._failed(raw):
            return self._finish("pc_01", "오류",
                                [f"최대 암호 사용 기간 조회 실패 (정보: {raw})"])

        # "Unlimited" / "제한 없음" 이면 만료가 없다는 뜻이라 취약
        if ("unlimited" in raw.lower()) or ("제한 없음" in raw) or ("없음" in raw):
            issues.append(f"최대 암호 사용 기간이 '제한 없음'으로 설정됨 (현재 값: {raw})")
            return self._finish("pc_01", "취약", issues)

        digits = "".join(ch for ch in raw if ch.isdigit())
        if not digits:
            return self._finish("pc_01", "오류",
                                [f"최대 암호 사용 기간 값을 해석할 수 없음 (원본: {raw})"])

        max_age = int(digits)
        if max_age > 90:
            issues.append(f"최대 암호 사용 기간이 {max_age}일로 기준(90일 이하)을 초과함")

        status = "취약" if issues else "양호"
        return self._finish("pc_01", status, issues,
                            f"최대 암호 사용 기간 {max_age}일 (기준: 90일 이하)")

    def pc_02(self):  # PC-02: 비밀번호 관리정책 설정
        issues = []
        details = []

        # 최소 암호 길이
        raw_len = self._net_accounts_value("Minimum password length", "최소 암호 길이")
        digits = "".join(ch for ch in raw_len if ch.isdigit())

        if self._failed(raw_len) or not digits:
            issues.append(f"최소 암호 길이 조회 실패 (정보: {raw_len})")
        else:
            min_len = int(digits)
            details.append(f"최소 암호 길이 {min_len}자")
            if min_len < 8:
                issues.append(f"최소 암호 길이가 {min_len}자로 기준(8자 이상) 미만")

        # 복잡성 만족 여부 (로컬 보안 정책을 내보내 PasswordComplexity 값을 확인)
        ps_script = (
            "$tmp = [System.IO.Path]::GetTempFileName(); "
            "secedit /export /cfg $tmp /areas SECURITYPOLICY | Out-Null; "
            "$line = Select-String -Path $tmp -Pattern 'PasswordComplexity'; "
            "Remove-Item $tmp -Force -ErrorAction SilentlyContinue; "
            "if ($line -match '(\\d+)\\s*$') { $Matches[1] } else { '' }"
        )
        complexity = self._run(ps_script)

        if self._failed(complexity):
            issues.append(f"암호 복잡성 정책 조회 실패 (정보: {complexity})")
        elif complexity.strip() != "1":
            issues.append("'암호는 복잡성을 만족해야 함' 정책이 '사용 안 함' 상태")
        else:
            details.append("복잡성 정책 사용")

        status = "취약" if issues else "양호"
        return self._finish("pc_02", status, issues, ", ".join(details))

    def pc_03(self):  # PC-03: 복구 콘솔에서 자동 로그온을 금지하도록 설정
        issues = []

        ps_script = (
            "$p = 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Setup\\RecoveryConsole'; "
            "if (Test-Path $p) { "
            "  $v = (Get-ItemProperty -Path $p -Name SecurityLevel -ErrorAction SilentlyContinue).SecurityLevel; "
            "  if ($null -eq $v) { 'NOTSET' } else { $v } "
            "} else { 'NOPATH' }"
        )
        value = self._run(ps_script)

        if self._failed(value):
            return self._finish("pc_03", "오류",
                                [f"복구 콘솔 설정 조회 실패 (정보: {value})"])

        # 키/값이 없으면 자동 로그온이 설정되지 않은 것이므로 양호
        if value in ("NOPATH", "NOTSET"):
            return self._finish("pc_03", "양호", [],
                                "복구 콘솔 자동 로그온 설정이 없어 기본값(사용 안 함) 상태")

        if value.strip() != "0":
            issues.append(f"복구 콘솔 자동 로그온 허용이 '사용'으로 설정됨 (SecurityLevel={value})")

        status = "취약" if issues else "양호"
        return self._finish("pc_03", status, issues,
                            "복구 콘솔 자동 로그온 허용이 '사용 안 함'으로 설정됨")

    # ==================================================================
    # 2. 서비스 관리
    # ==================================================================
    def pc_04(self):  # PC-04: 공유 폴더 제거
        issues = []

        # 기본 공유(C$, D$, ADMIN$) 및 일반 공유 목록 조회 (IPC$ 는 제외 불가라 제외)
        ps_script = (
            "Get-SmbShare -ErrorAction SilentlyContinue | "
            "Where-Object { $_.Name -ne 'IPC$' } | "
            "ForEach-Object { $_.Name }"
        )
        shares_raw = self._run(ps_script)

        if shares_raw.startswith("ERROR:"):
            return self._finish("pc_04", "오류",
                                [f"공유 폴더 조회 실패 (정보: {shares_raw})"])

        shares = [s.strip() for s in shares_raw.splitlines() if s.strip()]

        if not shares:
            return self._finish("pc_04", "양호", [], "공유 폴더가 존재하지 않음")

        default_shares = [s for s in shares if s.endswith("$")]
        normal_shares = [s for s in shares if not s.endswith("$")]

        if default_shares:
            issues.append(f"기본 공유 폴더 존재: {', '.join(default_shares)}")

        # 자동 공유 방지 레지스트리 확인
        ps_auto = (
            "$p = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters'; "
            "$v = (Get-ItemProperty -Path $p -Name AutoShareWks -ErrorAction SilentlyContinue).AutoShareWks; "
            "if ($null -eq $v) { 'NOTSET' } else { $v }"
        )
        auto_share = self._run(ps_auto)
        if auto_share in ("NOTSET", "1"):
            issues.append("AutoShareWks 값이 0으로 설정되지 않아 재부팅 시 기본 공유가 자동 생성됨")

        # 일반 공유의 Everyone 권한 확인
        for share in normal_shares:
            ps_acl = (
                f"(Get-SmbShareAccess -Name '{share}' -ErrorAction SilentlyContinue | "
                "Where-Object { $_.AccountName -match 'Everyone' -and "
                "$_.AccessControlType -eq 'Allow' }).Count"
            )
            everyone = self._run(ps_acl)
            if everyone.isdigit() and int(everyone) > 0:
                issues.append(f"공유 폴더 '{share}' 접근 권한에 Everyone 허용이 존재함")

        status = "취약" if issues else "양호"
        return self._finish("pc_04", status, issues,
                            f"공유 폴더 {len(shares)}개 확인, 기준 위반 없음")

    def pc_05(self):  # PC-05: 항목의 불필요한 서비스 제거
        issues = []

        names = ",".join(f"'{n}'" for n in UNNECESSARY_SERVICES)
        ps_script = (
            f"$targets = @({names}); "
            "Get-Service -ErrorAction SilentlyContinue | "
            "Where-Object { $targets -contains $_.Name -and $_.Status -eq 'Running' } | "
            "ForEach-Object { $_.Name }"
        )
        running_raw = self._run(ps_script)

        if running_raw.startswith("ERROR:"):
            return self._finish("pc_05", "오류",
                                [f"서비스 목록 조회 실패 (정보: {running_raw})"])

        running = [s.strip() for s in running_raw.splitlines() if s.strip()]

        for name in running:
            desc = UNNECESSARY_SERVICES.get(name, "")
            issues.append(f"{name} 서비스 실행 중" + (f" ({desc})" if desc else ""))

        status = "취약" if issues else "양호"
        return self._finish("pc_05", status, issues,
                            f"불필요 서비스 {len(UNNECESSARY_SERVICES)}종 중 실행 중인 항목 없음")

    def pc_06(self):  # PC-06: 비인가 상용 메신저 사용 금지
        issues = []

        # 설치 프로그램 목록(32/64비트 모두)에서 상용 메신저 탐지
        patterns = "|".join(COMMERCIAL_MESSENGERS)
        ps_script = (
            "$paths = @("
            "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
            "'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'); "
            "Get-ItemProperty -Path $paths -ErrorAction SilentlyContinue | "
            "Where-Object { $_.DisplayName -match '" + patterns + "' } | "
            "ForEach-Object { $_.DisplayName } | Sort-Object -Unique"
        )
        installed_raw = self._run(ps_script)

        if installed_raw.startswith("ERROR:"):
            return self._finish("pc_06", "오류",
                                [f"설치 프로그램 조회 실패 (정보: {installed_raw})"])

        installed = [s.strip() for s in installed_raw.splitlines() if s.strip()]
        if installed:
            issues.append(f"상용 메신저 설치 확인: {', '.join(installed)}")

        status = "취약" if issues else "양호"
        return self._finish("pc_06", status, issues,
                            "설치된 상용 메신저가 확인되지 않음")

    def pc_07(self):  # PC-07: 파일 시스템이 NTFS 포맷으로 설정
        issues = []

        # 고정 디스크(DriveType=3) 볼륨의 파일 시스템 확인
        ps_script = (
            "Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' | "
            "ForEach-Object { \"$($_.DeviceID)=$($_.FileSystem)\" }"
        )
        volumes_raw = self._run(ps_script)

        if self._failed(volumes_raw):
            return self._finish("pc_07", "오류",
                                [f"디스크 볼륨 조회 실패 (정보: {volumes_raw})"])

        volumes = [v.strip() for v in volumes_raw.splitlines() if v.strip()]
        for volume in volumes:
            drive, _, fs = volume.partition("=")
            if fs and fs.upper() != "NTFS":
                issues.append(f"{drive} 볼륨의 파일 시스템이 {fs} (NTFS 아님)")

        status = "취약" if issues else "양호"
        return self._finish("pc_07", status, issues,
                            f"고정 디스크 {len(volumes)}개 모두 NTFS")

    def pc_08(self):  # PC-08: 멀티 부팅이 가능하지 않도록 설정
        issues = []

        # 부팅 항목 개수 확인 (bcdedit 의 osdevice 항목 수)
        ps_script = (
            "$out = bcdedit /enum osloader 2>$null; "
            "if (-not $out) { $out = bcdedit /enum 2>$null }; "
            "($out | Select-String -Pattern '^osdevice').Count"
        )
        count_raw = self._run(ps_script)

        if self._failed(count_raw) or not count_raw.isdigit():
            # bcdedit 는 관리자 권한이 필요해 실패할 수 있다
            return self._finish("pc_08", "검토필요",
                                [f"부팅 항목 조회 불가 (관리자 권한 필요 가능, 정보: {count_raw})"])

        os_count = int(count_raw)
        if os_count > 1:
            issues.append(f"부팅 가능한 OS가 {os_count}개 확인됨 (멀티 부팅 상태)")

        status = "취약" if issues else "양호"
        return self._finish("pc_08", status, issues, "설치된 OS가 1개")

    def pc_09(self):  # PC-09: 브라우저 종료 시 임시 인터넷 파일 폴더 삭제
        issues = []

        # Cache\Persistent = 0 이면 '브라우저를 닫을 때 임시 인터넷 파일 폴더 비우기' 사용
        ps_script = (
            "$p = 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Cache'; "
            "$v = (Get-ItemProperty -Path $p -Name Persistent -ErrorAction SilentlyContinue).Persistent; "
            "if ($null -eq $v) { 'NOTSET' } else { $v }"
        )
        value = self._run(ps_script)

        if value.startswith("ERROR:"):
            return self._finish("pc_09", "오류",
                                [f"임시 인터넷 파일 설정 조회 실패 (정보: {value})"])

        if value == "NOTSET" or value.strip() != "0":
            issues.append(
                "'브라우저를 닫을 때 임시 인터넷 파일 폴더 비우기'가 사용으로 설정되지 않음"
            )

        status = "취약" if issues else "양호"
        # HKCU 는 SSH 접속 계정 기준이라 다른 사용자 프로필은 별도 확인이 필요하다
        note = "(SSH 접속 계정 기준 HKCU 값이며 타 사용자 프로필은 별도 확인 필요)"
        return self._finish("pc_09", status,
                            [i + " " + note for i in issues] if issues else [],
                            "임시 인터넷 파일 폴더 비우기 사용 " + note)

    # ==================================================================
    # 3. 패치 관리
    # ==================================================================
    def pc_10(self):  # PC-10: 주기적 보안 패치 및 벤더 권고사항 적용
        issues = []
        details = []

        # 마지막 핫픽스 설치일
        ps_hotfix = (
            "$h = Get-HotFix -ErrorAction SilentlyContinue | "
            "Sort-Object InstalledOn -Descending | Select-Object -First 1; "
            "if ($h -and $h.InstalledOn) { $h.InstalledOn.ToString('yyyy-MM-dd') } else { 'NONE' }"
        )
        last_patch = self._run(ps_hotfix)

        # 자동 업데이트 설정 (Windows Update 서비스 시작 유형)
        ps_wu = "(Get-Service -Name wuauserv -ErrorAction SilentlyContinue).StartType"
        wu_start = self._run(ps_wu)

        if self._failed(last_patch):
            issues.append(f"설치된 패치 목록 조회 실패 (정보: {last_patch})")
        elif last_patch == "NONE":
            issues.append("설치된 보안 패치 이력이 확인되지 않음")
        else:
            details.append(f"최근 패치 설치일 {last_patch}")

        if wu_start and not wu_start.startswith("ERROR:"):
            details.append(f"Windows Update 서비스 시작 유형 {wu_start}")
            if wu_start.strip().lower() == "disabled":
                issues.append("Windows Update 서비스가 '사용 안 함'으로 설정됨")

        if issues:
            return self._finish("pc_10", "취약", issues)

        # 내부 패치 관리 절차 수립 여부는 자동 판정 대상이 아니다 (가이드 판단 기준)
        return self._finish(
            "pc_10", "검토필요", [],
            ", ".join(details) + " / 내부 패치 관리 절차 수립 여부는 담당자 확인 필요"
        )

    def pc_11(self):  # PC-11: 지원이 종료되지 않은 Windows OS Build 적용
        ps_script = (
            "$os = Get-CimInstance -ClassName Win32_OperatingSystem; "
            "$dv = Get-ItemProperty -Path "
            "'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' "
            "-ErrorAction SilentlyContinue; "
            "\"$($os.Caption)|$($dv.DisplayVersion)|$($os.BuildNumber).$($dv.UBR)\""
        )
        raw = self._run(ps_script)

        if self._failed(raw) or "|" not in raw:
            return self._finish("pc_11", "오류",
                                [f"OS 빌드 정보 조회 실패 (정보: {raw})"])

        caption, display_version, build = (raw.split("|") + ["", "", ""])[:3]
        info = f"{caption.strip()} (버전 {display_version.strip()}, 빌드 {build.strip()})"

        # 지원 종료된 구버전은 명확히 취약으로 판정
        expired_keywords = ["Windows 7", "Windows 8", "Windows XP", "Windows Vista"]
        for keyword in expired_keywords:
            if keyword in caption:
                return self._finish("pc_11", "취약",
                                    [f"지원이 종료된 OS 사용 중: {info}"])

        # Windows 10/11 은 빌드별 지원 종료일이 계속 바뀌므로 자동 판정하지 않는다
        return self._finish(
            "pc_11", "검토필요", [],
            f"{info} — Microsoft 릴리스 상태 페이지에서 지원 종료 여부 확인 필요"
        )

    # ==================================================================
    # 4. 보안 관리
    # ==================================================================
    def pc_12(self):  # PC-12: Windows 자동 로그인 점검
        issues = []

        ps_script = (
            "$p = 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'; "
            "$v = (Get-ItemProperty -Path $p -Name AutoAdminLogon -ErrorAction SilentlyContinue).AutoAdminLogon; "
            "if ($null -eq $v) { 'NOTSET' } else { $v }"
        )
        value = self._run(ps_script)

        if self._failed(value):
            return self._finish("pc_12", "오류",
                                [f"자동 로그인 설정 조회 실패 (정보: {value})"])

        # 가이드: 별도 설정을 하지 않았다면 레지스트리가 없으며 이 경우 양호
        if value == "NOTSET":
            return self._finish("pc_12", "양호", [],
                                "AutoAdminLogon 레지스트리가 없어 자동 로그인 비활성 상태")

        if value.strip() != "0":
            issues.append(f"Windows 자동 로그인이 활성화됨 (AutoAdminLogon={value})")

        status = "취약" if issues else "양호"
        return self._finish("pc_12", status, issues,
                            "AutoAdminLogon 값이 0으로 설정됨")

    def pc_13(self):  # PC-13: 바이러스 백신 설치 및 주기적 업데이트
        issues = []

        # SecurityCenter2 에 등록된 백신 제품 목록
        ps_script = (
            "Get-CimInstance -Namespace 'root/SecurityCenter2' "
            "-ClassName AntiVirusProduct -ErrorAction SilentlyContinue | "
            "ForEach-Object { $_.displayName }"
        )
        products_raw = self._run(ps_script)

        if products_raw.startswith("ERROR:"):
            return self._finish("pc_13", "오류",
                                [f"백신 제품 조회 실패 (정보: {products_raw})"])

        products = [p.strip() for p in products_raw.splitlines() if p.strip()]
        if not products:
            return self._finish("pc_13", "취약", ["설치된 바이러스 백신이 확인되지 않음"])

        # Windows Defender 사용 시 시그니처 최신 여부까지 확인
        ps_defender = (
            "$s = Get-MpComputerStatus -ErrorAction SilentlyContinue; "
            "if ($s) { \"$($s.AntivirusSignatureAge)|$($s.AntivirusSignatureLastUpdated)\" } "
            "else { 'NOTAVAILABLE' }"
        )
        defender = self._run(ps_defender)

        detail = f"설치된 백신: {', '.join(products)}"

        if defender and not defender.startswith("ERROR:") and defender != "NOTAVAILABLE":
            age_raw = defender.split("|")[0].strip()
            if age_raw.isdigit():
                age = int(age_raw)
                detail += f", 시그니처 경과일 {age}일"
                if age > 7:
                    issues.append(f"백신 시그니처가 {age}일간 갱신되지 않음")
            status = "취약" if issues else "양호"
            return self._finish("pc_13", status, issues, detail)

        # 상용 백신은 갱신 상태를 표준 방식으로 읽을 수 없다
        return self._finish("pc_13", "검토필요", [],
                            detail + " / 업데이트 상태는 백신 콘솔에서 직접 확인 필요")

    def pc_14(self):  # PC-14: 백신 실시간 감시 기능 활성화
        issues = []

        ps_script = (
            "$s = Get-MpComputerStatus -ErrorAction SilentlyContinue; "
            "if ($s) { $s.RealTimeProtectionEnabled } else { 'NOTAVAILABLE' }"
        )
        value = self._run(ps_script)

        if value.startswith("ERROR:"):
            return self._finish("pc_14", "오류",
                                [f"실시간 감시 설정 조회 실패 (정보: {value})"])

        if not value or value == "NOTAVAILABLE":
            return self._finish(
                "pc_14", "검토필요", [],
                "Windows Defender 가 아닌 상용 백신 사용으로 보이며 실시간 감시 여부는 직접 확인 필요"
            )

        if value.strip().lower() != "true":
            issues.append("Windows Defender 실시간 보호 기능이 비활성화됨")

        status = "취약" if issues else "양호"
        return self._finish("pc_14", status, issues,
                            "Windows Defender 실시간 보호 기능 활성화 상태")

    def pc_15(self):  # PC-15: OS에서 제공하는 침입차단 기능 활성화
        issues = []

        ps_script = (
            "Get-NetFirewallProfile -ErrorAction SilentlyContinue | "
            "ForEach-Object { \"$($_.Name)=$($_.Enabled)\" }"
        )
        profiles_raw = self._run(ps_script)

        if self._failed(profiles_raw):
            return self._finish("pc_15", "오류",
                                [f"방화벽 프로필 조회 실패 (정보: {profiles_raw})"])

        profiles = [p.strip() for p in profiles_raw.splitlines() if p.strip()]
        for profile in profiles:
            name, _, enabled = profile.partition("=")
            if enabled.strip().lower() not in ("true", "1"):
                issues.append(f"{name} 프로필의 방화벽이 '사용 안 함' 상태")

        status = "취약" if issues else "양호"
        return self._finish("pc_15", status, issues,
                            f"방화벽 프로필 {len(profiles)}개 모두 사용 중")

    def pc_16(self):  # PC-16: 화면보호기 대기 시간 및 재시작 시 암호 보호
        issues = []
        details = []

        ps_script = (
            "$p = 'HKCU:\\Control Panel\\Desktop'; "
            "$i = Get-ItemProperty -Path $p -ErrorAction SilentlyContinue; "
            "\"$($i.ScreenSaveActive)|$($i.ScreenSaverIsSecure)|$($i.ScreenSaveTimeOut)\""
        )
        raw = self._run(ps_script)

        if self._failed(raw) or "|" not in raw:
            return self._finish("pc_16", "오류",
                                [f"화면보호기 설정 조회 실패 (정보: {raw})"])

        active, secure, timeout = (raw.split("|") + ["", "", ""])[:3]

        if active.strip() != "1":
            issues.append("화면보호기가 설정되어 있지 않음")

        if secure.strip() != "1":
            issues.append("화면보호기 재시작 시 비밀번호 보호가 설정되지 않음")

        timeout = timeout.strip()
        if timeout.isdigit():
            minutes = int(timeout) // 60
            details.append(f"대기 시간 {minutes}분")
            if int(timeout) > 600:
                issues.append(f"대기 시간이 {minutes}분으로 기준(10분 이하)을 초과함")
        else:
            issues.append("화면보호기 대기 시간이 설정되지 않음")

        status = "취약" if issues else "양호"
        note = "(SSH 접속 계정 기준 HKCU 값)"
        return self._finish("pc_16", status,
                            [i + " " + note for i in issues] if issues else [],
                            ", ".join(details) + " " + note)

    def pc_17(self):  # PC-17: 이동식 미디어 자동 실행 방지
        issues = []

        # NoDriveTypeAutoRun 이 255(0xFF)면 모든 드라이브의 자동 실행이 차단된 상태
        ps_script = (
            "$paths = @("
            "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer',"
            "'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer'); "
            "$result = 'NOTSET'; "
            "foreach ($p in $paths) { "
            "  $v = (Get-ItemProperty -Path $p -Name NoDriveTypeAutoRun -ErrorAction SilentlyContinue).NoDriveTypeAutoRun; "
            "  if ($null -ne $v) { $result = $v } "
            "} "
            "$result"
        )
        value = self._run(ps_script)

        if value.startswith("ERROR:"):
            return self._finish("pc_17", "오류",
                                [f"자동 실행 정책 조회 실패 (정보: {value})"])

        if value == "NOTSET":
            issues.append("자동 실행 차단 정책(NoDriveTypeAutoRun)이 설정되지 않음")
        elif value.isdigit():
            flags = int(value)
            # 이동식 드라이브(0x04) / CD-ROM(0x08) 비트가 모두 서 있어야 차단된 것
            if not (flags & 0x04):
                issues.append(f"이동식 드라이브 자동 실행이 차단되지 않음 (값: {flags})")
            if not (flags & 0x08):
                issues.append(f"CD/DVD 드라이브 자동 실행이 차단되지 않음 (값: {flags})")
        else:
            return self._finish("pc_17", "오류",
                                [f"자동 실행 정책 값을 해석할 수 없음 (원본: {value})"])

        status = "취약" if issues else "양호"
        return self._finish("pc_17", status, issues,
                            f"NoDriveTypeAutoRun={value} 로 이동식 미디어 자동 실행 차단됨")

    def pc_18(self):  # PC-18: 원격 지원을 금지하도록 정책을 설정
        issues = []

        ps_script = (
            "$p = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance'; "
            "$v = (Get-ItemProperty -Path $p -Name fAllowToGetHelp -ErrorAction SilentlyContinue).fAllowToGetHelp; "
            "if ($null -eq $v) { 'NOTSET' } else { $v }"
        )
        value = self._run(ps_script)

        if value.startswith("ERROR:"):
            return self._finish("pc_18", "오류",
                                [f"원격 지원 설정 조회 실패 (정보: {value})"])

        if value == "NOTSET":
            issues.append("원격 지원 정책이 명시적으로 '사용 안 함'으로 설정되지 않음")
        elif value.strip() != "0":
            issues.append(f"원격 지원이 '사용'으로 설정됨 (fAllowToGetHelp={value})")

        status = "취약" if issues else "양호"
        return self._finish("pc_18", status, issues,
                            "원격 지원이 '사용 안 함'으로 설정됨")
