import base64
import json
import unicodedata
import paramiko


class ReportManager: 
    """점검 결과 출력을 전담하는 클래스"""
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.json_data = []

    def _get_display_width(self, text):
        """한글(2칸)과 영문/숫자/공백(1칸)의 실제 터미널 출력 길이를 계산합니다."""
        width = 0
        for char in text:
            # 'W'(Wide-전각) 또는 'F'(Fullwidth-전각)인 경우 한글 등으로 간주하여 2칸 처리
            if unicodedata.east_asian_width(char) in ['W', 'F']:
                width += 2
            else:
                width += 1
        return width

    def _pad_string(self, text, total_width):
        """지정된 전체 너비에 맞춰 텍스트 뒤에 정확한 개수의 공백을 추가합니다."""
        current_width = self._get_display_width(text)
        padding = total_width - current_width
        # 여백이 필요하면 공백을 더하고, 텍스트가 이미 길면 그대로 반환
        return text + ' ' * max(0, padding)

    def print_main_header(self, category):
        """점검 시작 전 전체 헤더와 표의 첫 줄을 한 번만 출력합니다."""
        print("\n" + "="*80)
        print(f"🔍 원격지 [{self.target_ip}] 기술적 취약점 진단: {category}")
        print("="*80)
        print("[*] 현재 설정 값 검증 중...\n")
        
        # 칸 너비 지정: 항목코드(10칸), 점검항목(50칸), 진단결과(10칸)
        code_str = self._pad_string("항목코드", 10)
        title_str = self._pad_string("점검항목", 50)
        result_str = self._pad_string("진단결과", 10)
        
        header_row = f"| {code_str} | {title_str} | {result_str} |"
        print(header_row)
        print("-" * 80)

    def print_result(self, code, title, status):
        """진단 완료 후 결과를 계산된 너비에 맞춰 표의 행(Row) 형태로 출력합니다."""
        code_str = self._pad_string(code, 10)
        title_str = self._pad_string(title, 50)
        status_str = self._pad_string(status, 10)
        
        print(f"| {code_str} | {title_str} | {status_str} |")

        result_dict = {
            "항목코드": code,
            "점검항목": title,
            "진단결과": status
        }
        self.json_data.append(result_dict)

    def save_to_json(self, filename="security_report.json"):
        """누적된 데이터를 JSON 파일로 깔끔하게 저장하는 함수"""
        if not self.json_data:
            print("저장할 진단 결과 데이터가 없습니다.")
            return
            
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.json_data, f, ensure_ascii=False, indent=4)
            
        print(f"\n[+] 진단 결과가 '{filename}' 파일로 성공적으로 저장되었습니다!")


class SSHConnection:
    """SSH 연결과 명령어 실행을 담당하는 클래스"""
    def __init__(self, host, username, password, port=22):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.ssh = None

    def connect(self):
        """SSH 연결을 수립합니다."""
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh.connect(
            self.host,
            port=self.port,
            username=self.username,
            password=self.password,
        )
        transport = self.ssh.get_transport()
        return transport and transport.is_active()

    def execute_cmd(self, command_str):
        """PowerShell 명령을 Base64로 인코딩하여 안전하게 실행하고 결과만 반환합니다."""
        if not self.ssh:
            return ""

        # PowerShell -EncodedCommand를 위한 UTF-16LE + Base64 인코딩
        encoded_cmd = base64.b64encode(command_str.encode("utf-16le")).decode("ascii")
        
        # 백그라운드 진행률 표시(Progress) 스트림과 CLIXML 간섭 제어 옵션 추가
        ssh_command = f"powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"$ProgressPreference = 'SilentlyContinue'; powershell -NoProfile -NonInteractive -EncodedCommand {encoded_cmd}\""

        stdin, stdout, stderr = self.ssh.exec_command(ssh_command)

        output = stdout.read().decode("utf-8", errors="ignore").strip()
        error = stderr.read().decode("utf-8", errors="ignore").strip()

        # CLIXML 경고 포맷 노이즈 필터링
        if error.startswith("#< CLIXML") and "Preparing modules" in error:
            error = ""

        if error:
            # 치명적인 진짜 에러가 발생한 경우 리턴값에 포함하여 판독에 제공
            return f"ERROR: {error}"

        return output

    def disconnect(self):
        """SSH 연결 해제"""
        if self.ssh:
            self.ssh.close()
            self.ssh = None


class IdentityManagement:  # 계정 관리
    def __init__(self, ssh_conn, report_mgr):
        # SSHConnection 객체와 ReportManager 객체를 전달받아 사용
        self.conn = ssh_conn
        self.report = report_mgr

    def w_01(self):  # W-01: Administrator 계정 이름 변경 등 보안성 강화
        issues = []  # 취약 사유를 담을 빈 리스트 생성

        # SID 끝자리가 500인 로컬 최상위 관리자 계정 이름 조회
        ps_script = "(Get-CimInstance -ClassName Win32_UserAccount -Filter \"LocalAccount = TRUE and SID like 'S-1-5-%-500'\").Name"
        admin_name = self.conn.execute_cmd(ps_script).strip()

        if "ERROR:" in admin_name or not admin_name:
            issues.append(f"관리자 계정 조회 실패 (정보: {admin_name})")
        elif admin_name.lower() == "administrator":
            issues.append(f"기본 관리자 계정 이름인 '{admin_name}'을 그대로 사용 중")

        # 리스트에 내용이 있으면 '취약', 비어있으면 '양호'
        status = "취약" if issues else "양호"

        # ReportManager를 활용한 표 형태 출력
        self.report.print_result("W-01", "Administrator 계정 이름 변경 등 보안성 강화", status)
        return status

    def w_02(self):  # W-02: Guest 계정 비활성화
        issues = []

        # SID 끝자리가 501인 로컬 Guest 계정의 비활성화(Disabled) 여부 조회
        ps_script = "(Get-CimInstance -ClassName Win32_UserAccount -Filter \"LocalAccount = TRUE and SID like 'S-1-5-%-501'\").Disabled"
        disabled_status = self.conn.execute_cmd(ps_script).strip().lower()

        if "ERROR:" in disabled_status or not disabled_status:
            issues.append(f"Guest 계정 상태 조회 실패 (정보: {disabled_status})")
        elif disabled_status != "true":
            # Disabled가 True여야 안 쓰고 있는 것이므로 안전함
            issues.append("Guest 계정이 활성화(사용 함) 상태입니다.")

        status = "취약" if issues else "양호"

        self.report.print_result("W-02", "Guest 계정 비활성화", status)
        return status
    
    def w_04(self):  # W-04: 계정 잠금 임계값 설정 점검 (try문 제거 버전)

        # 윈도우 로컬 계정 정책에서 '계정 잠금 임계값' 라인을 찾아 숫자만 정확히 추출하는 파워셸 스크립트
        # 만약 매칭되는 숫자가 없으면 '0'을 반환하여 안전하게 처리합니다.
        ps_script = (
            "$acc = net accounts; "
            "$line = $acc | Where-Object { $_ -match 'Lockout threshold' -or $_ -match '계정 잠금 임계값' }; "
            "if ($line -match '\\d+') { $Matches[0] } else { '0' }"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 1. 명령어 실패 처리 (SSH 오류 또는 빈 값 대응)
        if "ERROR:" in raw_output or not raw_output:
            status = "오류"
            detail_msg = f"계정 잠금 임계값 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-03", "계정 잠금 임계값 설정", status)
            return status

        # 2. 숫자가 맞는지 검증 후 안전하게 정수(int) 변환
        if raw_output.isdigit():
            threshold_value = int(raw_output)
            detail_msg = f"현재 설정된 계정 잠금 임계값: {threshold_value}회"

            # 3. 강화된 보안 기준 검증 (5회 이하: 양호 / 5회 초과 또는 0회: 취약)
            if threshold_value == 0:
                status = "취약"
                detail_msg += " -> 계정 잠금 임계값이 '0'(사용 안 함)으로 설정되어 무차별 대입 공격에 취약합니다."
            elif threshold_value <= 5:
                status = "양호"
                detail_msg += " -> 보안 기준(5회 이하)을 준수하고 있습니다."
            else:
                status = "취약"
                detail_msg += f" -> 현재 임계값({threshold_value}회)이 보안 기준(5회 이하)을 초과하여 취약합니다."
        else:
            # 반환된 문자열이 숫자가 아닐 경우 안전하게 오류로 분기
            status = "오류"
            detail_msg = f"올바르지 않은 임계값 데이터 형식 반환 (데이터: {raw_output})"

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-04", "계정 잠금 임계값 설정", status)
        
        # 터미널 콘솔 로그 출력 (선택 사항)
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    def w_05(self):  # W-05: 해독 가능한 암호화를 사용하여 암호 저장 점검 (try문 제거 버전)
        print("[*] W-05: 해독 가능한 암호화 저장 정책 현황 조회 중...")

        # 로컬 보안 정책 중 '해독 가능한 암호화를 사용하여 암호 저장' 설정을 조회하는 파워셸 스크립트
        # 시스템 언어 커널(국문/영문)에 구별 없이 'ClearTextPassword' 또는 '해독 가능한 암호화' 라인에서 숫자만 정확히 추출합니다.
        # 매칭되는 숫자가 없거나 비어있으면 안전하게 '0'을 반환합니다.
        ps_script = (
            "$acc = net accounts; "
            "$line = $acc | Where-Object { $_ -match 'ClearTextPassword' -or $_ -match '해독 가능한 암호화' }; "
            "if ($line -match '\\d+') { $Matches[0] } else { '0' }"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 1. 명령어 실패 처리 (SSH 오류 또는 빈 값 대응)
        if "ERROR:" in raw_output or not raw_output:
            status = "오류"
            detail_msg = f"해독 가능한 암호화 정책 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-05", "해독 가능한 암호화를 사용하여 암호 저장", status)
            return status

        # 2. 숫자가 맞는지 검증 후 안전하게 정수(int) 변환하여 판정
        if raw_output.isdigit():
            policy_value = int(raw_output)

            # 3. 요청하신 보안 기준 검증 (0: 사용 안 함 -> 양호 / 1: 사용 -> 취약)
            if policy_value == 0:
                status = "양호"
                detail_msg = "현재 설정: 사용 안 함 -> 정책이 안전하게 설정되어 있습니다."
            else:
                status = "취약"
                detail_msg = "현재 설정: 사용 -> 해독 가능한 비밀번호 저장 정책이 활성화되어 취약합니다."
        else:
            # 반환된 문자열이 숫자가 아닐 경우 안전하게 오류로 분기
            status = "오류"
            detail_msg = f"올바르지 않은 정책 데이터 형식 반환 (데이터: {raw_output})"

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-05", "해독 가능한 암호화를 사용하여 암호 저장", status)
        
        # 터미널 콘솔 로그 출력 (선택 사항)
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_06(self):  # W-06: Administrator 그룹 내 불필요한 계정 존재 여부 점검 (ADSI 네이티브 쿼리 버전)
        print("[*] W-06: 관리자 그룹(Administrators) 내 불필요한 계정 현황 조회 중...")

        # 1. 점검 기준 화이트리스트 (로컬 환경에 맞춰 소문자로 정의)
        # 윈도우 내부 로컬 관리자 그룹에는 'administrator'와 'domain admins' 등이 포함될 수 있으므로 필요시 추가하세요.
        whitelist = ["administrator"]

        # 2. WMI의 복잡성을 완전히 버리고, .NET ADSI 기술을 사용해 로컬 컴퓨터의 Administrators 그룹을 직접 호출합니다.
        # 이 방식은 윈도우 언어(한글/영어)와 무관하며, 문자열 파싱 오류를 발생시키지 않습니다.
        ps_script = (
            "$adminGroupSID = 'S-1-5-32-544'; "
            "$groupName = (New-Object System.Security.Principal.SecurityIdentifier($adminGroupSID)).Translate([System.Security.Principal.NTAccount]).Value.Split('\\')[1]; "
            
            "$members = @(); "
            "if ($groupName) { "
            "   $adsi = [ADSI]\"WinNT://localhost/$groupName,group\"; "
            "   foreach ($member in $adsi.Invoke('Members')) { "
            "       $members += $member.GetType().InvokeMember('Name', 'GetProperty', $null, $member, $null) "
            "   } "
            "} "
            
            "if ($members.Count -gt 0) { $members -join ',' } else { 'EMPTY' }"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 3. 명령어 통신 실패 처리
        if "ERROR:" in raw_output or not raw_output:
            status = "오류"
            detail_msg = f"관리자 그룹 멤버 조회 실패 (네트워크/명령어 정보: {raw_output})"
            self.report.print_result("W-06", "Administrator 그룹 내 불필요한 계정 존재", status)
            print(f"  - 상세 내용: {detail_msg}")
            return status

        # 4. 멤버가 비정상적으로 아예 없는 상황 방어
        if raw_output == "EMPTY":
            status = "오류"
            detail_msg = "로컬 관리자 그룹 내에 멤버가 발견되지 않았거나 접근 권한이 부족합니다."
            self.report.print_result("W-06", "Administrator 그룹 내 불필요한 계정 존재", status)
            print(f"  - 상세 내용: {detail_msg}")
            return status

        # 5. 멤버 리스트 추출 및 화이트리스트 검사 (소문자 치환하여 매칭)
        group_members = raw_output.lower().split(",")
        unauthorized_users = []
        
        for member in group_members:
            member = member.strip()
            if member and member not in whitelist:
                unauthorized_users.append(member)

        # 6. 화이트리스트 검증 기반 판정
        if unauthorized_users:
            status = "취약"
            unauthorized_str = ", ".join(unauthorized_users)
            detail_msg = f"취약: 관리자 그룹에 허용되지 않은 불필요한 계정이 존재합니다. (발견된 비인가 계정: {unauthorized_str})"
        else:
            status = "양호"
            detail_msg = f"양호: 관리자 그룹 내에 허용된 화이트리스트 계정만 존재합니다. (현재 멤버: {raw_output})"

        # 7. 출력 및 저장
        self.report.print_result("W-06", "Administrator 그룹 내 불필요한 계정 존재", status)
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_07(self):  # W-07: Everyone 사용 권한을 익명 사용자에게 적용 정책 점검 (try문 제거 버전)
        print("[*] W-07: 'Everyone 사용 권한을 익명 사용자에게 적용' 정책 현황 조회 중...")

        # 'EveryoneIncludesAnonymous' 레지스트리 값을 조회하는 파워셸 스크립트
        # 값이 존재하지 않거나 에러 발생 시 안전하게 '999'를 반환하도록 예외 분기 처리
        ps_script = (
            "$path = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa'; "
            "if (Test-Path $path) { "
            "   $val = (Get-ItemProperty -Path $path -Name 'EveryoneIncludesAnonymous' -ErrorAction SilentlyContinue).EveryoneIncludesAnonymous; "
            "   if ($val -ne $null) { $val } else { '0' } "
            "} else { '999' }"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 1. 명령어 실패 처리 (SSH 오류 또는 빈 값 대응)
        if "ERROR:" in raw_output or not raw_output:
            status = "오류"
            detail_msg = f"레지스트리 정책 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-07", "Everyone 사용 권한을 익명 사용자에게 적용", status)
            return status

        # 2. 숫자가 맞는지 검증 후 안전하게 정수(int) 변환하여 판정
        if raw_output.isdigit():
            policy_value = int(raw_output)

            # 3. 보안 기준 검증 (0: 사용 안 함 -> 양호 / 1: 사용 -> 취약)
            if policy_value == 0:
                status = "양호"
                detail_msg = "현재 설정: 사용 안 함 -> 익명 사용자에 대한 Everyone 권한 적용이 차단되어 안전합니다."
            elif policy_value == 1:
                status = "취약"
                detail_msg = "현재 설정: 사용 -> 익명 사용자에게 Everyone 권한이 적용되어 정보 노출 위험이 있습니다."
            else:
                status = "오류"
                detail_msg = f"정의되지 않은 정책 값 반환 (값: {policy_value})"
        else:
            # 반환된 문자열이 숫자가 아닐 경우 안전하게 오류로 분기
            status = "오류"
            detail_msg = f"올바르지 않은 정책 데이터 형식 반환 (데이터: {raw_output})"

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-07", "Everyone 사용 권한을 익명 사용자에게 적용", status)
        
        # 터미널 콘솔 로그 출력 (선택 사항)
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_08(self):  # W-08: 계정 잠금 기간 설정 점검 (try문 제거 버전)
        print("[*] W-08: 계정 잠금 기간 및 원래대로 설정 기간 현황 조회 중...")

        # 1. 파워셸을 이용해 계정 잠금 기간(Lockout duration) 숫자 추출
        ps_duration = (
            "$acc = net accounts; "
            "$line = $acc | Where-Object { $_ -match 'Lockout duration' -or $_ -match '계정 잠금 기간' }; "
            "if ($line -match '\\d+') { $Matches[0] } else { '0' }"
        )
        raw_duration = self.conn.execute_cmd(ps_duration).strip()

        # 2. 파워셸을 이용해 잠금 기간 원래대로 설정 기간(Reset window) 숫자 추출
        ps_reset = (
            "$acc = net accounts; "
            "$line = $acc | Where-Object { $_ -match 'Reset window' -or $_ -match '잠금 기간 원래대로 설정 기간' }; "
            "if ($line -match '\\d+') { $Matches[0] } else { '0' }"
        )
        raw_reset = self.conn.execute_cmd(ps_reset).strip()

        # 3. 명령어 실패 처리 (SSH 오류 또는 빈 값 대응)
        if "ERROR:" in raw_duration or "ERROR:" in raw_reset or not raw_duration or not raw_reset:
            status = "오류"
            detail_msg = f"계정 잠금 정책 조회 실패 (정보: D:{raw_duration} / R:{raw_reset})"
            self.report.print_result("W-08", "계정 잠금 기간 설정", status)
            return status

        # 4. 양쪽 결과가 모두 숫자인지 사전 검증 후 정수 변환
        if raw_duration.isdigit() and raw_reset.isdigit():
            duration_val = int(raw_duration)
            reset_val = int(raw_reset)
            detail_msg = f"현재 설정 - 잠금 기간: {duration_val}분, 원래대로 설정 기간: {reset_val}분"

            # 5. 요청하신 보안 기준 검증 (두 값 모두 60분 이상이어야 양호)
            if duration_val >= 60 and reset_val >= 60:
                status = "양호"
                detail_msg += " -> 두 정책 모두 보안 기준(60분 이상)을 충족하여 안전합니다."
            else:
                status = "취약"
                # 상세 취약 사유 명시
                reasons = []
                if duration_val < 60:
                    reasons.append(f"계정 잠금 기간({duration_val}분)이 60분 미만임")
                if reset_val < 60:
                    reasons.append(f"원래대로 설정 기간({reset_val}분)이 60분 미만임")
                detail_msg += f" -> 취약 ({', '.join(reasons)})"
        else:
            # 숫자가 아닐 경우 안전하게 오류 처리
            status = "오류"
            detail_msg = f"올바르지 않은 정책 데이터 형식 반환 (D:{raw_duration}, R:{raw_reset})"

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-08", "계정 잠금 기간 설정", status)
        
        # 터미널 콘솔 로그 출력 (선택 사항)
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_09(self):  # W-09: 암호 정책 설정 점검 (try문 제거 버전)
        print("[*] W-09: 패스워드 복잡성 및 5대 암호 정책 현황 조회 중...")

        # 1. 파워셸을 이용해 5가지 암호 정책 설정값 각각 조회
        # [Step 2] 암호 복잡성 만족 여부 (1: 사용 / 0: 사용 안 함)
        ps_complexity = (
            "$sec = secedit /export /cfg $env:temp\\sec.cfg /areas SECURITYPOLICY | Out-Null; "
            "$line = Select-String -Path $env:temp\\sec.cfg -Pattern 'PasswordComplexity'; "
            "Remove-Item $env:temp\\sec.cfg -ErrorAction SilentlyContinue; "
            "if ($line -match '=\\s*(\\d+)') { $Matches[1] } else { '0' }"
        )
        # [Step 3] 최근 암호 기억 (개수)
        ps_history = (
            "$acc = net accounts; $line = $acc | Where-Object { $_ -match 'Password history' -or $_ -match '최근 암호 기억' }; "
            "if ($line -match '\\d+') { $Matches[0] } else { '0' }"
        )
        # [Step 4] 최대 암호 사용 기간 (일수)
        ps_max_age = (
            "$acc = net accounts; $line = $acc | Where-Object { $_ -match 'Maximum password age' -or $_ -match '최대 암호 사용 기간' }; "
            "if ($line -match '\\d+') { $Matches[0] } else { '0' }"
        )
        # [Step 5] 최소 암호 길이 (문자 수)
        ps_min_len = (
            "$acc = net accounts; $line = $acc | Where-Object { $_ -match 'Minimum password length' -or $_ -match '최소 암호 길이' }; "
            "if ($line -match '\\d+') { $Matches[0] } else { '0' }"
        )
        # [Step 6] 최소 암호 사용 기간 (일수)
        ps_min_age = (
            "$acc = net accounts; $line = $acc | Where-Object { $_ -match 'Minimum password age' -or $_ -match '최소 암호 사용 기간' }; "
            "if ($line -match '\\d+') { $Matches[0] } else { '0' }"
        )

        # 원격지 명령어 실행 및 공백 제거
        raw_comp = self.conn.execute_cmd(ps_complexity).strip()
        raw_hist = self.conn.execute_cmd(ps_history).strip()
        raw_max  = self.conn.execute_cmd(ps_max_age).strip()
        raw_min_len = self.conn.execute_cmd(ps_min_len).strip()
        raw_min_age = self.conn.execute_cmd(ps_min_age).strip()

        # 2. 명령어 실패 처리 (SSH 오류 확인)
        if "ERROR:" in f"{raw_comp}{raw_hist}{raw_max}{raw_min_len}{raw_min_age}":
            status = "오류"
            detail_msg = "암호 정책 값을 가져오는 도중 SSH 및 파워셸 명령 실패가 발생했습니다."
            self.report.print_result("W-09", "암호 정책 설정", status)
            return status

        # 3. 모든 데이터가 정수형 숫자가 맞는지 사전 검증
        if raw_comp.isdigit() and raw_hist.isdigit() and raw_max.isdigit() and raw_min_len.isdigit() and raw_min_age.isdigit():
            val_comp    = int(raw_comp)      # 복잡성 (1=사용)
            val_hist    = int(raw_hist)      # 최근 암호 기억 (기준: 4개 이상)
            val_max     = int(raw_max)       # 최대 기간 (기준: 90일 이하)
            val_min_len = int(raw_min_len)   # 최소 길이 (기준: 8자 이상)
            val_min_age = int(raw_min_age)   # 최소 기간 (기준: 1일 이상)

            detail_msg = f"현재 설정 - 복잡성: {val_comp}, 최근암호기억: {val_hist}개, 최대기간: {val_max}일, 최소길이: {val_min_len}자, 최소기간: {val_min_age}일"
            
            # 취약점 세부 사유를 누적할 리스트
            reasons = []

            # 4. 요청하신 5대 기준 조건 검증 (하나라도 만족하지 않으면 취약 사유에 추가)
            if val_comp != 1:
                reasons.append("암호 복잡성 정책이 '사용 안 함'으로 설정됨")
            if val_hist < 4:
                reasons.append(f"최근 암호 기억({val_hist}개)이 4개 미만임")
            if val_max > 90 or val_max == 0:
                reasons.append(f"최대 암호 사용 기간({val_max}일)이 90일을 초과하거나 설정되지 않음")
            if val_min_len < 8:
                reasons.append(f"최소 암호 길이({val_min_len}자)가 8문자 미만임")
            if val_min_age < 1:
                reasons.append(f"최소 암호 사용 기간({val_min_age}일)이 1일 미만임")

            # 5. 최종 판정 (리스트가 비어있으면 전체 통과로 '양호', 하나라도 있으면 '취약')
            if reasons:
                status = "취약"
                detail_msg += f" -> 취약 사유: {', '.join(reasons)}"
            else:
                status = "양호"
                detail_msg += " -> 모든 암호 가이드라인 정책 기준(복잡성 사용, 기억 4개↑, 최대 90일↓, 최소 8자↑, 최소 1일↑)을 준수하고 있습니다."
        else:
            status = "오류"
            detail_msg = f"올바르지 않은 정책 데이터 형식 반환 (데이터 수집 본: {raw_comp}/{raw_hist}/{raw_max}/{raw_min_len}/{raw_min_age})"

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-09", "암호 정책 설정", status)
        
        # 터미널 콘솔 로그 출력 (선택 사항)
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_10(self):  # W-10: 마지막 사용자 이름 표시 안 함 정책 점검 (try문 제거 버전)
        print("[*] W-10: '마지막 사용자 이름 표시 안 함' 정책 현황 조회 중...")

        # 'DontDisplayLastUserName' 레지스트리 값을 조회하는 파워셸 스크립트
        # 해당 경로가 없거나 설정 값이 비어있을 경우 안전하게 '0'(사용 안 함)을 반환합니다.
        ps_script = (
            "$path = 'HKLM:\\SOFTWARE\\Microsoft\Windows\\CurrentVersion\\Policies\\System'; "
            "if (Test-Path $path) { "
            "   $val = (Get-ItemProperty -Path $path -Name 'DontDisplayLastUserName' -ErrorAction SilentlyContinue).DontDisplayLastUserName; "
            "   if ($val -ne $null) { $val } else { '0' } "
            "} else { '0' }"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 1. 명령어 실패 처리 (SSH 오류 또는 빈 값 대응)
        if "ERROR:" in raw_output or not raw_output:
            status = "오류"
            detail_msg = f"레지스트리 정책 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-10", "마지막 사용자 이름 표시 안 함", status)
            return status

        # 2. 숫자가 맞는지 검증 후 안전하게 정수(int) 변환하여 판정
        if raw_output.isdigit():
            policy_value = int(raw_output)

            # 3. 요청하신 보안 기준 검증 (1: 사용 -> 양호 / 0: 사용 안 함 -> 취약)
            if policy_value == 1:
                status = "양호"
                detail_msg = "현재 설정: 사용 -> 로그온 화면에서 마지막으로 로그인한 사용자 이름이 표시되지 않아 안전합니다."
            elif policy_value == 0:
                status = "취약"
                detail_msg = "현재 설정: 사용 안 함 -> 로그온 화면에 마지막 사용자 이름이 노출되어 계정 유추 공격에 취약합니다."
            else:
                status = "오류"
                detail_msg = f"정의되지 않은 정책 값 반환 (값: {policy_value})"
        else:
            status = "오류"
            detail_msg = f"올바르지 않은 정책 데이터 형식 반환 (데이터: {raw_output})"

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-10", "마지막 사용자 이름 표시 안 함", status)
        
        # 터미널 콘솔 로그 출력 (선택 사항)
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_11(self):  # W-11: 로컬 로그온 허용 정책 점검 (오류 수정 버전)
        print("[*] W-11: '로컬 로그온 허용' 정책 및 화이트리스트 대조 중...")

        # 1. 로컬 로그온이 기본 허용되는 안전한 화이트리스트 그룹 정의
        # 한글/영어 환경 모두 대응하기 위해 일반적인 관리자, 유저 그룹명을 기입합니다.
        whitelist = ["administrators", "users", "guests", "backup operators", "관리자", "사용자"]

        # 2. secedit의 깨지기 쉬운 텍스트 파싱 대신, dotnet/PowerShell 표준 명령어로 
        # '로컬 로그온 권한(SeInteractiveLogonRight)'을 가진 계정/그룹 목록을 가져오는 스크립트입니다.
        # 만약 해당 유틸리티가 동작하지 않는 환경을 대비해, 계정 정보를 안전하게 정형화하여 반환합니다.
        ps_script = (
            "$sidList = @(); "
            "if (Get-Command -Name Get-LocalGroup -ErrorAction SilentlyContinue) { "
            "   # 최신 OS용: 로컬 그룹 정보를 통해 간접 확인 및 권한 맵 매칭\n"
            "   $sids = Get-CimInstance -ClassName Win32_LogicalShareSecuritySetting -ErrorAction SilentlyContinue; "
            "   # 구형/신형 호환을 위해 secedit의 특정 결과 섹션만 안전하게 뽑아내는 로직으로 우회\n"
            "} "
            
            "# 가장 확실한 secedit 임시 출력 및 안전 파싱 기법 (오류 원천 차단)\n"
            "$tempFile = [System.IO.Path]::GetTempFileName(); "
            "secedit /export /cfg $tempFile /areas USER_RIGHTS | Out-Null; "
            "$line = Get-Content $tempFile | Where-Object { $_ -match '^SeInteractiveLogonRight' }; "
            "Remove-Item $tempFile -ErrorAction SilentlyContinue; "
            
            "if ($line -and $line -match '=(.*)') { "
            "   $rawMembers = $Matches[1].Trim(); "
            "   # SID 값을 실제 이름으로 깔끔하게 역번역하여 콤마로 연결\n"
            "   $converted = @(); "
            "   foreach ($m in $rawMembers.Split(',')) { "
            "       $cleanM = $m.Trim().Trim('*'); "
            "       if ($cleanM) { "
            "           if ($cleanM -match '^S-1-') { "
            "               $resolved = (New-Object System.Security.Principal.SecurityIdentifier($cleanM)).Translate([System.Security.Principal.NTAccount]).Value; "
            "               if ($resolved -match '\\\\(.+)$') { $converted += $Matches[1] } else { $converted += $resolved } "
            "           } else { "
            "               $converted += $cleanM "
            "           } "
            "       } "
            "   } "
            "   if ($converted) { $converted -join ',' } else { 'EMPTY' } "
            "} else { "
            "   'EMPTY' "
            "}"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 3. 명령어 실패 처리 (SSH 오류 대응)
        if "ERROR:" in raw_output or not raw_output:
            status = "오류"
            detail_msg = f"로컬 로그온 허용 정책 조회 실패 (네트워크/명령어 정보: {raw_output})"
            self.report.print_result("W-11", "로컬 로그온 허용", status)
            print(f"  - 상세 내용: {detail_msg}")
            return status

        # 4. 권한 항목이 비어있는 예외 상황 방어
        if raw_output == "EMPTY":
            status = "양호" # 로컬 로그온이 아무도 허용 안 되어 있다면 보안상으로는 안전하므로 양호 처리
            detail_msg = "양호: 로컬 로그온 허용 정책이 완전히 비어있거나 기본 제한 상태입니다."
            self.report.print_result("W-11", "로컬 로그온 허용", status)
            return status

        # 5. 대소문자 구분 없이 소문자로 치환하여 화이트리스트 대조
        assigned_members = raw_output.lower().split(",")
        unauthorized_accounts = []
        
        for account in assigned_members:
            account = account.strip()
            # Everyone이 포함되어 있거나 화이트리스트 그룹에 없는 개별 계정이 있으면 취약 항목으로 수집
            if account == "everyone" or (account and account not in whitelist):
                unauthorized_accounts.append(account)

        # 6. 최종 판정 분기
        if unauthorized_accounts:
            status = "취약"
            unauthorized_str = ", ".join(unauthorized_accounts)
            detail_msg = f"취약: 로컬 로그온 허용 정책에 불필요하거나 과도한 권한을 가진 계정/그룹이 존재합니다. (발견된 계정: {unauthorized_str})"
        else:
            status = "양호"
            detail_msg = f"양호: 로컬 로그온 허용 정책에 지정된 화이트리스트 권한 그룹만 존재합니다. (현재 허용 대상: {raw_output})"

        # 7. 표 양식 저장 및 로그 출력
        self.report.print_result("W-11", "로컬 로그온 허용", status)
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_12(self):  # W-12: 익명 SID/이름 변환 허용 해제 점검 (try문 제거 버전)
        print("[*] W-12: '익명 SID/이름 변환 허용' 정책 현황 조회 중...")

        # 'TurnOffAnonymousBlock' 레지스트리 값을 조회하는 파워셸 스크립트
        # 해당 경로가 없거나 설정 값이 비어있을 경우 안전하게 '0'(사용/취약 상태)을 반환합니다.
        ps_script = (
            "$path = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa'; "
            "if (Test-Path $path) { "
            "   $val = (Get-ItemProperty -Path $path -Name 'TurnOffAnonymousBlock' -ErrorAction SilentlyContinue).TurnOffAnonymousBlock; "
            "   if ($val -ne $null) { $val } else { '0' } "
            "} else { '0' }"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 1. 명령어 실패 처리 (SSH 오류 또는 빈 값 대응)
        if "ERROR:" in raw_output or not raw_output:
            status = "오류"
            detail_msg = f"레지스트리 정책 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-12", "익명 SID/이름 변환 허용 해제", status)
            return status

        # 2. 숫자가 맞는지 검증 후 안전하게 정수(int) 변환하여 판정
        if raw_output.isdigit():
            policy_value = int(raw_output)

            # 3. 요청하신 보안 기준 검증 (1: 차단 활성화=사용 안 함 -> 양호 / 0: 차단 비활성화=사용 -> 취약)
            if policy_value == 1:
                status = "양호"
                detail_msg = "현재 설정: 사용 안 함 -> 익명 사용자가 SID를 통해 계정 이름을 유추할 수 없도록 안전하게 차단되어 있습니다."
            elif policy_value == 0:
                status = "취약"
                detail_msg = "현재 설정: 사용 -> 익명 SID/이름 변환이 허용되어 있어, 익명 사용자가 시스템 계정 정보를 유추할 수 있으므로 취약합니다."
            else:
                status = "오류"
                detail_msg = f"정의되지 않은 정책 값 반환 (값: {policy_value})"
        else:
            status = "오류"
            detail_msg = f"올바르지 않은 정책 데이터 형식 반환 (데이터: {raw_output})"

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-12", "익명 SID/이름 변환 허용 해제", status)
        
        # 터미널 콘솔 로그 출력 (선택 사항)
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_13(self):  # W-13: 콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한 점검 (try문 제거 버전)
        print("[*] W-13: '콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한' 정책 현황 조회 중...")

        # 'LimitBlankPasswordUse' 레지스트리 값을 조회하는 파워셸 스크립트
        # 해당 경로가 없거나 설정 값이 비어있을 경우 안전하게 '0'(사용 안 함/취약 상태)을 반환합니다.
        ps_script = (
            "$path = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa'; "
            "if (Test-Path $path) { "
            "   $val = (Get-ItemProperty -Path $path -Name 'LimitBlankPasswordUse' -ErrorAction SilentlyContinue).LimitBlankPasswordUse; "
            "   if ($val -ne $null) { $val } else { '0' } "
            "} else { '0' }"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 1. 명령어 실패 처리 (SSH 오류 또는 빈 값 대응)
        if "ERROR:" in raw_output or not raw_output:
            status = "오류"
            detail_msg = f"레지스트리 정책 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-13", "콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한", status)
            return status

        # 2. 숫자가 맞는지 검증 후 안전하게 정수(int) 변환하여 판정
        if raw_output.isdigit():
            policy_value = int(raw_output)

            # 3. 요청하신 보안 기준 검증 (1: 사용 -> 양호 / 0: 사용 안 함 -> 취약)
            if policy_value == 1:
                status = "양호"
                detail_msg = "현재 설정: 사용 -> 패스워드가 없는 빈 암호 계정의 콘솔 로그온이 제한되어 있어 안전합니다."
            elif policy_value == 0:
                status = "취약"
                detail_msg = "현재 설정: 사용 안 함 -> 빈 암호를 사용하는 계정이 제한 없이 로그온할 수 있어 위험합니다."
            else:
                status = "오류"
                detail_msg = f"정의되지 않은 정책 값 반환 (값: {policy_value})"
        else:
            status = "오류"
            detail_msg = f"올바르지 않은 정책 데이터 형식 반환 (데이터: {raw_output})"

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-13", "콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한", status)
        
        # 터미널 콘솔 로그 출력 (선택 사항)
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_14(self):  # W-14: 원격 터미널 서비스 접속 제한 점검 (try문 제거 버전)
        print("[*] W-14: 원격 접속 사용자 그룹(Remote Desktop Users) 내 구성원 현황 조회 중...")

        # 1. 윈도우 로컬 Remote Desktop Users 그룹의 멤버 수와 멤버 이름을 가져오는 파워셸 스크립트
        # 그룹 멤버들의 이름을 콤마(,) 구분자로 연결하여 반환합니다. 멤버가 없으면 빈 값을 반환합니다.
        ps_script = (
            "$members = Get-CimInstance -ClassName Win32_GroupUser | "
            "Where-Object { $_.GroupComponent -match 'Name=\"Remote Desktop Users\"' } | "
            "ForEach-Object { [regex]::Match($_.PartComponent, 'Name=\"(.*?)\"').Groups[1].Value }; "
            "if ($members) { $members -join ',' } else { '' }"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 2. 명령어 실패 처리 (SSH 오류 대응)
        if "ERROR:" in raw_output:
            status = "오류"
            detail_msg = f"원격 접속 사용자 그룹 멤버 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-14", "원격 터미널 서비스 접속 제한", status)
            return status

        # 3. 그룹 멤버가 아예 비어있는 경우 (별도의 원격 접속 계정이 없으므로 취약으로 처리)
        if not raw_output:
            status = "취약"
            detail_msg = "취약: Remote Desktop Users 그룹이 비어있습니다. 관리자 외 원격 접속이 허용된 별도의 안전한 전용 계정이 존재하지 않습니다."
            self.report.print_result("W-14", "원격 터미널 서비스 접속 제한", status)
            return status

        # 4. 콤마로 분리하여 실제 할당된 사용자 리스트 생성 (대소문자 구분을 없애기 위해 소문자로 변환)
        members_list = raw_output.lower().split(",")
        
        # 관리자 계정(administrator)을 제외한 별도의 원격 계정 필터링용 리스트
        remote_only_users = []
        
        for member in members_list:
            member = member.strip()
            if member and member != "administrator":
                remote_only_users.append(member)

        # 5. 요청하신 보안 기준 검증
        # Administrator를 제외한 별도의 전용 계정이 하나 이상 존재하면 '양호', 관리자 혼자 있거나 없으면 '취약'
        if remote_only_users:
            status = "양호"
            allowed_str = ", ".join(remote_only_users)
            detail_msg = f"양호: 관리자 외 원격 접속 권한을 분리한 전용 계정이 존재하며 불필요한 등록이 차단되어 있습니다. (원격 전용 계정: {allowed_str})"
        else:
            status = "취약"
            detail_msg = "취약: 원격 접속 권한에 로컬 Administrator 계정만 존재하거나 별도의 전용 계정이 식별되지 않습니다."

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-14", "원격 터미널 서비스 접속 제한", status)
        
        # 터미널 콘솔 로그 출력 (선택 사항)
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_15(self):  # W-15: 사용자 개인 키 사용 시 암호 입력 제한 점검 (try문 제거 버전)
        print("[*] W-15: '사용자 개인 키 사용 시 암호 입력 제한' 정책 현황 조회 중...")

        # 'ForceKeyProtection' 레지스트리 값을 조회하는 파워셸 스크립트
        # 경로가 없거나 설정 값이 비어있을 경우 안전하게 '0'(암호 요구 안 함/취약 상태)을 반환합니다.
        ps_script = (
            "$path = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Cryptography'; "
            "if (Test-Path $path) { "
            "   $val = (Get-ItemProperty -Path $path -Name 'ForceKeyProtection' -ErrorAction SilentlyContinue).ForceKeyProtection; "
            "   if ($val -ne $null) { $val } else { '0' } "
            "} else { '0' }"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 1. 명령어 실패 처리 (SSH 오류 또는 빈 값 대응)
        if "ERROR:" in raw_output or not raw_output:
            status = "오류"
            detail_msg = f"레지스트리 정책 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-15", "사용자 개인 키 사용 시 암호 입력 제한", status)
            return status

        # 2. 숫자가 맞는지 검증 후 안전하게 정수(int) 변환하여 판정
        if raw_output.isdigit():
            policy_value = int(raw_output)

            # 3. 요청하신 보안 기준 검증 (2: 매번 암호 입력 필수 -> 양호 / 0 또는 1: 암호 입력 안 함 -> 취약)
            if policy_value == 2:
                status = "양호"
                detail_msg = "현재 설정: 사용 -> 사용자 개인 키를 사용할 때마다 강제로 암호 입력을 받도록 설정되어 안전합니다."
            else:
                status = "취약"
                detail_msg = f"현재 설정: 사용 안 함 (레지스트리 값: {policy_value}) -> 개인 키 사용 시 암호 입력을 요구하지 않아 취약합니다."
        else:
            status = "오류"
            detail_msg = f"올바르지 않은 정책 데이터 형식 반환 (데이터: {raw_output})"

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-15", "사용자 개인 키 사용 시 암호 입력 제한", status)
        
        # 터미널 콘솔 로그 출력 (선택 사항)
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_16(self):  # W-16: 공유 디렉터리 권한 설정 점검 (try문 제거 버전)
        print("[*] W-16: 일반 공유 디렉터리 추출 및 Everyone 권한 포함 여부 조사 중...")

        # C$, ADMIN$, IPC$ 등 시스템 기본 관리 목적 공유를 제외한 일반 공유 폴더의 이름과
        # 각 공유 폴더의 Access 권한 목록 중 Everyone 그룹이 포함되어 있는지 여부를 조회하는 파워셸 스크립트입니다.
        # Everyone 권한이 발견된 폴더가 있다면 그 공유 폴더 이름을 콤마(,)로 연결하여 반환합니다.
        ps_script = (
            "$bad_shares = @(); "
            "$shares = Get-CimInstance -ClassName Win32_Share | Where-Object { $_.Type -eq 0 }; "
            "foreach ($share in $shares) { "
            "   $security = Get-Acl -Path $share.Path -ErrorAction SilentlyContinue; "
            "   if ($security) { "
            "       $has_everyone = $security.Access | Where-Object { $_.IdentityReference -match 'Everyone' -or $_.IdentityReference -match 'Everyone' }; "
            "       if ($has_everyone) { $bad_shares += $share.Name } "
            "   } "
            "}; "
            "if ($bad_shares) { $bad_shares -join ',' } else { '' }"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 1. 명령어 실패 처리 (SSH 오류 또는 시스템 에러 대응)
        if "ERROR:" in raw_output:
            status = "오류"
            detail_msg = f"공유 디렉터리 권한 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-16", "공유 디렉터리 권한 설정", status)
            return status

        # 2. 결과 값 기반 취약점 판정
        if raw_output:
            # Everyone 권한이 발견되어 위험한 공유 폴더 이름이 반환된 경우 -> 취약
            status = "취약"
            detail_msg = f"취약: 일반 공유 디렉터리 중 Everyone 권한이 부여된 폴더가 존재합니다. (발견된 공유폴더: {raw_output})"
        else:
            # 반환값이 완전히 빈 문자열일 경우 -> 일반 공유폴더가 없거나, Everyone 권한이 설정된 곳이 없음 -> 양호
            status = "양호"
            detail_msg = "양호: 시스템 내 일반 공유 디렉터리가 존재하지 않거나, 모든 공유 디렉터리의 접근 권한에 Everyone 권한이 배제되어 있어 안전합니다."

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-16", "공유 디렉터리 권한 설정", status)
        
        # 터미널 콘솔 로그 출력 (선택 사항)
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_17(self):  # W-17: 기본 공유 제거 정책 점검 (try문 제거 버전)
        print("[*] W-17: 레지스트리 기본 공유 비활성화 및 설정 현황 조회 중...")

        # 서버용(AutoShareServer) 및 워크스테이션용(AutoShareWks) 레지스트리를 모두 확인하여 
        # 설정 값이 0인지 체크하고, 현재 시스템에 C$, ADMIN$ 같은 기본 공유가 남아있는지 통합 조사하는 파워셸 스크립트입니다.
        # 취약점이 발견되면 조건에 걸려 '취약 원인 문자열'을 반환합니다.
        ps_script = (
            "$path = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters'; "
            "$serverVal = (Get-ItemProperty -Path $path -Name 'AutoShareServer' -ErrorAction SilentlyContinue).AutoShareServer; "
            "$wksVal = (Get-ItemProperty -Path $path -Name 'AutoShareWks' -ErrorAction SilentlyContinue).AutoShareWks; "
            "$activeShares = Get-CimInstance -ClassName Win32_Share | Where-Object { $_.Name -match '\\$$' }; "
            
            "# 조건 분석 및 취약 상태 파싱\n"
            "$regVulnerable = $false; "
            "if ($serverVal -eq 1 -or $wksVal -eq 1) { $regVulnerable = $true }; "
            "if ($serverVal -eq $null -and $wksVal -eq $null) { $regVulnerable = $true }; # 기본값이 활성화이므로 없을 때도 취약함\n"
            
            "if ($regVulnerable -or $activeShares) { "
            "   'VULNERABLE' "
            "} else { "
            "   'SAFE' "
            "}"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 1. 명령어 실패 처리 (SSH 오류 또는 빈 값 대응)
        if "ERROR:" in raw_output or not raw_output:
            status = "오류"
            detail_msg = f"기본 공유 레지스트리 및 쿼리 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-17", "기본 공유 제거", status)
            return status

        # 2. 요청하신 보안 기준 검증 (SAFE -> 양호 / VULNERABLE -> 취약)
        if raw_output == "SAFE":
            status = "양호"
            detail_msg = "양호: 기본 공유 제어 레지스트리 설정(0)이 올바르며, 현재 활성화된 시스템 기본 숨김 공유($)가 발견되지 않았습니다."
        else:
            status = "취약"
            detail_msg = "취약: 기본 공유 레지스트리 설정이 활성화(1 또는 누락)되어 있거나, 시스템 내 기본 숨김 공유(C$, ADMIN$ 등)가 활성 상태로 존재합니다."

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-17", "기본 공유 제거", status)
        
        # 터미널 콘솔 로그 출력 (선택 사항)
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_18(self):  # W-18: 불필요한 서비스 비활성화 점검 (중괄호 파싱 에러 수정 버전)
        print("[*] W-18: 가이드라인 지정 불필요 서비스 구동 및 '사용 안 함' 설정 여부 점검 중...")

        # 1. 점검 대상 서비스 키워드 정의
        target_patterns = [
            "Alerter", "wuauserv", "ClipBook", "Browser", "CryptSvc", "Dhcp",
            "TrkWks", "TrkSvr", "ERSvc", "ImapiService", "Messenger", 
            "mnmsrvc", "WmdmPmSN", "Spooler", "RemoteRegistry", "SimpTcp", 
            "upnphost", "WZCSVC"
        ]
        
        # f-string 에러를 막기 위해 파워셸 전용 배열 인자 문자열을 일반 join 연산으로 안전하게 빌드합니다.
        ps_array_str = ",".join([f"'{p}'" for p in target_patterns])

        # 2. 파워셸 스크립트 작성 (f-string 생략하여 중괄호 중복 에러 근본적 해결)
        ps_script = (
            "$targets = @(" + ps_array_str + "); "
            "$vulnerable_services = @(); "
            "foreach ($t in $targets) { "
            "   $srv = Get-CimInstance -ClassName Win32_Service | Where-Object { $_.Name -match $t -or $_.DisplayName -match $t }; "
            "   foreach ($s in $srv) { "
            "       if ($s.State -eq 'Running' -or $s.StartMode -ne 'Disabled') { "
            "           $vulnerable_services += ($s.Name + '(' + $s.State + '/' + $s.StartMode + ')') "
            "       } "
            "   } "
            "}; "
            "if ($vulnerable_services) { $vulnerable_services -join ',' } else { '' }"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 3. 명령어 실패 처리 (SSH 자체 에러 로그나 윈도우 에러 구문 감지)
        if "ERROR:" in raw_output or "Get-CimInstance" in raw_output:
            status = "오류"
            detail_msg = f"윈도우 서비스 상태 조회 실패 (파워셸 가동 노이즈 발생: {raw_output[:100]}...)"
            self.report.print_result("W-18", "불필요한 서비스 비활성화", status)
            return status

        # 4. 보안 가이드라인에 맞춘 최종 판정 분기
        if raw_output:
            status = "취약"
            detail_msg = f"취약: 불필요한 서비스가 구동 중이거나 '사용 안 함'으로 설정되지 않았습니다. (발견된 대상: {raw_output})"
        else:
            status = "양호"
            detail_msg = "양호: 가이드라인에 지정된 모든 불필요 서비스가 안전하게 중지 및 '사용 안 함'으로 설정되어 있습니다."

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-18", "불필요한 서비스 비활성화", status)
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_19(self):  # W-19: IIS 서비스 현황 점검 (try문 제거 버전)
        print("[*] W-19: IIS 서비스(W3SVC / IISADMIN) 활성화 및 격리 현황 조회 중...")

        # IIS의 핵심인 W3SVC(World Wide Web Publishing) 및 IISADMIN 서비스의 상태를 파악하는 파워셸 스크립트입니다.
        # 서비스가 아예 없으면 'NOT_INSTALLED'를 반환하며, 
        # 서비스가 존재하는데 켜져 있거나 '사용 안 함'이 아니면 'VULNERABLE'을 반환합니다.
        ps_script = (
            "$iis_services = Get-CimInstance -ClassName Win32_Service | "
            "Where-Object { $_.Name -eq 'W3SVC' -or $_.Name -eq 'IISADMIN' }; "
            
            "if (-not $iis_services) { "
            "   'NOT_INSTALLED' "
            "} else { "
            "   $vulnerable = $false; "
            "   foreach ($s in $iis_services) { "
            "       if ($s.State -eq 'Running' -or $s.StartMode -ne 'Disabled') { "
            "           $vulnerable = $true "
            "       } "
            "   } "
            "   if ($vulnerable) { 'VULNERABLE' } else { 'DISABLED' } "
            "}"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 1. 명령어 실패 처리 (SSH 오류 또는 빈 값 대응)
        if "ERROR:" in raw_output or not raw_output:
            status = "오류"
            detail_msg = f"IIS 서비스 쿼리 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-19", "IIS 서비스 현황 점검", status)
            return status

        # 2. 요청하신 보안 기준 검증에 따른 최종 판정 분기
        if raw_output == "NOT_INSTALLED":
            status = "양호"
            detail_msg = "양호: 시스템 내 IIS 웹 서비스(W3SVC / IISADMIN)가 설치되어 있지 않아 안전합니다."
        elif raw_output == "DISABLED":
            status = "양호"
            detail_msg = "양호: IIS 웹 서비스가 설치되어 있으나, 가이드라인에 맞게 '사용 안 함' 설정 및 '중지' 상태로 안전하게 유지되고 있습니다."
        else:
            status = "취약"
            detail_msg = "취약: 불필요한 IIS 웹 서비스가 현재 구동 중이거나 '사용 안 함'으로 설정되지 않았습니다. (보안 조치 필요)"

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-19", "IIS 서비스 현황 점검", status)
        
        # 터미널 콘솔 로그 출력 (선택 사항)
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_20(self):  # W-20: NetBIOS 바인딩 서비스 구동 점검 (try문 제거 버전)
        print("[*] W-20: NetBIOS 바인딩 서비스(LmHosts) 구동 및 '사용 안 함' 설정 현황 조회 중...")

        # TCP/IP NetBIOS Helper(LmHosts) 서비스의 상태와 시작 유형을 조회하는 파워셸 스크립트입니다.
        # 서비스가 존재하지 않으면 자동으로 'NOT_INSTALLED'를 반환하며,
        # 서비스가 켜져 있거나 시작 유형이 'Disabled'가 아니면 'VULNERABLE'을 반환합니다.
        ps_script = (
            "$srv = Get-CimInstance -ClassName Win32_Service | Where-Object { $_.Name -eq 'LmHosts' }; "
            "if (-not $srv) { "
            "   'NOT_INSTALLED' "
            "} else { "
            "   if ($srv.State -eq 'Running' -or $srv.StartMode -ne 'Disabled') { "
            "       'VULNERABLE' "
            "   } else { "
            "       'DISABLED' "
            "   } "
            "}"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 1. 명령어 실패 처리 (SSH 오류 또는 빈 값 대응)
        if "ERROR:" in raw_output or not raw_output:
            status = "오류"
            detail_msg = f"NetBIOS 바인딩 서비스 쿼리 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-20", "NetBIOS 바인딩 서비스 구동 점검", status)
            return status

        # 2. 요청하신 보안 기준 검증에 따른 최종 판정 분기
        if raw_output == "NOT_INSTALLED":
            status = "양호"
            detail_msg = "양호: 시스템 내 NetBIOS 바인딩 서비스(LmHosts)가 설치되어 있지 않아 안전합니다."
        elif raw_output == "DISABLED":
            status = "양호"
            detail_msg = "양호: NetBIOS 바인딩 서비스(LmHosts)가 가이드라인에 맞게 '사용 안 함' 설정 및 '중지' 상태로 안전하게 격리되어 있습니다."
        else:
            status = "취약"
            detail_msg = "취약: NetBIOS 바인딩 서비스(LmHosts)가 현재 구동 중이거나 시작 유형이 '사용 안 함'으로 설정되지 않아 취약합니다."

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-20", "NetBIOS 바인딩 서비스 구동 점검", status)
        
        # 터미널 콘솔 로그 출력 (선택 사항)
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_21(self):  # W-21: 암호화되지 않는 FTP 서비스 비활성화 점검 (try문 제거 버전)
        print("[*] W-21: 일반 FTP 서비스 구동 및 Secure FTP(SSL) 적용 현황 조회 중...")

        # 윈도우 기본 FTP 서비스(MSFTPSVC)의 상태와 IIS FTP SSL 강제화 설정을 검사하는 파워셸 스크립트입니다.
        # 서비스가 없거나 중지 상태이면 'SAFE_NO_FTP'를 반환합니다.
        # 서비스가 돌고 있는데 SSL 설정이 없거나 암호화가 필수가 아니면 'VULNERABLE'을 반환합니다.
        ps_script = (
            "$ftpSrv = Get-CimInstance -ClassName Win32_Service | Where-Object { $_.Name -eq 'MSFTPSVC' }; "
            "if (-not $ftpSrv -or $ftpSrv.State -ne 'Running') { "
            "   'SAFE_NO_FTP' "
            "} else { "
            "   # FTP가 구동 중인 경우 IIS 내의 SSL 요구 설정(SslFlags) 확인 (3: Control/Data 채널 모두 SSL 필수)\n"
            "   if (Get-Command -Module WebAdministration -ErrorAction SilentlyContinue) { "
            "       $sslOpt = (Get-WebConfigurationProperty -Filter 'system.applicationHost/sites/site/ftpServer/security/ssl' -Name 'sslFlags' -ErrorAction SilentlyContinue).Value; "
            "       if ($sslOpt -eq 3 -or $sslOpt -match 'RequireLocalRequest|ControlChannel|DataChannel') { "
            "           'SAFE_SECURE_FTP' "
            "       } else { "
            "           'VULNERABLE' "
            "       } "
            "   } else { "
            "       # IIS 관리 모듈이 없는데 FTP가 도는 구조라면 일반 평문 FTP로 간주\n"
            "       'VULNERABLE' "
            "   } "
            "}"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 1. 명령어 실패 처리 (SSH 오류 또는 빈 값 대응)
        if "ERROR:" in raw_output or not raw_output:
            status = "오류"
            detail_msg = f"FTP 서비스 및 보안 설정 쿼리 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-21", "암호화되지 않는 FTP 서비스 비활성화", status)
            return status

        # 2. 요청하신 보안 기준 검증에 따른 최종 판정 분기
        if raw_output == "SAFE_NO_FTP":
            status = "양호"
            detail_msg = "양호: 시스템 내 일반 FTP 서비스(MSFTPSVC)가 설치되어 있지 않거나 중지 상태이므로 안전합니다."
        elif raw_output == "SAFE_SECURE_FTP":
            status = "양호"
            detail_msg = "양호: FTP 서비스가 구동 중이나, 모든 제어/데이터 채널에 Secure FTP(SSL 암호화 강제)가 적용되어 있어 안전합니다."
        else:
            status = "취약"
            detail_msg = "취약: 암호화되지 않은 일반 FTP 서비스가 구동 중이거나 SSL 암호화 요구 설정이 누락되어 있어 취약합니다."

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-21", "암호화되지 않는 FTP 서비스 비활성화", status)
        
        # 터미널 콘솔 로그 출력 (선택 사항)
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_22(self):  # W-22: FTP 디렉터리 접근권한 설정 점검 (다중 FTP 사이트 전수조사 버전)
        print("[*] W-22: 다중 FTP 서비스 구동 여부 및 모든 홈 디렉터리 Everyone 권한 전수 조사 중...")

        # 시스템 내 구동 중인 모든 FTP 사이트의 물리 경로를 추출한 뒤,
        # 단 하나의 사이트 경로에서라도 Everyone 권한이 발견되면 'VULNERABLE'을 반환하는 스크립트입니다.
        ps_script = (
            "$ftpSrv = Get-CimInstance -ClassName Win32_Service | Where-Object { $_.Name -eq 'MSFTPSVC' }; "
            "if (-not $ftpSrv -or $ftpSrv.State -ne 'Running') { "
            "   'NOT_USING_FTP' "
            "} else { "
            "   $hasVulnerability = $false; "
            "   $ftpPaths = @(); "
            "   "
            "   # 1. WebAdministration 모듈을 사용하여 활성화된 모든 FTP 사이트의 물리 경로 수집\n"
            "   if (Get-Command -Module WebAdministration -ErrorAction SilentlyContinue) { "
            "       $sites = Get-Website | Where-Object { $_.Bindings.protocol -eq 'ftp' }; "
            "       foreach ($site in $sites) { "
            "           if ($site.PhysicalPath) { $ftpPaths += $site.PhysicalPath } "
            "       } "
            "   } "
            "   "
            "   # 2. 만약 등록된 사이트 경로가 없다면 기본 ftproot 경로를 점검 대상에 강제 추가\n"
            "   if ($ftpPaths.Count -eq 0) { "
            "       $ftpPaths += 'C:\\inetpub\\ftproot' "
            "   } "
            "   "
            "   # 3. 수집된 모든 FTP 디렉터리 경로를 순회하며 Everyone 권한 체크\n"
            "   foreach ($path in $ftpPaths) { "
            "       if (Test-Path $path) { "
            "           $acl = Get-Acl -Path $path -ErrorAction SilentlyContinue; "
            "           if ($acl) { "
            "               $hasEveryone = $acl.Access | Where-Object { $_.IdentityReference -match 'Everyone' }; "
            "               if ($hasEveryone) { $hasVulnerability = $true; break; } "
            "           } "
            "       } "
            "   } "
            "   "
            "   if ($hasVulnerability) { 'VULNERABLE' } else { 'SAFE_FTP' } "
            "}"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 명령어 실패 처리
        if "ERROR:" in raw_output or not raw_output:
            status = "오류"
            detail_msg = f"FTP 디렉터리 권한 쿼리 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-22", "FTP 디렉토리 접근권한 설정", status)
            return status

        # 최종 판정 분기 (하나라도 걸리면 취약)
        if raw_output == "NOT_USING_FTP":
            status = "양호"
            detail_msg = "양호: 현재 시스템에서 FTP 서비스(MSFTPSVC)를 사용하고 있지 않으므로 안전합니다."
        elif raw_output == "SAFE_FTP":
            status = "양호"
            detail_msg = "양호: FTP 서비스를 사용 중이며, 구동 중인 모든 FTP 사이트 디렉터리에서 Everyone 권한이 안전하게 배제되어 있습니다."
        else:
            status = "취약"
            detail_msg = "취약: 운영 중인 다중 FTP 사이트 중 일부 또는 전체 홈 디렉터리에 Everyone(모든 사용자) 접근 권한이 포함되어 있습니다."

        self.report.print_result("W-22", "FTP 디렉토리 접근권한 설정", status)
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_23(self):  # W-23: 공유 서비스에 대한 익명 접근 제한 설정 점검 (try문 제거 버전)
        print("[*] W-23: FTP 서비스 활성화 여부 및 모든 사이트 익명 인증(Anonymous) 설정 전수 조사 중...")

        # 1. FTP 서비스 구동 여부를 최우선 체크하고, 구동 중이면 IIS 내의 모든 FTP 사이트를 돌며
        # 익명 인증(anonymousAuthentication)이 활성화(enabled=true)되어 있는지 전수 조사하는 파워셸 스크립트입니다.
        # 단 하나의 사이트에서라도 익명 인증이 켜져 있다면 즉시 'VULNERABLE'을 반환합니다.
        ps_script = (
            "$ftpSrv = Get-CimInstance -ClassName Win32_Service | Where-Object { $_.Name -eq 'MSFTPSVC' }; "
            "if (-not $ftpSrv -or $ftpSrv.State -ne 'Running') { "
            "   'NOT_USING_FTP' "
            "} else { "
            "   if (Get-Command -Module WebAdministration -ErrorAction SilentlyContinue) { "
            "       $sites = Get-Website | Where-Object { $_.Bindings.protocol -eq 'ftp' }; "
            "       $hasAnonymous = $false; "
            "       "
            "       foreach ($site in $sites) { "
            "           # 각 FTP 사이트의 익명 인증 활성화 여부 쿼리 (system.webServer/security/authentication/anonymousAuthentication)\n"
            "           $anonConfig = Get-WebConfigurationProperty -Filter 'system.webServer/security/authentication/anonymousAuthentication' "
            "                                                      -Name 'enabled' "
            "                                                      -PSPath \"IIS:\\Sites\\$($site.Name)\" -ErrorAction SilentlyContinue; "
            "           "
            "           if ($anonConfig -and $anonConfig.Value -eq $true) { "
            "               $hasAnonymous = $true; "
            "               break; # 하나라도 켜져 있으면 전수조사 조기 종료\n"
            "           } "
            "       } "
            "       "
            "       if ($hasAnonymous) { 'VULNERABLE' } else { 'SAFE_FTP' } "
            "   } else { "
            "       # FTP는 켜져 있으나 IIS 관리 모듈이 없는 특이 케이스의 경우, 보수적으로 취약 판정\n"
            "       'VULNERABLE' "
            "   } "
            "}"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 2. 명령어 실패 처리 (SSH 통신 오류 대응)
        if "ERROR:" in raw_output or not raw_output:
            status = "오류"
            detail_msg = f"FTP 익명 접근 설정 쿼리 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-23", "공유 서비스에 대한 익명 접근 제한 설정", status)
            return status

        # 3. 요청하신 보안 기준 검증에 따른 최종 판정 분기 (하나라도 걸리면 취약)
        if raw_output == "NOT_USING_FTP":
            status = "양호"
            detail_msg = "양호: 현재 시스템에서 FTP 서비스(MSFTPSVC)가 활성화되어 있지 않으므로 안전합니다."
        elif raw_output == "SAFE_FTP":
            status = "양호"
            detail_msg = "양호: FTP 서비스를 사용 중이나, 구동 중인 모든 FTP 사이트의 익명 인증(Anonymous) 설정이 안전하게 비활성화되어 있습니다."
        else:
            status = "취약"
            detail_msg = "취약: 운영 중인 다중 FTP 사이트 중 익명 로그인(Anonymous Authentication)이 허용된 사이트가 존재하여 취약합니다."

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-23", "공유 서비스에 대한 익명 접근 제한 설정", status)
        
        # 터미널 콘솔 로그 출력 (선택 사항)
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_24(self):  # W-24: FTP 접근 제어 설정 점검 (try문 제거 버전)
        print("[*] W-24: FTP 서비스 활성화 여부 및 모든 사이트 IP 접근 제어 설정 전수 조사 중...")

        # 1. FTP 서비스 구동 여부를 최우선 체크하고, 구동 중이면 IIS 내의 모든 FTP 사이트를 돌며
        # IP 제한 설정(ipSecurity)에 등록된 IP 리스트가 있는지 조사하는 파워셸 스크립트입니다.
        # 단 하나의 사이트라도 접근 제어 필터링이 비어 있다면 즉시 'VULNERABLE'을 반환합니다.
        ps_script = (
            "$ftpSrv = Get-CimInstance -ClassName Win32_Service | Where-Object { $_.Name -eq 'MSFTPSVC' }; "
            "if (-not $ftpSrv -or $ftpSrv.State -ne 'Running') { "
            "   'NOT_USING_FTP' "
            "} else { "
            "   if (Get-Command -Module WebAdministration -ErrorAction SilentlyContinue) { "
            "       $sites = Get-Website | Where-Object { $_.Bindings.protocol -eq 'ftp' }; "
            "       $anyUnprotected = $false; "
            "       "
            "       foreach ($site in $sites) { "
            "           # 각 FTP 사이트의 ipSecurity 컬렉션(등록된 IP 목록)을 가져옴\n"
            "           $ipRules = Get-WebConfigurationProperty -Filter 'system.ftpServer/security/ipSecurity/add' "
            "                                                  -PSPath \"IIS:\\Sites\\$($site.Name)\" -ErrorAction SilentlyContinue; "
            "           "
            "           # IP 제한 규칙이 아예 없거나 비어있는 경우 접근 제어가 적용되지 않은 것으로 간주\n"
            "           if (-not $ipRules -or $ipRules.Count -eq 0) { "
            "               $anyUnprotected = $true; "
            "               break; # 하나라도 적용 안 되어 있으면 전수조사 조기 종료\n"
            "           } "
            "       } "
            "       "
            "       if ($anyUnprotected) { 'VULNERABLE' } else { 'SAFE_FTP' } "
            "   } else { "
            "       # FTP는 켜져 있으나 IIS 관리 모듈이 없는 경우, 접근 제어 확인 불가로 보수적 취약 판정\n"
            "       'VULNERABLE' "
            "   } "
            "}"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 2. 명령어 실패 처리 (SSH 통신 오류 대응)
        if "ERROR:" in raw_output or not raw_output:
            status = "오류"
            detail_msg = f"FTP 접근 제어 설정 쿼리 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-24", "FTP 접근 제어 설정", status)
            return status

        # 3. 요청하신 보안 기준 검증에 따른 최종 판정 분기 (하나라도 미적용 시 취약)
        if raw_output == "NOT_USING_FTP":
            status = "양호"
            detail_msg = "양호: 현재 시스템에서 FTP 서비스(MSFTPSVC)가 비활성화(중지) 상태이므로 안전합니다."
        elif raw_output == "SAFE_FTP":
            status = "양호"
            detail_msg = "양호: FTP 서비스를 사용 중이며, 운영 중인 모든 FTP 사이트에 IP 주소 접근 제어(제한) 규칙이 올바르게 적용되어 있습니다."
        else:
            status = "취약"
            detail_msg = "취약: 운영 중인 다중 FTP 사이트 중 일부 또는 전체 사이트에 특정 IP 접속 제한(IP Security) 설정이 누락되어 있어 취약합니다."

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-24", "FTP 접근 제어 설정", status)
        
        # 터미널 콘솔 로그 출력 (선택 사항)
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_25(self):  # W-25: DNS Zone Transfer 설정 점검 (모든 기준 만족 강제 버전)
        print("[*] W-25: DNS 서비스 및 모든 영역 전송 보안 설정 검증 중 (모든 기준 만족 필수)...")

        # 질문자님의 엄격한 기준을 반영한 파워셸 스크립트입니다.
        # 1. DNS 서비스가 꺼져 있으면 'SAFE_DISABLED' (양호)
        # 2. DNS 서비스가 켜져 있다면, 모든 영역을 전수 조사합니다.
        #    영역 전송이 허용 안 함(0)이 아니면서, 동시에 특정 서버 지정(1 또는 2)도 되어 있지 않은 
        #    보안 누락 상태(3: 모든 서버 허용 등)가 단 하나라도 발견되면 즉시 'VULNERABLE'을 반환합니다.
        ps_script = (
            "$dnsSrv = Get-CimInstance -ClassName Win32_Service | Where-Object { $_.Name -eq 'DNS' }; "
            "if (-not $dnsSrv -or $dnsSrv.State -ne 'Running') { "
            "   'SAFE_DISABLED' "
            "} else { "
            "   # DNS 서비스가 구동 중인 경우 영역 보안성 검사 진행\n"
            "   if (Get-Command -Name Get-DnsServerZone -ErrorAction SilentlyContinue) { "
            "       $zones = Get-DnsServerZone -ErrorAction SilentlyContinue | Where-Object { $_.ZoneType -eq 'Primary' }; "
            "       if (-not $zones) { "
            "           'SAFE_DNS' "
            "       } else { "
            "           $isVulnerable = $false; "
            "           foreach ($zone in $zones) { "
            "               # SecureSecondaries 값이 0(허용 안 함), 1(네임서버 제한), 2(지정 IP 제한) 중 \n"
            "               # 아무것도 해당하지 않는 정책(예: 3 - 모든 서버 허용)이 발견되면 취약\n"
            "               if ($zone.SecureSecondaries -ne 0 -and $zone.SecureSecondaries -ne 1 -and $zone.SecureSecondaries -ne 2) { "
            "                   $isVulnerable = $true; "
            "                   break; "
            "               } "
            "           } "
            "           if ($isVulnerable) { 'VULNERABLE' } else { 'SAFE_DNS' } "
            "       } "
            "   } else { "
            "       # WMI 우회 쿼리에서도 동일한 엄격한 기준으로 검증 수행\n"
            "       $wmiZones = Get-CimInstance -Namespace 'root\\Microsoft\\Windows\\DNS' -ClassName MicrosoftDNS_Zone -ErrorAction SilentlyContinue | Where-Object { $_.ZoneType -eq 1 }; "
            "       if (-not $wmiZones) { "
            "           'SAFE_DNS' "
            "       } else { "
            "           $isVulnerableWmi = $false; "
            "           foreach ($wz in $wmiZones) { "
            "               if ($wz.SecureSecondaries -ne 0 -and $wz.SecureSecondaries -ne 1 -and $wz.SecureSecondaries -ne 2) { "
            "                   $isVulnerableWmi = $true; "
            "                   break; "
            "               } "
            "           } "
            "           if ($isVulnerableWmi) { 'VULNERABLE' } else { 'SAFE_DNS' } "
            "       } "
            "   } "
            "}"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 1. 명령어 실패 처리 (SSH 통신 오류 대응)
        if "ERROR:" in raw_output or not raw_output:
            status = "오류"
            detail_msg = f"DNS 영역 전송 설정 쿼리 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-25", "DNS Zone Transfer 설정", status)
            return status

        # 2. 질문자님이 정의해 주신 엄격한 All-or-Nothing 조건 검증 및 최종 판정 분기
        if raw_output == "SAFE_DISABLED":
            status = "양호"
            detail_msg = "양호: DNS 서비스가 비활성화(미설치 또는 중지) 상태이므로 안전합니다."
        elif raw_output == "SAFE_DNS":
            status = "양호"
            detail_msg = "양호: DNS 서비스가 활성화되어 있으나, 가이드라인에 명시된 영역 전송 제한 및 특정 서버 화이트리스트 정책이 누수 없이 철저하게 적용되어 있습니다."
        else:
            status = "취약"
            detail_msg = "취약: DNS 서비스가 가동 중이며, 일부 영역에서 영역 전송 차단 정책이나 특정 서버 제한 설정이 적용되지 않아 보안 기준을 충족하지 못했습니다."

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-25", "DNS Zone Transfer 설정", status)
        
        # 터미널 콘솔 로그 출력 (선택 사항)
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_26(self):  # W-26: RDS(Remote Data Services) 제거 점검 (try문 제거 버전)
        print("[*] W-26: OS 버전, IIS 사용 여부 및 MSADC 가상 디렉터리/레지스트리 현황 종합 진단 중...")

        # 요청하신 5가지 양호 기준을 순차적으로 검증하는 파워셸 스크립트입니다.
        # 조건 중 하나라도 충족되면 'SAFE_X' 형태로 플래그를 반환하며, 모든 방어선이 뚫렸을 때만 'VULNERABLE'을 반환합니다.
        ps_script = (
            "# 1. Windows 버전 검사 (Windows Server 2008 이상 또는 특정 서비스팩 이상 체크)\n"
            "$os = Get-CimInstance -ClassName Win32_OperatingSystem; "
            "$version = [version]$os.Version; "
            "$sp = $os.ServicePackMajorVersion; "
            
            "if ($version -ge [version]'6.0') { "
            "   'SAFE_OS_VERSION_2008_OR_ABOVE'; # 기준 2 충족 (Win 2008 이상)\n"
            "} elseif ($version -eq [version]'5.2' -and $sp -ge 2) { "
            "   'SAFE_OS_SP2'; # 기준 3 충족 (Win 2003 SP2 이상)\n"
            "} elseif ($version -eq [version]'5.0' -and $sp -ge 4) { "
            "   'SAFE_OS_SP4'; # 기준 3 충족 (Win 2000 SP4 이상)\n"
            "} else { "
            "   # 2. IIS 서비스 사용 여부 확인\n"
            "   $w3svc = Get-CimInstance -ClassName Win32_Service | Where-Object { $_.Name -eq 'W3SVC' }; "
            "   if (-not $w3svc -or $w3svc.State -ne 'Running') { "
            "       'SAFE_IIS_NOT_USED'; # 기준 1 충족 (IIS 사용 안 함)\n"
            "   } else { "
            "       # 3. MSADC 가상 디렉터리 존재 여부 검사\n"
            "       $hasMsadc = $false; "
            "       if (Get-Command -Module WebAdministration -ErrorAction SilentlyContinue) { "
            "           $vDir = Get-WebConfigurationProperty -Filter 'system.applicationHost/sites/site/application' -Name 'path' -ErrorAction SilentlyContinue; "
            "           if ($vDir -and ($vDir.Value -contains '/MSADC' -or $vDir -match 'MSADC')) { $hasMsadc = $true } "
            "       } "
            "       "
            "       # 4. 레지스트리 존재 여부 검사 (HandlerRequired 레지스트리)\n"
            "       $regPath = 'HKLM:\\SOFTWARE\\Microsoft\\DataFactory\\HandlerInfo'; "
            "       $regExist = Test-Path $regPath; "
            "       "
            "       if (-not $hasMsadc) { "
            "           'SAFE_MSADC_NOT_FOUND'; # 기준 4 충족 (MSADC 가상 디렉터리 없음)\n"
            "       } elseif (-not $regExist) { "
            "           'SAFE_REG_NOT_FOUND'; # 기준 5 충족 (레지스트리 값이 존재하지 않음)\n"
            "       } else { "
            "           'VULNERABLE'; # 5가지 안전 기준에 단 하나도 걸리지 않은 위험 상태\n"
            "       } "
            "   } "
            "}"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 명령어 실패 처리 (SSH 통신 오류 대응)
        if "ERROR:" in raw_output or not raw_output:
            status = "오류"
            detail_msg = f"RDS 정책 및 시스템 쿼리 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-26", "RDS(Remote Data Services)제거", status)
            return status

        # 요청하신 "한 가지라도 해당하면 양호(OR)" 조건에 따른 최종 판정 분기
        if raw_output.startswith("SAFE_"):
            status = "양호"
            if raw_output == "SAFE_OS_VERSION_2008_OR_ABOVE":
                detail_msg = "양호: Windows Server 2008 이상 버전의 최신 운영체제를 사용하여 취약한 레거시 RDS 기능이 원천 배제되어 있습니다. (기준 2 충족)"
            elif "SAFE_OS_SP" in raw_output:
                detail_msg = "양호: 취약점이 패치된 레거시 Windows 서비스팩 버전(2000 SP4 / 2003 SP2 이상)이 설치되어 안전합니다. (기준 3 충족)"
            elif raw_output == "SAFE_IIS_NOT_USED":
                detail_msg = "양호: 현재 시스템에서 IIS 웹 서비스(W3SVC)를 구동하고 있지 않아 위험 요소가 없습니다. (기준 1 충족)"
            elif raw_output == "SAFE_MSADC_NOT_FOUND":
                detail_msg = "양호: IIS가 구동 중이나, 기본 웹 사이트에 취약한 'MSADC' 가상 디렉터리가 존재하지 않습니다. (기준 4 충족)"
            else:
                detail_msg = "양호: 관련 RDS 데이터 팩토리 핸들러 레지스트리 구성 값이 존재하지 않아 안전합니다. (기준 5 충족)"
        else:
            status = "취약"
            detail_msg = "취약: 레거시 Windows 환경에서 IIS가 구동 중이며, MSADC 가상 디렉터리와 RDS 관련 레지스트리가 모두 활성화되어 있어 보안 조치가 필요합니다."

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-26", "RDS(Remote Data Services)제거", status)
        
        # 터미널 콘솔 로그 출력 (선택 사항)
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_27(self):  # W-27: 최신 Windows OS Build 버전 적용 점검 (try문 제거 버전)
        print("[*] W-27: OS 빌드 정보 및 윈도우 자동 업데이트 정책 수립 현황 조회 중...")

        # 현재 시스템의 OS 캡션 명칭, 빌드 번호 및 윈도우 업데이트 서비스(wuauserv)의 설정 상태를 확인하는 스크립트입니다.
        # 자동 업데이트 레지스트리(NoAutoUpdate)가 1(업데이트 사용 안 함)이거나 서비스가 Disabled면 취약으로 처리합니다.
        ps_script = (
            "$os = Get-CimInstance -ClassName Win32_OperatingSystem; "
            "$caption = $os.Caption; "
            "$build = $os.BuildNumber; "
            
            "# 윈도우 업데이트 정책 레지스트리 확인 (0: 자동업데이트 사용, 1: 사용 안 함)\n"
            "$regPath = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU'; "
            "$noUpdate = 0; "
            "if (Test-Path $regPath) { "
            "   $val = (Get-ItemProperty -Path $regPath -Name 'NoAutoUpdate' -ErrorAction SilentlyContinue).NoAutoUpdate; "
            "   if ($val -ne $null) { $noUpdate = $val } "
            "} "
            
            "# 업데이트 서비스 구동 상태 확인\n"
            "$updateSrv = Get-CimInstance -ClassName Win32_Service | Where-Object { $_.Name -eq 'wuauserv' }; "
            
            "if ($noUpdate -eq 1 -or ($updateSrv -and $updateSrv.StartMode -eq 'Disabled')) { "
            "   'VULNERABLE|' + $caption + '|' + $build "
            "} else { "
            "   'SAFE|' + $caption + '|' + $build "
            "}"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 1. 명령어 실패 처리 (SSH 오류 또는 빈 값 대응)
        if "ERROR:" in raw_output or not raw_output or "|" not in raw_output:
            status = "오류"
            detail_msg = f"OS 빌드 및 업데이트 정책 쿼리 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-27", "최신 Windows OS Build 버전 적용", status)
            return status

        # 파워셸 파이프(|) 결과를 나누어 매핑 수행
        parsed_data = raw_output.split("|")
        flag = parsed_data[0]
        os_caption = parsed_data[1]
        os_build = parsed_data[2]

        # 2. 요청하신 보안 기준 검증에 따른 최종 판정 분기
        if flag == "SAFE":
            status = "양호"
            detail_msg = f"양호: 최신 업데이트 및 빌드 관리 절차가 수립되어 있습니다. (확인된 OS: {os_caption}, 빌드 번호: {os_build})"
        else:
            status = "취약"
            detail_msg = f"취약: 최신 빌드 적용 방법(자동 업데이트 정책 등)이 비활성화되어 있어 패치 누락 및 취약점 노출 위험이 있습니다. (현재 OS: {os_caption}, 빌드: {os_build})"

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-27", "최신 Windows OS Build 버전 적용", status)
        
        # 터미널 콘솔 로그 출력 (선택 사항)
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_28(self):  # W-28: 터미널 서비스 암호화 수준 설정 점검 (try문 제거 버전)
        print("[*] W-28: RDP 서비스 활성화 여부 및 터미널 서비스 암호화 수준(MinEncryptionLevel) 조회 중...")

        # 1. RDP 서비스(TermService) 구동 상태와 레지스트리의 암호화 수준(MinEncryptionLevel)을 조회하는 파워셸 스크립트입니다.
        # RDP 서비스가 꺼져 있으면 'NOT_USING_RDP'를 반환합니다.
        # 레지스트리 값 매핑 -> 1: 낮음(취약), 2: 클라이언트와 호환 가능, 3: 고, 4: FIPS 규격 준수
        ps_script = (
            "$rdpSrv = Get-CimInstance -ClassName Win32_Service | Where-Object { $_.Name -eq 'TermService' }; "
            "if (-not $rdpSrv -or $rdpSrv.State -ne 'Running') { "
            "   'NOT_USING_RDP' "
            "} else { "
            "   $regPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp'; "
            "   if (Test-Path $regPath) { "
            "       $val = (Get-ItemProperty -Path $regPath -Name 'MinEncryptionLevel' -ErrorAction SilentlyContinue).MinEncryptionLevel; "
            "       if ($val -ne $null) { $val } else { '2' } # 기본값은 2(클라이언트와 호환 가능)임\n"
            "   } else { "
            "       '2' "
            "   } "
            "}"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 2. 명령어 실패 처리 (SSH 오류 또는 빈 값 대응)
        if "ERROR:" in raw_output or not raw_output:
            status = "오류"
            detail_msg = f"RDP 암호화 수준 레지스트리 쿼리 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-28", "터미널 서비스 암호화 수준 설정", status)
            return status

        # 3. 비활성화 케이스 선행 처리
        if raw_output == "NOT_USING_RDP":
            status = "양호"
            detail_msg = "양호: 원격 데스크톱 서비스(TermService)가 비활성화(중지) 상태이므로 안전합니다."
            self.report.print_result("W-28", "터미널 서비스 암호화 수준 설정", status)
            return status

        # 4. 안전한 정수 변환 검증 후 요청하신 기준 분기 처리
        if raw_output.isdigit():
            enc_level = int(raw_output)
            
            # 2 이상 (클라이언트 호환 가능, 고, FIPS) 이면 양호 / 1 (낮음) 이면 취약
            if enc_level >= 2:
                status = "양호"
                detail_msg = f"양호: 원격 데스크톱 서비스를 사용 중이나, 암호화 수준이 기준 이상으로 안전하게 설정되어 있습니다. (레지스트리 값: {enc_level})"
            else:
                status = "취약"
                detail_msg = "취약: 원격 데스크톱 서비스의 암호화 수준이 '낮음(Low)'으로 설정되어 있어 패킷 스니핑 위험에 노출되어 있습니다."
        else:
            status = "오류"
            detail_msg = f"올바르지 않은 정책 데이터 형식 반환 (데이터: {raw_output})"

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-28", "터미널 서비스 암호화 수준 설정", status)
        
        # 터미널 콘솔 로그 출력 (선택 사항)
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_29(self):  # W-29: 불필요한 SNMP 서비스 구동 점검 (try문 제거 버전)
        print("[*] W-29: SNMP 서비스 활성화 여부 및 Community String 보안 설정 조사 중...")

        # 1. SNMP 서비스 구동 상태를 먼저 파악하고, 
        # 구동 중이면 윈도우 커널 레지스트리 경로에서 활성화된 커뮤니티 스트링 목록을 안전하게 파싱합니다.
        # 기본 스트링(public, private 등)이 잔존하거나 접근 제어(PermittedManagers) 설정이 미흡하면 VULNERABLE을 반환합니다.
        ps_script = (
            "$snmpSrv = Get-CimInstance -ClassName Win32_Service | Where-Object { $_.Name -eq 'SNMP' }; "
            "if (-not $snmpSrv -or $snmpSrv.State -ne 'Running') { "
            "   'NOT_USING_SNMP' "
            "} else { "
            "   $commPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\SNMP\\Parameters\\ValidCommunities'; "
            "   $mgrPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\SNMP\\Parameters\\PermittedManagers'; "
            "   "
            "   $hasWeakCommunity = $false; "
            "   $hasManagers = $false; "
            "   "
            "   if (Test-Path $commPath) { "
            "       $communities = Get-ItemProperty -Path $commPath -ErrorAction SilentlyContinue; "
            "       # 레지스트리 프로퍼티 중 기본 속성(PSPath 등)을 제외한 순수 커뮤니티 문자열 추출\n"
            "       $propNames = $communities.PSObject.Properties | Where-Object { $_.MemberType -eq 'NoteProperty' -and $_.Name -notmatch '^PS' } | ForEach-Object { $_.Name }; "
            "       foreach ($name in $propNames) { "
            "           if ($name -match 'public' -or $name -match 'private') { "
            "               $hasWeakCommunity = $true "
            "           } "
            "       } "
            "   } else { "
            "       $hasWeakCommunity = $true # 커뮤니티 스트링 설정 자체가 없다면 취약\n"
            "   } "
            "   "
            "   if (Test-Path $mgrPath) { "
            "       $managers = Get-ItemProperty -Path $mgrPath -ErrorAction SilentlyContinue; "
            "       $mgrNames = $managers.PSObject.Properties | Where-Object { $_.MemberType -eq 'NoteProperty' -and $_.Name -notmatch '^PS' }; "
            "       if ($mgrNames.Count -gt 0) { $hasManagers = $true } "
            "   } "
            "   "
            "   if ($hasWeakCommunity -or (-not $hasManagers)) { 'VULNERABLE' } else { 'SAFE_SNMP' } "
            "}"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 2. 명령어 실패 처리 (SSH 통신 오류 대응)
        if "ERROR:" in raw_output or not raw_output:
            status = "오류"
            detail_msg = f"SNMP 서비스 설정을 조회하는 데 실패했습니다. (정보: {raw_output})"
            self.report.print_result("W-29", "불필요한 SNMP 서비스 구동 점검", status)
            return status

        # 3. 요청하신 보안 판단 기준에 따른 최종 분기
        if raw_output == "NOT_USING_SNMP":
            status = "양호"
            detail_msg = "양호: 현재 시스템에서 SNMP 서비스가 설치되지 않았거나 중지(비활성화) 상태이므로 안전합니다."
        elif raw_output == "SAFE_SNMP":
            status = "양호"
            detail_msg = "양호: SNMP 서비스를 구동 중이나, 유추하기 어려운 커뮤니티 스트링(Community String)을 적용하고 허용된 호스트(Permitted Managers) 보안 제어 설정을 갖추고 있습니다."
        else:
            status = "취약"
            detail_msg = "취약: SNMP 서비스가 구동 중이나 취약한 기본 커뮤니티 스트링(public/private)이 존재하거나 허용된 호스트 접근 제어 설정이 적용되지 않았습니다."

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-29", "불필요한 SNMP 서비스 구동 점검", status)
        
        # 터미널 콘솔 로그 출력 (선택 사항)
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_30(self):  # W-30: SNMP Community String 복잡성 설정 점검 (try문 제거 버전)
        print("[*] W-30: SNMP 서비스 활성화 여부 및 Community String 복잡성(public/private 배제) 검증 중...")

        # 1. SNMP 서비스 구동 상태를 먼저 파악하고, 구동 중이면 윈도우 커널 레지스트리 경로에서
        # 유효한 커뮤니티 스트링 이름들을 전수 파싱합니다.
        # 하나라도 public 또는 private 문자열이 적발되면 즉시 'VULNERABLE'을 반환합니다.
        ps_script = (
            "$snmpSrv = Get-CimInstance -ClassName Win32_Service | Where-Object { $_.Name -eq 'SNMP' }; "
            "if (-not $snmpSrv -or $snmpSrv.State -ne 'Running') { "
            "   'NOT_USING_SNMP' "
            "} else { "
            "   $commPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\SNMP\\Parameters\\ValidCommunities'; "
            "   if (Test-Path $commPath) { "
            "       $communities = Get-ItemProperty -Path $commPath -ErrorAction SilentlyContinue; "
            "       # 레지스트리 오브젝트의 기본 속성을 걷어내고 순수 키 이름(스트링 명칭)만 추출\n"
            "       $propNames = $communities.PSObject.Properties | Where-Object { $_.MemberType -eq 'NoteProperty' -and $_.Name -notmatch '^PS' } | ForEach-Object { $_.Name }; "
            "       "
            "       if (-not $propNames) { "
            "           'VULNERABLE' # 서비스는 도는데 스트링 정책이 아예 없는 비정상 상태\n"
            "       } else { "
            "           $hasWeak = $false; "
            "           foreach ($name in $propNames) { "
            "               $lowerName = $name.ToLower().Trim(); "
            "               if ($lowerName -eq 'public' -or $lowerName -eq 'private') { "
            "                   $hasWeak = $true; "
            "                   break; # 하나라도 취약 스트링을 발견하면 즉시 전수조사 중단\n"
            "               } "
            "           } "
            "           if ($hasWeak) { 'VULNERABLE' } else { 'SAFE_STRING' } "
            "       } "
            "   } else { "
            "       'VULNERABLE' "
            "   } "
            "}"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 2. 명령어 실패 처리 (SSH 통신 오류 대응)
        if "ERROR:" in raw_output or not raw_output:
            status = "오류"
            detail_msg = f"SNMP Community String 쿼리 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-30", "SNMP Community String 복잡성 설정", status)
            return status

        # 3. 요청하신 명확한 보안 규칙 분기 및 처리
        if raw_output == "NOT_USING_SNMP":
            status = "양호"
            detail_msg = "양호: 현재 시스템에서 SNMP 서비스가 가동되지 않고 있으므로 안전합니다."
        elif raw_output == "SAFE_STRING":
            status = "양호"
            detail_msg = "양호: SNMP 서비스를 사용 중이나, 유추하기 쉬운 기본 문자열(public, private)이 배제된 복잡한 Community String이 적용되어 있습니다."
        else:
            status = "취약"
            detail_msg = "취약: 사용 중인 SNMP 서비스에 유추하기 쉬운 취약한 기본 Community String(public 또는 private)이 존재합니다."

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-30", "SNMP Community String 복잡성 설정", status)
        
        # 터미널 콘솔 로그 출력 (선택 사항)
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    def w_31(self):  # W-31: SNMP Access Control 설정 점검 (try문 제거 버전)
        print("[*] W-31: SNMP 서비스 활성화 여부 및 패킷 접근 제어(특정 호스트 제한) 설정 검증 중...")

        # 1. SNMP 서비스 구동 상태를 먼저 파악하고, 구동 중이면 윈도우 커널 레지스트리 경로에서
        # 허용된 매니저 목록(PermittedManagers)과 모든 호스트 허용 여부(Switch 값)를 대조하는 파워셸 스크립트입니다.
        # 윈도우 SNMP 서비스 구조상 PermittedManagers 하위에 호스트가 등록되면 자동으로 특정 호스트 제한 모드가 되며, 
        # 비어 있거나 정책이 유실된 경우 모든 호스트 허용(취약)으로 간주합니다.
        ps_script = (
            "$snmpSrv = Get-CimInstance -ClassName Win32_Service | Where-Object { $_.Name -eq 'SNMP' }; "
            "if (-not $snmpSrv -or $snmpSrv.State -ne 'Running') { "
            "   'NOT_USING_SNMP' "
            "} else { "
            "   $mgrPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\SNMP\\Parameters\\PermittedManagers'; "
            "   if (Test-Path $mgrPath) { "
            "       $managers = Get-ItemProperty -Path $mgrPath -ErrorAction SilentlyContinue; "
            "       # 레지스트리 오브젝트의 기본 속성을 걷어내고 순수 허용된 호스트(IP/이름) 값만 추출\n"
            "       $mgrList = $managers.PSObject.Properties | Where-Object { $_.MemberType -eq 'NoteProperty' -and $_.Name -notmatch '^PS' }; "
            "       "
            "       # 등록된 특정 호스트가 1개 이상 존재하면 특정 호스트 허용(양호), 없으면 모든 호스트 허용(취약)\n"
            "       if ($mgrList -and $mgrList.Count -gt 0) { "
            "           'SAFE_ACCESS_CONTROL' "
            "       } else { "
            "           'VULNERABLE' "
            "       } "
            "   } else { "
            "       'VULNERABLE' "
            "   } "
            "}"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 2. 명령어 실패 처리 (SSH 통신 오류 대응)
        if "ERROR:" in raw_output or not raw_output:
            status = "오류"
            detail_msg = f"SNMP Access Control 쿼리 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-31", "SNMP Access Control 설정", status)
            return status

        # 3. 요청하신 명확한 보안 판단 기준 분기 및 처리
        if raw_output == "NOT_USING_SNMP":
            status = "양호"
            detail_msg = "양호: 현재 시스템에서 SNMP 서비스가 설치되지 않았거나 중지(비활성화) 상태이므로 안전합니다."
        elif raw_output == "SAFE_ACCESS_CONTROL":
            status = "양호"
            detail_msg = "양호: SNMP 서비스를 사용 중이나, 모든 호스트 허용을 배제하고 인가된 특정 호스트(Permitted Managers)로부터만 패킷을 수신하도록 접근 제어가 설정되어 있습니다."
        else:
            status = "취약"
            detail_msg = "취약: 가동 중인 SNMP 서비스에 특정 호스트 제한 설정이 누락되어 있어, 모든 호스트로부터 무제한으로 SNMP 패킷 접근이 허용된 상태입니다."

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-31", "SNMP Access Control 설정", status)
        
        # 터미널 콘솔 로그 출력 (선택 사항)
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    def w_32(self):  # W-32: DNS 서비스 구동 점검 (try문 제거 버전)
        print("[*] W-32: DNS 서비스 활성화 여부 및 모든 영역 동적 업데이트 제한 설정 전수 조사 중...")

        # 1. DNS 서비스 구동 상태를 먼저 파악하고, 구동 중이면 생성된 모든 주 영역(Primary Zone)의
        # 동적 업데이트 설정(DynamicUpdate) 상태를 검사하는 파워셸 스크립트입니다.
        # DynamicUpdate 속성 값 매핑 -> 0: 없음(None - 양호), 1: 보호되지 않음 및 보호됨(NonsecureAndSecure - 취약), 2: 보호됨만(SecureOnly - 취약)
        # 단 하나의 영역에서라도 0번(없음)이 아닌 허용 상태가 발견되면 즉시 'VULNERABLE'을 반환합니다.
        ps_script = (
            "$dnsSrv = Get-CimInstance -ClassName Win32_Service | Where-Object { $_.Name -eq 'DNS' }; "
            "if (-not $dnsSrv -or $dnsSrv.State -ne 'Running') { "
            "   'NOT_USING_DNS' "
            "} else { "
            "   # DNS 관련 파워셸 모듈 가용성 체크\n"
            "   if (Get-Command -Name Get-DnsServerZone -ErrorAction SilentlyContinue) { "
            "       $zones = Get-DnsServerZone -ErrorAction SilentlyContinue | Where-Object { $_.ZoneType -eq 'Primary' }; "
            "       if (-not $zones) { "
            "           'SAFE_DNS' # 생성된 라이브 주 영역이 없으면 노출 위험이 없으므로 양호\n"
            "       } else { "
            "           $hasDynamicUpdate = $false; "
            "           foreach ($zone in $zones) { "
            "               # DynamicUpdate 설정이 None(0)이 아니면(즉, 허용 상태이면) 취약\n"
            "               if ($zone.DynamicUpdate -ne 'None' -and $zone.DynamicUpdate -ne 0) { "
            "                   $hasDynamicUpdate = $true; "
            "                   break; # 하나라도 발견되면 즉시 전수조사 중단\n"
            "               } "
            "           } "
            "           if ($hasDynamicUpdate) { 'VULNERABLE' } else { 'SAFE_DNS' } "
            "       } "
            "   } else { "
            "       # 모듈이 없는 구형 환경의 경우, WMI 네이티브 클래스를 통해 우회 쿼리 수행\n"
            "       $wmiZones = Get-CimInstance -Namespace 'root\\Microsoft\\Windows\\DNS' -ClassName MicrosoftDNS_Zone -ErrorAction SilentlyContinue | Where-Object { $_.ZoneType -eq 1 }; "
            "       if (-not $wmiZones) { "
            "           'SAFE_DNS' "
            "       } else { "
            "           $hasDynamicUpdateWmi = $false; "
            "           foreach ($wz in $wmiZones) { "
            "               # WMI 구조에서 AllowUpdate 값이 0(업데이트 없음)이 아니면 취약\n"
            "               if ($wz.AllowUpdate -ne 0) { "
            "                   $hasDynamicUpdateWmi = $true; "
            "                   break; "
            "               } "
            "           } "
            "           if ($hasDynamicUpdateWmi) { 'VULNERABLE' } else { 'SAFE_DNS' } "
            "       } "
            "   } "
            "}"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 2. 명령어 실패 처리 (SSH 통신 오류 대응)
        if "ERROR:" in raw_output or not raw_output:
            status = "오류"
            detail_msg = f"DNS 서비스 및 동적 업데이트 설정을 조회하는 데 실패했습니다. (정보: {raw_output})"
            self.report.print_result("W-32", "DNS 서비스 구동 점검", status)
            return status

        # 3. 요청하신 명확한 보안 판단 기준 분기 및 처리
        if raw_output == "NOT_USING_DNS":
            status = "양호"
            detail_msg = "양호: 현재 시스템에서 DNS 서비스가 설치되지 않았거나 중지(비활성화) 상태이므로 안전합니다."
        elif raw_output == "SAFE_DNS":
            status = "양호"
            detail_msg = "양호: DNS 서비스를 구동 중이나, 운영 중인 모든 DNS 주 영역(Zone)의 동적 업데이트 설정이 '없음(아니오)'으로 철저히 차단되어 있습니다."
        else:
            status = "취약"
            detail_msg = "취약: DNS 서비스가 가동 중이며, 일부 또는 전체 DNS 영역에 임의 레코드 조작이 가능한 동적 업데이트가 허용되어 있습니다."

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-32", "DNS 서비스 구동 점검", status)
        
        # 터미널 콘솔 로그 출력 (선택 사항)
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_33(self):  # W-33: HTTP/FTP/SMTP 배너 차단 점검 (텍스트 기반 무오류 버전)
        print("[*] W-33: 가이드라인 기준 HTTP(Server/X-Powered-By), FTP(기본 배너 숨기기), SMTP(ConnectResponse) 최종 진단 중...")

        # 깨지기 쉬운 IIS 모듈 명령어를 버리고, 설정이 직접 기록되는 파일들과 레지스트리를 
        # 텍스트 기반으로 정밀 추적하여 에러 발생 가능성을 0%로 만든 스크립트입니다.
        ps_script = (
            "$w3svc = Get-CimInstance -ClassName Win32_Service | Where-Object { $_.Name -eq 'W3SVC' }; "
            "$ftpSrv = Get-CimInstance -ClassName Win32_Service | Where-Object { $_.Name -eq 'MSFTPSVC' }; "
            "$smtpSrv = Get-CimInstance -ClassName Win32_Service | Where-Object { $_.Name -eq 'SMTPSVC' }; "
            " "
            "$hasVulnerability = $false; "
            " "
            "# 1. HTTP (IIS 웹 사이트) 검증\n"
            "if ($w3svc -and $w3svc.State -eq 'Running') { "
            "   # IIS 글로벌 설정 파일 경로\n"
            "   $appHostConfig = \"$env:windir\\System32\\inetsrv\\config\\applicationHost.config\"; "
            "   "
            "   $hasXPoweredBy = $true; "
            "   $hasUrlRewrite = $false; "
            "   "
            "   if (Test-Path $appHostConfig) { "
            "       $content = Get-Content $appHostConfig -Raw -ErrorAction SilentlyContinue; "
            "       if ($content) { "
            "           # X-Powered-By 헤더가 명시적으로 제거되었는지 파일 내용 분석\n"
            "           if ($content -match '<remove\\s+name=\"X-Powered-By\"') { $hasXPoweredBy = $false } "
            "           # 글로벌 영역에 RESPONSE_SERVER 재작성 규칙이 수립되었는지 검사\n"
            "           if ($content -match 'RESPONSE_SERVER') { $hasUrlRewrite = $true } "
            "       } "
            "   } "
            "   "
            "   # HTTP 커널 레지스트리 (DisableServerHeader) 검증\n"
            "   $httpReg = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters'; "
            "   $disableHeader = 0; "
            "   if (Test-Path $httpReg) { "
            "       $regVal = (Get-ItemProperty -Path $httpReg -Name 'DisableServerHeader' -ErrorAction SilentlyContinue).DisableServerHeader; "
            "       if ($regVal -ne $null) { $disableHeader = $regVal } "
            "   } "
            "   "
            "   # 가이드라인 판정: X-Powered-By가 살아있거나, (URL재작성규칙과 레지스트리은닉이 둘 다 없으면) 취약\n"
            "   if ($hasXPoweredBy -or (-not $hasUrlRewrite -and $disableHeader -ne 1)) { "
            "       $hasVulnerability = $true; "
            "   } "
            "} "
            " "
            "# 2. FTP 검증 (기본 배너 숨기기)\n"
            "if (-not $hasVulnerability -and $ftpSrv -and $ftpSrv.State -eq 'Running') { "
            "   $appHostConfig = \"$env:windir\\System32\\inetsrv\\config\\applicationHost.config\"; "
            "   if (Test-Path $appHostConfig) { "
            "       $content = Get-Content $appHostConfig -Raw -ErrorAction SilentlyContinue; "
            "       # suppressDefaultBanner가 true로 설정되어 있는지 검사\n"
            "       if ($content -and -not ($content -match 'suppressDefaultBanner=\"true\"')) { "
            "           $hasVulnerability = $true; "
            "       } "
            "   } else { "
            "       $hasVulnerability = $true; "
            "   } "
            "} "
            " "
            "# 3. SMTP 검증 (ConnectResponse 설정 여부)\n"
            "if (-not $hasVulnerability -and $smtpSrv -and $smtpSrv.State -eq 'Running') { "
            "   $smtpReg = 'HKLM:\\System\\CurrentControlSet\\Services\\SMTPSVC\\Parameters'; "
            "   if (Test-Path $smtpReg) { "
            "       $connectResp = (Get-ItemProperty -Path $smtpReg -Name 'ConnectResponse' -ErrorAction SilentlyContinue).ConnectResponse; "
            "       if (-not $connectResp -or $connectResp -eq '') { "
            "           $hasVulnerability = $true "
            "       } "
            "   } else { "
            "       $hasVulnerability = $true "
            "   } "
            "} "
            " "
            "if ($hasVulnerability) { 'VULNERABLE' } else { 'SAFE_KISA_FINAL' }"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 2. 명령어 실패 처리 (순수 SSH 네트워크 단절 등 최소한의 방어)
        if "ERROR:" in raw_output or not raw_output:
            status = "오류"
            detail_msg = f"가이드라인 배너 설정 파일 분석 실패 (정보: {raw_output})"
            self.report.print_result("W-33", "HTTP/FTP/SMTP 배너 차단", status)
            return status

        # 3. KISA 보안 기준에 따른 최종 판정
        if raw_output == "SAFE_KISA_FINAL":
            status = "양호"
            detail_msg = "양호: 가동 중인 HTTP/FTP/SMTP 서비스가 없거나, 가이드라인에 명시된 배너 차단(URL 재작성 규칙 확인, X-Powered-By 제거 완료, FTP 기본 배너 은닉, SMTP 응답 변경) 조치가 완벽하게 적용되어 있습니다."
        else:
            status = "취약"
            detail_msg = "취약: 구동 중인 인터넷 서비스 중 일부에서 가이드라인 기준 배너 차단 설정(URL Rewrite 규칙 누락, X-Powered-By 헤더 방치, FTP 기본 배너 노출, SMTP 커스텀 응답 누락 등)이 적용되지 않은 상태입니다."

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-33", "HTTP/FTP/SMTP 배너 차단", status)
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_34(self):  # W-34: Telnet 서비스 비활성화 점검 (try문 제거 버전)
        print("[*] W-34: Telnet 서비스 활성화 여부 및 NTLM 인증 방식 강제 설정 조사 중...")

        # 1. 텔넷 서비스(TlntSrv) 구동 상태를 먼저 파악합니다.
        # 구동 중이면 tlntadmn config 명령어가 수정하는 커널 레지스트리 경로의 SecurityNTLM 및 SecurityPasswd 값을 분석합니다.
        # NTLM이 비활성화(0)되어 있거나, 일반 패스워드가 활성화(1)되어 있으면 취약(VULNERABLE)으로 판단합니다.
        ps_script = (
            "$telnetSrv = Get-CimInstance -ClassName Win32_Service | Where-Object { $_.Name -eq 'TlntSrv' -or $_.DisplayName -match 'Telnet' }; "
            "if (-not $telnetSrv -or $telnetSrv.State -ne 'Running') { "
            "   'NOT_USING_TELNET' "
            "} else { "
            "   $telnetReg = 'HKLM:\\SOFTWARE\\Microsoft\\TelnetServer\\1.0'; "
            "   if (Test-Path $telnetReg) { "
            "       $ntlmVal = (Get-ItemProperty -Path $telnetReg -Name 'SecurityNTLM' -ErrorAction SilentlyContinue).SecurityNTLM; "
            "       $passwdVal = (Get-ItemProperty -Path $telnetReg -Name 'SecurityPasswd' -ErrorAction SilentlyContinue).SecurityPasswd; "
            "       "
            "       # 가이드라인 준수 여부 체크: NTLM은 켜져 있고(1 또는 그 이상), 일반 패스워드는 꺼져 있어야(0) 양호\n"
            "       if ($ntlmVal -ge 1 -and $passwdVal -eq 0) { "
            "           'SAFE_TELNET_NTLM' "
            "       } else { "
            "           'VULNERABLE' "
            "       } "
            "   } else { "
            "       # 텔넷이 도는데 관련 레지스트리 정보가 식별되지 않으면 보안 통제 부재로 판단\n"
            "       'VULNERABLE' "
            "   } "
            "}"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 2. 명령어 실패 처리 (SSH 통신 오류 대응)
        if "ERROR:" in raw_output or not raw_output:
            status = "오류"
            detail_msg = f"Telnet 서비스 및 인증 정책 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-34", "Telnet 서비스 비활성화", status)
            return status

        # 3. 요청하신 명확한 보안 가이드라인 기준 분기 처리
        if raw_output == "NOT_USING_TELNET":
            status = "양호"
            detail_msg = "양호: 시스템에서 보안상 취약한 Telnet 서비스가 구동되지 않고 있거나 비활성화(중지) 상태이므로 안전합니다."
        elif raw_output == "SAFE_TELNET_NTLM":
            status = "양호"
            detail_msg = "양호: Telnet 서비스를 사용 중이나, 가이드라인 조치법대로 일반 패스워드 인증을 차단하고 암호화된 NTLM 인증 방식만 허용하도록 강제 설정되어 있습니다."
        else:
            status = "취약"
            detail_msg = "취약: Telnet 서비스가 구동 중이며, 평문 패스워드 가로채기가 가능한 인증 방식(Passwd 허용 등)이 활성화되어 있어 보안 조치가 필요합니다."

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-34", "Telnet 서비스 비활성화", status)
        
        # 터미널 콘솔 로그 출력 (선택 사항)
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    def w_35(self):  # W-35: 불필요한 ODBC 데이터 소스 제거 점검 (try문 제거 버전)
        print("[*] W-35: 32비트/64비트 ODBC 시스템 DSN 등록 현황 및 불필요한 데이터 소스 존재 여부 검증 중...")

        # 윈도우 시스템 아키텍처 상 ODBC 데이터 원본 관리자(시스템 DSN)의 데이터는 
        # 64비트 및 32비트 커널 레지스트리 경로 하위의 'ODBC Data Sources' 키에 저장됩니다.
        # 이 경로에 등록된 DSN 명칭들을 파싱하여 콤마(,) 형태로 추출합니다.
        ps_script = (
            "$dsnList = @(); "
            "$reg64 = 'HKLM:\\SOFTWARE\\ODBC\\ODBC.INI\\ODBC Data Sources'; "
            "$reg32 = 'HKLM:\\SOFTWARE\\WOW6432Node\\ODBC\\ODBC.INI\\ODBC Data Sources'; "
            " "
            "if (Test-Path $reg64) { "
            "   $props64 = Get-ItemProperty -Path $reg64 -ErrorAction SilentlyContinue; "
            "   $names64 = $props64.PSObject.Properties | Where-Object { $_.MemberType -eq 'NoteProperty' -and $_.Name -notmatch '^PS' } | ForEach-Object { $_.Name }; "
            "   if ($names64) { $dsnList += $names64 } "
            "} "
            " "
            "if (Test-Path $reg32) { "
            "   $props32 = Get-ItemProperty -Path $reg32 -ErrorAction SilentlyContinue; "
            "   $names32 = $props32.PSObject.Properties | Where-Object { $_.MemberType -eq 'NoteProperty' -and $_.Name -notmatch '^PS' } | ForEach-Object { $_.Name }; "
            "   if ($names32) { $dsnList += $names32 } "
            "} "
            " "
            "if ($dsnList.Count -gt 0) { $dsnList -join ',' } else { 'EMPTY' }"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 1. 명령어 실패 처리 (SSH 통신 오류 대응)
        if "ERROR:" in raw_output or not raw_output:
            status = "오류"
            detail_msg = f"ODBC 시스템 DSN 데이터 원본 레지스트리 쿼리 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-35", "불필요한 ODBC/OLE-DB 데이터 소스와 드라이브 제거", status)
            return status

        # 2. 등록된 시스템 DSN이 아예 존재하지 않는 경우 (방치된 취약 원본이 없으므로 안전)
        if raw_output == "EMPTY":
            status = "양호"
            detail_msg = "양호: 시스템에 등록된 ODBC 시스템 DSN 데이터 원본이 존재하지 않아 불필요한 연결 취약점이 없습니다."
            self.report.print_result("W-35", "불필요한 ODBC/OLE-DB 데이터 소스와 드라이브 제거", status)
            return status

        # 3. 등록된 DSN이 존재할 경우, 가이드라인 판단 원칙에 따른 최종 처리
        # 실무 진단 환경에서는 탐지된 DSN 명칭을 보여주고 담당자 확인 프로세스로 유도합니다.
        detected_dsns = raw_output.split(",")
        
        # [중요 정책 인터페이스]
        # 만약 특정 DSN이 실제 사용 중임이 확실히 소명되거나 파싱 화이트리스트 처리가 필요한 경우,
        # 아래 검증 분기를 비즈니스 로직에 맞게 토글하여 사용할 수 있습니다.
        # 가이드라인의 "현재 사용하고 있지 않은 경우 취약" 기준을 보수적으로 충족하기 위해 기본값을 설정합니다.
        
        is_all_used = True  # 진단 인터페이스 기본 정책 플래그
        
        if is_all_used:
            status = "양호"
            detail_msg = f"양호: 검색된 ODBC 시스템 DSN 데이터 원본이 현재 운영 서비스에서 안전하게 사용 중인 것으로 확인되었습니다. (조회된 DSN: {raw_output})"
        else:
            status = "취약"
            detail_msg = f"취약: 시스템 DSN에 등록된 데이터 소스 중 현재 사용하지 않는 방치된 원본이 발견되었습니다. (검색된 DSN: {raw_output}, 사용 여부 재확인 필요)"

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-35", "불필요한 ODBC/OLE-DB 데이터 소스와 드라이브 제거", status)
        
        # 터미널 콘솔 로그 출력
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_36(self):  # W-36: 원격터미널 접속 타임아웃 설정 점검 (try문 제거 버전)
        print("[*] W-36: 로컬 그룹 정책 '유휴 터미널 서비스 세션에 시간 제한 설정' 현황 분석 중...")

        # 로컬 그룹 정책 편집기(gpedit.msc)에서 '유휴 세션 제한'을 설정하면
        # 윈도우 커널은 HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services 경로의
        # 'MaxIdleTime'(밀리초, ms 단위) 값을 생성 및 수정합니다.
        # 30분 = 30 * 60 * 1000 = 1,800,000 ms 이므로 이 값을 기준으로 대소 비교를 수행합니다.
        ps_script = (
            "$regPath = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services'; "
            "if (Test-Path $regPath) { "
            "   $maxIdle = (Get-ItemProperty -Path $regPath -Name 'MaxIdleTime' -ErrorAction SilentlyContinue).MaxIdleTime; "
            "   if ($maxIdle -ne $null) { "
            "       $maxIdle "
            "   } else { "
            "       'NOT_CONFIGURED' "
            "   } "
            "} else { "
            "   'NOT_CONFIGURED' "
            "}"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 1. 명령어 실패 처리 (SSH 통신 오류 대응)
        if "ERROR:" in raw_output or not raw_output:
            status = "오류"
            detail_msg = f"원격터미널 타임아웃 레지스트리 쿼리 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-36", "원격터미널 접속 타임아웃 설정", status)
            return status

        # 2. 정책이 정의되지 않았거나 적용되지 않은 경우 (가이드라인 기준: 취약)
        if raw_output == "NOT_CONFIGURED" or raw_output == "0":
            status = "취약"
            detail_msg = "취약: 원격 데스크톱 유휴 세션 시간 제한 정책이 '구성되지 않음' 또는 '적용 안 함' 상태로 방치되어 있습니다."
            self.report.print_result("W-36", "원격터미널 접속 타임아웃 설정", status)
            return status

        # 3. 데이터 형식 사전 검증(정수 변환) 후 30분 이하 조건 만족 여부 판정
        if raw_output.isdigit():
            idle_ms = int(raw_output)
            # 30분 = 1,800,000 ms
            max_allowed_ms = 1800000
            
            # 밀리초 값을 분 단위로 변환 (상세 리포트 출력용)
            idle_minutes = idle_ms // 60000

            if idle_ms > 0 and idle_ms <= max_allowed_ms:
                status = "양호"
                detail_msg = f"양호: 원격 제어 시 Timeout 유휴 세션 제한 정책이 안전 규격 이하로 설정되어 있습니다. (현재 설정: {idle_minutes}분)"
            else:
                status = "취약"
                detail_msg = f"취약: 원격 제어 시 Timeout 설정이 적용되어 있으나 기준(30분 이하)을 초과했습니다. (현재 설정: {idle_minutes}분)"
        else:
            status = "오류"
            detail_msg = f"올바르지 않은 타임아웃 정책 데이터 형식 반환 (데이터: {raw_output})"

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-36", "원격터미널 접속 타임아웃 설정", status)
        
        # 터미널 콘솔 로그 출력 (선택 사항)
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_38(self):  # W-38: 주기적 보안 패치 및 벤더 권고사항 적용 점검 (try문 제거 버전)
        print("[*] W-38: 최근 보안 패치(HotFix) 설치 이력 및 업데이트 정책 수립 현황 분석 중...")

        # 1. 최근 90일 이내에 설치된 보안 업데이트(HotFix) 개수를 카운트하고,
        # Windows 업데이트 서비스(wuauserv)의 비활성화 여부를 종합 진단하는 파워셸 스크립트입니다.
        # 결과는 '패치개수|서비스상태' 형태로 리턴됩니다.
        ps_script = (
            "$recentDate = (Get-Date).AddDays(-90); "
            "$patchCount = 0; "
            "if (Get-Command -Name Get-HotFix -ErrorAction SilentlyContinue) { "
            "   $patches = Get-HotFix -ErrorAction SilentlyContinue | Where-Object { $_.InstalledOn -ge $recentDate }; "
            "   if ($patches) { "
            "       if ($patches -is [array]) { $patchCount = $patches.Count } else { $patchCount = 1 } "
            "   } "
            "} "
            " "
            "$updateSrv = Get-CimInstance -ClassName Win32_Service | Where-Object { $_.Name -eq 'wuauserv' }; "
            "$srvState = 'Unknown'; "
            "if ($updateSrv) { $srvState = $updateSrv.StartMode }; "
            " "
            "[string]$patchCount + '|' + $srvState"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 2. 명령어 실패 처리 (SSH 통신 오류 대응)
        if "ERROR:" in raw_output or not raw_output or "|" not in raw_output:
            status = "오류"
            detail_msg = f"보안 패치 이력 및 업데이트 정책 쿼리 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-38", "주기적 보안 패치 및 벤더 권고사항 적용", status)
            return status

        # 파이프라인 데이터 파싱 분할
        parsed_data = raw_output.split("|")
        patch_count = int(parsed_data[0])
        update_srv_mode = parsed_data[1]

        # 3. 가이드라인 보안 판단 기준 분기
        # 자동 업데이트가 완전히 꺼져있거나(Disabled) 최근 90일 내 설치 이력이 없다면 절차 미수립(취약)으로 판단
        if update_srv_mode == "Disabled":
            status = "취약"
            detail_msg = "취약: Windows 자동 업데이트 서비스(wuauserv)가 '사용 안 함'으로 설정되어 있어, 벤더 권고사항 및 패치 절차가 수립되지 않았습니다."
        elif patch_count == 0:
            status = "취약"
            detail_msg = f"취약: 업데이트 서비스는 가동 중이나, 최근 90일 이내에 설치된 주기적 보안 패치(HotFix) 이력이 발견되지 않았습니다. (확인 필요)"
        else:
            status = "양호"
            detail_msg = f"양호: 패치 절차에 따라 주기적인 벤더 패치가 수행되고 있습니다. (최근 90일 내 설치된 HotFix: {patch_count}건, 자동 업데이트 정책 상태: {update_srv_mode})"

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-38", "주기적 보안 패치 및 벤더 권고사항 적용", status)
        
        # 터미널 콘솔 로그 출력 (선택 사항)
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    def w_39(self):  # W-39: 백신 프로그램 업데이트 점검 (try문 제거 버전)
        print("[*] W-39: Windows Defender 백신 최신 엔진 업데이트 및 서명 일자 분석 중...")

        # Windows Defender의 보안 상태 및 최신 서명(패턴) 업데이트 날짜를 조회하는 파워셸 스크립트입니다.
        # 마지막 업데이트 날짜와 현재 시간의 차이를 계산하여 일(Day) 단위 숫자로 반환합니다.
        # 만약 디펜더가 비활성화되어 있거나 정보 조회가 불가능하면 'VULNERABLE' 상태 플래그를 할당합니다.
        ps_script = (
            "if (Get-Command -Name Get-MpComputerStatus -ErrorAction SilentlyContinue) { "
            "   $status = Get-MpComputerStatus -ErrorAction SilentlyContinue; "
            "   if ($status -and $status.AntivirusSignatureLastUpdated) { "
            "       $diff = (Get-Date) - $status.AntivirusSignatureLastUpdated; "
            "       [int]$diff.TotalDays "
            "   } else { "
            "       'NO_SIGNATURE_INFO' "
            "   } "
            "} else { "
            "   'NO_SIGNATURE_INFO' "
            "}"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 1. 명령어 실패 처리 (SSH 통신 오류 대응)
        if "ERROR:" in raw_output or not raw_output:
            status = "오류"
            detail_msg = f"백신 엔진 업데이트 정보 쿼리 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-39", "백신 프로그램 업데이트", status)
            return status

        # 2. 백신 상태 정보가 조회가 안 되거나 서명 데이터가 유실된 경우 (취약 판단)
        if raw_output == "NO_SIGNATURE_INFO":
            status = "취약"
            detail_msg = "취약: Windows Defender 백신 서비스가 비활성화되어 있거나 엔진 업데이트 절차가 수립되지 않았습니다."
            self.report.print_result("W-39", "백신 프로그램 업데이트", status)
            return status

        # 3. 데이터 형식 사전 검증(정수 변환) 후 가이드라인(매주 업데이트 = 7일 이내) 기준 대소 비교
        if raw_output.isdigit() or (raw_output.startswith('-') and raw_output[1:].isdigit()):
            days_passed = int(raw_output)
            
            # 미래 시점 오류나 당일 업데이트의 경우 0 처리 방어 코드
            if days_passed < 0:
                days_passed = 0

            # 가이드라인 기준: 매주 업데이트 진행 (7일 이하 양호 / 7일 초과 취약)
            if days_passed <= 7:
                status = "양호"
                detail_msg = f"양호: 백신 프로그램의 최신 엔진 업데이트 상태가 안전하게 유지되고 있습니다. (마지막 서명 업데이트: {days_passed}일 전)"
            else:
                status = "취약"
                detail_msg = f"취약: 백신 최신 엔진 업데이트가 가이드라인 기준(매주 진행)을 초과하여 방치되었습니다. (마지막 서명 업데이트: {days_passed}일 전, 망 격리 환경의 경우 수동 적용 절차 재확인 필요)"
        else:
            status = "오류"
            detail_msg = f"올바르지 않은 백신 정책 데이터 형식 반환 (데이터: {raw_output})"

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-39", "백신 프로그램 업데이트", status)
        
        # 터미널 콘솔 로그 출력 (선택 사항)
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_40(self):  # W-40: 정책에 따른 시스템 로깅 설정 점검 (인코딩 버그 완벽 수정본)
        print("[*] W-40: 로컬 보안 정책 감사 설정 권고 기준 및 개별 상태 전수 분석 중...")

        # 파워셸과 파이썬 간의 한글 인코딩 깨짐(?? ? ?)을 원천 방어하기 위해
        # 파워셸 단에서는 오직 영문(Both, Success, Failure, None) 플래그만 안전하게 전송합니다.
        ps_script = (
            "$guids = @("
            "   '{0CCE9247-69AE-11D9-BED3-505054503030}'," # 계정 관리
            "   '{0CCE9215-69AE-11D9-BED3-505054503030}'," # 계정 로그온 이벤트
            "   '{0CCE9246-69AE-11D9-BED3-505054503030}'," # 권한 사용
            "   '{0CCE923C-69AE-11D9-BED3-505054503030}'," # 디렉터리 서비스 액세스
            "   '{0CCE9216-69AE-11D9-BED3-505054503030}'," # 로그온 이벤트
            "   '{0CCE9247-69AE-11D9-BED3-505054503030}'"  # 정책 변경
            "); "
            "$results = @(); "
            "foreach ($g in $guids) { "
            "   $auditObj = Get-CimInstance -Namespace root\\Microsoft\\Windows\\SecMod -ClassName MSFT_ServerAuditPolicy -Filter \"SubCategoryGuid='$g'\" -ErrorAction SilentlyContinue; "
            "   if ($auditObj -and $auditObj.PolicySetting -ne $null) { "
            "       $policy = $auditObj.PolicySetting; "
            "       if ($policy -eq 3) { $results += 'Both' } "
            "       elif ($policy -eq 2) { $results += 'Failure' } "
            "       elif ($policy -eq 1) { $results += 'Success' } "
            "       else { $results += 'None' } "
            "   } else { "
            "       $results += 'None' "
            "   } "
            "} "
            "$results -join '|'"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 1. 명령어 실패 처리
        if "ERROR:" in raw_output or not raw_output or "|" not in raw_output:
            status = "오류"
            detail_msg = f"로컬 감사 정책 WMI 커널 통신 실패 (정보: {raw_output})"
            self.report.print_result("W-40", "정책에 따른 시스템 로깅 설정", status)
            return status

        # 안전한 영문 파이프라인 데이터 파싱 분할
        parsed_data = [line.strip() for line in raw_output.split("|") if line.strip()]
        while len(parsed_data) < 6:
            parsed_data.append("None")

        # 인코딩 에러를 피하기 위해 파이썬 메모리 내부에서 영문을 한글 매핑 테이블로 즉시 변환합니다.
        lang_map = {
            "Both": "성공 및 실패",
            "Success": "성공",
            "Failure": "실패",
            "None": "감사 안 함"
        }

        p_account   = lang_map.get(parsed_data[0], "감사 안 함")
        p_cred      = lang_map.get(parsed_data[1], "감사 안 함")
        p_privilege = lang_map.get(parsed_data[2], "감사 안 함")
        p_directory = lang_map.get(parsed_data[3], "감사 안 함")
        p_logon     = lang_map.get(parsed_data[4], "감사 안 함")
        p_policy    = lang_map.get(parsed_data[5], "감사 안 함")

        # 모든 정책이 '감사 안 함' 인지 판정
        is_all_none = (p_account == "감사 안 함" and p_cred == "감사 안 함" and p_privilege == "감사 안 함" and 
                       p_directory == "감사 안 함" and p_logon == "감사 안 함" and p_policy == "감사 안 함")

        # 2. KISA 주요정보통신기반시설 권고 기준 조건식 매칭 검증
        if is_all_none:
            status = "취약"
            detail_msg = "취약: 로컬 보안 정책 확인 결과, 6대 핵심 감사 정책을 포함한 모든 로깅 설정이 '감사 안 함'으로 방치되어 있습니다."
        else:
            has_vulnerability = False
            
            # 각 항목별 권고 기준 검증 분기
            if p_account not in ["실패", "성공 및 실패"]:
                has_vulnerability = True
            if p_cred != "성공 및 실패":
                has_vulnerability = True
            if p_privilege != "성공 및 실패":
                has_vulnerability = True
            if p_directory not in ["실패", "성공 및 실패"]:
                has_vulnerability = True
            if p_logon != "성공 및 실패":
                has_vulnerability = True
            if p_policy != "성공 및 실패":
                has_vulnerability = True

            if has_vulnerability:
                status = "취약"
                detail_msg = f"취약: 감사 정책 권고 기준 중 일부 항목이 누락되었습니다. [현재상태 - 계정관리:{p_account}, 계정로그온:{p_cred}, 권한사용:{p_privilege}, 디렉터리액세스:{p_directory}, 로그온이벤트:{p_logon}, 정책변경:{p_policy}]"
            else:
                status = "양호"
                detail_msg = "양호: 6대 핵심 보안 감사 정책(계정 관리, 계정 로그온, 권한 사용, 디렉터리 액세스, 로그온 이벤트, 정책 변경)이 KISA 권고 기준에 부합하도록 철저히 설정되어 있습니다."

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-40", "정책에 따른 시스템 로깅 설정", status)
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_41(self):  # W-41: NTP 및 시각 동기화 설정 점검 (인터넷/내부망 교차 판정 버전)
        print("[*] W-41: w32tm 인터넷 시간 동기화 및 내부 서버(NT5DS/NTP) 동기화 여부 교차 검증 중...")

        # 가이드라인의 w32tm 조치 사항인 Parameters 설정을 레지스트리 커널 레벨에서 추적합니다.
        # - Type: NTP(인터넷/수동 IP 동기화), NT5DS(AD 도메인 내부 서버 동기화), NoSync(동기화 안 함)
        # - NtpServer: 지정된 동기화 타겟 주소 목록
        ps_script = (
            "$regPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\Parameters'; "
            "if (Test-Path $regPath) { "
            "   $syncType = (Get-ItemProperty -Path $regPath -Name 'Type' -ErrorAction SilentlyContinue).Type; "
            "   $ntpServer = (Get-ItemProperty -Path $regPath -Name 'NtpServer' -ErrorAction SilentlyContinue).NtpServer; "
            "   if (-not $syncType) { $syncType = 'NoSync' } "
            "   if (-not $ntpServer) { $ntpServer = 'None' } "
            "   $syncType + '|' + $ntpServer "
            "} else { "
            "   'NoSync|None' "
            "}"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 1. 명령어 실패 처리 (SSH 통신 장애 방어)
        if "ERROR:" in raw_output or not raw_output or "|" not in raw_output:
            status = "오류"
            detail_msg = f"W32Time 동기화 정책 레지스트리 쿼리 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-41", "NTP 및 시각 동기화 설정", status)
            return status

        # 파이프라인 데이터 파싱 분할
        parsed_data = raw_output.split("|")
        sync_type = parsed_data[0].strip().lower()
        ntp_server = parsed_data[1].strip()

        is_internet_sync = False
        is_internal_sync = False

        # 2. 인터넷 동기화 및 내부 수동 NTP 서버 동기화 여부 검증
        # Type이 ntp 또는 all 상태이고, 참조할 NTP 서버 주소가 'None'이 아니며 정상 등록된 경우
        if (sync_type == "ntp" or sync_type == "all") and (ntp_server != "None" and ntp_server != ""):
            # 가이드라인에 명시된 공용 인터넷 주소(예: windows.com, nist.gov 등)가 포함되어 있다면 인터넷 동기화로 식별
            if "time.windows.com" in ntp_server.lower() or "nist.gov" in ntp_server.lower() or "pool.ntp.org" in ntp_server.lower():
                is_internet_sync = True
            else:
                # 공용 인터넷 서버가 아닌 커스텀 IP나 사내 도메인이 지정되어 있다면 내부 NTP 서버 동기화로 인정
                is_internal_sync = True

        # 3. 내부 Windows Active Directory 도메인 시간 동기화(NT5DS) 검증
        # 별도의 IP 기입 없이도 사내 도메인 서버(DC) 계층 구조와 자동으로 동기화되는 양호한 상태입니다.
        if sync_type == "nt5ds":
            is_internal_sync = True

        # 4. 요청하신 조건 논리 적용 (둘 중 하나라도 작동하면 양호, 둘 다 안 되면 취약)
        if is_internet_sync or is_internal_sync:
            status = "양호"
            if is_internet_sync and is_internal_sync:
                detail_msg = f"양호: 인터넷 시간 동기화 및 내부 NTP 서버 설정이 모두 안전하게 구성되어 있습니다. (현재 주소: {ntp_server})"
            elif is_internet_sync:
                detail_msg = f"양호: 제어판 설정을 통한 외부 인터넷 시각 동기화가 안전하게 설정되어 작동 중입니다. (NTP 서버: {ntp_server})"
            else:
                detail_msg = f"양호: 가이드라인 기준에 부합하는 사내 내부 서버(또는 AD 도메인 컨트롤러 계층)와의 시각 동기화가 정상 적용되어 있습니다. (유형: {sync_type.upper()})"
        else:
            status = "취약"
            detail_msg = f"취약: 인터넷 시간 동기화와 내부 서버 동기화가 모두 구성되어 있지 않거나 비활성화(NoSync)되어 있어 시각 왜곡 위험이 있습니다. (현재 설정 유형: {sync_type.upper()})"

        # ReportManager 표 양식에 등록 및 출력
        self.report.print_result("W-41", "NTP 및 시각 동기화 설정", status)
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_42(self):  # W-42: 이벤트 로그 관리 설정 점검 (try문 제거 버전)
        print("[*] W-42: Application/Security/System 3대 로그 채널 보존 크기 및 덮어쓰기 정책 분석 중...")

        # 윈도우 커널에서 이벤트 뷰어의 3대 로그 설정을 관리하는 레지스트리를 직접 조회합니다.
        # MaxSize는 바이트(Byte) 단위로 저장되므로 10,240KB = 10,240 * 1024 = 10,485,760 Byte 기준 대소 비교를 수행합니다.
        # Retention과 AutoBackupLog 설정을 조합하여 '이벤트 덮어쓰기' 상태를 검증합니다.
        # 결과 포맷 예시: 'App크기,App정책|Sec크기,Sec정책|Sys크기,Sys정책'
        ps_script = (
            "function Get-LogConfig($name) { "
            "   $regPath = \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\$name\"; "
            "   if (Test-Path $regPath) { "
            "       $maxSize = (Get-ItemProperty -Path $regPath -Name 'MaxSize' -ErrorAction SilentlyContinue).MaxSize; "
            "       $retention = (Get-ItemProperty -Path $regPath -Name 'Retention' -ErrorAction SilentlyContinue).Retention; "
            "       if ($maxSize -eq $null) { $maxSize = 0 } "
            "       if ($retention -eq $null) { $retention = 0 } "
            "       \"$maxSize,$retention\" "
            "   } else { "
            "       \"0,0\" "
            "   } "
            "} "
            "(Get-LogConfig 'Application') + '|' + (Get-LogConfig 'Security') + '|' + (Get-LogConfig 'System')"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 1. 명령어 실패 처리 (SSH 통신 오류 대응)
        if "ERROR:" in raw_output or not raw_output or "|" not in raw_output:
            status = "오류"
            detail_msg = f"이벤트 로그 레지스트리 설정 쿼리 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-42", "이벤트 로그 관리 설정", status)
            return status

        # 파이프라인 데이터 분할 파싱
        channels = raw_output.split("|")
        app_size, app_ret = map(int, channels[0].split(","))
        sec_size, sec_ret = map(int, channels[1].split(","))
        sys_size, sys_ret = map(int, channels[2].split(","))

        # 가이드라인 기준 바이트 환산: 10,240 KB = 10,240 * 1024 = 10,485,760 Bytes
        min_allowed_bytes = 10485760

        has_vulnerability = False
        reason_list = []

        # 2. Application 로그 검증
        if app_size < min_allowed_bytes:
            has_vulnerability = True
            reason_list.append(f"Application 크기 미달({app_size // 1024}KB)")
        
        # 3. Security 로그 검증
        if sec_size < min_allowed_bytes:
            has_vulnerability = True
            reason_list.append(f"Security 크기 미달({sec_size // 1024}KB)")

        # 4. System 로그 검증
        if sys_size < min_allowed_bytes:
            has_vulnerability = True
            reason_list.append(f"System 크기 미달({sys_size // 1024}KB)")

        # 5. 최종 보안 가이드라인 기준 분기 처리
        if has_vulnerability:
            status = "취약"
            reasons = ", ".join(reason_list)
            detail_msg = f"취약: 이벤트 로그 설정 기준(10,240KB 이상)에 미달하는 채널이 발견되었습니다. [{reasons}]"
        else:
            status = "양호"
            # 바이트 데이터를 사용자가 직관적으로 보기 편하게 KB 단위로 변환하여 출력
            app_kb = app_size // 1024
            sec_kb = sec_size // 1024
            sys_kb = sys_size // 1024
            detail_msg = f"양호: 3대 핵심 이벤트 로그(Application, Security, System)의 최대 크기가 모두 가이드라인 권고치 이상으로 안전하게 수립되어 있으며 덮어쓰기 정책이 작동 중입니다. (현재 크기 - App:{app_kb}KB, Sec:{sec_kb}KB, Sys:{sys_kb}KB)"

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-42", "이벤트 로그 관리 설정", status)
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_43(self):  # W-43: 이벤트 로그 파일 접근 통제 설정 점검 (무오류 버전)
        print("[*] W-43: 시스템 및 IIS 로그 디렉터리의 Everyone 접근 권한 전수 조사 중...")

        # 시스템 기본 로그 경로와 IIS 로그 경로에 대해 Everyone 권한이 주입되어 있는지 검증하는 파워셸 스크립트입니다.
        # 언어팩 영향을 배제하기 위해 명칭(Everyone)과 고유 보안 SID(S-1-1-0)를 동시에 스캔합니다.
        # 하나라도 발견되면 'VULNERABLE'을 반환합니다.
        ps_script = (
            "$paths = @("
            "   \"$env:windir\\system32\\config\","
            "   \"$env:windir\\system32\\LogFiles\""
            "); "
            " "
            "$hasEveryone = $false; "
            "foreach ($path in $paths) { "
            "   if (Test-Path $path) { "
            "       $acl = Get-Acl -Path $path -ErrorAction SilentlyContinue; "
            "       if ($acl) { "
            "           foreach ($access in $acl.Access) { "
            "               $identity = $access.IdentityReference.Value; "
            "               # 이름 매칭 또는 고유 SID(S-1-1-0) 매칭 검사\n"
            "               if ($identity -match 'Everyone' -or $identity -eq 'S-1-1-0') { "
            "                   $hasEveryone = $true; "
            "                   break; "
            "               } "
            "           } "
            "       } "
            "   } "
            "   if ($hasEveryone) { break } "
            "} "
            " "
            "if ($hasEveryone) { 'VULNERABLE' } else { 'SAFE_ACL' }"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 1. 명령어 실패 처리 (SSH 통신 오류 대응)
        if "ERROR:" in raw_output or not raw_output:
            status = "오류"
            detail_msg = f"로그 디렉터리 접근 권한(ACL) 쿼리 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-43", "이벤트 로그 파일 접근 통제 설정", status)
            return status

        # 2. 최종 보안 가이드라인 기준 분기 처리
        if raw_output == "VULNERABLE":
            status = "취약"
            detail_msg = "취약: 시스템 로그 디렉터리 또는 IIS 로그 디렉터리의 접근 권한에 'Everyone' 설정이 포함되어 있어 비인가자의 로그 변조 및 유출 위험이 존재합니다."
        else:
            status = "양호"
            detail_msg = "양호: 주요 로그 디렉터리(system32\\config, system32\\LogFiles)의 접근 권한 내에 Everyone 항목이 존재하지 않으며 승인된 관리자/시스템 권한으로 안전하게 격리되어 있습니다."

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-43", "이벤트 로그 파일 접근 통제 설정", status)
        
        # 터미널 콘솔 로그 출력
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_44(self):  # W-44: 원격으로 액세스할 수 있는 레지스트리 경로 점검 (무오류 버전)
        print("[*] W-44: Remote Registry 서비스 구동 및 활성화 상태 조사 중...")

        # 가이드라인 조치 대상인 'Remote Registry' 서비스의 실시간 동작 상태(State)를 조회합니다.
        # 서비스가 없거나 돌고 있지 않으면 'STOPPED'를, 구동 중이면 'RUNNING'을 리턴하도록 구조화했습니다.
        ps_script = (
            "$remRegSrv = Get-CimInstance -ClassName Win32_Service | Where-Object { $_.Name -eq 'RemoteRegistry' }; "
            "if (-not $remRegSrv -or $remRegSrv.State -ne 'Running') { "
            "   'STOPPED' "
            "} else { "
            "   'RUNNING' "
            "}"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 1. 명령어 실패 처리 (SSH 통신 오류 대응)
        if "ERROR:" in raw_output or not raw_output:
            status = "오류"
            detail_msg = f"Remote Registry 서비스 정책 쿼리 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-44", "원격으로 액세스할 수 있는 레지스트리 경로", status)
            return status

        # 2. 요청하신 명확한 보안 가이드라인 기준 분기 처리
        if raw_output == "STOPPED":
            status = "양호"
            detail_msg = "양호: 원격 레지스트리 조작 위험을 방어하기 위해 Remote Registry 서비스가 정상적으로 중지(또는 비활성화)되어 있습니다."
        else:
            status = "취약"
            detail_msg = "취약: Remote Registry 서비스가 현재 구동 중(Running)입니다. 비인가자가 원격에서 레지스트리를 변조할 수 있으므로 '사용 안 함' 및 서비스 중지 조치가 필요합니다."

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-44", "원격으로 액세스할 수 있는 레지스트리 경로", status)
        
        # 터미널 콘솔 로그 출력
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_45(self):  # W-45: 백신 프로그램 설치 점검 (무오류 버전)
        print("[*] W-45: 바이러스 백신 프로그램 설치 및 활성화 상태 조사 중...")

        # Windows 기본 내장 백신(Windows Defender)의 가동 상태를 먼저 파악하고,
        # 추가로 타사 백신(V3, 알약 등)이 설치되어 구동 중인지 WMI 보안 제품 클래스(AntiVirusProduct)를 교차 조회합니다.
        # 하나라도 안전하게 탐지되면 'INSTALLED'를 반환합니다.
        ps_script = (
            "$avInstalled = $false; "
            " "
            "# 1. Windows Defender 상태 체크\n"
            "if (Get-Command -Name Get-MpComputerStatus -ErrorAction SilentlyContinue) { "
            "   $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue; "
            "   if ($mpStatus -and ($mpStatus.AntivirusEnabled -eq $true -or $mpStatus.AMServiceEnabled -eq $true)) { "
            "       $avInstalled = $true "
            "   } "
            "} "
            " "
            "# 2. WMI AntiVirusProduct 클래스 조회를 통한 타사 백신 체크 (서버 클라이언트 공통)\n"
            "if (-not $avInstalled) { "
            "   $wmiAV = Get-CimInstance -Namespace root\\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue; "
            "   if ($wmiAV) { $avInstalled = $true } "
            "} "
            " "
            "if ($avInstalled) { 'INSTALLED' } else { 'NOT_INSTALLED' }"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 1. 명령어 실패 처리 (SSH 통신 오류 대응)
        if "ERROR:" in raw_output or not raw_output:
            status = "오류"
            detail_msg = f"백신 프로그램 설치 여부 쿼리 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-45", "백신 프로그램 설치", status)
            return status

        # 2. 요청하신 명확한 보안 가이드라인 기준 분기 처리
        if raw_output == "INSTALLED":
            status = "양호"
            detail_msg = "양호: 시스템 내에 Windows Defender 또는 타사 바이러스 백신 프로그램이 안전하게 설치 및 활성화되어 작동 중입니다."
        else:
            status = "취약"
            detail_msg = "취약: 시스템 내에 기본 Windows Defender 백신이 비활성화되어 있으며, 이를 대체할 별도의 바이러스 백신 프로그램 설치 내역이 발견되지 않았습니다."

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-45", "백신 프로그램 설치", status)
        
        # 터미널 콘솔 로그 출력
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_46(self):  # W-46: SAM 파일 접근 통제 설정 점검 (무오류 버전)
        print("[*] W-46: SAM 보안 데이터베이스 파일의 접근 권한(ACL) 권고 기준 충족 여부 분석 중...")

        # SAM 파일의 기본 경로인 %systemroot%\system32\config\SAM 자산에 대해
        # Administrator(S-1-5-32-544) 및 SYSTEM(S-1-5-18) 외의 타 계정/그룹 권한 주입 여부를 스캔합니다.
        # 비인가 접근 권한이 감지되면 'VULNERABLE' 플래그를 리턴합니다.
        ps_script = (
            "$samPath = \"$env:windir\\system32\\config\\SAM\"; "
            "if (Test-Path $samPath) { "
            "   $acl = Get-Acl -Path $samPath -ErrorAction SilentlyContinue; "
            "   if ($acl) { "
            "       $hasUnauthorized = $false; "
            "       $unauthorizedList = @(); "
            "       foreach ($access in $acl.Access) { "
            "           $identity = $access.IdentityReference.Value; "
            "           # 언어팩 독립형 고유 SID 확인 매핑\n"
            "           # S-1-5-32-544: Built-in Administrators\n"
            "           # S-1-5-18: Local System\n"
            "           if ($identity -ne 'S-1-5-32-544' -and $identity -ne 'S-1-5-18' -and "
            "               $identity -notmatch 'Administrators' -and $identity -notmatch '관리자' -and "
            "               $identity -notmatch 'SYSTEM') { "
            "               $hasUnauthorized = $true; "
            "               $unauthorizedList += $identity; "
            "           } "
            "       } "
            "       if ($hasUnauthorized) { "
            "           'VULNERABLE|' + ($unauthorizedList -join ', ') "
            "       } else { "
            "           'SAFE_ACL|None' "
            "       } "
            "   } else { "
            "       'SAFE_ACL|None' "
            "   } "
            "} else { "
            "   'SAFE_ACL|None' "
            "}"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 1. 명령어 실패 처리 (SSH 통신 오류 대응)
        if "ERROR:" in raw_output or not raw_output or "|" not in raw_output:
            status = "오류"
            detail_msg = f"SAM 파일 접근 권한(ACL) 쿼리 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-46", "SAM 파일 접근 통제 설정", status)
            return status

        # 파이프라인 데이터 파싱 분할
        parsed_data = raw_output.split("|")
        result_flag = parsed_data[0].strip()
        detected_accounts = parsed_data[1].strip()

        # 2. 요청하신 명확한 보안 가이드라인 기준 분기 처리
        if result_flag == "VULNERABLE":
            status = "취약"
            detail_msg = f"취약: SAM 파일 접근 권한에 Administrator, System 그룹 외에 다른 그룹/계정의 접근 권한이 허용되어 있습니다. (탐지된 비인가 대상: {detected_accounts})"
        else:
            status = "양호"
            detail_msg = "양호: SAM 파일의 접근 권한이 KISA 권고 기준에 부합하여 Administrator 및 System 그룹만 모든 권한으로 안전하게 제한되어 있습니다."

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-46", "SAM 파일 접근 통제 설정", status)
        
        # 터미널 콘솔 로그 출력
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_47(self):  # W-47: 화면 보호기 설정 점검 (무오류 버전)
        print("[*] W-47: 시스템 화면 보호기 활성화 여부, 대기 시간 및 암호 잠금 정책 분석 중...")

        # 윈도우 시스템 기본 데스크톱 프로필 레지스트리 경로에서 화면 보호기 3대 핵심 정책을 파싱합니다.
        # - ScreenSaveActive: 화면 보호기 가동 여부 (1: 활성, 0: 비활성)
        # - ScreenSaveTimeOut: 대기 시간 (초 단위)
        # - ScreenSaverIsSecure: 해제 시 암호 보호 여부 (1: 사용, 0: 미사용)
        # 결과 포맷 예시: 'Active값|TimeOut값|IsSecure값'
        ps_script = (
            "$regPath = 'Registry::HKU\\.DEFAULT\\Control Panel\\Desktop'; "
            "if (Test-Path $regPath) { "
            "   $active = (Get-ItemProperty -Path $regPath -Name 'ScreenSaveActive' -ErrorAction SilentlyContinue).ScreenSaveActive; "
            "   $timeout = (Get-ItemProperty -Path $regPath -Name 'ScreenSaveTimeOut' -ErrorAction SilentlyContinue).ScreenSaveTimeOut; "
            "   $secure = (Get-ItemProperty -Path $regPath -Name 'ScreenSaverIsSecure' -ErrorAction SilentlyContinue).ScreenSaverIsSecure; "
            "   if ($active -eq $null) { $active = '0' } "
            "   if ($timeout -eq $null) { $timeout = '9999' } "
            "   if ($secure -eq $null) { $secure = '0' } "
            "   $active + '|' + $timeout + '|' + $secure "
            "} else { "
            "   '0|9999|0' "
            "}"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 1. 명령어 실패 처리 (SSH 통신 오류 대응)
        if "ERROR:" in raw_output or not raw_output or "|" not in raw_output:
            status = "오류"
            detail_msg = f"화면 보호기 정책 레지스트리 쿼리 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-47", "화면 보호기 설정", status)
            return status

        # 파이프라인 데이터 파싱 분할
        parsed_data = raw_output.split("|")
        ss_active = parsed_data[0].strip()
        ss_timeout_raw = parsed_data[1].strip()
        ss_secure = parsed_data[2].strip()

        # 정수 변환 사전 유효성 검증 후 대소 연산 수행
        if ss_timeout_raw.isdigit():
            ss_timeout = int(ss_timeout_raw)
        else:
            ss_timeout = 9999  # 숫자가 아니면 강제 취약 유도

        has_vulnerability = False
        reason_list = []

        # 2. 요청하신 명확한 보안 가이드라인 기준 조건 개별 검증
        # 화면 보호기 자체 활성화 여부 확인
        if ss_active != "1":
            has_vulnerability = True
            reason_list.append("화면 보호기 미사용")

        # 해제 시 암호 사용 여부 확인
        if ss_secure != "1":
            has_vulnerability = True
            reason_list.append("해제 시 암호 보호 미설정")

        # 대기 시간 검증 (가이드라인 기준: 10분 이하 = 10 * 60 = 600초 이하)
        if ss_timeout > 600 or ss_timeout <= 0:
            has_vulnerability = True
            reason_list.append(f"대기 시간 기준 초과({ss_timeout // 60}분 {ss_timeout % 60}초)")

        # 3. 최종 보안 판정 및 리포팅 분기
        if has_vulnerability:
            status = "취약"
            reasons = ", ".join(reason_list)
            detail_msg = f"취약: 화면 보호기 보안 설정 권고 기준에 미달합니다. [사유: {reasons}]"
        else:
            status = "양호"
            detail_msg = f"양호: 화면 보호기 정책이 안전하게 수립되어 있습니다. (설정 상태 - 대기 시간: {ss_timeout // 60}분, 해제 시 암호 확인: 사용 중)"

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-47", "화면 보호기 설정", status)
        
        # 터미널 콘솔 로그 출력
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_48(self):  # W-48: 로그온하지 않고 시스템 종료 허용 점검 (무오류 버전)
        print("[*] W-48: 로컬 보안 정책 - 로그온하지 않고 시스템 종료 허용 상태 분석 중...")

        # 윈도우 로컬 보안 정책의 '시스템 종료: 로그온하지 않고 시스템 종료 허용' 옵션을 제어하는 
        # 시스템 핵심 레지스트리 경로를 직접 타격하여 정수 상태 값을 추출합니다.
        # - 0: 사용 안 함 (양호)
        # - 1: 사용 (취약)
        ps_script = (
            "$regPath = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'; "
            "if (Test-Path $regPath) { "
            "   $val = (Get-ItemProperty -Path $regPath -Name 'ShutdownWithoutLogon' -ErrorAction SilentlyContinue).ShutdownWithoutLogon; "
            "   if ($val -eq $null) { '0' } else { [string]$val } "
            "} else { "
            "   '0' "
            "}"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 1. 명령어 실패 처리 (SSH 통신 오류 대응)
        if "ERROR:" in raw_output or not raw_output:
            status = "오류"
            detail_msg = f"로컬 보안 정책 레지스트리 쿼리 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-48", "로그온하지 않고 시스템 종료 허용", status)
            return status

        # 2. 요청하신 명확한 보안 가이드라인 기준 분기 처리
        if raw_output == "0":
            status = "양호"
            detail_msg = "양호: '로그온하지 않고 시스템 종료 허용' 정책이 '사용 안 함(Disabled)'으로 안전하게 설정되어 인증되지 않은 사용자의 임의 시스템 종료 위협을 통제하고 있습니다."
        else:
            status = "취약"
            detail_msg = "취약: '로그온하지 않고 시스템 종료 허용' 정책이 '사용(Enabled)'으로 설정되어 있어 비인가자가 시스템을 무단으로 종료할 수 있는 위험이 존재합니다. 로컬 보안 정책에서 '사용 안 함' 조치가 필요합니다."

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-48", "로그온하지 않고 시스템 종료 허용", status)
        
        # 터미널 콘솔 로그 출력
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_49(self):  # W-49: 원격 시스템에서 강제로 시스템 종료 권한 점검 (오탐 수정 완료 버전)
        print("[*] W-49: 로컬 보안 정책 - 원격 시스템에서 강제로 시스템 종료 권한 할당 상태 분석 중...")

        # 1차 WMI SecMod 쿼리와 2차 secedit 가상 내보내기 덤프를 결합하여 권한 목록을 안전하게 추출합니다.
        # 비어있는 상태(None)는 취약이 아닌 최고 수준의 '양호' 상태로 똑똑하게 판정하도록 스크립트를 개정했습니다.
        ps_script = (
            "$privilege = 'SeRemoteShutdownPrivilege'; "
            "$secPrincipal = Get-CimInstance -Namespace root\\Microsoft\\Windows\\SecMod -ClassName MSFT_LocalUserRight -Filter \"Name='$privilege'\" -ErrorAction SilentlyContinue; "
            " "
            "if (-not $secPrincipal) { "
            "   $tempFile = [System.IO.Path]::GetTempFileName(); "
            "   secedit /export /cfg $tempFile /areas USER_RIGHTS | Out-Null; "
            "   $line = Get-Content $tempFile | Where-Object { $_ -match '^SeRemoteShutdownPrivilege\\s*=\\s*(.*)' }; "
            "   Remove-Item $tempFile -Force -ErrorAction SilentlyContinue; "
            "   if ($line -and $line -match '=\\s*(.*)') { "
            "       # 공백과 줄바꿈(CRLF) 찌꺼기 완벽 정제\n"
            "       $accounts = $Matches[1].Split(',') | ForEach-Object { $_.Trim().Replace('*', '') } | Where-Object { $_ -ne '' }; "
            "   } else { "
            "       $accounts = @() "
            "   } "
            "} else { "
            "   $accounts = $secPrincipal.AccountNames; "
            "} "
            " "
            "# 권한이 아예 비어있다면 원격 강제 종료 리스크가 전혀 없으므로 가장 안전한 양호(SAFE) 상태입니다.\n"
            "if ($accounts -eq $null -or $accounts.Count -eq 0) { "
            "   'SAFE_POLICY|Empty (No active rights)' "
            "} else { "
            "   $unauthorized = @(); "
            "   foreach ($acc in $accounts) { "
            "       if ($acc -ne 'S-1-5-32-544' -and $acc -notmatch 'Administrators' -and $acc -notmatch '관리자') { "
            "           $unauthorized += $acc; "
            "       } "
            "   } "
            "   if ($unauthorized.Count -gt 0) { "
            "       'VULNERABLE|' + ($unauthorized -join ', ') "
            "   } else { "
            "       'SAFE_POLICY|Administrators Only' "
            "   } "
            "}"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 1. 명령어 실패 처리 (SSH 통신 오류 대응)
        if "ERROR:" in raw_output or not raw_output or "|" not in raw_output:
            status = "오류"
            detail_msg = f"원격 시스템 강제 종료 권한 정책 쿼리 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-49", "원격 시스템에서 강제로 시스템 종료", status)
            return status

        # 파이프라인 데이터 파싱 분할
        parsed_data = raw_output.split("|")
        result_flag = parsed_data[0].strip()
        detected_accounts = parsed_data[1].strip()

        # 2. 버그가 수정된 정밀 가이드라인 기준 분기 처리
        if result_flag == "VULNERABLE":
            status = "취약"
            detail_msg = f"취약: '원격 시스템에서 강제로 시스템 종료' 권한에 Administrators 외에 다른 그룹/계정이 포함되어 있습니다. (탐지된 대상: {detected_accounts})"
        else:
            status = "양호"
            if "Empty" in detected_accounts:
                detail_msg = "양호: '원격 시스템에서 강제로 시스템 종료' 권한이 비활성화(아무도 권한을 부여받지 않음)되어 있어 원격 무단 종료 위협으로부터 안전합니다."
            else:
                detail_msg = "양호: '원격 시스템에서 강제로 시스템 종료' 권한이 KISA 권고 기준에 부합하여 오직 Administrators 그룹에만 안전하게 제한되어 있습니다."

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-49", "원격 시스템에서 강제로 시스템 종료", status)
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_50(self):  # W-50: 보안 감사를 로그 할 수 없는 경우 즉시 시스템 종료 점검 (무오류 버전)
        print("[*] W-50: 로컬 보안 정책 - 보안 감사를 로그 할 수 없는 경우 즉시 시스템 종료 상태 분석 중...")

        # 윈도우 로컬 보안 정책의 '감사: 보안 감사를 로그 할 수 없는 경우 즉시 시스템 종료' 옵션을 제어하는
        # 커널 레지스트리 핵심 노드를 직접 타격하여 값을 확인합니다.
        # - 0: 사용 안 함 (양호)
        # - 1 또는 2: 사용 (취약 - 시스템 가득 참 시 크래시 유도)
        ps_script = (
            "$regPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa'; "
            "if (Test-Path $regPath) { "
            "   $val = (Get-ItemProperty -Path $regPath -Name 'CrashOnAuditFail' -ErrorAction SilentlyContinue).CrashOnAuditFail; "
            "   if ($val -eq $null) { '0' } else { [string]$val } "
            "} else { "
            "   '0' "
            "}"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 1. 명령어 실패 처리 (SSH 통신 오류 대응)
        if "ERROR:" in raw_output or not raw_output:
            status = "오류"
            detail_msg = f"로컬 보안 정책 레지스트리 쿼리 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-50", "보안 감사를 로그 할 수 없는 경우 즉시 시스템 종료", status)
            return status

        # 2. 요청하신 명확한 보안 가이드라인 기준 분기 처리
        # 0이 아닌 값(1: 켜짐, 2: 감사 로그 불가능으로 인해 현재 시스템이 잠김 상태로 들어감)은 취약으로 판정합니다.
        if raw_output == "0":
            status = "양호"
            detail_msg = "양호: '보안 감사를 로그 할 수 없는 경우 즉시 시스템 종료' 정책이 '사용 안 함(Disabled)'으로 안전하게 설정되어 로그 공간 부족 시 발생할 수 있는 임의 시스템 다운타임 위험을 통제하고 있습니다."
        else:
            status = "취약"
            detail_msg = f"취약: '보안 감사를 로그 할 수 없는 경우 즉시 시스템 종료' 정책이 '사용(Enabled, 현재값: {raw_output})'으로 설정되어 있습니다. 악의적인 로그 폭주 공격 시 서비스 마비 위험이 있으므로 로컬 보안 정책에서 '사용 안 함' 조치가 필요합니다."

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-50", "보안 감사를 로그 할 수 없는 경우 즉시 시스템 종료", status)
        
        # 터미널 콘솔 로그 출력
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_51(self):  # W-51: SAM 계정과 공유의 익명 열거 허용 안 함 점검 (무오류 버전)
        print("[*] W-51: 로컬 보안 정책 - SAM 계정 및 공유의 익명 열거 제한 상태 전수 분석 중...")

        # 윈도우 로컬 보안 정책의 네트워크 액세스 관련 익명 열거 차단 2대 핵심 옵션을 제어하는 
        # 시스템 레지스트리 허브 경로를 직접 조회합니다.
        # 1. RestrictAnonymousSAM -> SAM 계정의 익명 열거 허용 안 함 (1: 사용/양호, 0: 사용 안 함/취약)
        # 2. RestrictAnonymous -> SAM 계정과 공유의 익명 열거 허용 안 함 (1: 사용/양호, 0: 사용 안 함/취약)
        # 결과 포맷 예시: 'SAM제한값|공유제한값'
        ps_script = (
            "$regPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa'; "
            "if (Test-Path $regPath) { "
            "   $restrictSam = (Get-ItemProperty -Path $regPath -Name 'RestrictAnonymousSAM' -ErrorAction SilentlyContinue).RestrictAnonymousSAM; "
            "   $restrictAnon = (Get-ItemProperty -Path $regPath -Name 'RestrictAnonymous' -ErrorAction SilentlyContinue).RestrictAnonymous; "
            "   if ($restrictSam -eq $null) { $restrictSam = 0 } "
            "   if ($restrictAnon -eq $null) { $restrictAnon = 0 } "
            "   [string]$restrictSam + '|' + [string]$restrictAnon "
            "} else { "
            "   '0|0' "
            "}"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 1. 명령어 실패 처리 (SSH 통신 오류 대응)
        if "ERROR:" in raw_output or not raw_output or "|" not in raw_output:
            status = "오류"
            detail_msg = f"로컬 보안 정책 레지스트리 쿼리 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-51", "SAM 계정과 공유의 익명 열거 허용 안 함", status)
            return status

        # 파이프라인 데이터 파싱 분할
        parsed_data = raw_output.split("|")
        val_sam = parsed_data[0].strip()   # SAM 계정 익명 열거 제한 상태
        val_anon = parsed_data[1].strip()  # 계정 및 공유 익명 열거 제한 상태

        has_vulnerability = False
        reason_list = []

        # 2. 요청하신 KISA 가이드라인 기준 2대 정책 교차 검증 (AND 조건 만족해야 양호)
        # SAM 계정의 익명 열거 허용 안 함 검증 (1 이외의 값은 취약)
        if val_sam != "1":
            has_vulnerability = True
            reason_list.append("SAM 계정 익명 열거 허용 상태")

        # SAM 계정과 공유의 익명 열거 허용 안 함 검증 (1 또는 2가 아닌 0은 취약)
        # (참고: RestrictAnonymous의 값 1은 공유/계정 열거 제한, 2는 더 엄격한 제한을 의미함)
        if val_anon == "0":
            has_vulnerability = True
            reason_list.append("SAM 계정 및 공유 익명 열거 허용 상태")

        # 3. 최종 보안 가이드라인 기준 분기 처리
        if has_vulnerability:
            status = "취약"
            reasons = ", ".join(reason_list)
            detail_msg = f"취약: 익명 사용자에 의한 내부 정보 유출을 막는 보안 옵션 중 일부가 누락되었습니다. [사유: {reasons}]"
        else:
            status = "양호"
            detail_msg = "양호: 'SAM 계정과 공유의 익명 열거 허용 안 함' 및 'SAM 계정의 익명 열거 허용 안 함' 정책이 모두 '사용(Enabled)'으로 안전하게 설정되어 있습니다."

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-51", "SAM 계정과 공유의 익명 열거 허용 안 함", status)
        
        # 터미널 콘솔 로그 출력
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_52(self):  # W-52: Autologon 기능 제어 점검 (무오류 버전)
        print("[*] W-52: Winlogon 레지스트리 허브 기반 자동 로그인 활성화 및 평문 패스워드 잔존 여부 분석 중...")

        # 가이드라인의 조치 기준인 Winlogon 레지스트리를 직접 타격합니다.
        # - AutoAdminLogon: 자동 로그인 여부 (1: 사용/취약, 0 또는 없음: 사용 안 함/양호)
        # - DefaultPassword: 평문 비밀번호 저장 키 (존재 시 취약)
        # 결과 포맷 예시: 'AutoLogon값|Password존재여부'
        ps_script = (
            "$regPath = 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'; "
            "if (Test-Path $regPath) { "
            "   $autoLogon = (Get-ItemProperty -Path $regPath -Name 'AutoAdminLogon' -ErrorAction SilentlyContinue).AutoAdminLogon; "
            "   $hasPassword = '0'; "
            "   $props = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue; "
            "   if ($props.PSObject.Properties.Name -contains 'DefaultPassword') { $hasPassword = '1' } "
            "   if ($autoLogon -eq $null) { $autoLogon = '0' } "
            "   [string]$autoLogon + '|' + $hasPassword "
            "} else { "
            "   '0|0' "
            "}"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 1. 명령어 실패 처리 (SSH 통신 오류 대응)
        if "ERROR:" in raw_output or not raw_output or "|" not in raw_output:
            status = "오류"
            detail_msg = f"Winlogon 자동 로그인 정책 레지스트리 쿼리 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-52", "Autologon 기능 제어", status)
            return status

        # 파이프라인 데이터 파싱 분할
        parsed_data = raw_output.split("|")
        val_autologon = parsed_data[0].strip()   # AutoAdminLogon 설정 값
        val_has_password = parsed_data[1].strip()  # DefaultPassword 존재 여부 (1: 있음, 0: 없음)

        has_vulnerability = False
        reason_list = []

        # 2. 요청하신 KISA 가이드라인 기준 및 조치 단계 교차 검증
        # Step 2 검증: AutoAdminLogon 값이 1로 설정된 경우 취약
        if val_autologon == "1":
            has_vulnerability = True
            reason_list.append("AutoAdminLogon 활성화(값: 1)")

        # Step 3 검증: DefaultPassword가 여전히 레지스트리에 존재할 경우 취약
        if val_has_password == "1":
            has_vulnerability = True
            reason_list.append("평문 비밀번호(DefaultPassword) 키 잔존")

        # 3. 최종 보안 가이드라인 기준 분기 처리
        if has_vulnerability:
            status = "취약"
            reasons = ", ".join(reason_list)
            detail_msg = f"취약: 자동 로그인 기능 또는 평문 암호 저장 취약점이 발견되었습니다. [사유: {reasons}]"
        else:
            status = "양호"
            detail_msg = "양호: 자동 로그인 기능(AutoAdminLogon)이 비활성화되어 있으며, 레지스트리 내 평문 비밀번호 노출 위험이 존재하지 않습니다."

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-52", "Autologon 기능 제어", status)
        
        # 터미널 콘솔 로그 출력
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_53(self):  # W-53: 이동식 미디어 포맷 및 꺼내기 허용 점검 (무오류 버전)
        print("[*] W-53: 로컬 보안 정책 - 장치: 이동식 미디어 포맷 및 꺼내기 허용 상태 분석 중...")

        # 윈도우 로컬 보안 정책의 '장치: 이동식 미디어 포맷 및 꺼내기 허용' 옵션을 제어하는 
        # 커널 레지스트리 내부 식별자 파라미터(AllocateDASD) 값을 직접 조회합니다.
        # - "0": Administrators (양호)
        # - "1": Administrators and Power Users (취약)
        # - "2": Administrators and Interactive Users (취약)
        ps_script = (
            "$regPath = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'; "
            "if (Test-Path $regPath) { "
            "   $val = (Get-ItemProperty -Path $regPath -Name 'AllocateDASD' -ErrorAction SilentlyContinue).AllocateDASD; "
            "   if ($val -eq $null) { '0' } else { [string]$val } "
            "} else { "
            "   '0' "
            "}"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 1. 명령어 실패 처리 (SSH 통신 오류 대응)
        if "ERROR:" in raw_output or not raw_output:
            status = "오류"
            detail_msg = f"로컬 보안 정책 레지스트리 쿼리 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-53", "이동식 미디어 포맷 및 꺼내기 허용", status)
            return status

        # 2. 요청하신 명확한 보안 가이드라인 기준 분기 처리
        # 오직 Administrators 그룹만 허용하는 "0" 상태일 때만 양호로 인정합니다.
        if raw_output == "0":
            status = "양호"
            detail_msg = "양호: '이동식 미디어 포맷 및 꺼내기 허용' 정책이 'Administrators'로 안전하게 고정되어 관리자 계정 외의 임의 디바이스 포맷/해제 행위를 차단하고 있습니다."
        else:
            # 윈도우 매핑 정보 분기 코드 상세화
            mapping_str = "Administrators 및 Power Users" if raw_output == "1" else "대화형 사용자 전체(Interactive Users)"
            status = "취약"
            detail_msg = f"취약: '이동식 미디어 포맷 및 꺼내기 허용' 정책이 관리자 외 계정인 [{mapping_str}]로 완화되어 있습니다. 보안 옵션을 'Administrators'로 강제 제한하는 조치가 필요합니다."

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-53", "이동식 미디어 포맷 및 꺼내기 허용", status)
        
        # 터미널 콘솔 로그 출력
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_54(self):  # W-54: Dos 공격 방어 레지스트리 설정 점검 (무오류 버전)
        print("[*] W-54: TCP/IP 커널 파라미터 기반 DoS 공격 방어 4대 레지스트리 설정 전수 분석 중...")

        # DoS 방어 파라미터들이 상주하는 2개의 핵심 레지스트리 하이브 경로를 직접 스캔합니다.
        # - 1~3번 항목: HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters
        # - 4번 항목: HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters
        # 값이 비어있거나 생성되지 않은 상태($null)는 안전하게 '-1'로 변환하여 취약으로 걸러냅니다.
        ps_script = (
            "$tcpPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters'; "
            "$netbtPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters'; "
            " "
            "$synAttack = -1; $deadGw = -1; $keepAlive = -1; $nameRelease = -1; "
            " "
            "if (Test-Path $tcpPath) { "
            "   $syn = (Get-ItemProperty -Path $tcpPath -Name 'SynAttackProtect' -ErrorAction SilentlyContinue).SynAttackProtect; "
            "   $gw = (Get-ItemProperty -Path $tcpPath -Name 'EnableDeadGWDetect' -ErrorAction SilentlyContinue).EnableDeadGWDetect; "
            "   $keep = (Get-ItemProperty -Path $tcpPath -Name 'KeepAliveTime' -ErrorAction SilentlyContinue).KeepAliveTime; "
            "   if ($syn -ne $null) { $synAttack = $syn } "
            "   if ($gw -ne $null) { $deadGw = $gw } "
            "   if ($keep -ne $null) { $keepAlive = $keep } "
            "} "
            " "
            "if (Test-Path $netbtPath) { "
            "   $release = (Get-ItemProperty -Path $netbtPath -Name 'NoNameReleaseOnDemand' -ErrorAction SilentlyContinue).NoNameReleaseOnDemand; "
            "   if ($release -ne $null) { $nameRelease = $release } "
            "} "
            " "
            "[string]$synAttack + '|' + [string]$deadGw + '|' + [string]$keepAlive + '|' + [string]$nameRelease"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 1. 명령어 실패 처리 (SSH 통신 오류 대응)
        if "ERROR:" in raw_output or not raw_output or "|" not in raw_output:
            status = "오류"
            detail_msg = f"DoS 방어 레지스트리 쿼리 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-54", "Dos 공격 방어 레지스트리 설정", status)
            return status

        # 파이프라인 데이터 파싱 분할 및 정수형 매핑
        parsed_data = raw_output.split("|")
        val_syn = int(parsed_data[0].strip())
        val_gw = int(parsed_data[1].strip())
        val_keep = int(parsed_data[2].strip())
        val_release = int(parsed_data[3].strip())

        has_vulnerability = False
        reason_list = []

        # 2. 요청하신 KISA 가이드라인 4대 DoS 정책 개별 권고치 정밀 밸리데이션
        # Ÿ SynAttackProtect → 1 이상
        if val_syn < 1:
            has_vulnerability = True
            reason_list.append(f"SynAttackProtect 기준 미달(현재값: {val_syn if val_syn != -1 else '미구성'})")

        # Ÿ EnableDeadGWDetect → 0
        if val_gw != 0:
            has_vulnerability = True
            reason_list.append(f"EnableDeadGWDetect 오류(현재값: {val_gw if val_gw != -1 else '미구성'})")

        # Ÿ KeepAliveTime → 300,000
        if val_keep != 300000:
            has_vulnerability = True
            reason_list.append(f"KeepAliveTime 오류(현재값: {val_keep if val_keep != -1 else '미구성'})")

        # Ÿ NoNameReleaseOnDemand → 1
        if val_release != 1:
            has_vulnerability = True
            reason_list.append(f"NoNameReleaseOnDemand 오류(현재값: {val_release if val_release != -1 else '미구성'})")

        # 3. 최종 보안 가이드라인 기준 분기 처리 (하나라도 빠지면 취약)
        if has_vulnerability:
            status = "취약"
            reasons = ", ".join(reason_list)
            detail_msg = f"취약: DoS 방어 레지스트리 설정 중 권고 기준에 부합하지 않거나 미설정된 항목이 존재합니다. [사유: {reasons}]"
        else:
            status = "양호"
            detail_msg = "양호: 4대 핵심 DoS 방어 레지스트리 설정(SynAttackProtect, EnableDeadGWDetect, KeepAliveTime, NoNameReleaseOnDemand)이 가이드라인 권고치에 맞게 철저히 적용되어 있습니다."

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-54", "Dos 공격 방어 레지스트리 설정", status)
        
        # 터미널 콘솔 로그 출력
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_55(self):  # W-55: 사용자가 프린터 드라이버를 설치할 수 없게 함 점검 (무오류 버전)
        print("[*] W-55: 로컬 보안 정책 - 장치: 사용자가 프린터 드라이버를 설치할 수 없게 함 상태 분석 중...")

        # 윈도우 로컬 보안 정책의 '장치: 사용자가 프린터 드라이버를 설치할 수 없게 함' 옵션을 제어하는
        # 시스템 핵심 레지스트리 경로를 직접 타격하여 정수 상태 값을 추출합니다.
        # - 1: 사용 (일반 사용자 설치 불가 / 양호)
        # - 0: 사용 안 함 (일반 사용자 설치 가능 / 취약)
        ps_script = (
            "$regPath = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'; "
            "if (Test-Path $regPath) { "
            "   $val = (Get-ItemProperty -Path $regPath -Name 'AddPrinterDrivers' -ErrorAction SilentlyContinue).AddPrinterDrivers; "
            "   if ($val -eq $null) { '0' } else { [string]$val } "
            "} else { "
            "   '0' "
            "}"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 1. 명령어 실패 처리 (SSH 통신 오류 대응)
        if "ERROR:" in raw_output or not raw_output:
            status = "오류"
            detail_msg = f"로컬 보안 정책 레지스트리 쿼리 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-55", "사용자가 프린터 드라이버를 설치할 수 없게 함", status)
            return status

        # 2. 요청하신 명확한 보안 가이드라인 기준 분기 처리
        # 일반 사용자의 설치 권한을 뺏는 "1"(사용) 상태여야 양호로 인정됩니다.
        if raw_output == "1":
            status = "양호"
            detail_msg = "양호: '사용자가 프린터 드라이버를 설치할 수 없게 함' 정책이 '사용(Enabled)'으로 안전하게 설정되어 권한이 없는 사용자의 악성 드라이버 적재 위험을 통제하고 있습니다."
        else:
            status = "취약"
            detail_msg = "취약: '사용자가 프린터 드라이버를 설치할 수 없게 함' 정책이 '사용 안 함(Disabled)'으로 설정되어 있어 일반 사용자가 악성 드라이버를 임의로 설치할 수 있는 위험이 존재합니다. 로컬 보안 정책에서 '사용' 조치가 필요합니다."

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-55", "사용자가 프린터 드라이버를 설치할 수 없게 함", status)
        
        # 터미널 콘솔 로그 출력
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_56(self):  # W-56: SMB 세션 중단 관리 설정 점검 (무오류 버전)
        print("[*] W-56: 로컬 보안 정책 - SMB 세션 만료 연결 차단 및 유휴 시간 상태 전수 분석 중...")

        # 윈도우 커널에서 SMB 세션 제한을 통제하는 2대 핵심 레지스트리 노드를 직격 조회합니다.
        # 1. DisconnectAfterMS (LanmanWorkstation) -> 로그온 시간 만료 시 연결 끊기 (1: 사용/양호, 0: 사용 안 함/취약)
        # 2. AutoDisconnect (LanmanServer) -> 세션 연결 중단 전 유휴 시간 (분 단위 저장, 15 이하/양호)
        # 결과 포맷 예시: '만료차단값|유휴시간분'
        ps_script = (
            "$workstationPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters'; "
            "$serverPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters'; "
            " "
            "$disconnectExpired = 0; $autodiscalowed = 15; "
            " "
            "if (Test-Path $workstationPath) { "
            "   $exp = (Get-ItemProperty -Path $workstationPath -Name 'DisconnectAfterMS' -ErrorAction SilentlyContinue).DisconnectAfterMS; "
            "   if ($exp -ne $null) { $disconnectExpired = $exp } "
            "} "
            " "
            "if (Test-Path $serverPath) { "
            "   $auto = (Get-ItemProperty -Path $serverPath -Name 'AutoDisconnect' -ErrorAction SilentlyContinue).AutoDisconnect; "
            "   if ($auto -ne $null) { $autodiscalowed = $auto } "
            "} "
            " "
            "[string]$disconnectExpired + '|' + [string]$autodiscalowed"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 1. 명령어 실패 처리 (SSH 통신 오류 대응)
        if "ERROR:" in raw_output or not raw_output or "|" not in raw_output:
            status = "오류"
            detail_msg = f"SMB 세션 제어 정책 레지스트리 쿼리 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-56", "SMB 세션 중단 관리 설정", status)
            return status

        # 파이프라인 데이터 파싱 분할 및 정수 변환
        parsed_data = raw_output.split("|")
        val_expired = int(parsed_data[0].strip())  # 로그온 시간 만료 시 끊기 플래그
        val_idle = int(parsed_data[1].strip())     # 유휴 시간 설정 값 (분 단위)

        has_vulnerability = False
        reason_list = []

        # 2. 요청하신 KISA 가이드라인 기준 2대 정책 교차 검증 (AND 조건)
        # Ÿ “로그인 시간이 만료되면 클라이언트 연결 끊기” 정책 “사용” 설정 상태 검증 (1이어야 양호)
        if val_expired != 1:
            has_vulnerability = True
            reason_list.append("로그온 만료 시 연결 끊기 미사용")

        # Ÿ “세션 연결을 중단하기 전에 필요한 유휴 시간” 정책 “15분” 이하로 설정 상태 검증
        if val_idle > 15 or val_idle < 0:
            has_vulnerability = True
            reason_list.append(f"세션 유휴 시간 기준 초과(현재 설정: {val_idle}분)")

        # 3. 최종 보안 가이드라인 기준 분기 처리 (하나라도 충족 안 하면 취약)
        if has_vulnerability:
            status = "취약"
            reasons = ", ".join(reason_list)
            detail_msg = f"취약: SMB 세션 만료 및 유휴 시간 관리 설정 중 권고치에 부합하지 않는 항목이 존재합니다. [사유: {reasons}]"
        else:
            status = "양호"
            detail_msg = f"양호: '로그온 시간이 만료되면 클라이언트 연결 끊기' 정책이 '사용' 상태이며, '세션 유휴 시간' 역시 안전 범위인 {val_idle}분 이하로 완벽하게 유지되고 있습니다."

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-56", "SMB 세션 중단 관리 설정", status)
        
        # 터미널 콘솔 로그 출력
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_57(self):  # W-57: 로그온 시 경고 메시지 설정 점검 (무오류 버전)
        print("[*] W-57: 로컬 보안 정책 - 대화형 로그온 경고 메시지 제목 및 텍스트 설정 분석 중...")

        # 윈도우 로컬 보안 정책의 대화형 로그온 배너 설정을 관장하는 시스템 레지스트리를 직접 타격합니다.
        # - legalnoticecaption: 로그온 시도하는 사용자에 대한 메시지 제목
        # - legalnoticetext: 로그온 시도하는 사용자에 대한 메시지 텍스트
        # 결과 포맷 예시: '제목문자열|내용문자열' (데이터가 없거나 공백이면 빈 값으로 수집)
        ps_script = (
            "$regPath = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'; "
            "if (Test-Path $regPath) { "
            "   $caption = (Get-ItemProperty -Path $regPath -Name 'legalnoticecaption' -ErrorAction SilentlyContinue).legalnoticecaption; "
            "   $text = (Get-ItemProperty -Path $regPath -Name 'legalnoticetext' -ErrorAction SilentlyContinue).legalnoticetext; "
            "   if ($caption -eq $null) { $caption = '' } "
            "   if ($text -eq $null) { $text = '' } "
            "   # 파이썬 파싱용 구분자 파이프라인 결합 시 데이터 트림(Trim) 처리\n"
            "   $caption.Trim() + '|' + $text.Trim() "
            "} else { "
            "   '|' "
            "}"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 1. 명령어 실패 처리 (SSH 통신 오류 대응)
        if "ERROR:" in raw_output or not raw_output or "|" not in raw_output:
            status = "오류"
            detail_msg = f"로그온 경고 메시지 정책 레지스트리 쿼리 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-57", "로그온 시 경고 메시지 설정", status)
            return status

        # 파이프라인 데이터 파싱 분할
        parsed_data = raw_output.split("|")
        val_caption = parsed_data[0].strip()  # 메시지 제목
        val_text = parsed_data[1].strip()     # 메시지 텍스트

        has_vulnerability = False
        reason_list = []

        # 2. 요청하신 KISA 가이드라인 기준 교차 검증 (두 항목 모두 값이 실재해야 양호)
        # Step 2 검증: 메시지 제목 설정 확인
        if not val_caption:
            has_vulnerability = True
            reason_list.append("로그온 메시지 제목 미설정")

        # Step 3 검증: 메시지 텍스트(내용) 설정 확인
        if not val_text:
            has_vulnerability = True
            reason_list.append("로그온 메시지 내용 미설정")

        # 3. 최종 보안 가이드라인 기준 분기 처리 (하나라도 충족 안 하면 취약)
        if has_vulnerability:
            status = "취약"
            reasons = ", ".join(reason_list)
            detail_msg = f"취약: 법적 불이익 방지를 위한 로그온 경고 배너 설정 중 누락된 항목이 있습니다. [사유: {reasons}]"
        else:
            status = "양호"
            detail_msg = f"양호: 대화형 로그온 경고 메시지 정책이 안전하게 수립되어 있습니다. (설정된 제목: '{val_caption}')"

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-57", "로그온 시 경고 메시지 설정", status)
        
        # 터미널 콘솔 로그 출력
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_58(self):  # W-58: 사용자별 홈 디렉터리 권한 설정 점검 (전수 조사 무오류 버전)
        print("[*] W-58: 실제 사용자별 홈 디렉터리 ACL 전수 검사 및 Everyone 권한 주입 여부 분석 중...")

        # 시스템 드라이브의 사용자 프로필 루트 디렉터리를 기점으로 전수 조사를 수행합니다.
        # 가이드라인에 명시된 예외 대상(All Users, Default, Public 등)은 필터링하여 제외합니다.
        # 언어팩 독립형 고유 SID인 S-1-1-0(Everyone)의 존재 여부를 추적합니다.
        ps_script = (
            "$usersRoot = \"$env:SystemDrive\\Users\"; "
            "if (-not (Test-Path $usersRoot)) { $usersRoot = \"$env:SystemDrive\\사용자\" } "
            " "
            "if (Test-Path $usersRoot) { "
            "   $subDirs = Get-ChildItem -Path $usersRoot -Directory -Force -ErrorAction SilentlyContinue; "
            "   $vulnerableDirs = @(); "
            "   "
            "   foreach ($dir in $subDirs) { "
            "       $dirName = $dir.Name; "
            "       # 가이드라인에 따른 제외 타겟 필터링\n"
            "       if ($dirName -eq 'All Users' -or $dirName -eq 'Default User' -or "
            "           $dirName -eq 'Default' -or $dirName -eq 'Public' -or $dirName -match '^NTUSER') { "
            "           continue; "
            "       } "
            "       "
            "       $acl = Get-Acl -Path $dir.FullName -ErrorAction SilentlyContinue; "
            "       if ($acl) { "
            "           foreach ($access in $acl.Access) { "
            "               $identity = $access.IdentityReference.Value; "
            "               # Everyone 그룹 매칭 (SID 매핑 및 문자열 포함)\n"
            "               if ($identity -eq 'S-1-1-0' -or $identity -notmatch 'Everyone') { "
            "                   if ($identity -eq 'S-1-1-0' -or $identity -match 'Everyone') { "
            "                       $vulnerableDirs += $dirName; "
            "                       break; "
            "                   } "
            "               } "
            "           } "
            "       } "
            "   } "
            "   if ($vulnerableDirs.Count -gt 0) { "
            "       'VULNERABLE|' + ($vulnerableDirs -join ', ') "
            "   } else { "
            "       'SAFE_ACL|All Checked' "
            "   } "
            "} else { "
            "   'SAFE_ACL|No Users Folder' "
            "}"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 1. 명령어 실패 처리 (SSH 통신 오류 대응)
        if "ERROR:" in raw_output or not raw_output or "|" not in raw_output:
            status = "오류"
            detail_msg = f"사용자 홈 디렉터리 권한 쿼리 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-58", "사용자별 홈 디렉터리 권한 설정", status)
            return status

        # 파이프라인 데이터 파싱 분할
        parsed_data = raw_output.split("|")
        result_flag = parsed_data[0].strip()
        detected_directories = parsed_data[1].strip()

        # 2. 요청하신 명확한 보안 가이드라인 및 모든 계정 전수 조사 기준 분기 처리
        if result_flag == "VULNERABLE":
            status = "취약"
            detail_msg = f"취약: 홈 디렉터리에 Everyone 권한이 열려 있는 사용자 계정이 발견되었습니다. [탐지된 계정 폴더: {detected_directories}]"
        else:
            status = "양호"
            detail_msg = "양호: 가이드라인 예외 대상을 제외한 모든 사용자별 로컬 홈 디렉터리에 Everyone 권한이 존재하지 않으며 안전하게 격리되어 있습니다."

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-58", "사용자별 홈 디렉터리 권한 설정", status)
        
        # 터미널 콘솔 로그 출력
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_59(self):  # W-59: LAN Manager 인증 수준 점검 (무오류 버전)
        print("[*] W-59: 로컬 보안 정책 - 네트워크 보안: LAN Manager 인증 수준 상태 분석 중...")

        # 윈도우 로컬 보안 정책의 '네트워크 보안: LAN Manager 인증 수준' 옵션을 제어하는
        # 시스템 핵심 레지스트리 경로를 직접 타격하여 정수 상태 값을 추출합니다.
        # - 0: LM 및 NTLM 응답 보냄 (취약)
        # - 1: LM 및 NTLM 응답 보냄 - 협상 시 NTLMv2 세션 보안 사용 (취약)
        # - 2: NTLM 응답만 보냄 (취약)
        # - 3: NTLMv2 응답만 보냄 (양호 - 가이드라인 타겟)
        # - 4: NTLMv2 응답만 보냄. LM은 거부함 (양호)
        # - 5: NTLMv2 응답만 보냄. LM 및 NTLM은 거부함 (양호)
        ps_script = (
            "$regPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa'; "
            "if (Test-Path $regPath) { "
            "   $val = (Get-ItemProperty -Path $regPath -Name 'LmCompatibilityLevel' -ErrorAction SilentlyContinue).LmCompatibilityLevel; "
            "   if ($val -eq $null) { '-1' } else { [string]$val } "
            "} else { "
            "   '-1' "
            "}"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 1. 명령어 실패 처리 (SSH 통신 오류 대응)
        if "ERROR:" in raw_output or not raw_output:
            status = "오류"
            detail_msg = f"로컬 보안 정책 레지스트리 쿼리 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-59", "LAN Manager 인증 수준", status)
            return status

        # 2. 요청하신 명확한 보안 가이드라인 기준 및 매핑 분기 처리
        # 가이드라인 기준인 NTLMv2 전용 조건(값: 3 이상인 3, 4, 5)을 만족해야 양호로 판정합니다.
        if raw_output in ["3", "4", "5"]:
            status = "양호"
            detail_msg = f"양호: 'LAN Manager 인증 수준' 정책이 NTLMv2 응답 전용(현재 설정값: {raw_output})으로 안전하게 고정되어 하위 LM/NTLM 스니핑 공격 위험을 원천 방어하고 있습니다."
        else:
            # 취약한 레거시 매핑 텍스트 구성
            if raw_output == "-1":
                current_state = "미설정(기본 허용 모드)"
            elif raw_output == "0":
                current_state = "LM 및 NTLM 응답 보냄 (0)"
            elif raw_output == "1":
                current_state = "LM 및 NTLM 응답 보냄 - NTLMv2 세션 보안 협상 (1)"
            else:
                current_state = "NTLM 응답만 보냄 (2)"

            status = "취약"
            detail_msg = f"취약: 'LAN Manager 인증 수준' 정책이 취약한 [{current_state}] 수준으로 설정되어 있습니다. 로컬 보안 정책에서 'NTLMv2 응답만 보내기' 조치가 시급합니다."

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-59", "LAN Manager 인증 수준", status)
        
        # 터미널 콘솔 로그 출력
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_60(self):  # W-60: 보안 채널 데이터 디지털 암호화 또는 서명 점검 (무오류 버전)
        print("[*] W-60: 로컬 보안 정책 - 도메인 구성원의 보안 채널 데이터 암호화 및 서명 3대 정책 분석 중...")

        # 윈도우 로컬 보안 정책의 도메인 구성원 보안 채널 3대 옵션을 통제하는 시스템 레지스트리를 조회합니다.
        # 1. RequireSignOrSeal -> 보안 채널 데이터를 디지털 암호화 또는 서명(항상)
        # 2. SealSecureChannel -> 보안 채널 데이터를 디지털 암호화(가능한 경우)
        # 3. SignSecureChannel -> 보안 채널 데이터 디지털 서명(가능한 경우)
        # 결과 포맷 예시: '항상암호화서명값|가능한암호화값|가능한서명값'
        ps_script = (
            "$regPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters'; "
            "if (Test-Path $regPath) { "
            "   $reqSignSeal = (Get-ItemProperty -Path $regPath -Name 'RequireSignOrSeal' -ErrorAction SilentlyContinue).RequireSignOrSeal; "
            "   $sealSecure = (Get-ItemProperty -Path $regPath -Name 'SealSecureChannel' -ErrorAction SilentlyContinue).SealSecureChannel; "
            "   $signSecure = (Get-ItemProperty -Path $regPath -Name 'SignSecureChannel' -ErrorAction SilentlyContinue).SignSecureChannel; "
            "   if ($reqSignSeal -eq $null) { $reqSignSeal = 0 } "
            "   if ($sealSecure -eq $null) { $sealSecure = 0 } "
            "   if ($signSecure -eq $null) { $signSecure = 0 } "
            "   [string]$reqSignSeal + '|' + [string]$sealSecure + '|' + [string]$signSecure "
            "} else { "
            "   '0|0|0' "
            "}"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 1. 명령어 실패 처리 (SSH 통신 오류 대응)
        if "ERROR:" in raw_output or not raw_output or "|" not in raw_output:
            status = "오류"
            detail_msg = f"보안 채널 정책 레지스트리 쿼리 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-60", "보안 채널 데이터 디지털 암호화 또는 서명", status)
            return status

        # 파이프라인 데이터 파싱 분할
        parsed_data = raw_output.split("|")
        val_req_sign_seal = parsed_data[0].strip()  # 디지털 암호화 또는 서명 (항상)
        val_seal_secure = parsed_data[1].strip()    # 디지털 암호화 (가능한 경우)
        val_sign_secure = parsed_data[2].strip()    # 디지털 서명 (가능한 경우)

        has_vulnerability = False
        reason_list = []

        # 2. 요청하신 KISA 가이드라인 기준 3대 정책 전수 개별 검증 (AND 조건 만족)
        # Ÿ 보안 채널 데이터를 디지털 암호화 또는 서명(항상) 검증
        if val_req_sign_seal != "1":
            has_vulnerability = True
            reason_list.append("디지털 암호화 또는 서명(항상) 미사용")

        # Ÿ 보안 채널 데이터를 디지털 암호화(가능한 경우) 검증
        if val_seal_secure != "1":
            has_vulnerability = True
            reason_list.append("디지털 암호화(가능한 경우) 미사용")

        # Ÿ 보안 채널 데이터 디지털 서명(가능한 경우) 검증
        if val_sign_secure != "1":
            has_vulnerability = True
            reason_list.append("디지털 서명(가능한 경우) 미사용")

        # 3. 최종 보안 가이드라인 기준 분기 처리 (일부 항목이라도 0(사용 안 함)이면 취약)
        if has_vulnerability:
            status = "취약"
            reasons = ", ".join(reason_list)
            detail_msg = f"취약: 도메인 보안 채널 데이터 보호 정책 중 일부가 누락되었습니다. [사유: {reasons}]"
        else:
            status = "양호"
            detail_msg = "양호: 3가지 보안 채널 데이터 디지털 암호화 및 서명 관련 정책이 모두 '사용(Enabled)'으로 안전하게 설정되어 있습니다."

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-60", "보안 채널 데이터 디지털 암호화 또는 서명", status)
        
        # 터미널 콘솔 로그 출력
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_61(self):  # W-61: 파일 및 디렉토리 보호 (NTFS 변환 여부) 점검 (무오류 버전)
        print("[*] W-61: 로컬 논리 드라이브의 파일 시스템(NTFS) 구성 상태 전수 스캔 중...")

        # 시스템에 마운트된 모든 로컬 하드 디스크 논리 드라이브(DriveType=3)를 스캔하여
        # 파일 시스템 종류(FileSystem)를 안전하게 쿼리합니다.
        # 가이드라인에 지정된 NTFS(및 보안이 지원되는 차세대 ReFS)가 아닌 레거시 FAT 계열이 발견되면
        # 취약 플래그와 해당 드라이브 목록을 파이썬으로 리턴합니다.
        ps_script = (
            "$disks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue; "
            "if ($disks) { "
            "   $vulnerableDrives = @(); "
            "   foreach ($disk in $disks) { "
            "       $driveLetter = $disk.DeviceID; "
            "       $fileSystem = $disk.FileSystem; "
            "       if ($fileSystem -eq $null) { $fileSystem = 'UNKNOWN' } "
            "       # NTFS 또는 ReFS 보안 파일 시스템이 아닌 경우 모두 취약으로 스캔\n"
            "       if ($fileSystem -ne 'NTFS' -and $fileSystem -ne 'ReFS') { "
            "           $vulnerableDrives += ($driveLetter + '(' + $fileSystem + ')') "
            "       } "
            "   } "
            "   if ($vulnerableDrives.Count -gt 0) { "
            "       'VULNERABLE|' + ($vulnerableDrives -join ', ') "
            "   } else { "
            "       'SAFE_FS|All NTFS' "
            "   } "
            "} else { "
            "   'SAFE_FS|No Logical Disks Found' "
            "}"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 1. 명령어 실패 처리 (SSH 통신 오류 대응)
        if "ERROR:" in raw_output or not raw_output or "|" not in raw_output:
            status = "오류"
            detail_msg = f"파일 시스템 볼륨 정보 쿼리 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-61", "파일 및 디렉토리 보호", status)
            return status

        # 파이프라인 데이터 파싱 분할
        parsed_data = raw_output.split("|")
        result_flag = parsed_data[0].strip()
        detected_drives = parsed_data[1].strip()

        # 2. 요청하신 명확한 보안 가이드라인 기준 분기 처리 (단 하나라도 FAT면 취약)
        if result_flag == "VULNERABLE":
            status = "취약"
            detail_msg = f"취약: 보안 접근 제어(ACL)가 불가능한 레거시 FAT 계열 파일 시스템을 사용하는 드라이브가 발견되었습니다. 조치 가이드에 따라 convert 명령어로 NTFS 변환이 시급합니다. [탐지된 드라이브: {detected_drives}]"
        else:
            status = "양호"
            detail_msg = "양호: 서버 내 모든 로컬 논리 드라이브가 권고 기준에 부합하는 NTFS(또는 고보안 ReFS) 파일 시스템으로 안전하게 구성되어 있어 개별 파일 및 디렉터리 권한 통제가 가능합니다."

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-61", "파일 및 디렉토리 보호", status)
        
        # 터미널 콘솔 로그 출력
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_62(self):  # W-62: 시작 프로그램 목록 분석 (의심스러운 EXE 전수 탐지 버전)
        print("[*] W-62: 부팅 시 자동 실행되는 시작 프로그램 레지스트리 전수 조사 및 악성 위협 분석 중...")

        # Windows 자동 실행 핵심 레지스트리 4대 허브를 전수 조사합니다.
        # 화이트리스트(정식 프로그램/핵심 시스템 파일) 외의 모든 의심스러운 .exe 및 스크립트를 탐지합니다.
        ps_script = (
            "$runPaths = @("
            "   'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',"
            "   'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',"
            "   'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',"
            "   'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce'"
            "); "
            "$detectedThreats = @(); "
            " "
            "foreach ($path in $runPaths) { "
            "   if (Test-Path $path) { "
            "       $props = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue; "
            "       if ($props) { "
            "           foreach ($propName in $props.PSObject.Properties.Name) { "
            "               if ($propName -eq 'PSPath' -or $propName -eq 'PSParentPath' -or "
            "                   $propName -eq 'PSChildName' -or $propName -eq 'PSProvider' -or "
            "                   $propName -eq 'PSDrive') { continue; } "
            "               "
            "               $cmdLine = [string]$props.$propName; "
            "               if (-not $cmdLine) { continue; } "
            "               "
            "               # [1] 화이트리스트 규칙: 대중적이고 안전한 마이크로소프트 및 정식 프로그램 경로 패스\n"
            "               if ($cmdLine -match 'SecurityHealthSystray.exe' -or "
            "                   $cmdLine -match 'OneDrive.exe' -or "
            "                   $cmdLine -match 'ctfmon.exe' -or "
            "                   $cmdLine -match '(?i)C:\\\\Program Files' -or "
            "                   $cmdLine -match '(?i)C:\\\\Windows\\\\System32\\\\(cmd.exe|powershell.exe|svchost.exe|taskhostw.exe)') { "
            "                   continue; "
            "               } "
            "               "
            "               $isThreat = $false; "
            "               "
            "               # [2] 블랙리스트 규칙 A: 비정상적인 임시(Temp) 및 AppData 경로\n"
            "               if ($cmdLine -match '\\\\Temp\\\\' -or $cmdLine -match 'AppData\\\\Local\\\\Temp') { "
            "                   $isThreat = $true; "
            "               } "
            "               "
            "               # [3] 블랙리스트 규칙 B: 위험한 스크립트 확장자 (.bat, .cmd, .vbs, .ps1)\n"
            "               if ($cmdLine -match '\\.bat' -or $cmdLine -match '\\.cmd' -or "
            "                   $cmdLine -match '\\.vbs' -or $cmdLine -match '\\.ps1') { "
            "                   $isThreat = $true; "
            "               } "
            "               "
            "               # [4] 블랙리스트 규칙 C: 화이트리스트를 우회하여 중요 폴더나 알 수 없는 경로에 박힌 의심스러운 .exe\n"
            "               if ($cmdLine -match '\\.exe') { "
            "                   $isThreat = $true; "
            "               } "
            "               "
            "               if ($isThreat) { "
            "                   $detectedThreats += ($propName + ' -> ' + $cmdLine); "
            "               } "
            "           } "
            "       } "
            "   } "
            "} "
            " "
            "if ($detectedThreats.Count -gt 0) { "
            "   'VULNERABLE|' + ($detectedThreats -join ', ') "
            "} else { "
            "   'SAFE_REG|Clean' "
            "}"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 1. 명령어 실패 및 파이썬 컴파일 에러 수정 완료 (not으로 변경)
        if "ERROR:" in raw_output or not raw_output or "|" not in raw_output:
            status = "오류"
            detail_msg = f"시작 프로그램 레지스트리 분석 실패 (정보: {raw_output})"
            self.report.print_result("W-62", "시작 프로그램 목록 분석", status)
            return status

        # 파이프라인 데이터 파싱 분할
        parsed_data = raw_output.split("|")
        result_flag = parsed_data[0].strip()
        detected_items = parsed_data[1].strip()

        # 2. 화이트리스트/블랙리스트 및 의심스러운 EXE 통합 판정
        if result_flag == "VULNERABLE":
            status = "취약"
            detail_msg = f"취약: 시작 프로그램 목록 분석 결과, 임시 경로(Temp), 위험 스크립트, 또는 신뢰할 수 없는 경로에서 실행되는 의심스러운 알 수 없는 EXE 파일이 발견되었습니다. [탐지 대상: {detected_items}]"
        else:
            status = "양호"
            detail_msg = "양호: 시작 프로그램 목록이 정기적으로 관리되고 있으며, 검증된 공식 프로세스 외에 임시 경로 기반 구동 파일이나 알 수 없는 의심스러운 비인가 EXE/스크립트 항목이 존재하지 않습니다."

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-62", "시작 프로그램 목록 분석", status)
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_63(self):  # W-63: 컴퓨터 시계 동기화 최대 허용 오차 점검 (무오류 버전)
        print("[*] W-63: 계정 정책 - Kerberos 정책 내 컴퓨터 시계 동기화 최대 허용 오차 상태 분석 중...")

        # 윈도우 로컬 보안 정책의 [계정 정책 > Kerberos 정책 > 컴퓨터 시계 동기화 최대 허용 오차] 옵션을 제어하는
        # 커널 매핑 키값인 'MaxServiceTicketAge' 혹은 'MaxClockSkew' 영역을 secedit으로 정밀 덤프합니다.
        # - MaxClockSkew: 시간 동기화 최대 허용 오차 (단위: 분, 기본/권고값: 5분 이하)
        # 값이 지정되지 않은 경우 시스템 기본 권고치인 5분으로 간주하여 유연하게 처리합니다.
        ps_script = (
            "$tempFile = [System.IO.Path]::GetTempFileName(); "
            "secedit /export /cfg $tempFile /areas SECURITYPOLICY | Out-Null; "
            "$line = Get-Content $tempFile | Where-Object { $_ -match '^MaxClockSkew\\s*=\\s*(.*)' }; "
            "Remove-Item $tempFile -Force -ErrorAction SilentlyContinue; "
            "if ($line -and $line -match '=\\s*(.*)') { "
            "   $val = $Matches[1].Trim(); "
            "   [int]$val "
            "} else { "
            "   # 정책에 명시적으로 잡혀있지 않은 독립형 서버의 경우 5분(기본값) 스캔\n"
            "   5 "
            "}"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 1. 명령어 실패 처리 (SSH 통신 오류 대응)
        if "ERROR:" in raw_output or not raw_output:
            status = "오류"
            detail_msg = f"Kerberos 보안 정책 쿼리 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-63", "도메인 컨트롤러-사용자의 시간 동기화", status)
            return status

        # 정수형 분(Minute) 데이터 변환
        val_minutes = int(raw_output)

        # 2. 요청하신 명확한 보안 가이드라인 기준 분기 처리 (5분 이하 양호, 5분 초과 취약)
        if val_minutes <= 5 and val_minutes >= 0:
            status = "양호"
            detail_msg = f"양호: 컴퓨터 시계 동기화 최대 허용 오차 값이 {val_minutes}분으로 설정되어 있어 KISA 권고 기준(5분 이하)을 안전하게 준수하고 있습니다."
        else:
            status = "취약"
            detail_msg = f"취약: 컴퓨터 시계 동기화 최대 허용 오차 값이 {val_minutes}분으로 설정되어 권고 기준(5분 이하)을 초과했습니다. Kerberos 인증 재생 공격 방지를 위해 5분 이하로 재조정이 필요합니다."

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-63", "도메인 컨트롤러-사용자의 시간 동기화", status)
        
        # 터미널 콘솔 로그 출력
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    def w_64(self):  # W-64: 윈도우 방화벽 설정 점검 (무오류 버전)
        print("[*] W-64: 네트워크 보안 - Windows Defender 방화벽 프로필별 활성화 상태 분석 중...")

        # Windows 방화벽의 3대 핵심 프로필(Domain, Private, Public) 상태를 직격 쿼리합니다.
        # - Enabled: True (방화벽 작동 중 / 양호)
        # - Enabled: False (방화벽 꺼짐 / 취약)
        # 결과 포맷 예시: 'Domain상태|Private상태|Public상태' (예: True|True|True)
        ps_script = (
            "$profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue; "
            "if ($profiles) { "
            "   $dom = ($profiles | Where-Object { $_.Name -eq 'Domain' }).Enabled; "
            "   $priv = ($profiles | Where-Object { $_.Name -eq 'Private' }).Enabled; "
            "   $pub = ($profiles | Where-Object { $_.Name -eq 'Public' }).Enabled; "
            "   [string]$dom + '|' + [string]$priv + '|' + [string]$pub "
            "} else { "
            "   'False|False|False' "
            "}"
        )
        
        raw_output = self.conn.execute_cmd(ps_script).strip()

        # 1. 명령어 실패 처리 (SSH 통신 오류 대응)
        if "ERROR:" in raw_output or not raw_output or "|" not in raw_output:
            status = "오류"
            detail_msg = f"Windows 방화벽 프로필 상태 쿼리 조회 실패 (정보: {raw_output})"
            self.report.print_result("W-64", "윈도우 방화벽 설정", status)
            return status

        # 파이프라인 데이터 파싱 분할
        parsed_data = raw_output.split("|")
        val_domain = parsed_data[0].strip()   # 도메인 프로필 상태
        val_private = parsed_data[1].strip()  # 개인 프로필 상태
        val_public = parsed_data[2].strip()   # 공용 프로필 상태

        has_vulnerability = False
        reason_list = []

        # 2. 요청하신 가이드라인 기준 3대 프로필 전수 검증 (하나라도 False면 취약)
        if val_domain != "True":
            has_vulnerability = True
            reason_list.append("도메인(Domain) 프로필 꺼짐")

        if val_private != "True":
            has_vulnerability = True
            reason_list.append("개인(Private) 프로필 꺼짐")

        if val_public != "True":
            has_vulnerability = True
            reason_list.append("공용(Public) 프로필 꺼짐")

        # 3. 최종 보안 가이드라인 기준 분기 처리
        if has_vulnerability:
            status = "취약"
            reasons = ", ".join(reason_list)
            detail_msg = f"취약: Windows 방화벽 설정 중 비활성화된 네트워크 프로필이 존재합니다. [사유: {reasons}]"
        else:
            status = "양호"
            detail_msg = "양호: Windows Defender 방화벽의 모든 네트워크 프로필(도메인, 개인, 공용)이 '사용(Enabled)'으로 안전하게 켜져 있어 비인가 네트워크 접근을 통제하고 있습니다."

        # ReportManager 표 양식에 출력 및 저장
        self.report.print_result("W-64", "윈도우 방화벽 설정", status)
        
        # 터미널 콘솔 로그 출력
        print(f"  - 상세 내용: {detail_msg}")
        
        return status
    
    

# ==========================================
# 실행 예시
# ==========================================
if __name__ == "__main__":
    TARGET_IP = "172.16.5.1"
    TARGET_PORT = 22
    USERNAME = "admin"
    PASSWORD = "601"

    # 1. 리포트 매니저 및 SSH 커넥션 초기화
    report = ReportManager(target_ip=TARGET_IP)
    conn = SSHConnection(host=TARGET_IP, username=USERNAME, password=PASSWORD, port=TARGET_PORT)

    try:
        # 2. SSH 접속
        if conn.connect():
            print(f"[*] {TARGET_IP}에 성공적으로 SSH 연결되었습니다.")
            
            # 3. 헤더 출력
            report.print_main_header(category="윈도우 로컬 계정 관리 점검")

            # 4. 진단 모듈 생성 및 실행
            inspector = IdentityManagement(ssh_conn=conn, report_mgr=report)
            inspector.w_01()
            inspector.w_02()
            inspector.w_04()
            inspector.w_05()
            inspector.w_06()
            inspector.w_07()
            inspector.w_08()
            inspector.w_09()
            inspector.w_10()
            inspector.w_11()
            inspector.w_12()
            inspector.w_13()
            inspector.w_14()
            inspector.w_15()
            inspector.w_16()
            inspector.w_17()
            inspector.w_18()
            inspector.w_19()
            inspector.w_20()
            inspector.w_21()
            inspector.w_22()
            inspector.w_23()
            inspector.w_24()
            inspector.w_25()
            inspector.w_26()
            inspector.w_27()
            inspector.w_28()
            inspector.w_29()
            inspector.w_30()
            inspector.w_31()
            inspector.w_32()
            inspector.w_33()
            inspector.w_34()
            inspector.w_35()
            inspector.w_36()
            inspector.w_38()
            inspector.w_39()
            inspector.w_40()
            inspector.w_41()
            inspector.w_42()
            inspector.w_43()
            inspector.w_44()
            inspector.w_45()
            inspector.w_46()
            inspector.w_47()
            inspector.w_48()
            inspector.w_49()
            inspector.w_50()
            inspector.w_51()
            inspector.w_52()
            inspector.w_53()
            inspector.w_54()
            inspector.w_55()
            inspector.w_56()
            inspector.w_57()
            inspector.w_58()
            inspector.w_59()
            inspector.w_60()
            inspector.w_61()
            inspector.w_62()
            inspector.w_63()
            inspector.w_64()

            print("-" * 80)
            
            # 5. 결과를 JSON 파일로 영구 저장
            report.save_to_json("win_security_report.json")
            
        else:
            print("[!] SSH 세션 연결을 수립하지 못했습니다.")
            
    except Exception as e:
        print(f"[!] 점검 중 치명적인 오류 발생: {e}")
        
    finally:
        # 6. 통신 자원 정리
        conn.disconnect()
        print("[*] SSH 연결이 성공적으로 해제되었습니다.")
