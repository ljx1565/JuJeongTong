import paramiko
import unicodedata
import json
import re

class SSHConnection:
    """SSH 연결 및 명령어 실행을 전담하는 클래스"""
    def __init__(self, hostname, port, username, password):
        self.hostname = hostname
        self.port = port
        self.username = username
        self.password = password
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.os_type = "unknown"

    def connect(self):
        self.ssh.connect(self.hostname, port=self.port, username=self.username, password=self.password)
        print(f"[*] {self.hostname} 에 성공적으로 접속했습니다.")
        self._detect_os()

    def disconnect(self):
        self.ssh.close()
        print(f"[*] {self.hostname} 접속을 종료했습니다.")

    def execute_cmd(self, cmd):
        stdin, stdout, stderr = self.ssh.exec_command(cmd)
        return stdout.read().decode('utf-8').strip()

    def _detect_os(self):
        """서버의 OS 환경을 판별합니다."""
        os_info = self.execute_cmd("cat /etc/os-release").lower()
        if "debian" in os_info or "ubuntu" in os_info:
            self.os_type = "debian"
        elif "rhel" in os_info or "centos" in os_info or "rocky" in os_info:
            self.os_type = "redhat"
        print(f"[*] 감지된 OS 타입: {self.os_type.upper()}")

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
        print("\n" + "="*70)
        print("Redhat 버전 8버전 이상, Debian 버전 20.04 이상 시설만 검증하는 코드입니다.")
        print(f"🔍 원격지 [{self.target_ip}] 기술적 취약점 진단: {category}")
        print("="*70)
        print("[*] 현재 설정 값 검증 중...\n")
        
        # 칸 너비 지정: 항목코드(10칸), 점검항목(40칸), 진단결과(10칸)
        code_str = self._pad_string("항목코드", 10)
        title_str = self._pad_string("점검항목", 50)
        result_str = self._pad_string("진단결과", 10)
        
        header_row = f"| {code_str} | {title_str} | {result_str} |"
        print(header_row)
        print("-" * 70)

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

       
class IdentityManagement:  # 계정 관리
    def __init__(self, ssh_conn, report_mgr):
            # SSHConnection 객체를 전달받아 내부에서 사용
            self.conn = ssh_conn
            self.report = report_mgr

    def u_01(self):  # root 계정 원격 접속 제한 점검

        issues = [] # 취약 사유를 담을 빈 리스트 생성

        # 1. SSH 점검: /etc/ssh/sshd_config 파일에 PermitRootLogin 설정 확인
        ssh_cmd = "grep -i '^PermitRootLogin' /etc/ssh/sshd_config | awk '{print $2}'"
        ssh_result = self.conn.execute_cmd(ssh_cmd).lower()

        if ssh_result != "no":
            issues.append(f"PermitRootLogin 설정 취약 (현재 값: {ssh_result})")

        # 2. Telnet 점검: /etc/securetty 파일 내에 주석 처리되지 않은 pts/x 가 있는지 확인
        securetty_cmd = "cat /etc/securetty 2>/dev/null | grep -E '^pts/[0-9]+'"
        pts_result = self.conn.execute_cmd(securetty_cmd)

        if pts_result:
            issues.append("securetty 파일 내 활성화된 pts 설정 존재")

        # 리스트에 내용이 있으면 '취약', 비어있으면 '양호'로 한 줄 처리
        status = "취약" if issues else "양호"

        self.report.print_result("U-01", "root 계정 원격 접속 제한", status)

        return status

    def u_02(self):  # 비밀번호 관리정책 설정 

        issues = [] # 취약 사유를 담을 빈 리스트 생성
        
        if self.conn.os_type == "redhat":
            
            # [Step 1 & 5] login.defs 기한 검사 (PASS_MAX_DAYS 90 이하, PASS_MIN_DAYS 1 이상)
            max_days = self.conn.execute_cmd("awk '/^PASS_MAX_DAYS/ {print $2}' /etc/login.defs")
            min_days = self.conn.execute_cmd("awk '/^PASS_MIN_DAYS/ {print $2}' /etc/login.defs")
            
            if not max_days or int(max_days) > 90 or not min_days or int(min_days) < 1:
                issues.append("login.defs 패스워드 기한 설정 미흡 (최대 90일, 최소 1일)")

            # [Step 2] pwquality.conf 복잡성 검사 
            # (가이드: 최소 요구 항목은 반드시 -1, 길이는 8 이상)
            minlen = self.conn.execute_cmd("grep -i '^minlen' /etc/security/pwquality.conf | awk -F= '{print $2}' | tr -d ' '")
            dcredit = self.conn.execute_cmd("grep -i '^dcredit' /etc/security/pwquality.conf | awk -F= '{print $2}' | tr -d ' '")
            ucredit = self.conn.execute_cmd("grep -i '^ucredit' /etc/security/pwquality.conf | awk -F= '{print $2}' | tr -d ' '")
            lcredit = self.conn.execute_cmd("grep -i '^lcredit' /etc/security/pwquality.conf | awk -F= '{print $2}' | tr -d ' '")
            ocredit = self.conn.execute_cmd("grep -i '^ocredit' /etc/security/pwquality.conf | awk -F= '{print $2}' | tr -d ' '")

            pwq_enforce = self.conn.execute_cmd("grep -E '^[[:space:]]*enforce_for_root' /etc/security/pwquality.conf 2>/dev/null")

            if not minlen or int(minlen) < 8:
                issues.append("비밀번호 최소 길이(minlen) 8자리 미만")
            if dcredit != "-1" or ucredit != "-1" or lcredit != "-1" or ocredit != "-1":
                issues.append("비밀번호 복잡성(dcredit, ucredit, lcredit, ocredit) 설정 미흡")

            # [Step 3 & 4] 최근 비밀번호 기억 검사 (remember=4 이상)
            # 가이드에 따라 /etc/security/pwhistory.conf 또는 /etc/pam.d/system-auth 검사
            cmd_remember = "grep -oP 'remember=\\K\\d+' /etc/security/pwhistory.conf /etc/pam.d/system-auth 2>/dev/null | head -1"
            remember = self.conn.execute_cmd(cmd_remember)
            
            # pwhistory.conf 내 enforce_for_root 및 file 속성 활성화 여부 검사
            pwh_enforce = self.conn.execute_cmd("grep -E '^[[:space:]]*enforce_for_root' /etc/security/pwhistory.conf 2>/dev/null")
            pwh_file = self.conn.execute_cmd("grep -E '^[[:space:]]*file[[:space:]]*=[[:space:]]*/etc/security/opasswd' /etc/security/pwhistory.conf 2>/dev/null")

            if not remember or int(remember) < 4:
                issues.append("최근 비밀번호 기억(remember) 4회 미만 설정됨")
            if not pwh_enforce:
                issues.append("pwhistory.conf 내 enforce_for_root 미설정")
            if not pwh_file:
                issues.append("pwhistory.conf 내 file=/etc/security/opasswd 미설정")

        elif self.conn.os_type == "debian":  # 데비안 
            
            # login.defs 기한 검사
            max_days = self.conn.execute_cmd("awk '/^PASS_MAX_DAYS/ {print $2}' /etc/login.defs")
            min_days = self.conn.execute_cmd("awk '/^PASS_MIN_DAYS/ {print $2}' /etc/login.defs")
            
            if not max_days or int(max_days) > 90 or not min_days or int(min_days) < 1:
                issues.append("login.defs 패스워드 기한 설정 미흡 (최대 90일, 최소 1일)")

            # pwquality.conf 복잡성 및 enforce_for_root 검사
            minlen = self.conn.execute_cmd("grep -i '^minlen' /etc/security/pwquality.conf | awk -F= '{print $2}' | tr -d ' '")
            dcredit = self.conn.execute_cmd("grep -i '^dcredit' /etc/security/pwquality.conf | awk -F= '{print $2}' | tr -d ' '")
            ucredit = self.conn.execute_cmd("grep -i '^ucredit' /etc/security/pwquality.conf | awk -F= '{print $2}' | tr -d ' '")
            lcredit = self.conn.execute_cmd("grep -i '^lcredit' /etc/security/pwquality.conf | awk -F= '{print $2}' | tr -d ' '")
            ocredit = self.conn.execute_cmd("grep -i '^ocredit' /etc/security/pwquality.conf | awk -F= '{print $2}' | tr -d ' '")
            pwq_enforce = self.conn.execute_cmd("grep -E '^[[:space:]]*enforce_for_root' /etc/security/pwquality.conf 2>/dev/null")

            if not minlen or int(minlen) < 8:
                issues.append("비밀번호 최소 길이(minlen) 8자리 미만")
            if dcredit != "-1" or ucredit != "-1" or lcredit != "-1" or ocredit != "-1":
                issues.append("비밀번호 복잡성(dcredit, ucredit, lcredit, ocredit) 설정 미흡")
            if not pwq_enforce:
                issues.append("pwquality.conf 내 enforce_for_root 미설정")

            # common-password 파일 점검 (Debian 환경)
            pam_file = "/etc/pam.d/common-password"
            # 주석(#) 처리되지 않은 유효한 설정 라인만 가져옵니다.
            pam_content = self.conn.execute_cmd(f"grep -v '^[[:space:]]*#' {pam_file}")
            
            pwq_idx, pwh_idx, unix_idx = -1, -1, -1
            
            # 파일 내용 중 각 모듈이 처음 등장하는 줄 번호(인덱스)를 기록합니다.
            for i, line in enumerate(pam_content.splitlines()):
                if 'pam_pwquality.so' in line and pwq_idx == -1:
                    pwq_idx = i
                if 'pam_pwhistory.so' in line and pwh_idx == -1:
                    pwh_idx = i
                if 'pam_unix.so' in line and unix_idx == -1:
                    unix_idx = i

            # pam_pwquality.so 검증
            if pwq_idx == -1:
                issues.append(f"{pam_file} 내 pam_pwquality.so 모듈 미설정")
            elif unix_idx != -1 and pwq_idx > unix_idx:
                issues.append(f"{pam_file} 내 pam_pwquality.so 모듈이 pam_unix.so 보다 아래에 위치함")
                
            # pam_pwhistory.so 검증
            if pwh_idx == -1:
                issues.append(f"{pam_file} 내 pam_pwhistory.so 모듈 미설정")
            elif unix_idx != -1 and pwh_idx > unix_idx:
                issues.append(f"{pam_file} 내 pam_pwhistory.so 모듈이 pam_unix.so 보다 아래에 위치함")

        status = "취약" if issues else "양호"

        self.report.print_result("U-02", "비밀번호 관리정책 설정", status)
        return status

    def u_03(self):  # 계정 잠금 임계값 설정

        issues = []

        if self.conn.os_type == "redhat":
            
            # 검사할 대상 파일 리스트
            pam_files = ["/etc/pam.d/system-auth", "/etc/pam.d/password-auth"]
            
            for pam_file in pam_files:
                # 1. 파일 내에 주석 처리되지 않은 pam_faillock.so 모듈 라인이 있는지 확인
                faillock_line = self.conn.execute_cmd(f"grep -E '^[[:space:]]*auth.+pam_faillock\\.so' {pam_file} 2>/dev/null")
                
                if not faillock_line:
                    issues.append(f"{pam_file} 내 pam_faillock.so 설정 없음")
                else:
                    # 2. deny 설정 값 추출 및 검증 (가이드 권고: 10 이하)
                    deny_val = self.conn.execute_cmd(f"echo \"{faillock_line}\" | grep -oP 'deny=\\K\\d+' | head -1")
                    if not deny_val or int(deny_val) > 10:
                        issues.append(f"{pam_file} 내 deny 설정 미흡 (현재: {deny_val if deny_val else '없음'}, 권고: 10 이하)")

                    # 3. unlock_time 설정 값 추출 및 검증 (가이드 권고: 120 이상)
                    unlock_time_val = self.conn.execute_cmd(f"echo \"{faillock_line}\" | grep -oP 'unlock_time=\\K\\d+' | head -1")
                    if not unlock_time_val or int(unlock_time_val) < 120:
                        issues.append(f"{pam_file} 내 unlock_time 설정 미흡 (현재: {unlock_time_val if unlock_time_val else '없음'}, 권고: 120 이상)")

        elif self.conn.os_type == "debian":
            
            pam_file = "/etc/pam.d/common-auth"
            
            # 1. auth 라인 점검 (pam_tally.so 또는 pam_tally2.so)
            auth_tally_line = self.conn.execute_cmd(f"grep -E '^[[:space:]]*auth.+pam_tally(2)?\\.so' {pam_file} 2>/dev/null")
            
            if not auth_tally_line:
                issues.append(f"{pam_file} 내 auth 모듈(pam_tally) 설정 없음")
            else:
                # deny 검증
                deny_val = self.conn.execute_cmd(f"echo \"{auth_tally_line}\" | grep -oP 'deny=\\K\\d+' | head -1")
                if not deny_val or int(deny_val) > 10:
                    issues.append(f"{pam_file} 내 deny 설정 미흡 (현재: {deny_val if deny_val else '없음'}, 권고: 10 이하)")

                # unlock_time 검증
                unlock_time_val = self.conn.execute_cmd(f"echo \"{auth_tally_line}\" | grep -oP 'unlock_time=\\K\\d+' | head -1")
                if not unlock_time_val or int(unlock_time_val) < 120:
                    issues.append(f"{pam_file} 내 unlock_time 설정 미흡 (현재: {unlock_time_val if unlock_time_val else '없음'}, 권고: 120 이상)")
                
                # no_magic_root 설정 여부 검증 (auth 라인)
                if 'no_magic_root' not in auth_tally_line:
                    issues.append(f"{pam_file} 내 auth 라인에 no_magic_root 누락")

            # 2. account 라인 점검 (pam_tally.so 또는 pam_tally2.so)
            account_tally_line = self.conn.execute_cmd(f"grep -E '^[[:space:]]*account.+pam_tally(2)?\\.so' {pam_file} 2>/dev/null")
            
            if not account_tally_line:
                issues.append(f"{pam_file} 내 account 모듈(pam_tally) 설정 없음")
            else:
                # no_magic_root 설정 여부 검증 (account 라인)
                if 'no_magic_root' not in account_tally_line:
                    issues.append(f"{pam_file} 내 account 라인에 no_magic_root 누락")
                # reset 설정 여부 검증 (account 라인)
                if 'reset' not in account_tally_line:
                    issues.append(f"{pam_file} 내 account 라인에 reset 누락")

        status = "취약" if issues else "양호"
        self.report.print_result("U-03", "계정 잠금 임계값 설정", status)
        
        return status

    def u_04(self):  # 비밀번호 파일 보호 설정

        issues = []
        
        # /etc/passwd 파일 내 계정의 두 번째 필드가 'x'인지 확인
        # awk 명령어를 사용하여 두 번째 필드($2)가 'x'가 아닌 계정이 하나라도 있는지 찾습니다.
        cmd_passwd = "awk -F: '$2 != \"x\" {print $1}' /etc/passwd" 
        non_x_users = self.conn.execute_cmd(cmd_passwd)
        
        if non_x_users:
            issues.append("/etc/passwd 두 번째 필드가 'x'가 아닌 계정 존재")

        # 2. pwconv(쉐도우 비밀번호) 적용 여부 확인
        # 쉐도우 패스워드 시스템이 적용되면 /etc/shadow 파일이 생성됩니다.
        cmd_shadow = "test -f /etc/shadow && echo 'applied' || echo 'not_applied'"
        pwconv_status = self.conn.execute_cmd(cmd_shadow)

        if pwconv_status != "applied":
            issues.append("쉐도우 패스워드 시스템 미적용 (pwconv 적용 필요)")

        # 리스트에 이슈가 하나라도 있으면 취약, 없으면 양호
        status = "취약" if issues else "양호"
        self.report.print_result("U-04", "비밀번호 파일 보호", status)
        
        return status

    def u_05(self):  # root 이외의 UID가 '0' 금지 설정

        issues = []

        # /etc/passwd 파일에서 UID(세 번째 필드)가 0이면서 
        # 계정명(첫 번째 필드)이 'root'가 아닌 계정만 필터링하여 출력합니다.
        cmd = "awk -F: '$3 == 0 && $1 != \"root\" {print $1}' /etc/passwd"
        uid_zero_users = self.conn.execute_cmd(cmd)

        if uid_zero_users:
            # 발견된 계정들을 보기 좋게 쉼표로 연결
            users = uid_zero_users.replace('\n', ', ')
            issues.append(f"root 계정 외에 UID가 0인 계정 존재: {users}")

        # 리스트에 이슈가 하나라도 있으면 취약, 없으면 양호
        status = "취약" if issues else "양호"
        self.report.print_result("U-05", "root 이외의 UID가 '0' 금지", status)
        
        return status

    def u_06(self):  # 사용자 계정 su 기능 제한 설정

        issues = []

        # 1. 일반 사용자 존재 여부 점검 (가이드라인 예외 조건 처리)
        # UID가 1000 이상이면서 nobody(65534)가 아닌 실제 일반 계정이 있는지 확인
        normal_users_cmd = "awk -F: '$3 >= 1000 && $3 != 65534 {print $1}' /etc/passwd"
        normal_users = self.conn.execute_cmd(normal_users_cmd)

        if not normal_users.strip():
            # 일반 사용자가 아예 없으면 su 제한 자체가 불필요하므로 즉시 양호 처리
            self.report.print_result("U-06", "사용자 계정 su 기능 제한", "양호")
            return "양호"

        # 2. wheel 그룹 존재 여부 확인
        wheel_group = self.conn.execute_cmd("grep '^wheel:' /etc/group")
        if not wheel_group:
            issues.append("시스템에 wheel(su 허용) 그룹이 존재하지 않음")

        # 3. 투트랙(Two-Track) 검증 변수 초기화
        is_pam_secure = False
        is_perm_secure = False

        # [트랙 1] PAM 모듈(pam_wheel.so) 이용 방식 검증
        pam_su_file = "/etc/pam.d/su"
        # 주석(#)이 없으며 auth required pam_wheel.so 구문이 포함되어 있는지 정규식 검사
        pam_wheel_line = self.conn.execute_cmd(f"grep -E '^[[:space:]]*auth.+required.+pam_wheel\\.so' {pam_su_file} 2>/dev/null")
        
        if pam_wheel_line:
            # 2. 옵션이 있는지 파이썬의 'in'으로 확실하게 검사합니다.
            if "use_uid" in pam_wheel_line or "group=" in pam_wheel_line:
                is_pam_secure = True
            else:
                # 라인은 있지만 옵션이 빠져있다면 취약 사유로 기록합니다.
                issues.append(f"{pam_su_file} 내 pam_wheel.so에 필수 옵션(use_uid 또는 group=wheel) 누락")

        # [트랙 2] 파일 권한(Permission) 제어 방식 검증
        # stat 명령어로 /bin/su 또는 /usr/bin/su의 권한과 그룹을 가져옴 (출력 예: -rwsr-xr-x root)
        su_stat = self.conn.execute_cmd("stat -c '%A %G' /bin/su 2>/dev/null || stat -c '%A %G' /usr/bin/su 2>/dev/null")
        
        if su_stat:
            # split() 결과물의 개수를 조건문으로 확인하여 안전하게 처리합니다.
            stat_parts = su_stat.split()
            if len(stat_parts) >= 2:
                perms = stat_parts[0]
                # 권한 문자열의 맨 끝 3자리(others 권한)가 '---' 이면 일반 사용자의 실행이 원천 차단된 것
                if perms[-3:] == "---":
                    is_perm_secure = True

        # 4. 최종 결과 판정
        # PAM과 파일 권한 둘 다 설정되어 있지 않은 경우에만 취약으로 판정
        if not is_pam_secure and not is_perm_secure:
            issues.append("su 명령어 사용 제한 미설정 (PAM 및 권한 제한 모두 없음)")

        status = "취약" if issues else "양호"
        self.report.print_result("U-06", "사용자 계정 su 기능 제한", status)
        
        return status

    # 현재 필요하다고 생각되어지지않는 검사들
    # def u_07(self):  # 불필요한 계정 제거 설정  
    # def u_08(self):  # 관리자 그룹에 최소한의 계정 포함 설정
    # def u_09(self):  # 계정이 존재하지 않는 GID 금지 설정
    
    def u_10(self):  # 동일한 UID 금지 설정

        issues = []

        # /etc/passwd 파일에서 3번째 필드(UID)만 추출 후, 정렬하여 중복된 값만 출력합니다.
        cmd = "awk -F: '{print $3}' /etc/passwd | sort | uniq -d"
        duplicate_uids = self.conn.execute_cmd(cmd)

        # 결과값이 존재한다면 중복된 UID가 있다는 뜻입니다.
        if duplicate_uids:
            # 출력된 중복 UID들을 보기 좋게 쉼표(,)로 연결합니다.
            uids = duplicate_uids.strip().replace('\n', ', ')
            issues.append(f"중복된 UID 존재: {uids}")

        # 리스트에 이슈가 있으면 취약, 없으면 양호
        status = "취약" if issues else "양호"
        self.report.print_result("U-10", "동일한 UID 금지", status)
        
        return status

    def u_11(self):  # 사용자 shell 점검 설정

        issues = []

        # 1. 점검 대상 시스템 계정 목록 (정규식 파이프(|)로 연결)
        target_users = "daemon|bin|sys|adm|listen|nobody|nobody4|noaccess|diag|operator|games|gopher"

        # 2. awk를 사용하여 대상 계정들의 이름($1)과 부여된 쉘($7)을 추출합니다.
        # 출력 형태 예시: daemon:/usr/sbin/nologin
        cmd = f"awk -F: '$1 ~ /^({target_users})$/ {{print $1 \":\" $7}}' /etc/passwd"
        result = self.conn.execute_cmd(cmd)

        if result:
            # 3. 추출된 결과값을 한 줄씩 반복하며 쉘 상태를 확인합니다.
            for line in result.strip().split('\n'):
                parts = line.split(':')
                
                # split() 결과가 정상적으로 [계정, 쉘] 2개로 나뉘었는지 조건문으로 확인 
                if len(parts) == 2:
                    user = parts[0]
                    shell = parts[1].strip()

                    # 4. 쉘에 'false' 또는 'nologin' 문자열이 포함되어 있지 않으면 취약으로 판단
                    # (최신 데비안/우분투 계열은 /usr/sbin/nologin을 사용하는 경우도 있어 문자열 포함 여부로 유연하게 검사합니다)
                    if "false" not in shell and "nologin" not in shell:
                        issues.append(f"{user} 계정에 불필요한 쉘 부여됨 (현재 쉘: {shell})")

        # 5. 리스트에 이슈가 있으면 취약, 없으면 양호
        status = "취약" if issues else "양호"
        self.report.print_result("U-11", "사용자 shell 점검", status)
        
        return status

    # def u_12(self):  # 세션 종료 시간 설정 (모니터링 용도일 경우 예외처리 필요)
        
    #     issues = []

    #     # TMOUT=600 또는 export TMOUT=600 형식에서 숫자만 추출 (초 단위)
    #     tmout_cmd = "grep -E '^[[:space:]]*(export[[:space:]]+)?TMOUT[[:space:]]*=' /etc/profile | awk -F= '{print $2}' | sed 's/[^0-9]//g' | head -1"
    #     tmout_val = self.conn.execute_cmd(tmout_cmd)

    #     # 값이 없거나 숫자가 아닌 경우 미설정으로 간주
    #     if not tmout_val or not tmout_val.isdigit():
    #         issues.append("/etc/profile 내 TMOUT(세션 타임아웃) 미설정")
    #     else:
    #         # 600초(10분) 초과 시 취약
    #         if int(tmout_val) > 600:
    #             issues.append(f"/etc/profile 내 TMOUT 설정 미흡 (현재: {tmout_val}초, 권고: 600초 이하)")
        
    #     # csh 관련 설정 파일이 시스템에 존재하는지 우선 확인합니다.
    #     csh_check = self.conn.execute_cmd("ls /etc/csh.cshrc /etc/csh.login 2>/dev/null")

    #     if csh_check.strip():
    #         # set autologout=10 형식에서 숫자만 추출 (분 단위)
    #         autologout_cmd = "grep -hE '^[[:space:]]*set[[:space:]]+autologout[[:space:]]*=' /etc/csh.cshrc /etc/csh.login 2>/dev/null | awk -F= '{print $2}' | sed 's/[^0-9]//g' | head -1"
    #         autologout_val = self.conn.execute_cmd(autologout_cmd)

    #         if not autologout_val or not autologout_val.isdigit():
    #             issues.append("csh 환경(autologout) 세션 타임아웃 미설정")
    #         else:
    #             # 10분 초과 시 취약
    #             if int(autologout_val) > 10:
    #                 issues.append(f"csh 환경(autologout) 설정 미흡 (현재: {autologout_val}분, 권고: 10분 이하)")

    #     status = "취약" if issues else "양호"
    #     self.report.print_result("U-12", "세션 타임아웃 설정", status)
        
    #     return status

    def u_13(self):  # 안전한 비밀번호 암호화 알고리즘 사용 설정

        issues = []

        if self.conn.os_type == "redhat":
            
            # [Step 1] /etc/shadow 파일 점검 (실제 취약 계정 존재 여부)
            # $1$(MD5) 또는 $2$(Blowfish) 등 취약한 해시로 암호화된 계정을 찾습니다.
            shadow_cmd = "awk -F: '$2 ~ /^\\$1\\$/ || $2 ~ /^\\$2/ {print $1}' /etc/shadow 2>/dev/null"
            weak_users = self.conn.execute_cmd(shadow_cmd).strip()

            if weak_users:
                users = weak_users.replace('\n', ', ')
                issues.append(f"/etc/shadow 파일 내 취약한 해시 알고리즘(MD5, Blowfish) 사용 계정 존재: {users}")

            # [Step 2] /etc/login.defs 파일 내 ENCRYPT_METHOD 값 설정 점검
            # 값이 SHA256, SHA512 (또는 최신 보안 표준인 YESCRYPT)인지 검사합니다.
            login_defs_cmd = "grep -E '^[[:space:]]*ENCRYPT_METHOD' /etc/login.defs | awk '{print $2}' | head -1"
            encrypt_method = self.conn.execute_cmd(login_defs_cmd).strip().upper()

            if not encrypt_method:
                issues.append("/etc/login.defs 파일 내 ENCRYPT_METHOD 미설정")
            elif encrypt_method not in ["SHA256", "SHA512", "YESCRYPT"]:
                issues.append(f"/etc/login.defs 파일 내 취약한 알고리즘 설정됨 (현재: {encrypt_method})")

            # [Step 3] /etc/pam.d/system-auth 파일 내 안전한 알고리즘 설정 점검
            pam_file = "/etc/pam.d/system-auth"
            pam_cmd = f"grep -E '^[[:space:]]*password.*pam_unix\\.so' {pam_file} 2>/dev/null | head -1"
            pam_line = self.conn.execute_cmd(pam_cmd).strip().lower()

            if not pam_line:
                issues.append(f"{pam_file} 내 pam_unix.so 설정 없음")
            else:
                if "sha256" not in pam_line and "sha512" not in pam_line and "yescrypt" not in pam_line:
                    issues.append(f"{pam_file} 내 pam_unix.so에 안전한 알고리즘(sha256/sha512 등) 누락")

        elif self.conn.os_type == "debian":

            # [Step 1] /etc/shadow 파일 점검 (RedHat과 동일)
            shadow_cmd = "awk -F: '$2 ~ /^\\$1\\$/ || $2 ~ /^\\$2/ {print $1}' /etc/shadow 2>/dev/null"
            weak_users = self.conn.execute_cmd(shadow_cmd).strip()

            if weak_users:
                users = weak_users.replace('\n', ', ')
                issues.append(f"/etc/shadow 파일 내 취약한 해시 알고리즘(MD5, Blowfish) 사용 계정 존재: {users}")

            # [Step 2] /etc/login.defs 파일 점검 (RedHat과 동일)
            login_defs_cmd = "grep -E '^[[:space:]]*ENCRYPT_METHOD' /etc/login.defs | awk '{print $2}' | head -1"
            encrypt_method = self.conn.execute_cmd(login_defs_cmd).strip().upper()

            if not encrypt_method:
                issues.append("/etc/login.defs 파일 내 ENCRYPT_METHOD 미설정")
            elif encrypt_method not in ["SHA256", "SHA512", "YESCRYPT"]:
                issues.append(f"/etc/login.defs 파일 내 취약한 알고리즘 설정됨 (현재: {encrypt_method})")

            # [Step 3] /etc/pam.d/common-password 파일 점검 (Debian 전용)
            pam_file = "/etc/pam.d/common-password"

            # password 구문과 pam_unix.so 모듈을 검사합니다.
            # password로 시작하고 중간에 어떤 옵션이 있든 pam_unix.so가 선언되어 있는 라인만
            pam_cmd = f"grep -E '^[[:space:]]*password.*pam_unix\\.so' {pam_file} 2>/dev/null | head -1"
            pam_line = self.conn.execute_cmd(pam_cmd).strip().lower()

            if not pam_line:
                issues.append(f"{pam_file} 내 pam_unix.so 설정 없음")
            else:
                if "sha256" not in pam_line and "sha512" not in pam_line and "yescrypt" not in pam_line:
                    issues.append(f"{pam_file} 내 pam_unix.so에 안전한 알고리즘(sha256/sha512/yescrypt 등) 누락")
        

        status = "취약" if issues else "양호"
        self.report.print_result("U-13", "안전한 비밀번호 암호화 알고리즘 사용", status)
        
        return status


class FileDirectoryManagement:  # 파일 및 디렉토리 관리 
    def __init__(self, ssh_conn, report_mgr):
        self.conn = ssh_conn
        self.report = report_mgr

    def u_14(self): # root 홈, 패스 디렉터리 권한 및 패스 설정

        issues = []

        cmd = "echo $PATH"
        path_env = self.conn.execute_cmd(cmd).strip()

        if not path_env:
            issues.append("PATH 환경변수를 확인할 수 없습니다.")
        else:
            # PATH 환경변수를 콜론(:) 기준으로 분리하여 리스트로 만듭니다.
            # 예시: "/usr/local/bin:/usr/bin:." -> ['/usr/local/bin', '/usr/bin', '.']
            path_list = path_env.split(':')
            
            # 요소가 단 1개뿐인 특수한 경우 (예: PATH=".")
            if len(path_list) == 1:
                if path_list[0] == "." or path_list[0] == "":
                    issues.append(f"PATH 환경변수에 '.'(현재 디렉터리)이 단독으로 설정되어 있습니다. (현재: {path_env})")
            else:
                # 리스트의 '마지막 요소를 제외한' 부분(맨 앞 ~ 중간)만 검사 대상(target)으로 지정합니다.
                # 파이썬의 리스트 슬라이싱[:-1]을 활용하면 마지막 경로를 아주 쉽게 제외할 수 있습니다.
                target_elements = path_list[:-1]
                
                # 대상(맨 앞~중간)에 '.' 이나 빈 문자열("")이 포함되어 있는지 확인합니다.
                # 리눅스 PATH에서 :: 처럼 콜론이 두 번 연속되거나 맨 앞이 : 로 시작하면 빈 문자열("")로 인식되며, 이는 '.'과 완전히 동일하게 취급되어 매우 취약합니다.
                if "." in target_elements or "" in target_elements:
                    issues.append(f"PATH 환경변수 맨 앞 또는 중간에 '.'(현재 디렉터리)이 포함되어 있습니다. (현재: {path_env})")

        status = "취약" if issues else "양호"
        self.report.print_result("U-14", "root 홈, 패스 디렉터리 권한 및 패스 설정", status)
        
        return status

    def u_15(self):  # 파일 및 디렉터리 소유자 설정
        issues = []

        cmd = r"find /\( -nouser -o -nogroup \) -xdev -ls 2>/dev/null"
        orphan_files = self.conn.execute_cmd(cmd)

        if orphan_files:
            files_preview = orphan_files.replace('\n', ', ')
            issues.append(f"소유자 또는 그룹이 없는 파일/디렉터리 존재")

        status = "취약" if issues else "양호"
        self.report.print_result("U-15", "파일 및 디렉터리 소유자 설정", status)
        
        return status
        
    def u_16(self):  # /etc/passwd 파일 소유자 및 권한 설정

        issues = []
        target_file = "/etc/passwd"

        # stat 명령어를 사용하여 파일의 소유자 이름(%U)과 8진수 권한(%a)만 깔끔하게 추출합니다.
        cmd = f"stat -c '%U %a' {target_file} 2>/dev/null"  # 소유자와 권한만 출력된다.
        stat_result = self.conn.execute_cmd(cmd).strip()

        if not stat_result:
            issues.append(f"{target_file} 파일을 찾을 수 없거나 상태를 확인할 수 없습니다.")
        else:
            # 공백을 기준으로 소유자와 권한을 분리합니다.
            parts = stat_result.split()
            
            if len(parts) >= 2:
                owner = parts[0]
                perms = parts[1]

                # 1. 소유자 검사 (root인지 확인)
                if owner != "root":
                    issues.append(f"{target_file} 파일의 소유자가 root가 아님 (현재 소유자: {owner})")

                # 2. 권한 검사 (644 이하인지 확인)
                # 추출한 권한 문자열이 숫자로만 되어있는지 방어 로직 추가
                if perms.isdigit():
                    # 파이썬의 정수 비교를 활용하면 644 이하인지 아주 직관적으로 알 수 있습니다.
                    # (예: 600, 640은 644보다 작으므로 통과 / 664, 666, 777은 644보다 크므로 취약)
                    if int(perms) > 644:
                        issues.append(f"{target_file} 파일의 권한이 644보다 큼 (현재 권한: {perms})")
                else:
                    issues.append(f"권한 값을 숫자로 판별할 수 없습니다. (확인된 값: {perms})")

        # 3. 최종 결과 판별 및 출력
        status = "취약" if issues else "양호"
        self.report.print_result("U-16", "/etc/passwd 파일 소유자 및 권한 설정", status)
        
        return status

    def u_17(self):  # 시스템 시작 스크립트 권한 설정

        issues = []

        # 소유자가 root가 아님 (! --user root) or 일반 사용자(Other)에게 쓰기 권한이 있음(-perm -002)
        cmd = r"find /etc/rc.d /etc/init.d /etc/systemd/system -type f \( ! -user root -o -perm -002 \) 2>/dev/null | head -5"
        vulnerable_scripts = self.conn.execute_cmd(cmd).strip()

        if vulnerable_scripts:
            # 발견된 취약한 스크립트 파일들을 쉼표로 연결하여 보여줍니다.
            scripts_preview = vulnerable_scripts.replace('\n', ', ')
            issues.append(f"권한/소유자가 취약한 시작 스크립트 발견 (예시: {scripts_preview})")

        # 결과값이 있으면(취약한 파일이 하나라도 발견되면) 취약, 없으면 양호
        status = "취약" if issues else "양호"
        self.report.print_result("U-17", "시스템 시작 스크립트 권한 설정", status)
        
        return status

    def u_18(self):  # /etc/shadow 파일 소유자 및 권한 설정
        issues = []
        target_file = "/etc/shadow"

        cmd = f"stat -c '%U %a' {target_file} 2>/dev/null"
        stat_result = self.conn.execute_cmd(cmd).strip()

        if not stat_result:
            issues.append(f"{target_file} 파일을 찾을 수 없거나 상태를 확인할 수 없습니다.")
        else:
            parts = stat_result.split()
            
            if len(parts) >= 2:
                owner = parts[0]
                perms = parts[1]

                if owner != "root":
                    issues.append(f"{target_file} 파일의 소유자가 root가 아님 (현재 소유자: {owner})")

                if perms.isdigit():
                    if int(perms) > 400:
                        issues.append(f"{target_file} 파일의 권한이 400보다 큼 (현재 권한: {perms})")
                else:
                    issues.append(f"권한 값을 숫자로 판별할 수 없습니다. (확인된 값: {perms})")

        status = "취약" if issues else "양호"
        self.report.print_result("U-16", "/etc/passwd 파일 소유자 및 권한 설정", status)
        
        return status

    def u_19(self):  # /etc/hosts 파일 소유자 및 권한 설정
        issues = []
        target_file = "/etc/hosts"

        # stat 명령어를 사용하여 파일의 소유자 이름(%U)과 8진수 권한(%a)을 추출합니다.
        cmd = f"stat -c '%U %a' {target_file} 2>/dev/null"
        stat_result = self.conn.execute_cmd(cmd).strip()

        if not stat_result:
            issues.append(f"{target_file} 파일을 찾을 수 없거나 상태를 확인할 수 없습니다.")
        else:
            parts = stat_result.split()
            
            if len(parts) >= 2:
                owner = parts[0]
                perms = parts[1]

                # 1. 소유자 검사 (root인지 확인)
                if owner != "root":
                    issues.append(f"{target_file} 파일의 소유자가 root가 아님 (현재 소유자: {owner})")

                # 2. 권한 검사 (644 이하인지 확인 - U-16과 완벽히 동일!)
                if perms.isdigit():
                    if int(perms) > 644:
                        issues.append(f"{target_file} 파일의 권한이 644보다 큼 (현재 권한: {perms})")
                else:
                    issues.append(f"권한 값을 숫자로 판별할 수 없습니다. (확인된 값: {perms})")

        # 3. 최종 결과 판별 및 출력
        status = "취약" if issues else "양호"
        self.report.print_result("U-19", "/etc/hosts 파일 소유자 및 권한 설정", status)
        
        return status
    
    def u_20(self):  # /etc/(X)inetd.conf 파일 소유자 및 권한 설정
        issues = []
        
        # 가이드라인에 명시된 단일 파일들과 디렉터리들을 모두 타겟으로 지정합니다.
        targets = "/etc/inetd.conf /etc/xinetd.conf /etc/xinetd.d /etc/systemd/system.conf /etc/systemd"

        # find 명령어로 타겟 경로 내의 '모든 파일(-type f)'을 찾아 stat으로 경로, 소유자, 권한을 한 번에 뽑아냅니다.
        cmd = f"find {targets} -type f -exec stat -c '%n %U %a' {{}} + 2>/dev/null"
        result = self.conn.execute_cmd(cmd).strip()

        if not result:
            # 타겟 파일이나 폴더가 아예 없는 경우 (해당 서비스를 전혀 안 쓰는 상태) -> 안전하므로 넘어갑니다.
            pass
        else:
            lines = result.split('\n')
            vuln_files = []
            
            for line in lines:
                parts = line.strip().split()
                if len(parts) >= 3:
                    file_path = parts[0]
                    owner = parts[1]
                    perms = parts[2]

                    # 1. 소유자가 root가 아니거나, 2. 권한이 600보다 큰 경우를 모두 잡아냅니다.
                    if owner != "root" or (perms.isdigit() and int(perms) > 600):
                        vuln_files.append(f"{file_path}(소유자:{owner}, 권한:{perms})")

            # 취약한 파일이 발견된 경우
            if vuln_files:
                # systemd 폴더 안에는 파일이 수백 개 있을 수 있으므로, 터미널 도배 방지를 위해 딱 3개만 요약해서 보여줍니다.
                preview = ", ".join(vuln_files)
                issues.append(f"권한/소유자가 취약한 파일 발견 -> {preview}")

        # 최종 결과 판별 및 출력
        status = "취약" if issues else "양호"
        self.report.print_result("U-20", "/etc/(x)inetd.conf 파일 소유자 및 권한 설정", status)

        return status

    def u_21(self):  # /etc/(r)syslog.conf 파일 소유자 및 권한 설정
        issues = []
        
        # 검사 대상 파일 (구형 syslog 및 최신 rsyslog 설정 파일 모두 포함)
        targets = "/etc/syslog.conf /etc/rsyslog.conf"

        # stat 명령어로 존재하는 파일들의 경로, 소유자, 권한을 한 번에 추출합니다.
        cmd = f"stat -c '%n %U %a' {targets} 2>/dev/null"
        result = self.conn.execute_cmd(cmd).strip()

        if not result:
            # 두 파일 모두 존재하지 않으면 해당 로깅 데몬을 사용하지 않는 환경일 수 있습니다.
            pass
        else:
            lines = result.split('\n')
            
            # 가이드라인에 따른 양호 소유자 리스트
            allowed_owners = ["root", "bin", "sys"]
            
            for line in lines:
                parts = line.strip().split()
                if len(parts) >= 3:
                    file_path = parts[0]
                    owner = parts[1]
                    perms = parts[2]

                    # 1. 소유자 검사 (root, bin, sys 중 하나에 속하는지 파이썬의 'in'으로 직관적 확인)
                    if owner not in allowed_owners:
                        issues.append(f"{file_path} 파일의 소유자가 취약함 (현재 소유자: {owner})")

                    # 2. 권한 검사 (640 이하인지 확인)
                    if perms.isdigit():
                        if int(perms) > 640:
                            issues.append(f"{file_path} 파일의 권한이 640보다 큼 (현재 권한: {perms})")
                    else:
                        issues.append(f"{file_path} 권한 값을 숫자로 판별할 수 없습니다. (확인된 값: {perms})")

        # 3. 최종 결과 판별 및 출력
        status = "취약" if issues else "양호"
        self.report.print_result("U-21", "/etc/(r)syslog.conf 파일 소유자 및 권한 설정", status)
        
        return status

    def u_22(self):  # /etc/services 파일 소유자 및 권한 설정
        issues = []
        target_file = "/etc/services"

        # stat 명령어를 사용하여 파일의 소유자 이름(%U)과 8진수 권한(%a)을 추출합니다.
        cmd = f"stat -c '%U %a' {target_file} 2>/dev/null"
        stat_result = self.conn.execute_cmd(cmd).strip()

        if not stat_result:
            issues.append(f"{target_file} 파일을 찾을 수 없거나 상태를 확인할 수 없습니다.")
        else:
            parts = stat_result.split()
            
            if len(parts) >= 2:
                owner = parts[0]
                perms = parts[1]

                # 1. 소유자 검사 (root, bin, sys 중 하나에 속하는지 확인)
                allowed_owners = ["root", "bin", "sys"]
                if owner not in allowed_owners:
                    issues.append(f"{target_file} 파일의 소유자가 취약함 (현재 소유자: {owner})")

                # 2. 권한 검사 (644 이하인지 확인)
                if perms.isdigit():
                    if int(perms) > 644:
                        issues.append(f"{target_file} 파일의 권한이 644보다 큼 (현재 권한: {perms})")
                else:
                    issues.append(f"권한 값을 숫자로 판별할 수 없습니다. (확인된 값: {perms})")

        # 3. 최종 결과 판별 및 출력
        status = "취약" if issues else "양호"
        self.report.print_result("U-22", "/etc/services 파일 소유자 및 권한 설정", status)
        
        return status
    
    def u_23(self):  # SUID, SGID, Sticky bit 설정 파일 점검
        issues = []
        
        cmd = r"find / -xdev -user root -type f \( -perm -04000 -o -perm -02000 \) 2>/dev/null"
        result = self.conn.execute_cmd(cmd).strip()

        if result:
            files = result.split('\n')
            suspicious_files = []
            
            # 2. 오탐 방지: 정상적인 OS 시스템 파일들이 위치하는 '안전 구역(화이트리스트)'
            safe_paths = (
                '/bin/', '/sbin/', 
                '/usr/bin/', '/usr/sbin/', '/usr/lib/', '/usr/libexec/', 
                '/lib/', '/lib64/'
            )
            
            for file_path in files:
                file_path = file_path.strip()
                # 3. 발견된 파일이 '안전 구역' 밖에서 발견되었다면 해킹이 강력히 의심되므로 리스트에 추가합니다.
                if not file_path.startswith(safe_paths):
                    suspicious_files.append(file_path)
            
            # 안전 구역을 제외하고도 남은 파일이 있다면 취약으로 판정!
            if suspicious_files:
                preview = ", ".join(suspicious_files)
                issues.append(f"비표준 경로에 불필요한 SUID/SGID 파일 발견 -> {preview}")

        # 4. 최종 결과 판별 및 출력
        status = "취약" if issues else "양호"
        self.report.print_result("U-23", "SUID, SGID, Sticky bit 설정 파일 점검", status)
        
        return status

    def u_24(self):  # 사용자, 시스템 환경변수 파일 소유자 및 권한 설정
        issues = []
        
        # 1. /etc/passwd 파일에서 사용자 계정과 홈 디렉터리를 추출하고,
        # 2. 각 홈 디렉터리를 돌면서 가이드라인에 명시된 환경변수 파일들을 찾은 뒤,
        # 3. [파일경로] [소유자] [권한] [기준계정명] 형태로 한 번에 뽑아내는 원라이너(One-liner) 명령어입니다.
        cmd = (
            "awk -F: '$6 != \"\" && $6 != \"/\" {print $1, $6}' /etc/passwd | "
            "while read u d; do "
            "for f in .profile .kshrc .cshrc .bashrc .bash_profile .login .exrc .netrc; do "
            "if [ -f \"$d/$f\" ]; then echo $(stat -c '%n %U %a' \"$d/$f\" 2>/dev/null) $u; fi; "
            "done; done"
        )
        result = self.conn.execute_cmd(cmd).strip()

        vuln_files = []

        if result:
            for line in result.split('\n'):
                parts = line.strip().split()
                # 정상적으로 4개의 값이 모두 출력되었는지 확인합니다.
                if len(parts) >= 4:
                    file_path = parts[0]
                    owner = parts[1]
                    perms = parts[2]
                    expected_user = parts[3] # 이 홈 디렉터리의 실제 주인(계정명)

                    is_vuln = False
                    reason = ""

                    # 조건 1: 소유자가 root 또는 해당 계정(expected_user)이 아닌 경우 취약
                    if owner != "root" and owner != expected_user:
                        is_vuln = True
                        reason = f"잘못된 소유자({owner})"

                    # 조건 2: root 계정과 소유자 외에 쓰기(w) 권한이 부여된 경우 취약[cite: 1]
                    # 권한 문자열(예: 644)의 뒤에서 두 번째(그룹), 첫 번째(기타) 숫자를 비트 연산으로 확인하여 쓰기(w=2)가 있는지 판별합니다.
                    elif perms.isdigit() and len(perms) >= 3:
                        group_perm = int(perms[-2])
                        others_perm = int(perms[-1])

                        if (group_perm & 2) or (others_perm & 2):
                            is_vuln = True
                            reason = f"불필요한 쓰기 권한 부여({perms})"

                    # 취약점이 발견되면 리스트에 추가합니다.
                    if is_vuln:
                        vuln_files.append(f"{file_path} [{reason}]")

        # 4. 최종 결과 판별 및 출력
        if vuln_files:
            # 터미널이 너무 지저분해지는 것을 막기 위해 3개까지만 요약해서 보여줍니다.
            preview = ", ".join(vuln_files)
            issues.append(f"취약한 환경변수 파일 발견 -> {preview}")

        status = "취약" if issues else "양호"
        self.report.print_result("U-24", "사용자, 시스템 환경변수 파일 소유자 및 권한 설정", status)
        
        return status

    # def u_25(self):  # world writable 파일 점검 설정 (양호 판단기준이 파일 존재시 설정이유를 인지하고있으면, 없으면 취약)
    
    def u_26(self):  # /dev에 존재하지 않는 device 파일 점검 
        issues = []

        # /dev 디렉터리 내에 숨겨진 일반 파일(-type f)을 모두 찾습니다.
        cmd = "find /dev -type f 2>/dev/null"
        result = self.conn.execute_cmd(cmd).strip()

        if result:
            files = result.split('\n')
            suspicious_files = []
            
            for file_path in files:
                file_path = file_path.strip()
                
                # 가이드라인 예외 처리: mqueue, shm 경로에 있는 파일은 정상적인 시스템 파일이므로 무시합니다.[cite: 1]
                if "mqueue" in file_path or "shm" in file_path:
                    continue
                    
                # 예외가 아닌데 일반 파일이 발견되었다면 해킹(루트킷)이 의심되므로 리스트에 담습니다.
                suspicious_files.append(file_path)
            
            # 필터링 후에도 의심스러운 파일이 남아있다면 '취약'으로 판정합니다.
            if suspicious_files:
                preview = ", ".join(suspicious_files)
                issues.append(f"/dev 경로에 악성코드 위장 의심 파일 발견 -> {preview}")

        # 최종 결과 판별 및 출력 (의심 파일이 없으면 양호!)
        status = "취약" if issues else "양호"
        self.report.print_result("U-26", "/dev에 존재하지 않는 device 파일 점검", status)
        
        return status

    def u_27(self):  #  $HOME/.rhosts, hosts.equiv 사용 금지
        issues = []

        # 1. /etc/hosts.equiv 파일과 모든 사용자의 ~/.rhosts 파일을 찾아 3가지 기준을 한 번에 검사합니다.
        # 출력 형식: [파일경로] [소유자] [권한] [기준계정명] [+(플러스)존재여부: + 또는 -]
        cmd = (
            "f='/etc/hosts.equiv'; if [ -f \"$f\" ]; then "
            "echo \"$f $(stat -c '%U %a' \"$f\") root $(grep -q '+' \"$f\" && echo '+' || echo '-')\"; fi; "
            "awk -F: '$6 != \"\" && $6 != \"/\" {print $1, $6}' /etc/passwd | while read u d; do "
            "f=\"$d/.rhosts\"; if [ -f \"$f\" ]; then "
            "echo \"$f $(stat -c '%U %a' \"$f\" 2>/dev/null) $u $(grep -q '+' \"$f\" 2>/dev/null && echo '+' || echo '-')\"; fi; "
            "done"
        )

        """
        f='/etc/hosts.equiv'; 파일 경로를 f변수에 저장
        if [ -f "$f" ]; then  해당파일이 존재한다면 (-f) : 아래 내용을 실행하라
            echo "$f $(stat -c '%U %a' "$f") root $(grep -q '+' "$f" && echo '+' || echo '-')"; 파일의 정상적인 소유자는 무조건 root 
        fi;  (-q) 몰래 +기호가 있는지 찾는다 찾으면 + 출력, 못찾으면 - 출력

        awk -F: '$6 != "" && $6 != "/" {print $1, $6}' /etc/passwd |    시스템의 모든계정정보 /etc/passwd를 : 기준으로 분리, 6번째칸 비어있지 않고 일반사용자들만 1번째, 6번째칸을 출력
        while read u d; do      앞에서 실행한 명령어로 u에 계정명 d에 경로를 저장
            f="$d/.rhosts";     경로 뒤에 .rhosts를 붙여서 f에 저장
            if [ -f "$f" ]; then        
                echo "$f $(stat -c '%U %a' "$f" 2>/dev/null) $u $(grep -q '+' "$f" 2>/dev/null && echo '+' || echo '-')";   기존 계정명 자리에 root대신 u(계정명)를 넣어서 출력한다.
            fi; 
        done

        """
        # 서버에서 명령어를 실행하고 결과를 가져옵니다.
        result = self.conn.execute_cmd(cmd).strip()

        # 결과가 비어있다면 파일이 아예 존재하지 않는 것이므로 가장 안전한 '양호' 상태입니다.
        if result:
            for line in result.split('\n'):
                parts = line.strip().split()
                # 5개의 정보가 정상적으로 출력되었는지 확인합니다.
                if len(parts) >= 5:
                    file_path = parts[0]
                    owner = parts[1]
                    perms = parts[2]
                    expected_user = parts[3]
                    has_plus = parts[4]

                    is_vuln = False  # 이 파일이 취약한가?의 줄임말
                    reason = []

                    # 조건 1: 소유자가 root 또는 해당 계정이 아닌 경우
                    if owner != "root" and owner != expected_user:
                        is_vuln = True
                        reason.append(f"소유자 불일치({owner})")

                    # 조건 2: 권한이 600을 초과한 경우
                    if perms.isdigit() and int(perms) > 600:
                        is_vuln = True
                        reason.append(f"과도한 권한({perms})")

                    # 조건 3: 파일 내에 '+' 설정이 존재하는 경우 (가장 위험!)
                    if has_plus == '+':
                        is_vuln = True
                        reason.append("'+' 설정 존재")

                    # 3가지 조건 중 하나라도 걸리면 취약 리스트에 추가합니다.
                    if is_vuln:
                        # 여러 개의 이유가 있을 수 있으므로 쉼표로 묶어서 예쁘게 출력합니다.
                        issues.append(f"{file_path} [{', '.join(reason)}]")

        # 최종 결과 판별 및 출력
        status = "취약" if issues else "양호"
        self.report.print_result("U-27", "$HOME/.rhosts, hosts.equiv 사용 금지", status)
        
        return status

    def u_28(self):  #  접속 IP 및 포트 제한
        issues = []
        is_safe = False
        active_firewalls = []

        # 1. TCP Wrapper 점검 (/etc/hosts.deny 파일 확인)
        # 주석('#')을 제외하고 ALL:ALL 설정이 들어있는지 확인합니다.
        cmd_tcp_wrapper = "grep -v '^#' /etc/hosts.deny 2>/dev/null | grep -i 'ALL: ALL'"
        if self.conn.execute_cmd(cmd_tcp_wrapper).strip():
            is_safe = True
            active_firewalls.append("TCP Wrapper (hosts.deny 적용됨)")

        # 2. Firewalld 점검 (Rocky Linux 8 이상 기본 방화벽)
        cmd_firewalld = "systemctl is-active firewalld 2>/dev/null"  # 방화벽이 꺼져있으면 에러가나고, 켜져있어도 텍스트가 나와 원하는 정보 필터링하기 힘들다. 살아있 => active / 죽어있 => inactice
        if self.conn.execute_cmd(cmd_firewalld).strip() == "active":
            is_safe = True
            active_firewalls.append("Firewalld")

        # 3. UFW 점검 (Ubuntu 기본 방화벽)
        cmd_ufw = "ufw status 2>/dev/null | grep -w 'active'"
        if self.conn.execute_cmd(cmd_ufw).strip():
            is_safe = True
            active_firewalls.append("UFW")

        # 4. Iptables 점검 (전통적인 리눅스 방화벽)
        # INPUT 체인에 기본 제목(Chain, target 등)을 제외한 실제 방화벽 룰이 존재하는지 개수를 셉니다.
        cmd_iptables = "iptables -L INPUT -n 2>/dev/null | grep -v 'Chain' | grep -v 'target' | grep '[a-zA-Z0-9]' | wc -l"  # 쓸데없는 제목 줄을 전부 걸러낸뒤 -v : 해당문자가진 문자열 제거, 등록된 규칙이 존재하는지 카운트 
        iptables_count = self.conn.execute_cmd(cmd_iptables).strip()
        if iptables_count.isdigit() and int(iptables_count) > 0:
            is_safe = True
            active_firewalls.append("Iptables (접근 제어 룰 존재)")

        # 5. 최종 결과 판별
        if is_safe:
            status = "양호"
        else:
            status = "취약"
            issues.append("TCP Wrapper, Firewalld, UFW, Iptables 등 어떠한 접근 제어 설정도 활성화되지 않음")

        self.report.print_result("U-28", "접속 IP 및 포트 제한", status)
        
        return status

    def u_29(self):  #  hosts.lpd 파일 소유자 및 권한 설정
        issues = []
        target_file = "/etc/hosts.lpd"

        # stat 명령어로 소유자(%U)와 8진수 권한(%a)을 한 번에 추출합니다.
        cmd = f"stat -c '%U %a' {target_file} 2>/dev/null"
        stat_result = self.conn.execute_cmd(cmd).strip()

        if not stat_result:
            # 명령어 실행 결과가 없으면 파일이 존재하지 않는 것이며,
            # 가이드라인에 따라 이는 완벽한 '양호' 상태이므로 아무 작업도 하지 않고 넘어갑니다.
            pass
        else:
            parts = stat_result.split()
            
            if len(parts) >= 2:
                owner = parts[0]
                perms = parts[1]

                # 1. 소유자 검사 (root인지 확인)
                if owner != "root":
                    issues.append(f"{target_file} 파일의 소유자가 root가 아님 (현재 소유자: {owner})")

                # 2. 권한 검사 (600 이하인지 확인)
                if perms.isdigit():
                    if int(perms) > 600:
                        issues.append(f"{target_file} 파일의 권한이 600보다 큼 (현재 권한: {perms})")
                else:
                    issues.append(f"권한 값을 숫자로 판별할 수 없습니다. (확인된 값: {perms})")

        # 3. 최종 결과 판별 및 출력
        # issues 리스트에 에러 메시지가 하나라도 담겨있으면 '취약', 비어있으면 '양호'로 판정합니다.
        status = "취약" if issues else "양호"
        self.report.print_result("U-29", "hosts.lpd 파일 소유자 및 권한 설정", status)
        
        return status

    def u_30(self):  #  UMASK 설정 관리
        issues = []

        # 1. /etc/login.defs 파일 점검 (주석이 아닌 대소문자 구분 없는 umask 설정 추출)
        cmd_login = "grep -i '^umask' /etc/login.defs 2>/dev/null | awk '{print $2}'"  # 대소문자를 무시하고 검색, '^' 맨처음에 해당 문자가있는것
        login_umasks = self.conn.execute_cmd(cmd_login).strip().split('\n')

        # 2. /etc/profile 파일 점검 (앞에 공백이 있는 경우도 꼼꼼하게 잡아내기 위해 정규표현식 사용)
        cmd_profile = "grep -iE '^[[:space:]]*umask' /etc/profile 2>/dev/null | awk '{print $2}'"  # 대소문자 무시 + 확장 정규표현식 사용(띄어쓰기 대비), '*' 0개 이상 반복됨(공백노상관)
        profile_umasks = self.conn.execute_cmd(cmd_profile).strip().split('\n')

        # UMASK 값을 8진수로 변환하여 022(8진수) 이상인지 비교하는 내부 함수
        def check_umask(umask_str, file_name):
            if not umask_str:
                return
                
            # isdigit()을 사용하여 문자열이 숫자(0~9)로만 이루어져 있는지 사전에 검증합니다.
            if umask_str.isdigit():
                # 정상적인 숫자라면 8진수로 변환하여 크기 비교 진행
                if int(umask_str, 8) < int('022', 8):  # 022가 8진수니까 10진수로 변환해서 비교
                    issues.append(f"{file_name} 파일 내 UMASK 값이 취약함 (현재 설정값: {umask_str})")
            else:
                # 만약 숫자가 아닌 값(예: 쉘 변수 등)이 들어있을 경우 수동 점검을 유도합니다.
                issues.append(f"{file_name} 파일 내 UMASK 값을 숫자로 판별할 수 없음 (수동 확인 필요: {umask_str})")

        # 추출된 각 설정값들을 하나씩 검사 로직에 통과시킵니다.
        for u in login_umasks:
            if u: check_umask(u, "/etc/login.defs")

        for u in profile_umasks:
            if u: check_umask(u, "/etc/profile")

        # 만약 두 파일 모두에서 UMASK 설정이 단 한 줄도 발견되지 않았다면
        # 시스템 기본값에 의존하는 상태이므로 수동 점검을 유도합니다.
        if not any(login_umasks) and not any(profile_umasks):  # any() : 리스트 안에 값이 있으면 True반환 없으면 False
            issues.append("/etc/login.defs 및 /etc/profile에 UMASK 설정이 존재하지 않음")

        # 3. 최종 결과 판별 및 출력
        status = "취약" if issues else "양호"
        self.report.print_result("U-30", "UMASK 설정 관리", status)
        
        return status

    def u_31(self):  #  홈 디렉토리 소유자 및 권한 설정
        issues = []

        # [명령어 동작 원리]
        # 1. awk로 /etc/passwd를 읽어 홈 디렉터리가 존재하는 계정명($1)과 경로($6)를 추출합니다.
        # 2. while 루프로 한 줄씩 읽으면서 해당 경로가 실제 디렉터리(-d)인지 확인합니다.
        # 3. stat 명령어로 [홈디렉터리경로] [실제소유자] [8진수ㅔ권한] [기준계정명] 형태로 출력합니다.
        cmd = (
            "awk -F: '$6 != \"\" && $6 != \"/\" {print $1, $6}' /etc/passwd | "
            "while read u d; do "
            "if [ -d \"$d\" ]; then "
            "echo \"$d $(stat -c '%U %a' \"$d\" 2>/dev/null) $u\"; "
            "fi; "
            "done"
        )
        
        result = self.conn.execute_cmd(cmd).strip()

        vuln_dirs = []

        if result:
            for line in result.split('\n'):
                parts = line.strip().split()
                # 정상적으로 4개의 데이터(경로, 소유자, 권한, 계정명)가 출력되었는지 확인합니다.
                if len(parts) >= 4:
                    dir_path = parts[0]
                    owner = parts[1]
                    perms = parts[2]
                    expected_user = parts[3]

                    is_vuln = False
                    reason = []

                    # 조건 1: 홈 디렉터리의 소유자가 해당 계정(expected_user)과 일치하지 않는 경우
                    if owner != expected_user:
                        is_vuln = True
                        reason.append(f"소유자 불일치({owner})")

                    # 조건 2: 타 사용자에게 쓰기(w) 권한이 부여된 경우
                    # isdigit()으로 권한이 정상적인 숫자인지 확인한 후, 비트 연산(& 2)으로 쓰기 권한을 검사합니다.
                    if perms.isdigit() and len(perms) >= 3:
                        group_perm = int(perms[-2])  # 그룹 사용자 권한
                        others_perm = int(perms[-1]) # 기타 사용자 권한

                        if (group_perm & 2) or (others_perm & 2):  # 비트 연산자 
                            is_vuln = True
                            reason.append(f"타 사용자 쓰기 권한 부여({perms})")

                    # 취약점이 발견되면 이유와 함께 리스트에 저장합니다.
                    if is_vuln:
                        vuln_dirs.append(f"{dir_path} [{', '.join(reason)}]")

        # 4. 최종 결과 판별 및 출력
        if vuln_dirs:
            # 터미널 창 보호를 위해 취약한 디렉터리가 많더라도 최대 3개까지만 요약해서 출력합니다.
            preview = ", ".join(vuln_dirs)
            issues.append(f"취약한 홈 디렉터리 발견 -> {preview}")

        status = "취약" if issues else "양호"
        self.report.print_result("U-31", "홈디렉토리 소유자 및 권한 설정", status)
        
        return status

    def u_32(self):  #  홈 디렉토리로 지정한 디렉토리의 존재 관리
        issues = []

        # [명령어 동작 원리]
        # 1. awk로 /etc/passwd를 읽어 홈 디렉터리가 지정된 계정명($1)과 경로($6)를 추출합니다.
        # 2. while 루프로 한 줄씩 읽습니다.
        # 3. 이번에는 [ -d "$d" ](존재하는가?) 대신 [ ! -d "$d" ](존재하지 않는가?)를 사용하여 
        #    실제 물리적으로 없는 디렉터리만 찾아내어 출력합니다.
        cmd = (
            "awk -F: '$6 != \"\" {print $1, $6}' /etc/passwd | "
            "while read u d; do "
            "if [ ! -d \"$d\" ]; then "  # admin(root) 디렉터리가 없으면 참
            "echo \"$u $d\"; "
            "fi; "
            "done"
        )
        
        result = self.conn.execute_cmd(cmd).strip()

        if result:
            for line in result.split('\n'):
                parts = line.strip().split()
                # 계정명과 디렉터리 경로, 딱 2개의 데이터가 제대로 들어왔는지 사전에 검증합니다. 
                if len(parts) >= 2:
                    user = parts[0]
                    home_dir = parts[1]
                    
                    # 실무 팁: 리눅스의 기본 시스템(데몬) 계정 중 'nobody' 등은 
                    # 보안을 위해 의도적으로 홈 디렉터리를 생성하지 않는 경우가 있습니다.
                    # 하지만 가이드라인의 원칙에 따라 존재하지 않는다면 일단 취약으로 판정합니다.
                    issues.append(f"'{user}' 계정의 홈 디렉터리({home_dir})가 시스템에 존재하지 않음")

        # 4. 최종 결과 판별 및 출력
        # 홈 디렉터리가 존재하지 않는 계정이 단 하나라도 발견되면 '취약'으로 판정합니다.
        status = "취약" if issues else "양호"
        self.report.print_result("U-32", "홈 디렉토리로 지정한 디렉토리의 존재 관리", status)
        
        return status

    # def u_33(self):  #  숨겨진 파일 및 디렉토리 검색 및 제거

class ServiceManagement:  # 서비스 관리 
    def __init__(self, ssh_conn, report_mgr):
            # SSHConnection 객체를 전달받아 내부에서 사용
            self.conn = ssh_conn
            self.report = report_mgr

    # def u_34(self):  # Finger 서비스 비활성화 (해당 X)

    def u_35(self):  # 공유 서비스에 대한 익명 접근 제한 설정
        issues = []

        # 1. 기본 FTP 계정 점검
        # /etc/passwd에서 ftp 또는 anonymous 계정이 존재하는지 확인합니다.
        cmd_ftp_acc = "awk -F: '$1==\"ftp\" || $1==\"anonymous\" {print $1}' /etc/passwd" 
        ftp_acc = self.conn.execute_cmd(cmd_ftp_acc).strip().split('\n')
        for acc in ftp_acc:
            if acc:
                issues.append(f"시스템에 익명 FTP 계정 활성화됨 (계정명: {acc})")

        # 2. vsFTP 서비스 점검
        # 주석(#)이 아닌 줄에서 anonymous_enable 설정이 YES로 되어 있는지 확인합니다.
        cmd_vsftp = "grep -iE '^[[:space:]]*anonymous_enable[[:space:]]*=[[:space:]]*yes' /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null"
        if self.conn.execute_cmd(cmd_vsftp).strip():
            issues.append("vsFTP 서비스에서 익명 접근(anonymous_enable=YES)이 허용됨")

        # 3. ProFTP 서비스 점검
        # 주석 처리가 안 된 <Anonymous ~ftp> 블록이 활성화되어 있는지 확인합니다.
        cmd_proftp = "grep -iE '^[[:space:]]*<Anonymous' /etc/proftpd.conf /etc/proftpd/proftpd.conf 2>/dev/null"
        if self.conn.execute_cmd(cmd_proftp).strip():
            issues.append("ProFTP 서비스에서 익명 접근(<Anonymous> 블록)이 허용됨")

        # 4. NFS 서비스 점검
        # /etc/exports 파일에서 주석을 제외(grep -v)하고, anonuid 또는 anongid 설정이 있는지 확인합니다.
        cmd_nfs = "grep -vE '^[[:space:]]*#' /etc/exports 2>/dev/null | grep -iE 'anonuid|anongid'"
        if self.conn.execute_cmd(cmd_nfs).strip():
            issues.append("NFS 서비스(/etc/exports)에서 익명 접근(anonuid/anongid)이 허용됨")

        # 5. Samba 서비스 점검
        # /etc/samba/smb.conf 파일에서 주석을 제외하고 guest ok = yes 인지 확인합니다.
        cmd_samba = "grep -vE '^[[:space:]]*#' /etc/samba/smb.conf 2>/dev/null | grep -iE 'guest ok[[:space:]]*=[[:space:]]*yes'"
        if self.conn.execute_cmd(cmd_samba).strip():
            issues.append("Samba 서비스(/etc/samba/smb.conf)에서 익명 접근(guest ok = yes)이 허용됨")

        # 6. 최종 결과 판별
        # 5가지 검사 중 하나라도 걸리면 취약, 아무것도 걸리지 않으면(서비스를 안 쓰거나 잘 막아둔 경우) 양호
        status = "취약" if issues else "양호"
        self.report.print_result("U-35", "공유 서비스에 대한 익명 접근 제한 설정", status)
        
        return status

    def u_36(self):  # r 계열 서비스 비활성화
        issues = []

        # 1. 과거 환경 (inetd) 점검
        # /etc/inetd.conf 파일에서 주석(#)을 제외하고 rlogin, rsh, rexec 문자열이 존재하는지 확인합니다.
        cmd_inetd = "grep -vE '^[[:space:]]*#' /etc/inetd.conf 2>/dev/null | grep -iE 'rlogin|rsh|rexec'"
        if self.conn.execute_cmd(cmd_inetd).strip():
            issues.append("inetd 환경에서 r 계열 서비스(rlogin/rsh/rexec)가 활성화되어 있음")

        # 2. 과도기 환경 (xinetd) 점검
        # /etc/xinetd.d/ 디렉터리 하위의 rlogin, rsh, rexec 설정 파일에서 disable = no 로 설정되어 있는지 확인합니다.
        # (disable = yes 가 안전한 상태이며, 파일이 없으면 안전한 것으로 간주합니다)
        cmd_xinetd = "grep -iE '^[[:space:]]*disable[[:space:]]*=[[:space:]]*no' /etc/xinetd.d/rlogin /etc/xinetd.d/rsh /etc/xinetd.d/rexec 2>/dev/null"
        if self.conn.execute_cmd(cmd_xinetd).strip():
            issues.append("xinetd 환경에서 r 계열 서비스가 활성화(disable=no)되어 있음")

        # 3. 최신 환경 (systemd) 점검
        # 현재 '실행 중(active)'인 서비스와 소켓 목록 중에서 rlogin, rsh, rexec 이름이 들어간 것을 뽑아냅니다.
        # 가이드라인의 명령어를 스크립트에 맞게 오탐이 없도록 최적화했습니다.
        cmd_systemd = "systemctl list-units --type=service --type=socket --state=active 2>/dev/null | grep -iE 'rlogin|rsh|rexec'"
        if self.conn.execute_cmd(cmd_systemd).strip():
            issues.append("systemd 환경에서 r 계열 서비스(또는 소켓)가 실행 중(active)임")

        # 4. 최종 결과 판별
        # 3가지 환경 중 어디에서든 활성화된 흔적이 발견되면 취약 처리합니다.
        status = "취약" if issues else "양호"
        self.report.print_result("U-36", "r 계열 서비스 비활성화", status)
        
        return status

    def u_37(self):  # crontab 설정파일 권한 설정 미흡
        issues = []

        # 가이드라인에 명시된 주요 명령어 및 설정/작업 파일 경로를 모두 포함합니다.
        target_paths = (
            "/usr/bin/crontab /usr/bin/at /etc/crontab /etc/cron.allow /etc/cron.deny "
            "/etc/at.allow /etc/at.deny /etc/cron.hourly /etc/cron.daily "
            "/etc/cron.weekly /etc/cron.monthly /etc/cron.d /var/spool/cron /var/spool/at"
        )

        # find 명령어로 존재하는 파일(-type f)만 골라내어, stat 명령어에 넘겨 한 번에 정보를 추출합니다.
        # 출력 형태: [경로] [소유자] [8진수 권한] (예: /etc/crontab root 644)
        cmd = f"find {target_paths} -type f -exec stat -c '%n %U %a' {{}} + 2>/dev/null"
        result = self.conn.execute_cmd(cmd).strip()

        # 권한을 한 자리씩 엄격하게 비교하는 내부 함수
        def is_permission_vuln(current_perm, max_perm):
            if not current_perm.isdigit():
                return False
                
            # '755' -> '0755', '640' -> '0640' 형태로 빈자리를 0으로 채워 무조건 4자리(특수권한 포함)로 맞춥니다.
            cur = current_perm.zfill(4)  # .zfill() : 문자열 왼쪽에 0을 채워 지정한 길이로 만들어주는 메서드
            mx = max_perm.zfill(4)
            
            # 각 자리수(특수권한, 소유자, 그룹, 기타사용자)별로 허용된 최대 권한을 초과하는지 검사합니다.
            for i in range(4):
                if int(cur[i]) > int(mx[i]):
                    return True  
            return False   # True: 취약 / False: 양호

        if result:
            for line in result.split('\n'):
                parts = line.strip().split()
                
                # 정상적으로 경로, 소유자, 권한 3가지 데이터가 파싱되었는지 확인합니다.
                if len(parts) >= 3:
                    filepath = parts[0]
                    owner = parts[1]
                    perms = parts[2]

                    # 1. 명령어 파일 검사 분기 (crontab, at) -> 기준: root 소유, 750 이하
                    if filepath in ["/usr/bin/crontab", "/usr/bin/at"]:
                        is_vuln = False
                        reason = []
                        
                        # 명령어 파일의 소유자가 root인지 검사합니다.
                        if owner != "root":
                            is_vuln = True
                            reason.append(f"소유자 불일치({owner})")
                            
                        # 명령어 파일의 권한이 750 이하(SUID 없음, 일반사용자 권한 0)인지 검사합니다.
                        if is_permission_vuln(perms, "0750"):
                            is_vuln = True
                            reason.append(f"권한 초과({perms}, 기준 750 이하)")
                            
                        if is_vuln:
                            issues.append(f"명령어 파일({filepath}) 취약 [{', '.join(reason)}]")
                    
                    # 2. 일반 설정 및 스풀 파일 검사 분기 -> 기준: root 소유, 640 이하
                    else:
                        is_vuln = False
                        reason = []
                        
                        # 설정 파일의 소유자가 root인지 검사합니다.
                        if owner != "root":
                            is_vuln = True
                            reason.append(f"소유자 불일치({owner})")
                        
                        # 설정 파일의 권한이 640 이하인지 검사합니다.
                        if is_permission_vuln(perms, "0640"):
                            is_vuln = True
                            reason.append(f"권한 초과({perms}, 기준 640 이하)")
                            
                        if is_vuln:
                            issues.append(f"설정 파일({filepath}) 취약 [{', '.join(reason)}]")

        # 3. 최종 결과 판별 및 출력
        if issues:
            status = "취약"
        else:
            status = "양호"
            
        self.report.print_result("U-37", "crontab 설정파일 권한 설정 미흡", status)
        
        return status

    def u_38(self):  # DoS 공격에 취약한 서비스 비활성화 설정 (NTP, DNS, SNMP, SMTP 서비스들을 사용하기 때문에 제외)
        issues = []

        # 점검할 서비스 목록을 변수로 분리하고, 요청하신 서비스들을 제외했습니다.
        target_services = "echo|discard|daytime|chargen"

        # 1. 과거 환경 (inetd) 점검
        # 주석 처리되지 않은 활성 라인 중 타겟 서비스가 있는지 단어 단위(-w)로 확인합니다.
        cmd_inetd = f"grep -vE '^[[:space:]]*#' /etc/inetd.conf 2>/dev/null | grep -iwE '{target_services}'"  # -w 정확히 하나의 단어로 떨어지는 문자만 / -v 지정한 문자열이 포함된 줄을 제외(반전)하고 출력
        if self.conn.execute_cmd(cmd_inetd).strip():
            issues.append("inetd 환경에서 DoS 취약 서비스(echo/discard/daytime/chargen)가 활성화되어 있음")

        # 2. 과도기 환경 (xinetd) 점검
        # 대상이 되는 4개의 xinetd 설정 파일만 콕 집어서 disable = no 로 켜져 있는지 확인합니다.
        cmd_xinetd = (
            "grep -iE '^[[:space:]]*disable[[:space:]]*=[[:space:]]*no' "
            "/etc/xinetd.d/echo /etc/xinetd.d/discard /etc/xinetd.d/daytime /etc/xinetd.d/chargen 2>/dev/null"
        )
        if self.conn.execute_cmd(cmd_xinetd).strip():
            issues.append("xinetd 환경에서 DoS 취약 서비스가 활성화(disable=no)되어 있음")

        # 3. 최신 환경 (systemd) 점검
        # 현재 활성화(active)된 서비스와 소켓 목록에서 타겟 서비스 4개만 필터링합니다.
        cmd_systemd = f"systemctl list-units --type=service --type=socket --state=active 2>/dev/null | grep -iwE '{target_services}'"
        if self.conn.execute_cmd(cmd_systemd).strip():
            issues.append("systemd 환경에서 DoS 취약 서비스(또는 소켓)가 실행 중(active)임")

        # 4. 최종 결과 판별 및 출력
        if issues:
            status = "취약" 
        else:
            status = "양호"
            
        self.report.print_result("U-38", "DoS 공격에 취약한 서비스 비활성화", status)
        
        return status

    def u_39(self):  # 불필요한 NFS 서비스 비활성화 설정 / 이거 사용하는지 물어보고 필요없으면 삭제
        issues = []

        # 1. 최신 리눅스 환경 (systemd) 점검
        # 오탐 방지를 위해 --state=active로 현재 실행 중인 것만 필터링합니다.
        # CentOS/Rocky 계열(nfs-server) 및 Ubuntu 계열(nfs-kernel-server) 서비스명을 모두 포괄하는 정규식을 사용합니다.
        cmd_systemd = "systemctl list-units --type=service --state=active 2>/dev/null | grep -iE 'nfs-server|nfs-kernel-server|nfs\\.service'"
        systemd_result = self.conn.execute_cmd(cmd_systemd).strip()

        if systemd_result:
            for line in systemd_result.split('\n'):
                parts = line.strip().split()
                if parts:
                    service_name = parts[0]
                    issues.append(f"systemd 환경: NFS 관련 서비스({service_name})가 활성화되어 있습니다.")

        # 3. 최종 결과 판별 및 출력
        if issues:
            status = "취약"
        else:
            status = "양호"
            
        self.report.print_result("U-39", "불필요한 NFS 서비스 비활성화", status)
        
        return status
        
    def u_40(self):  # NFS 접근 통제 설정
        issues = []
        target_file = "/etc/exports"

        # 1. 파일 권한 및 소유자 확인
        cmd_stat = f"stat -c '%U %a' {target_file} 2>/dev/null"
        stat_result = self.conn.execute_cmd(cmd_stat).strip()

        # 권한을 한 자리씩 엄격하게 비교하는 내부 함수 (U-37 재활용)
        def is_permission_vuln(current_perm, max_perm):
            if not current_perm.isdigit():
                return False
            cur = current_perm.zfill(4)
            mx = max_perm.zfill(4)
            for i in range(4):
                if int(cur[i]) > int(mx[i]):
                    return True
            return False

        if stat_result:
            parts = stat_result.split()
            if len(parts) >= 2:
                owner = parts[0]
                perms = parts[1]

                # 소유자가 root인지 확인합니다.
                if owner != "root":
                    issues.append(f"{target_file} 소유자가 root가 아님 (현재: {owner})")
                
                # 파일 권한이 644 이하인지 확인합니다.
                if is_permission_vuln(perms, "0644"):
                    issues.append(f"{target_file} 권한이 644를 초과함 (현재: {perms})")
        else:
            # 파일이 아예 존재하지 않는다면 NFS를 사용하지 않는 것이므로 안전하다고 간주합니다.
            pass

        # 2. NFS 접근 통제(공유 설정) 취약 여부 점검
        # 주석(#)이 제외된 활성화된 설정 내용만 가져옵니다.
        cmd_exports = f"grep -vE '^[[:space:]]*#' {target_file} 2>/dev/null"
        exports_result = self.conn.execute_cmd(cmd_exports).strip()

        if exports_result:
            for line in exports_result.split('\n'):
                parts = line.strip().split()
                
                # 파일 내에 설정이 존재할 경우 (ex: /home/share *(rw,sync))
                if len(parts) > 1:
                    # parts[0]은 공유할 디렉터리 경로이므로 제외하고, parts[1]부터인 호스트 설정 부분을 검사합니다.
                    for host_config in parts[1:]:
                        # 호스트 설정이 '*' 로 시작한다면 모든 IP의 접근을 허용하는 매우 취약한 상태입니다.
                        if host_config.startswith('*'):
                            issues.append(f"NFS 접근 통제 미흡 (모든 호스트 '*' 허용): {line.strip()}")
                            break

        # 3. 최종 결과 판별 및 출력
        if issues:
            status = "취약"
        else:
            status = "양호"
            
        self.report.print_result("U-40", "NFS 접근 통제", status)
        
        return status

    def u_41(self):  # 불필요한 automountd 제거 설정 (NFS 및 삼바 서비스 사용시 automountd 사용여부 확인)
        issues = []

        # 최신 리눅스 서비스 관리자인 systemd에서 상태가 'active'인 서비스만 필터링합니다.
        cmd_systemd = "systemctl list-units --type=service --state=active 2>/dev/null | grep -iE 'automount|autofs'"
        systemd_result = self.conn.execute_cmd(cmd_systemd).strip()

        if systemd_result:
            for line in systemd_result.split('\n'):
                parts = line.strip().split()
                if parts:
                    service_name = parts[0]
                    # 발견된 서비스의 이름을 추출하여 취약 리스트에 추가합니다.
                    issues.append(f"automount 관련 데몬({service_name})이 활성화되어 실행 중입니다.")

        if issues:
            status = "취약"
        else:
            status = "양호"
            
        self.report.print_result("U-41", "불필요한 automountd 제거", status)
        
        return status
    
    def u_42(self):  # 불필요한 RPC 서비스 비활성화 
        issues = []

        # rpc.* 형태와 단일 이름 형태를 모두 정규식 파이프(|)로 묶어 한 번에 검색합니다.
        rpc_services = (
            "rpc\\.cmsd|rpc\\.ttdbserverd|sadmind|rusersd|walld|sprayd|"
            "rstatd|rpc\\.nisd|rexd|rpc\\.pcnfsd|rpc\\.statd|rpc\\.ypupdated|"
            "rpc\\.rquotad|kcms_server|cachefsd"
        )

        # systemctl을 통해 현재 active 상태인 서비스 목록을 뽑고, 위에서 정의한 위험 서비스들만 필터링합니다.
        cmd_systemd = f"systemctl list-units --type=service --state=active 2>/dev/null | grep -iE '{rpc_services}'"
        systemd_result = self.conn.execute_cmd(cmd_systemd).strip()

        if systemd_result:
            # grep 결과가 존재한다면 하나 이상의 위험 RPC 서비스가 켜져 있다는 뜻입니다.
            issues.append("Vulnerable RPC service detected")

        if issues:
            status = "취약"
        else:
            status = "양호"
            
        self.report.print_result("U-42", "불필요한 RPC 서비스 비활성화", status)
        
        return status
    
    def u_43(self):  # NIS, NIS+ 점검 NIS (Network Information Service)는 과거 수십 대의 유닉스/리눅스 서버를 묶어서 관리할 때 사용하던 '중앙 계정/정보 관리 시스템
        issues = []

        # 가이드라인에 명시된 NIS 관련 서비스 데몬 목록입니다. (특수문자 마침표는 \\. 으로 이스케이프 처리)
        nis_services = "ypserv|ypbind|ypxfrd|rpc\\.yppasswdd|rpc\\.ypupdated"

        # 최신 환경에서는 패키지가 아예 없으므로, 이 명령어를 치자마자 빈 값이 반환되며 빠르게 넘어갑니다.
        cmd = f"systemctl list-units --type=service --state=active 2>/dev/null | grep -iE '{nis_services}'"
        result = self.conn.execute_cmd(cmd).strip()

        if result:
            # 나중에 추적할 수 있도록 어떤 서비스가 켜져 있는지 리스트에 상세히 담아둡니다.
            for line in result.split('\n'):
                parts = line.strip().split()
                if parts:
                    service_name = parts[0]
                    issues.append(f"취약한 NIS 관련 서비스({service_name})가 활성화되어 있습니다.")

        # 최종 결과 판별 (ReportManager 연동)
        if issues:
            status = "취약"
        else:
            status = "양호"
            
        self.report.print_result("U-43", "NIS, NIS+ 점검", status)
        
        return status
    
    def u_44(self):  # tftp, talk 서비스 비활성화
        issues = []

        # 점검 대상 서비스 목록 (tftp는 네트워크 장비용으로 종종 쓰이므로 발견 확률이 있습니다.)
        target_services = "tftp|talk|ntalk"

        cmd = f"systemctl list-units --type=service --state=active 2>/dev/null | grep -iE '{target_services}'"
        result = self.conn.execute_cmd(cmd).strip()

        if result:
            # 어떤 서비스(tftp인지 talk인지) 때문에 걸렸는지 정확히 리스트에 저장합니다.
            for line in result.split('\n'):
                parts = line.strip().split()
                if parts:
                    service_name = parts[0]
                    issues.append(f"취약한 통신 서비스({service_name})가 활성화되어 있습니다.")

        # 최종 결과 판별 (ReportManager 연동)
        if issues:
            status = "취약"
        else:
            status = "양호"
            
        self.report.print_result("U-44", "tftp, talk 서비스 비활성화", status)
        
        return status
    
    # def u_45(self):  # 메일 서비스 버전 점검 (메일 서비스를 사용하지 않아서 )
    # def u_46(self):  # 일반 사용자의 메일 서비스 실행 방지
    # def u_47(self):  # 스팸 메일 릴레이 제한
    # def u_48(self):  # expn, vrfy 명령어 제한 ()

    def u_49(self):  # DNS 보안 버전 패치 (DNS 서비스가 실행 중이면 일단 '취약', 관리자가 직접 버전을 확인바람)
        issues = []

        # 1. 최신 리눅스 환경에서 DNS 데몬(named) 활성화 여부 확인
        cmd_named = "systemctl list-units --type=service --state=active 2>/dev/null | grep -iE 'named\\.service'"
        result_named = self.conn.execute_cmd(cmd_named).strip()

        if result_named:
            # 2. 서비스가 실행 중이라면 가이드라인(Step 3)에 따라 버전을 확인합니다.
            cmd_version = "named -v 2>/dev/null"
            version_info = self.conn.execute_cmd(cmd_version).strip()

            if version_info:
                # 나중에 관리자가 ISC 홈페이지와 비교할 수 있도록 버전을 기록해 둡니다.
                issues.append(f"DNS 서비스가 실행 중입니다. (수집된 버전: {version_info} - 최신 버전과 수동 비교 필요)")
            else:
                issues.append("DNS 서비스가 실행 중이나 버전을 확인할 수 없습니다.")

        # 3. 최종 결과 판별 (ReportManager 연동)
        if issues:
            # DNS 서비스가 켜져 있으므로, 패치 관리 정책 확인을 위해 일단 '취약'을 띄워 점검자의 주의를 환기합니다.
            status = "취약"
            
            # [Debug] 관리자가 나중에 버전을 확인하고 싶을 때 주석을 해제하여 사용합니다.
            # print(f"[Debug] U-49 상세 내역: {issues}")
        else:
            # 서비스 자체를 사용하지 않으면 가이드라인에 따라 완벽한 '양호'입니다.
            status = "양호"
            
        self.report.print_result("U-49", "DNS 보안 버전 패치", status)
        
        return status

    def u_50(self):  # DNS Zone Transfer 설정
        issues = []

        # 1. DNS 서비스 활성화 여부 확인 (U-49와 동일)
        cmd_named = "systemctl list-units --type=service --state=active 2>/dev/null | grep -iE 'named\\.service'"
        
        if self.conn.execute_cmd(cmd_named).strip():
            # 2. 서비스가 켜져 있다면, 주요 설정 파일 2곳에서 allow-transfer 설정을 추출합니다.
            # 주석(#, //)이 포함된 라인은 제외하고 실제 적용된 설정만 가져옵니다.
            cmd_conf = (
                "grep -E '^[[:space:]]*allow-transfer' /etc/named.conf /etc/bind/named.conf.options 2>/dev/null"
            )
            result_conf = self.conn.execute_cmd(cmd_conf).strip()

            if result_conf:
                # 설정이 존재할 경우 한 줄씩 분석합니다.
                for line in result_conf.split('\n'):
                    # 대소문자 구분 없이 텍스트를 검사합니다.
                    line_lower = line.lower()
                    
                    # 설정값 내에 'any'가 포함되어 있다면 모든 사용자에게 Zone 전송을 허용하는 매우 취약한 상태입니다.
                    if "any" in line_lower:
                        issues.append(f"취약 설정 발견 (Zone Transfer가 모든 사용자에게 허용됨): {line.strip()}")
            else:
                # 설정 파일에 allow-transfer 명시 자체가 없다면, BIND 기본값에 의해 거부되거나 취약할 수 있으므로 
                # 관리자 수동 확인을 요하기 위해 취약으로 판정합니다.
                issues.append("allow-transfer 설정이 명시되어 있지 않아 수동 점검이 필요합니다.")

        # 3. 최종 결과 판별 (ReportManager 연동)
        if issues:
            status = "취약"
            # print(f"[Debug] U-50 상세 내역: {issues}")
        else:
            # 서비스가 꺼져 있거나, 설정에 'any'가 없고 정상적인 IP만 들어있다면 양호입니다.
            status = "양호"
            
        self.report.print_result("U-50", "DNS ZoneTransfer 설정", status)
        
        return status
    
    def u_51(self):  # DNS 서비스의 취약한 동적 업데이트 설정 금지
        issues = []

        # 1. DNS 서비스 활성화 여부 확인
        cmd_named = "systemctl list-units --type=service --state=active 2>/dev/null | grep -iE 'named\\.service'"
        
        if self.conn.execute_cmd(cmd_named).strip():
            # 2. 메인 설정 파일뿐만 아니라, Include로 자주 참조되는 Zone 설정 파일까지 모두 동시에 검색합니다.
            target_files = "/etc/named.conf /etc/bind/named.conf.options /etc/named.rfc1912.zones"
            
            # 주석(#, //)을 제외하고 allow-update 설정이 들어간 라인만 정밀하게 추출합니다.
            cmd_conf = f"grep -iE '^[[:space:]]*allow-update' {target_files} 2>/dev/null"
            result_conf = self.conn.execute_cmd(cmd_conf).strip()

            if result_conf:
                for line in result_conf.split('\n'):
                    line_lower = line.lower()
                    # 동적 업데이트를 '아무나(any)' 할 수 있게 열어두면 악의적인 데이터 변조가 가능해 취약합니다.
                    if "any" in line_lower:
                        issues.append(f"취약 설정 발견 (동적 업데이트가 모든 사용자에게 허용됨): {line.strip()}")
            else:
                # 명시적으로 설정이 없다면 BIND 기본값 정책상 안전할 수 있으나,
                # 회원의 질문처럼 '완전히 엉뚱한 이름'으로 Include 된 파일에 숨어있을 가능성을 대비해 경고를 남깁니다.
                issues.append("allow-update 설정 확인 불가 (Include 된 커스텀 Zone 파일이 있다면 수동 점검 필요)")

        # 3. 최종 결과 판별 (ReportManager 연동)
        if issues:
            status = "취약"
            # print(f"[Debug] U-51 상세 내역: {issues}")
        else:
            status = "양호"
            
        self.report.print_result("U-51", "DNS 서비스의 취약한 동적 업데이트 설정 금지", status)
        
        return status
    
    def u_52(self):  # Telnet 서비스 비활성화
        issues = []

        # 가이드라인에 따라 --type=socket 옵션을 주어 활성화된 소켓 목록 중 telnet을 찾습니다.
        cmd = "systemctl list-units --type=socket --state=active 2>/dev/null | grep -iE 'telnet\\.socket'"
        result = self.conn.execute_cmd(cmd).strip()

        if result:
            # telnet 소켓이 하나라도 발견되면 즉시 취약으로 간주합니다.
            for line in result.split('\n'):
                parts = line.strip().split()
                if parts:
                    socket_name = parts[0]
                    issues.append(f"취약한 Telnet 서비스({socket_name})가 활성화되어 있습니다.")

        # 최종 결과 판별 (ReportManager 연동)
        if issues:
            status = "취약"
            # print(f"[Debug] U-52 취약 원인: {issues}")
        else:
            status = "양호"
            
        self.report.print_result("U-52", "Telnet 서비스 비활성화", status)
        
        return status
    
    def u_53(self):  # FTP 서비스 정보 노출 제한 / 이게 Banner grabbing
        issues = []

        # 1. vsFTPd 점검
        cmd_vsftpd_active = "systemctl is-active vsftpd 2>/dev/null"
        if self.conn.execute_cmd(cmd_vsftpd_active).strip() == "active":
            # 주석을 제외하고 ftpd_banner 옵션이 설정되어 있는지 확인합니다.
            vsftpd_files = "/etc/vsftpd.conf /etc/vsftpd/vsftpd.conf"
            cmd_vsftpd_conf = f"grep -iE '^[[:space:]]*ftpd_banner' {vsftpd_files} 2>/dev/null"
            
            if not self.conn.execute_cmd(cmd_vsftpd_conf).strip():
                # 설정이 없다면 기본적으로 데몬 이름과 버전이 노출되므로 취약합니다.
                issues.append("vsFTPd: ftpd_banner 설정이 적용되지 않아 기본 배너(버전 정보)가 노출됩니다.")

        # 2. ProFTPD 점검
        cmd_proftpd_active = "systemctl is-active proftpd 2>/dev/null"
        if self.conn.execute_cmd(cmd_proftpd_active).strip() == "active":
            proftpd_files = "/etc/proftpd.conf /etc/proftpd/proftpd.conf"
            cmd_proftpd_conf = f"grep -iE '^[[:space:]]*ServerIdent' {proftpd_files} 2>/dev/null"
            proftpd_result = self.conn.execute_cmd(cmd_proftpd_conf).strip().lower()
            
            # ServerIdent 설정이 아예 없거나, 'on'으로 켜져 있는데 커스텀 배너(따옴표)가 지정되지 않은 경우 취약
            if not proftpd_result:
                issues.append("ProFTPD: ServerIdent 설정이 누락되어 버전 정보가 노출됩니다.")
            elif "on" in proftpd_result and not ('"' in proftpd_result or "'" in proftpd_result):
                issues.append(f"ProFTPD: ServerIdent가 활성화되었으나 커스텀 배너가 없습니다. ({proftpd_result})")

        # 3. 최종 결과 판별 (ReportManager 연동)
        if issues:
            status = "취약"
            # print(f"[Debug] U-53 상세 내역: {issues}")
        else:
            # FTP 서비스가 아예 꺼져 있거나, 켜져 있더라도 배너 차단 설정이 완벽하다면 양호
            status = "양호"
            
        self.report.print_result("U-53", "FTP 서비스 정보 노출 제한", status)
        
        return status
    
    def u_54(self):  # 암호화되지 않는 FTP 서비스 활성화
        issues = []

        # 1. vsFTPd 서비스 활성화 여부 확인
        cmd_vsftpd = "systemctl is-active vsftpd 2>/dev/null"
        if self.conn.execute_cmd(cmd_vsftpd).strip() == "active":
            issues.append("암호화되지 않은 FTP 서비스(vsftpd)가 실행 중입니다.")

        # 2. ProFTPD 서비스 활성화 여부 확인
        cmd_proftpd = "systemctl is-active proftpd 2>/dev/null"
        if self.conn.execute_cmd(cmd_proftpd).strip() == "active":
            issues.append("암호화되지 않은 FTP 서비스(proftpd)가 실행 중입니다.")

        # 3. 최종 결과 판별 (ReportManager 연동)
        if issues:
            status = "취약"
            # print(f"[Debug] U-54 상세 내역: {issues}")
        else:
            status = "양호"
            
        self.report.print_result("U-54", "암호화되지 않은 FTP 서비스 비활성화", status)
        
        return status
    
    def u_55(self):  # FTP 계정 shell 제한
        issues = []

        # 오탐 방지를 위해 정규식(^ftp:)을 사용하여 정확히 'ftp' 계정 라인만 추출합니다.
        cmd = "grep '^ftp:' /etc/passwd 2>/dev/null"
        result = self.conn.execute_cmd(cmd).strip()

        if result:
            # 예시: ftp:x:134:65534::/srv/ftp:/usr/sbin/nologin
            # 리스트의 맨 마지막 값([-1])을 즉시 쉘 정보로 가져옵니다.
            shell = result.split(':')[-1].strip()
            
            # 가이드라인에 명시된 안전한 쉘 목록
            safe_shells = ["/bin/false", "/sbin/nologin", "/usr/sbin/nologin"]
            
            if shell not in safe_shells:
                issues.append(f"ftp 계정에 로그인 가능한 쉘({shell})이 부여되어 있습니다.")

        # 최종 결과 판별 (ReportManager 연동)
        if issues:
            status = "취약"
            # print(f"[Debug] U-55 상세 내역: {issues}")
        else:
            status = "양호"
            
        self.report.print_result("U-55", "FTP 계정 shell 제한", status)
        
        return status
    
    def u_56(self):  # FTP 서비스 접근 제어 설정
        issues = []

        # 1. FTP 서비스 활성화 여부 확인 (가이드라인의 명령어 파이프라인 구조 적용)
        cmd_ftp = "systemctl list-units --type=service 2>/dev/null | grep -iE 'vsftpd|proftp'"
        result_ftp = self.conn.execute_cmd(cmd_ftp).strip()

        if result_ftp:
            # 2. 서비스가 실행 중인 경우, 가이드라인에 명시된 접근 제어 파일 목록을 순회하며 점검합니다.
            target_files = [
                "/etc/ftpusers", "/etc/ftpd/ftpusers",
                "/etc/vsftpd/ftpusers", "/etc/vsftpd.ftpusers",
                "/etc/vsftpd/user_list", "/etc/vsftpd.user_list"
            ]
            
            file_found = False  # 접근 제어 파일이 시스템에 단 하나라도 존재하는지 기억해 두는 것
            for file_path in target_files:
                # 파일이 존재하는 경우 stat 명령어로 소유자(%U)와 8진수 권한(%a)을 동시 추출합니다.
                cmd_stat = f"stat -c '%U %a' {file_path} 2>/dev/null"
                stat_result = self.conn.execute_cmd(cmd_stat).strip()
                
                if stat_result:
                    file_found = True
                    owner, perm = stat_result.split()
                    
                    # [판단 기준 1] 소유자가 root인지 확인 (Step 3, 4 대응)
                    if owner != "root":
                        issues.append(f"접근 제어 파일({file_path})의 소유자가 root가 아닙니다. (현재: {owner})")
                        
                    # [판단 기준 2] 권한이 640 이하인지 확인 (Step 5 대응)
                    # 8진수로 변환하여 크기 비교 (예: 644, 666, 777 등은 640보다 크므로 취약 처리)
                    if int(perm, 8) > int("640", 8):
                        issues.append(f"접근 제어 파일({file_path})의 권한이 640보다 큽니다. (현재: {perm})")

            # [판단 기준 3] 서비스는 켜져 있는데 제어 파일이 단 하나도 없다면 접근 통제가 없는 것으로 간주 (취약)
            if not file_found:
                issues.append("FTP 서비스가 실행 중이나, 접근 제어 설정 파일(ftpusers 등)이 존재하지 않습니다.")
                
        # 3. 최종 결과 판별 (ReportManager 연동)
        if issues:
            status = "취약"
            # print(f"[Debug] U-56 상세 내역: {issues}")
        else:
            status = "양호"
            
        self.report.print_result("U-56", "FTP 서비스 접근 제어 설정", status)
        
        return status
    
    def u_57(self):  # FTPusers 파일 설정
        issues = []
        file_found = False

        # --- [로직 1] 공통 ftpusers 파일 점검 ---
        target_ftpusers = [
            "/etc/ftpusers", "/etc/ftpd/ftpusers",
            "/etc/vsftpd/ftpusers", "/etc/vsftpd.ftpusers"
        ]
        
        for file_path in target_ftpusers:
            if self.conn.execute_cmd(f"ls {file_path} 2>/dev/null").strip():
                file_found = True
                cmd_check = f"grep -w '^root' {file_path} 2>/dev/null"
                if not self.conn.execute_cmd(cmd_check).strip():
                    issues.append(f"접근 제어 파일({file_path})이 존재하나 root 차단이 누락되었습니다.")

        # --- [로직 2] vsFTPd 전용 설정 (userlist_enable) 점검 ---
        vsftpd_confs = ["/etc/vsftpd.conf", "/etc/vsftpd/vsftpd.conf"]
        
        for conf_path in vsftpd_confs:
            if self.conn.execute_cmd(f"ls {conf_path} 2>/dev/null").strip():
                file_found = True
                
                cmd_userlist = f"grep -iE '^[[:space:]]*userlist_enable' {conf_path} 2>/dev/null"
                userlist_enable = self.conn.execute_cmd(cmd_userlist).strip().upper()
                
                # 가이드라인(Step 1): userlist_enable=YES 인 경우에만 user_list 파일을 2차 점검합니다.
                if "YES" in userlist_enable:
                    # 가이드라인(Step 3 참고): userlist_deny 옵션 확인 (기본값 YES=블랙리스트, NO=화이트리스트)
                    cmd_deny = f"grep -iE '^[[:space:]]*userlist_deny' {conf_path} 2>/dev/null"
                    userlist_deny = self.conn.execute_cmd(cmd_deny).strip().upper()
                    
                    is_deny_list = False if "NO" in userlist_deny else True
                    
                    user_list_files = ["/etc/vsftpd/user_list", "/etc/vsftpd.user_list"]
                    ulist_found = False
                    
                    for ul_path in user_list_files:
                        if self.conn.execute_cmd(f"ls {ul_path} 2>/dev/null").strip():
                            ulist_found = True
                            root_in_ul = self.conn.execute_cmd(f"grep -w '^root' {ul_path} 2>/dev/null").strip()
                            
                            # 차단(Deny) 모드인데 root가 리스트에 없으면 취약
                            if is_deny_list and not root_in_ul:
                                issues.append(f"vsFTPd: userlist_deny=YES 이나 {ul_path}에 root 차단이 누락되었습니다.")
                            # 허용(Allow) 모드인데 root가 리스트에 있으면 취약
                            elif not is_deny_list and root_in_ul:
                                issues.append(f"vsFTPd: userlist_deny=NO 이나 {ul_path}에 root가 포함되어 접속이 허용됩니다.")
                    
                    if not ulist_found and is_deny_list:
                        issues.append(f"vsFTPd: userlist_enable=YES 이나 user_list 파일이 존재하지 않습니다.")

        # --- [로직 3] ProFTPD 전용 설정 (RootLogin) 점검 ---
        proftpd_confs = ["/etc/proftpd.conf", "/etc/proftpd/proftpd.conf"]
        
        for conf_path in proftpd_confs:
            if self.conn.execute_cmd(f"ls {conf_path} 2>/dev/null").strip():
                file_found = True
                cmd_useftp = f"grep -iE '^[[:space:]]*UseFtpUsers' {conf_path} 2>/dev/null"
                useftp_result = self.conn.execute_cmd(cmd_useftp).strip().lower()
                
                # 가이드라인(Step 2, 3): UseFtpUsers가 'off'인 경우 RootLogin 설정이 'off'인지 연계 확인
                if "off" in useftp_result:
                    cmd_rootlogin = f"grep -iE '^[[:space:]]*RootLogin' {conf_path} 2>/dev/null"
                    rootlogin_result = self.conn.execute_cmd(cmd_rootlogin).strip().lower()
                    if "off" not in rootlogin_result:
                        issues.append(f"ProFTPD: UseFtpUsers가 off이나, RootLogin off 설정이 없습니다. ({conf_path})")

        # --- [로직 4] 통제 파일 부재 점검 ---
        if not file_found:
            issues.append("FTP 메인 설정 파일 및 접근 제어 파일이 시스템에 전혀 존재하지 않습니다.")
                
        # 최종 결과 판별 (ReportManager 연동)
        if issues:
            status = "취약"
            # print(f"[Debug] U-57 상세 내역: {issues}")
        else:
            status = "양호"
            
        self.report.print_result("U-57", "Ftpusers 파일 설정", status)
        
        return status
    
    def u_58(self):  # 불필요한 SNMP 서비스 구동 점검
        issues = []

        # 가이드라인에 명시된 list-units | grep 방식을 사용하여 snmpd 점검
        cmd = "systemctl list-units --type=service 2>/dev/null | grep -i 'snmpd'"
        result = self.conn.execute_cmd(cmd).strip()

        if result:
            # 검색된 결과에서 첫 번째 항목(서비스 이름)만 깔끔하게 추출하여 로그에 남깁니다.
            service_name = result.split()[0]
            issues.append(f"불필요한 SNMP 서비스({service_name})가 실행 중입니다.")

        # 최종 결과 판별 (ReportManager 연동)
        if issues:
            status = "취약" # SNMP 서비스를 사용하는 경우
            # print(f"[Debug] U-58 상세 내역: {issues}")
        else:
            status = "양호" # SNMP 서비스를 사용하지 않는 경우
            
        self.report.print_result("U-58", "불필요한 SNMP 서비스 구동 점검", status)
        
        return status
    
    def u_59(self):  # 안전한 SNMP 버전 사용
        issues = []

        # 1. SNMP 서비스가 실행 중인지 확인
        cmd_snmpd = "systemctl is-active snmpd 2>/dev/null"
        if self.conn.execute_cmd(cmd_snmpd).strip() == "active":
            
            conf_path = "/etc/snmp/snmpd.conf"
            
            # 2. v1/v2(취약한 버전) 설정이 하나라도 켜져 있는지 확인 (주석 제외)
            # rocommunity, rwcommunity, com2sec 등은 통신이 평문으로 전송되는 v1/v2c의 전용 문법입니다.
            cmd_check_v2 = f"grep -iE '^[[:space:]]*(rocommunity|rwcommunity|com2sec)' {conf_path} 2>/dev/null"
            result_v2 = self.conn.execute_cmd(cmd_check_v2).strip()
            
            if result_v2:
                # v2 이하의 설정이 발견되었으므로 즉시 취약 처리
                issues.append("취약한 프로토콜(SNMP v1/v2) 설정인 community string이 활성화되어 있습니다.")
            else:
                # v1/v2 설정이 없다면 안전한 v3를 쓰는지 교차 검증합니다.
                cmd_check_v3 = f"grep -iE '^[[:space:]]*(rouser|rwuser)' {conf_path} 2>/dev/null"
                if not self.conn.execute_cmd(cmd_check_v3).strip():
                    issues.append("SNMP 데몬은 실행 중이나, 안전한 v3(rouser) 설정이 명확하지 않아 수동 확인이 필요합니다.")

        # 3. 최종 결과 판별 (ReportManager 연동)
        if issues:
            status = "취약" # SNMP 서비스를 v2 이하로 사용하는 경우
            # print(f"[Debug] U-59 상세 내역: {issues}")
        else:
            status = "양호" # SNMP 서비스를 v3 이상으로 사용하거나, 서비스 자체를 안 쓰는 경우
            
        self.report.print_result("U-59", "안전한 SNMP 버전 사용", status)
        
        return status
    
    def u_60(self):  # SNMP Community String 복잡성 설정
        issues = []

        # 1. SNMP 서비스 활성화 여부 확인
        cmd_snmpd = "systemctl is-active snmpd 2>/dev/null"
        if self.conn.execute_cmd(cmd_snmpd).strip() == "active":
            
            conf_path = "/etc/snmp/snmpd.conf"
            
            # Redhat 계열(com2sec) 및 Debian 계열(rocommunity, rwcommunity) 설정 추출
            cmd_check = f"grep -iE '^[[:space:]]*(rocommunity|rwcommunity|com2sec)' {conf_path} 2>/dev/null"
            result = self.conn.execute_cmd(cmd_check).strip()

            if result:
                for line in result.split('\n'):
                    parts = line.strip().split()
                    if not parts:
                        continue

                    directive = parts[0].lower()
                    comm_string = ""

                    # 설정 파일 문법에 따라 Community String이 위치한 인덱스 추출
                    if directive in ['rocommunity', 'rwcommunity'] and len(parts) >= 2:
                        comm_string = parts[1]
                    elif directive == 'com2sec' and len(parts) >= 4:
                        # com2sec 설정의 경우 일반적으로 4번째(마지막) 값이 community string 입니다.
                        comm_string = parts[-1]

                    if comm_string:
                        # [판단 기준 1] 기본값 사용 여부 검사
                        if comm_string.lower() in ["public", "private"]:
                            issues.append(f"취약: 기본 Community String('{comm_string}')을 사용 중입니다.")
                            continue

                        # 복잡도 계산을 위한 문자열 분석
                        length = len(comm_string)
                        has_alpha = bool(re.search(r'[a-zA-Z]', comm_string))
                        has_digit = bool(re.search(r'\d', comm_string))
                        has_special = bool(re.search(r'[^a-zA-Z0-9]', comm_string))

                        # [판단 기준 2, 3] 문자열 조합 및 길이 검사
                        if has_alpha and has_digit and has_special:
                            if length < 8:
                                issues.append(f"취약: 영문+숫자+특수문자 포함이나 8자리 미만입니다. (현재 {length}자리: '{comm_string}')")
                        elif has_alpha and has_digit:
                            if length < 10:
                                issues.append(f"취약: 영문+숫자 포함이나 10자리 미만입니다. (현재 {length}자리: '{comm_string}')")
                        else:
                            # 영문자만 있거나, 숫자만 있는 등 복잡도 조합을 아예 만족하지 못하는 경우
                            issues.append(f"취약: Community String이 영문+숫자 또는 영문+숫자+특수문자 조합을 만족하지 않습니다. ('{comm_string}')")
            else:
                # SNMP 서비스는 동작 중이나 v1/v2 설정이 없는 경우 (v3 사용 추정)
                issues.append("참고: SNMP v3 인증을 사용할 경우, 해당 계정의 비밀번호 복잡도 수동 점검이 필요합니다.")

        # 최종 결과 판별 (ReportManager 연동)
        if issues and any("취약" in issue for issue in issues):
            status = "취약"
            # print(f"[Debug] U-60 상세 내역: {issues}")
        elif issues: 
            # 취약 항목 없이 참고(수동 점검) 메시지만 있는 경우 관리자 확인을 위해 양호/수동 처리
            # status = "수동점검"
            status = "양호"
        else:
            status = "양호"
            
        self.report.print_result("U-60", "SNMP Community String 복잡성 설정", status)
        
        return status
    
    def u_61(self):  # SNMP Access Control 설정
        issues = []

        # 1. SNMP 서비스 활성화 여부 확인
        cmd_snmpd = "systemctl is-active snmpd 2>/dev/null"
        if self.conn.execute_cmd(cmd_snmpd).strip() == "active":
            
            conf_path = "/etc/snmp/snmpd.conf"
            
            # v1/v2c 관련 설정 라인 추출
            cmd_check = f"grep -iE '^[[:space:]]*(rocommunity|rwcommunity|com2sec)' {conf_path} 2>/dev/null"
            result = self.conn.execute_cmd(cmd_check).strip()

            if result:
                for line in result.split('\n'):
                    parts = line.strip().split()
                    if not parts:
                        continue

                    directive = parts[0].lower()

                    # [로직 1] Redhat 계열 (com2sec) 검증
                    # 형식: com2sec [이름] [허용IP] [Community String]
                    if directive == 'com2sec':
                        if len(parts) >= 3:
                            # 3번째 위치(인덱스 2)가 허용할 네트워크 주소입니다.
                            source = parts[2].lower()
                            if source in ['default', '0.0.0.0', '0.0.0.0/0']:
                                issues.append(f"취약: com2sec 설정에 접근 제한이 적용되지 않았습니다. (현재 IP: {source})")
                                
                    # [로직 2] Debian 계열 (rocommunity, rwcommunity) 검증
                    # 형식: rocommunity [Community String] [허용IP]
                    elif directive in ['rocommunity', 'rwcommunity']:
                        if len(parts) == 2:
                            # IP가 아예 생략된 경우, 기본적으로 Any(모든 IP) 허용으로 작동하므로 매우 취약합니다.
                            issues.append(f"취약: {directive} 설정에 허용 IP가 명시되지 않아 모든 접근이 허용됩니다.")
                        elif len(parts) >= 3:
                            # 3번째 위치(인덱스 2)가 허용할 네트워크 주소입니다.
                            source = parts[2].lower()
                            if source in ['default', '0.0.0.0', '0.0.0.0/0']:
                                issues.append(f"취약: {directive} 설정에 접근 제한이 적용되지 않았습니다. (현재 IP: {source})")
            else:
                # SNMP 서비스는 동작 중이나 v1/v2 설정이 없는 경우 (v3 사용 등)
                issues.append("참고: SNMP 설정 파일에 접근 제어 내역이 확인되지 않아 수동 점검이 필요합니다.")

        # 3. 최종 결과 판별 (ReportManager 연동)
        if issues and any("취약" in issue for issue in issues):
            status = "취약" # 접근 제어 설정이 되어 있지 않은 경우
            # print(f"[Debug] U-61 상세 내역: {issues}")
        elif issues: 
            # status = "수동점검"
            status = "양호"
        else:
            status = "양호" # 접근 제어 설정이 올바르게 되어 있는 경우
            
        self.report.print_result("U-61", "SNMP Access Control 설정", status)
        
        return status
    
    # def u_62(self):  # 로그인 시 경고 메시지 설정
    
    def u_63(self):  # sudo 명령어 접근 관리
        issues = []
        file_path = "/etc/sudoers"
        
        # stat 명령어로 소유자(%U)와 8진수 권한(%a)을 동시에 추출합니다.
        cmd_stat = f"stat -c '%U %a' {file_path} 2>/dev/null"
        result = self.conn.execute_cmd(cmd_stat).strip()
        
        if result:
            owner, perm = result.split()
            
            # [판단 기준 1] 소유자가 root가 아닌 경우 취약 처리
            if owner != "root":
                issues.append(f"{file_path} 파일의 소유자가 root가 아닙니다. (현재 소유자: {owner})")
                
            # [판단 기준 2] 권한이 640을 초과하는 경우 취약 처리
            # 리눅스 파일 권한(예: 440, 644 등)을 8진수로 변환하여 640과 대소 비교
            if int(perm, 8) > int("640", 8):
                issues.append(f"{file_path} 파일의 권한이 640을 초과합니다. (현재 권한: {perm})")
        else:
            # sudoers 파일이 아예 존재하지 않는 비정상적인 상황에 대한 예외 처리
            issues.append(f"{file_path} 파일이 존재하지 않습니다.")
            
        # 최종 결과 판별 (ReportManager 연동)
        if issues:
            status = "취약"
            # print(f"[Debug] U-63 상세 내역: {issues}")
        else:
            status = "양호"
            
        self.report.print_result("U-63", "sudo 명령어 접근 관리", status)
        
        return status
    
class PatchManagement:  # 패치 관리
    def __init__(self, ssh_conn, report_mgr):
            # SSHConnection 객체를 전달받아 내부에서 사용
            self.conn = ssh_conn
            self.report = report_mgr

    def u_64(self):  # 주기적 보안 패치 및 벤더 권고사항 적용
        issues = []
        
        latest_os_list = [
            "Rocky Linux 9.4 (Blue Onyx)", 
            "Ubuntu 22.04.4 LTS",
            "CentOS Linux 7 (Core)" # 예시: 사내 정책상 예외를 두는 경우
        ]
        latest_kernel_list = [
            "5.14.0-427.el9.x86_64", 
            "5.15.0-105-generic",
            "3.10.0-1160.el7.x86_64"
        ]
        
        # 가이드라인에 명시된 OS 및 커널 버전 확인 명령어
        cmd = "hostnamectl 2>/dev/null"
        result = self.conn.execute_cmd(cmd).strip()
        
        if result:
            os_info = ""
            kernel_info = ""
            
            # 출력 결과에서 OS와 커널 정보만 파싱
            for line in result.split('\n'):
                if "Operating System:" in line:
                    os_info = line.split(':', 1)[1].strip()
                elif "Kernel:" in line:
                    kernel_info = line.split(':', 1)[1].strip()
                    
            if os_info and kernel_info:
                # 1. OS 버전이 허용된 최신 목록에 있는지 검사
                if os_info not in latest_os_list:
                    issues.append(f"OS 버전이 최신(인가된) 상태가 아닙니다. (현재: {os_info})")
                    
                # 2. 커널 버전이 허용된 최신 목록에 있는지 검사
                if kernel_info not in latest_kernel_list:
                    issues.append(f"Kernel 버전이 최신(인가된) 상태가 아닙니다. (현재: {kernel_info})")
            else:
                issues.append("hostnamectl 결과에서 OS 및 커널 정보를 파싱할 수 없습니다.")
        else:
            issues.append("시스템에서 hostnamectl 명령어를 실행할 수 없습니다.")
            
        # 최신 버전 목록에 없어서 issues에 내용이 하나라도 담겼다면 '취약'
        if issues:
            status = "취약"
            # print(f"[Debug] U-64 상세 내역: {issues}")
        else:
            status = "양호"
            
        self.report.print_result("U-64", "주기적 보안 패치 및 벤더 권고상항 적용", status)
        
        return status

class LogManagement:  # 로그 관리
    def __init__(self, ssh_conn, report_mgr):
            # SSHConnection 객체를 전달받아 내부에서 사용
            self.conn = ssh_conn
            self.report = report_mgr

    def u_65(self):  # NTP 및 시각 동기화 설정
        issues = []
        is_synced = False
        service_running = False

        # --- [로직 1] 기존 NTP 서비스 점검 ---
        cmd_ntp = "systemctl list-units --type=service 2>/dev/null | grep -i 'ntp'"
        if self.conn.execute_cmd(cmd_ntp).strip():
            service_running = True
            
            # 동기화 상태 확인 (ntpq -pn)
            # ntpq 결과에서 줄의 맨 앞이 '*'로 시작하면 현재 성공적으로 동기화된 피어(Peer)를 의미합니다.
            ntpq_result = self.conn.execute_cmd("ntpq -pn 2>/dev/null").strip()
            for line in ntpq_result.split('\n'):
                if line.strip().startswith('*'):
                    is_synced = True
                    break
            
            if not is_synced:
                issues.append("NTP 서비스가 실행 중이나, 정상적으로 동기화된 타임 서버('*' 표시)가 없습니다.")

        # --- [로직 2] Chrony 서비스 점검 (RHEL 8 이상 등) ---
        cmd_chrony = "systemctl list-units --type=service 2>/dev/null | grep -i 'chrony'"
        if self.conn.execute_cmd(cmd_chrony).strip():
            service_running = True
            
            # 동기화 상태 확인 (chronyc sources)
            # chronyc 결과에서 줄의 맨 앞이 '^*'로 시작하면 시스템 시계를 동기화 중인 최적의 소스를 의미합니다.
            chrony_result = self.conn.execute_cmd("chronyc sources 2>/dev/null").strip()
            for line in chrony_result.split('\n'):
                if line.strip().startswith('^*'):
                    is_synced = True
                    break
                    
            if not is_synced and not issues: 
                # NTP에서 이미 에러가 났을 경우 중복 출력 방지를 위해 not issues 조건 추가
                issues.append("Chrony 서비스가 실행 중이나, 정상적으로 동기화된 타임 서버('^*' 표시)가 없습니다.")

        # --- [로직 3] 서비스 구동 여부 종합 판단 ---
        if not service_running:
            issues.append("시스템에 시간 동기화(NTP 또는 Chrony) 서비스가 활성화되어 있지 않습니다.")

        # 4. 최종 결과 판별 (ReportManager 연동)
        if not service_running or not is_synced:
            status = "취약"
            # print(f"[Debug] U-65 상세 내역: {issues}")
        else:
            status = "양호"
            
        self.report.print_result("U-65", "NTP 및 시각 동기화 설정", status)
        
        return status
    
    def u_66(self):  # 정책에 따른 시스템 로깅 설정
        issues = []
        
        # 1. 두 설정 파일의 내용을 하나로 합쳐서 읽어옵니다.
        cmd_conf = "cat /etc/rsyslog.conf /etc/rsyslog.d/default.conf 2>/dev/null"
        config_content = self.conn.execute_cmd(cmd_conf).strip()
        
        # 파일이 없거나 읽을 수 없는 경우 즉시 취약 처리
        if not config_content or "no such file" in config_content.lower() or "permission denied" in config_content.lower():
            issues.append("설정 파일(/etc/rsyslog.conf 등)을 읽을 수 없거나 내용이 없습니다.")
            self.report.print_result("U-66", "정책에 따른 시스템 로깅 설정", "취약")
            return "취약"

        # --- 점검해야 할 핵심 6대 로깅 가이드라인 규격 정의 ---
        required_policies = {
            "*.info;mail.none;authpriv.none;cron.none": "/var/log/messages", # 시스템 일반 로그
            "auth,authpriv.*": "/var/log/secure",                            # 인증 및 보안 로그
            "mail.*": "/var/log/maillog",                                    # 메일 송수신 로그
            "cron.*": "/var/log/cron",                                       # 예약 작업 로그
            "*.alert": "/dev/console",                                       # 콘솔 경고 로그
            "*.emerg": "*"                                                   # 전체 사용자 긴급 알림
        }

        missing_policies = {} 
        
        # 2. 각 필수 정책이 파일 안에 활성화되어 있는지 확인
        for facility, log_file in required_policies.items():
            
            # 정규표현식(Regex) 조합
            # ^\s* : 줄 시작에 공백이나 탭만 허용 (주석 '#' 문자가 오면 자동으로 매칭 실패)
            # re.escape() : facility와 log_file 문자열의 '*'나 '.' 같은 특수문자를 일반 문자로 안전하게 치환
            # [\s\t]+-? : Facility와 경로 사이의 하나 이상의 공백/탭, 그리고 선택적인 비동기 쓰기 기호(-)
            pattern = rf"^\s*{re.escape(facility)}[\s\t]+-?{re.escape(log_file)}"
            matched = False
            
            for line in config_content.splitlines():
                # 빈 줄이 아니고, 해당 정규식 패턴과 일치하는 라인이 있다면
                if line.strip() and re.search(pattern, line):
                    matched = True
                    break
            
            if not matched:
                # 매칭되지 않았다면 (주석 처리 되었거나 설정이 누락되었다면) 딕셔너리에 추가
                missing_policies[facility] = log_file
                issues.append(f"누락된 로깅 정책: {facility} -> {log_file}")
                
        # 3. 최종 결과 판별 (ReportManager 연동)
        if missing_policies:
            status = "취약"
            # print(f"[Debug] U-66 상세 내역: {issues}")
        else:
            status = "양호"
            
        self.report.print_result("U-66", "정책에 따른 시스템 로깅 설정", status)
        
        return status
    
    def u_67(self):  #  로그 디렉터리 소유자 및 권한 설정
        issues = []
        
        # find 명령어로 /var/log 바로 아래(-maxdepth 1)에 있는 일반 파일(-type f)만 
        # 모두 찾아서 stat 명령어로 소유자(%U), 8진수 권한(%a), 파일명(%n)을 한 번에 추출합니다.
        cmd_stat = "find /var/log -maxdepth 1 -type f -exec stat -c '%U %a %n' {} + 2>/dev/null"
        result = self.conn.execute_cmd(cmd_stat).strip()
        
        if result:
            for line in result.split('\n'):
                parts = line.strip().split()
                # 출력이 최소 3개(소유자, 권한, 파일명) 이상인지 확인
                if len(parts) >= 3:
                    owner = parts[0]
                    perm = parts[1]
                    # 파일명에 띄어쓰기가 있을 경우를 대비해 3번째 인덱스부터는 다시 합쳐줍니다.
                    filepath = " ".join(parts[2:])
                    
                    # [판단 기준 1] 소유자가 root가 아닌 경우
                    if owner != "root":
                        issues.append(f"취약: '{filepath}' 파일의 소유자가 root가 아닙니다. (현재 소유자: {owner})")
                        
                    # [판단 기준 2] 권한이 644를 초과하는 경우 (예: 645, 666 등)
                    if int(perm, 8) > int("644", 8):
                        issues.append(f"취약: '{filepath}' 파일의 권한이 644를 초과합니다. (현재 권한: {perm})")
        else:
            issues.append("/var/log 디렉터리 내에 점검할 로그 파일이 존재하지 않거나 권한 부족으로 읽을 수 없습니다.")

        # 최종 결과 판별 (ReportManager 연동)
        if issues:
            status = "취약"
            # print(f"[Debug] U-67 상세 내역: {issues}")
        else:
            status = "양호"
            
        self.report.print_result("U-67", "로그 디렉터리 소유자 및 권한 설정", status)
        
        return status
    
# 실행부
if __name__ == "__main__":
    # 점검할 서버 정보 입력 (실제 환경에 맞게 수정)
    TARGET_IP = "172.16.18.70"
    TARGET_PORT = 22  # 나중에 ssh 포트변호 바꿀꺼 생각
    TARGET_USER = "root"
    TARGET_PASS = "asd123!@"

    # 객체 생성 및 점검 수행
    server_conn = SSHConnection(TARGET_IP, TARGET_PORT, TARGET_USER, TARGET_PASS)
    server_conn.connect()

    report_mgr = ReportManager(TARGET_IP)

    report_mgr.print_main_header("계정 관리")
    # 2. 계정 관리 진단 클래스에 연결 객체를 주입하고 점검 수행
    identity_check = IdentityManagement(server_conn, report_mgr)
    identity_check.u_01()
    identity_check.u_02()
    identity_check.u_03()
    identity_check.u_04()
    identity_check.u_05()
    identity_check.u_06()
    # identity_check.u_07()
    # identity_check.u_08()
    # identity_check.u_09()
    identity_check.u_10()
    identity_check.u_11()
    # identity_check.u_12()
    identity_check.u_13()

    files_check = FileDirectoryManagement(server_conn, report_mgr)
    files_check.u_14()
    files_check.u_15()
    files_check.u_16()
    files_check.u_17()
    files_check.u_18()
    files_check.u_19()
    files_check.u_20()
    files_check.u_21()
    files_check.u_22()
    files_check.u_23()
    files_check.u_24()
    # files_check.u_25()
    files_check.u_26()
    files_check.u_27()
    files_check.u_28()
    files_check.u_29()
    files_check.u_30()
    files_check.u_31()
    files_check.u_32()

    service_check = ServiceManagement(server_conn, report_mgr)
    # service_check.u_34()
    service_check.u_35()
    service_check.u_36()
    service_check.u_37()
    service_check.u_38()
    service_check.u_39()
    service_check.u_40()
    service_check.u_41()
    service_check.u_42()
    service_check.u_43()
    service_check.u_44()
    # service_check.u_45()
    # service_check.u_46()
    # service_check.u_47()
    # service_check.u_48()
    service_check.u_49()
    service_check.u_50()
    service_check.u_51()
    service_check.u_52()
    service_check.u_53()
    service_check.u_54()
    service_check.u_55()
    service_check.u_56()
    service_check.u_57()
    service_check.u_58()
    service_check.u_59()
    service_check.u_60()
    service_check.u_61()
    # service_check.u_62()
    service_check.u_63()

    patch_check = PatchManagement(server_conn, report_mgr)
    patch_check.u_64()

    log_check = LogManagement(server_conn, report_mgr)
    log_check.u_65()
    log_check.u_66()
    log_check.u_67()


    report_mgr.save_to_json("linux_security_result.json")
    
    # 3. 모든 점검이 끝나면 SSH 연결 종료
    server_conn.disconnect()
