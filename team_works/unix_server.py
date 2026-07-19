class UnixServer:

    check_list = {
        "u_01": { "title": "root 원격 접속 제한" },
        "u_02": { "title": "비밀번호 정책" },
        "u_03": { "title": "계정 잠금" },
        "u_04": { "title": "계정 잠금" },
        "u_05": { "title": "UID 0 점검" },
        "u_06": { "title": "사용자 계정 su 제한" },
        "u_07": { "title": "불필요한 계정 제거" },
        "u_08": { "title": "관리자 그룹에 최소한의 계정 포함" },
        "u_09": { "title": "계정이 존재하지 않는 GID 금지" },
        "u_10": { "title": "UID 중복" },
        "u_11": { "title": "시스템 쉘" },
        "u_12": { "title": "타임아웃" },
        "u_13": { "title": "암호화 알고리즘" },
        "u_14": { "title": "PATH 환경변수" },
        "u_15": { "title": "소유자 없는 파일" },
        "u_16": { "title": "/etc/passwd 권한" },
        "u_17": { "title": "시작 스크립트 권한" },
        "u_18": { "title": "/etc/shadow 권한" },
        "u_19": { "title": "/etc/hosts 권한" },
        "u_20": { "title": "(x)inetd.conf 권한" },
        "u_21": { "title": "(r)syslog.conf 권한" },
        "u_22": { "title": "/etc/services 권한" },
        "u_23": { "title": "SUID/SGID 설정" },
        "u_24": { "title": "사용자 환경변수 파일" }
    }
    
    def __init__(self, conn):
        self.conn = conn

    def u_01(self):
        cmd = "grep -i '^PermitRootLogin' /etc/ssh/sshd_config | grep -v '^#' | awk '{print $2}'"
        result = self.conn.execute_cmd(cmd).strip().lower()
    
        if result == "no":
            return ("양호", "root 원격 접속 제한 설정됨")
        return ("취약", f"현재 설정값: '{result}', 기대값: 'no'")

    def u_02(self):
        cmd = "grep -E '^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN)' /etc/login.defs"
        output = self.conn.execute_cmd(cmd)
        issues = []
        if "PASS_MAX_DAYS" not in output or "90" not in output: issues.append("PASS_MAX_DAYS(90)")
        if "PASS_MIN_DAYS" not in output or "7" not in output: issues.append("PASS_MIN_DAYS(7)")
        if "PASS_MIN_LEN" not in output or "8" not in output: issues.append("PASS_MIN_LEN(8)")
        return ("취약", f"정책 미흡: {', '.join(issues)}") if issues else ("양호", "비밀번호 정책 적정")

    def u_03(self):
        pam_file = "/etc/pam.d/system-auth" if self.conn.os_type == "redhat" else "/etc/pam.d/common-auth"
        result = self.conn.execute_cmd(f"grep 'pam_faillock.so' {pam_file} 2>/dev/null 2>&1 && echo 'exist'")
        return ("양호", "계정 잠금 설정 확인됨") if result.strip() == "exist" else ("취약", "계정 잠금 설정 누락")

    def u_05(self):
        cmd = "awk -F: '$3 == 0 && $1 != \"root\" {print $1}' /etc/passwd"
        users = self.conn.execute_cmd(cmd).strip()
        return ("취약", f"UID 0 사용자 발견: {users}") if users else ("양호", "정상")

    def u_06(self):
        normal_users = self.conn.execute_cmd("awk -F: '$3 >= 1000 && $3 != 65534 {print $1}' /etc/passwd")
        if not normal_users.strip(): return ("양호", "일반 사용자 없음")
        is_pam = "use_uid" in self.conn.execute_cmd("grep -E 'auth.+required.+pam_wheel\\.so' /etc/pam.d/su 2>/dev/null")
        su_stat = self.conn.execute_cmd("stat -c '%A' /bin/su 2>/dev/null || stat -c '%A' /usr/bin/su 2>/dev/null")
        return ("양호", "su 제한 설정됨") if (is_pam or su_stat.endswith("---")) else ("취약", "su 권한 제한 설정 미흡")

    def u_10(self):
        dups = self.conn.execute_cmd("awk -F: '{print $3}' /etc/passwd | sort | uniq -d")
        return ("취약", f"중복 UID 발견: {dups}") if dups.strip() else ("양호", "중복 UID 없음")

    def u_11(self):
        target = "daemon|bin|sys|adm|listen|nobody|nobody4|noaccess|diag|operator|games|gopher"
        cmd = f"awk -F: '$1 ~ /^({target})$/ {{print $7}}' /etc/passwd"
        shells = self.conn.execute_cmd(cmd).splitlines()
        for s in shells:
            if "false" not in s and "nologin" not in s: return ("취약", f"시스템 계정 쉘 미설정: {s}")
        return ("양호", "시스템 계정 쉘 정상")

    def u_12(self):
        tmout = self.conn.execute_cmd("grep -E '^[[:space:]]*TMOUT[[:space:]]*=' /etc/profile | cut -d= -f2")
        if tmout.isdigit() and int(tmout) <= 600: return ("양호", "TMOUT 설정 적정")
        csh = self.conn.execute_cmd("grep 'autologout' /etc/csh.cshrc /etc/csh.login 2>/dev/null")
        return ("양호", "CSH autologout 설정 확인") if csh.strip() else ("취약", "세션 타임아웃 미설정")

    def u_13(self):
        weak = self.conn.execute_cmd("awk -F: '$2 ~ /^\\$1\\$/ || $2 ~ /^\\$2/ {print $1}' /etc/shadow")
        if weak.strip(): return ("취약", f"취약한 암호 알고리즘 사용 계정: {weak}")
        method = self.conn.execute_cmd("grep 'ENCRYPT_METHOD' /etc/login.defs | awk '{print $2}'")
        if method.upper() not in ["SHA256", "SHA512", "YESCRYPT"]: return ("취약", f"알고리즘 미흡: {method}")
        return ("양호", "안전한 암호화 알고리즘 사용 중")

    def u_14(self):
        cmd = "echo $PATH"
        path_env = self.conn.execute_cmd(cmd).strip()
        if not path_env: return ("취약", "PATH 환경변수 확인 불가")
        if "." in path_env.split(':') or "" in path_env.split(':'):
            return ("취약", f"PATH 환경변수 설정 미흡: {path_env}")
        return ("양호", "PATH 설정 적정")

    def u_15(self):
        cmd = r"find / \( -nouser -o -nogroup \) -xdev -ls 2>/dev/null"
        orphan = self.conn.execute_cmd(cmd).strip()
        return ("취약", "소유자/그룹 없는 파일 발견") if orphan else ("양호", "정상")

    def u_16(self):
        cmd = "stat -c '%U %a' /etc/passwd 2>/dev/null"
        res = self.conn.execute_cmd(cmd).strip()
        if not res: return ("취약", "파일 확인 불가")
        owner, perm = res.split()
        return ("취약", "/etc/passwd 권한/소유자 부적절") if owner != "root" or int(perm) > 644 else ("양호", "정상")

    def u_17(self):
        cmd = r"find /etc/rc.d /etc/init.d /etc/systemd/system -type f \( ! -user root -o -perm -002 \) 2>/dev/null | head -1"
        vuln = self.conn.execute_cmd(cmd).strip()
        return ("취약", f"취약한 스크립트 존재: {vuln}") if vuln else ("양호", "정상")

    def u_18(self):
        cmd = "stat -c '%U %a' /etc/shadow 2>/dev/null"
        res = self.conn.execute_cmd(cmd).strip()
        if not res: return ("취약", "파일 확인 불가")
        owner, perm = res.split()
        return ("취약", "/etc/shadow 권한/소유자 부적절") if owner != "root" or int(perm) > 400 else ("양호", "정상")

    def u_19(self):
        cmd = "stat -c '%U %a' /etc/hosts 2>/dev/null"
        res = self.conn.execute_cmd(cmd).strip()
        if not res: return ("취약", "파일 확인 불가")
        owner, perm = res.split()
        return ("취약", "/etc/hosts 권한/소유자 부적절") if owner != "root" or int(perm) > 644 else ("양호", "정상")

    def u_20(self):
        targets = "/etc/inetd.conf /etc/xinetd.conf /etc/xinetd.d /etc/systemd/system.conf /etc/systemd"
        cmd = f"find {targets} -type f -exec stat -c '%n %U %a' {{}} + 2>/dev/null"
        result = self.conn.execute_cmd(cmd).strip()
        if not result: return ("양호", "해당 서비스 미사용")
        for line in result.split('\n'):
            path, owner, perm = line.split()
            if owner != "root" or int(perm) > 600:
                return ("취약", f"권한/소유자 취약: {path}")
        return ("양호", "정상")

    def u_21(self):
        cmd = "stat -c '%n %U %a' /etc/syslog.conf /etc/rsyslog.conf 2>/dev/null"
        result = self.conn.execute_cmd(cmd).strip()
        if not result: return ("양호", "설정 파일 없음")
        for line in result.split('\n'):
            path, owner, perm = line.split()
            if owner not in ["root", "bin", "sys"] or int(perm) > 640:
                return ("취약", f"파일 설정 미흡: {path}")
        return ("양호", "정상")

    def u_22(self):
        cmd = "stat -c '%U %a' /etc/services 2>/dev/null"
        res = self.conn.execute_cmd(cmd).strip()
        if not res: return ("취약", "파일 확인 불가")
        owner, perm = res.split()
        if owner not in ["root", "bin", "sys"] or int(perm) > 644:
            return ("취약", "/etc/services 권한/소유자 부적절")
        return ("양호", "정상")

    def u_23(self):
        cmd = r"find / -xdev -user root -type f \( -perm -04000 -o -perm -02000 \) 2>/dev/null"
        result = self.conn.execute_cmd(cmd).strip()
        safe_paths = ('/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/', '/usr/lib/', '/usr/libexec/', '/lib/', '/lib64/')
        vulns = [f for f in result.split('\n') if f and not f.startswith(safe_paths)]
        return ("취약", f"비표준 SUID/SGID 발견: {vulns[0]}") if vulns else ("양호", "정상")

    def u_24(self):
        # /var/log 디렉토리 하위의 로그 파일 소유자 및 권한 점검
        cmd = "find /var/log -type f -exec stat -c '%n %U %a' {} + 2>/dev/null"
        result = self.conn.execute_cmd(cmd).strip()
        if not result: return ("양호", "로그 파일 없음")
        for line in result.split('\n'):
            path, owner, perm = line.split()
            # 소유자가 root가 아니거나, 권한이 640을 초과하면 취약
            if owner != "root" or int(perm) > 640:
                return ("취약", f"로그 파일 보안 설정 미흡: {path}")
        return ("양호", "정상")
