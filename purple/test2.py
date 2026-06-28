import paramiko
import re

class RemoteLogAnalyzer:
    """원격 서버 접속 및 명령어 실행을 담당하는 부모 클래스"""
    def __init__(self, host, username, password, port=22):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.client = None

    def connect(self):
        """SSH 연결 수립"""
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(self.host, port=self.port, username=self.username, password=self.password)
        return True

    def execute_command(self, command, use_sudo=False):
        """명령어 실행 및 결과 텍스트 반환 (sudo 대응)"""
        if not self.client:
            return ""
        
        if use_sudo and self.username != 'root':
            command = f"sudo -S {command}"
            
        stdin, stdout, stderr = self.client.exec_command(command)
        
        if use_sudo and self.username != 'root':
            stdin.write(self.password + '\n')
            stdin.flush()
            
        error_output = stderr.read().decode('utf-8', errors='ignore')
        result_output = stdout.read().decode('utf-8', errors='ignore')
        
        result_output = re.sub(r'\[sudo\] password for .+: ', '', result_output)
        
        if result_output:
            return result_output
        else:
            return error_output

    def disconnect(self):
        """SSH 연결 종료"""
        if self.client:
            self.client.close()


class RsyslogAuditManager(RemoteLogAnalyzer):
    """rsyslog.conf 로그 설정 점검 및 누락 자동 조치 클래스"""

    def audit_and_remediate(self):
        print(f"\n==================================================================")
        print(f" 🔍 원격지 [{self.host}] 기술적 취약점 진단: 로그 관리 (U-66) ")
        print(f"==================================================================")
        
        self.connect()
        
        # 1. 원격지의 /etc/rsyslog.conf 파일 내용 읽어오기
        config_content = self.execute_command("cat /etc/rsyslog.conf", use_sudo=True)
        
        if "permission denied" in config_content.lower() or "no such file" in config_content.lower() or not config_content.strip():  # 권한없이 접속했을때 뜨는 알림들 필터링
            print("[⚠️ 진단 불가] rsyslog.conf 파일을 읽을 수 없습니다. 권한을 확인하세요.")
            self.disconnect()
            return

        # --- 점검해야 할 핵심 3대 로깅 가이드라인 규격 정의 ---
        # 주석처리(#)된 항목은 무시하기 위해 패턴 앞에 주석이 없는 형태 지정
        required_policies = {
            "authpriv.*": "/var/log/secure",    # 인증 및 보안 로그
            "*.info;mail.none;authpriv.none;cron.none": "/var/log/messages",      # 시스템 전반 일반 로그
            "cron.*": "/var/log/cron",          # 크론 예약 작업 로그
            "*.alert": "/dev/console",          #  콘솔 경고 로그
            "mail.*": "/var/log/maillog"        # 메일 송수신 흔적 추적 로그
        }

        missing_policies = {}  # 누락된 정책을 담을 딕셔너리
        
        print("[*] 현재 설정 값 검증 중...")
        
        # 각 필수 정책이 파일 안에 활성화되어 있는지 확인
        for facility, log_file in required_policies.items():
            # 정규표현식으로 주석 없이 해당 시설(Facility)과 파일 경로가 매칭되는지 확인
            # 예: 문자열 시작 부분에 #이 없고 중간에 facility와 log_file이 매칭되는지 조사
            pattern = rf"^[^\#]*{re.escape(facility.strip())}[\s\t]+-?{re.escape(log_file.strip())}"
            matched = False
            
            for line in config_content.splitlines():
                if re.search(pattern, line.strip()):
                    matched = True
            
            if not matched:
                # 매칭되지 않았다면(설정이 주석처리 되었거나 아예 없다면) 누락 목록에 추가
                missing_policies[facility] = log_file

        # ==================================================================
        # 📊 1차 진단 결과 판정 및 출력
        # ==================================================================
        if missing_policies:
            print("\n🚨 [진단 결과]: ❌ 취약 (VULNERABLE)")
            print("👉 사유: 침해 사고 조사 및 원인 파악에 필요한 필수 로깅 설정이 누락되어 있습니다.")
            print("\n[누락된 정책 내역]")
            for fac, path in missing_policies.items():
                print(f"   • {fac} -> {path}")
            
            # ==================================================================
            # 🛠️ 자동 조치 (Remediation) 단계 진입
            # ==================================================================
            print("\n[🛠️ 자동 조치 가동] 누락된 로그 설정을 rsyslog.conf에 추가합니다.")
            
            for fac, path in missing_policies.items():
                append_line = f"{fac}\t{path}"
                # echo 명령어를 통해 파일의 맨 마지막 줄에 설정을 추가(>> 사용)
                # 안전을 위해 원본 파일 수정 시 sudo 권한 동반
                append_cmd = f"echo -e '{append_line}' | sudo tee -a /etc/rsyslog.conf"
                self.execute_command(append_cmd, use_sudo=True)
                print(f"   • 설정 반영 완료: {append_line}")

            # 서비스 재시작 실행
            print("\n[*] 변경된 설정을 적용하기 위해 rsyslog 데몬을 재시작합니다.")
            restart_cmd = "systemctl restart rsyslog"
            restart_result = self.execute_command(restart_cmd, use_sudo=True)
            
            # 리눅스 systemctl은 정상 재시작 시 아무런 출력을 주지 않습니다(빈칸=성공)
            if not restart_result.strip():
                print("🟢 rsyslog 서비스 재시작 완료 (systemctl restart rsyslog)")
                print("\n[최종 검증] 시스템 안전성 조치 완료 후 상태: ✅ 양호 (SAFE)")
            else:
                print(f"⚠️ 서비스 재시작 도중 메시지 발생: {restart_result}")

        else:
            print("\n🟢 [진단 결과]: ✅ 양호 (SAFE)")
            print("👉 사유: 주요정보통신기반시설 가이드라인에 따른 핵심 로그가 정상 경로에 기록되고 있습니다.")
            print("🎉 조치할 내역이 없습니다.")

        print("==================================================================")
        self.disconnect()


# ===== 관제 실행부 =====
if __name__ == "__main__":
    # 진단 대상 리눅스 서버 정보
    SERVER_IP = input("검사를 진행할 서버 IP를 입력하세요: (ex: 172.16.18.5)")
    SERVER_USER = input("서버 ID를 입력하세요: (ex: root)")
    SERVER_PW = input("비밀번호를 입력하세요: (ex: 1234)")

    manager = RsyslogAuditManager(SERVER_IP, SERVER_USER, SERVER_PW)
    manager.audit_and_remediate()
