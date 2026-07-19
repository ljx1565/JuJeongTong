import base64
import paramiko


class Window:

    def __init__(self, host, username, password, port=22):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.ssh = None

    def connect(self):
        """SSH 연결을 수립합니다. (try-except 없이 구현)"""
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # 연결을 시도합니다.
        # (만약 호스트 정보 불일치 등으로 접속 실패 시 프로그램은 자연스럽게 에러 메시지와 함께 중단되며,
        #  프로그램이 종료되면서 열려있던 자원과 소켓은 OS가 안전하게 회수합니다.)
        self.ssh.connect(
            self.host,
            port=self.port,
            username=self.username,
            password=self.password,
        )

        # SSH 세션의 활성화 여부를 확인하여 연결 성 패를 판별합니다.
        transport = self.ssh.get_transport()
        if transport and transport.is_active():
            print(f"[*] {self.host}에 성공적으로 SSH 연결되었습니다.")
            return True
        else:
            print("[!] SSH 연결이 활성화되지 않았습니다.")
            return False

    def disconnect(self):
        """SSH 연결을 해제합니다."""
        if self.ssh:
            self.ssh.close()
            self.ssh = None
            print("[*] SSH 연결이 성공적으로 해제되었습니다.")

    def __del__(self):
        """객체가 소멸할 때 자동으로 접속을 해제하는 안전 소멸자입니다."""
        if self.ssh:
            self.disconnect()

    def run_powershell(self, command_str):
        """PowerShell 명령을 Base64로 인코딩하여 안전하게 실행하고 결과를 반환합니다."""
        if not self.ssh:
            print("[!] SSH 연결이 수립되지 않아 명령을 실행할 수 없습니다.")
            return "", "SSH Connection Missing"

        # PowerShell -EncodedCommand를 위한 UTF-16LE + Base64 인코딩
        encoded_cmd = base64.b64encode(command_str.encode("utf-16le")).decode(
            "ascii"
        )
        
        # [수정 포인트] 파워셸 실행 시 진행 상태 바(Progress) 스트림과 CLIXML 출력을 끄도록 옵션 추가
        ssh_command = f"powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"$ProgressPreference = 'SilentlyContinue'; powershell -NoProfile -NonInteractive -EncodedCommand {encoded_cmd}\""

        stdin, stdout, stderr = self.ssh.exec_command(ssh_command)

        output = stdout.read().decode("utf-8", errors="ignore").strip()
        error = stderr.read().decode("utf-8", errors="ignore").strip()

        # [수정 포인트] 파워셸 최초 실행 시 발생하는 CLIXML 포맷의 경고/진행 정보를 필터링
        if error.startswith("#< CLIXML") and "Preparing modules" in error:
            error = ""

        return output, error

    def W_01_Administrator_Rename(self):
        """W-01: Administrator 계정 이름 변경 등 보안성 강화."""
        # SID 끝자리가 500인 로컬 최상위 관리자 계정 이름 조회
        ps_script = "(Get-CimInstance -ClassName Win32_UserAccount -Filter \"LocalAccount = TRUE and SID like 'S-1-5-%-500'\").Name"
        output, error = self.run_powershell(ps_script)

        # 오류 변수에 값이 들어있거나 결과가 비어있는 경우 조건문으로 분기 처리
        if error != "":
            return {
                "id": "W-01",
                "title": "Administrator 계정 이름 변경 등 보안성 강화",
                "result": "오류",
                "detail": f"조회 중 오류 발생: {error}",
            }

        admin_name = output.strip()
        if admin_name == "":
            return {
                "id": "W-01",
                "title": "Administrator 계정 이름 변경 등 보안성 강화",
                "result": "오류",
                "detail": "로컬 Administrator 계정을 식별할 수 없습니다.",
            }

        # 대소문자 무관 비교 후 결과 도출
        if admin_name.lower() == "administrator":
            return {
                "id": "W-01",
                "title": "Administrator 계정 이름 변경 등 보안성 강화",
                "result": "취약",
                "detail": f"기본 관리자 계정 이름인 '{admin_name}'을 그대로 사용 중입니다.",
            }
        else:
            return {
                "id": "W-01",
                "title": "Administrator 계정 이름 변경 등 보안성 강화",
                "result": "양호",
                "detail": f"관리자 계정 이름이 '{admin_name}'(으)로 안전하게 변경되어 있습니다.",
            }

    def W_02_Guest_Disable(self):
        """W-02: Guest 계정 비활성화."""
        # SID 끝자리가 501인 로컬 Guest 계정의 비활성화(Disabled) 여부 조회
        ps_script = "(Get-CimInstance -ClassName Win32_UserAccount -Filter \"LocalAccount = TRUE and SID like 'S-1-5-%-501'\").Disabled"
        output, error = self.run_powershell(ps_script)

        # 오류 변수에 값이 들어있거나 결과가 비어있는 경우 조건문으로 분기 처리
        if error != "":
            return {
                "id": "W-02",
                "title": "Guest 계정 비활성화",
                "result": "오류",
                "detail": f"조회 중 오류 발생: {error}",
            }

        disabled_status = output.strip().lower()
        if disabled_status == "":
            return {
                "id": "W-02",
                "title": "Guest 계정 비활성화",
                "result": "오류",
                "detail": "로컬 Guest 계정을 식별할 수 없습니다.",
            }

        # Disabled 속성이 True이면 사용 안 함(양호), False이면 사용 함(취약)
        if disabled_status == "true":
            return {
                "id": "W-02",
                "title": "Guest 계정 비활성화",
                "result": "양호",
                "detail": "Guest 계정이 정상적으로 비활성화(사용 안 함) 되어 있습니다.",
            }
        else:
            return {
                "id": "W-02",
                "title": "Guest 계정 비활성화",
                "result": "취약",
                "detail": "Guest 계정이 활성화(사용 함) 상태입니다. 비활성화 조치가 필요합니다.",
            }


# ==========================================
# 실행 예시
# ==========================================
if __name__ == "__main__":
    # 대상 윈도우 서버 정보 설정
    TARGET_IP = "172.16.5.1"
    TARGET_PORT = 22
    USERNAME = "admin"
    PASSWORD = "601"

    # 1. 객체 생성
    inspector = Window(
        host=TARGET_IP, username=USERNAME, password=PASSWORD, port=TARGET_PORT
    )

    # 2. SSH 접속 및 성공 여부 체크 (if문으로 판단)
    is_connected = inspector.connect()

    if is_connected:
        results = []
        
        # 3. 취약점 진단 함수 실행
        results.append(inspector.W_01_Administrator_Rename())
        results.append(inspector.W_02_Guest_Disable())

        # 4. 결과 출력
        print("\n" + "=" * 60)
        print("                 윈도우 보안 가이드라인 점검 결과")
        print("=" * 60)
        for res in results:
            print(f"[{res['id']}] {res['title']}")
            print(f"  - 판정 결과: {res['result']}")
            print(f"  - 상세 내용: {res['detail']}")
            print("-" * 60)

        # 5. 모든 작업이 정상 종료되었으므로 SSH 접속 해제
        inspector.disconnect()
    else:
        print("[!] 점검 대상 컴퓨터에 연결하지 못해 스크립트를 종료합니다.")
