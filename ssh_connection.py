import paramiko

try:
    import netmiko
except ImportError:
    netmiko = None

class SSHConnection:
    def __init__(self, hostname, port, username, password, device_type, device=None):
        self.hostname = hostname
        self.port = port
        self.username = username
        self.password = password
        self.device_type = device_type
        self.os_type = "unknown"
        # device_list.json 의 해당 항목 원본.
        # dbms/virtual 처럼 추가 접속 정보(db_info, virt_info)가 필요한 모듈이 꺼내 쓴다.
        self.device = device or {}

        # 병렬 실행 시 죽은 장비가 워커를 영구 점유하지 않도록 타임아웃을 둔다
        timeouts = self.device.get("timeouts") or {}
        self.connect_timeout = timeouts.get("connect", 15)   # 접속 단계
        self.command_timeout = timeouts.get("command", 120)  # 명령 1건
        
        self.ssh = None
        self.net_connect = None

    def connect(self):
        if self.device_type == "network":
            if netmiko is None:
                raise RuntimeError("network 점검에는 netmiko 설치가 필요합니다")
            self.net_connect = netmiko.ConnectHandler(
                device_type='cisco_ios', 
                host=self.hostname, port=self.port,
                username=self.username, password=self.password,
                conn_timeout=self.connect_timeout,
                banner_timeout=self.connect_timeout,
                auth_timeout=self.connect_timeout
            )
        else:
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh.connect(self.hostname, port=self.port,
                             username=self.username, password=self.password,
                             timeout=self.connect_timeout,
                             banner_timeout=self.connect_timeout,
                             auth_timeout=self.connect_timeout)
            self._detect_os() # 리눅스 서버일 때만 실행

    def _detect_os(self):
        # 파라미코를 통한 명령어 실행
        _, stdout, _ = self.ssh.exec_command("cat /etc/os-release", timeout=self.command_timeout)
        os_info = stdout.read().decode('utf-8').lower()
        
        if "debian" in os_info or "ubuntu" in os_info:
            self.os_type = "debian"
        elif "rhel" in os_info or "centos" in os_info or "rocky" in os_info:
            self.os_type = "redhat"

    def execute_cmd(self, cmd):
        if self.device_type == "network":
            return self.net_connect.send_command(cmd, read_timeout=self.command_timeout)
        else:
            _, stdout, _ = self.ssh.exec_command(cmd, timeout=self.command_timeout)
            return stdout.read().decode('utf-8', errors='replace').strip()

    def disconnect(self):
        if self.device_type == "network":
            self.net_connect.disconnect()
        else:
            self.ssh.close()
