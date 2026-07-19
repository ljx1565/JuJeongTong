import netmiko
import paramiko

class SSHConnection:
    def __init__(self, hostname, port, username, password, device_type):
        self.hostname = hostname
        self.port = port
        self.username = username
        self.password = password
        self.device_type = device_type
        self.os_type = "unknown"
        
        self.ssh = None
        self.net_connect = None

    def connect(self):
        if self.device_type == "network":
            self.net_connect = netmiko.ConnectHandler(
                device_type='cisco_ios', 
                host=self.hostname, port=self.port,
                username=self.username, password=self.password
            )
        else:
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh.connect(self.hostname, port=self.port, username=self.username, password=self.password)
            self._detect_os() # 리눅스 서버일 때만 실행

    def _detect_os(self):
        # 파라미코를 통한 명령어 실행
        _, stdout, _ = self.ssh.exec_command("cat /etc/os-release")
        os_info = stdout.read().decode('utf-8').lower()
        
        if "debian" in os_info or "ubuntu" in os_info:
            self.os_type = "debian"
        elif "rhel" in os_info or "centos" in os_info or "rocky" in os_info:
            self.os_type = "redhat"

    def execute_cmd(self, cmd):
        if self.device_type == "network":
            return self.net_connect.send_command(cmd)
        else:
            _, stdout, _ = self.ssh.exec_command(cmd)
            return stdout.read().decode('utf-8').strip()

    def disconnect(self):
        if self.device_type == "network":
            self.net_connect.disconnect()
        else:
            self.ssh.close()
