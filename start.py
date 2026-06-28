# ===== 관제 실행부 =====
if __name__ == "__main__":
    # 진단 대상 리눅스 서버 정보
    SERVER_IP = input("검사를 진행할 서버 IP를 입력하세요: (ex: 172.16.18.5)")
    SERVER_USER = input("서버 ID를 입력하세요: (ex: root)")
    SERVER_PW = input("비밀번호를 입력하세요: (ex: 1234)")

    manager = RsyslogAuditManager(SERVER_IP, SERVER_USER, SERVER_PW)
    manager.audit_and_remediate()
