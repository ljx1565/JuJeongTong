# JJT 주정통 점검 콘솔 — 서버 한 대 설치

원래 설계(`CODEX_REQUEST.md`)는 C&C 서버 · DB 서버 · 웹 서버 3대에 나눠 올리는 구조다.
이 문서는 **한 서버에 전부** 올리는 방법이다. 점검 로직(`main.py`, `team_works/`, `sql_manager.py`,
`ssh_connection.py`)은 손대지 않고 그대로 쓴다.

```
[브라우저] ──HTTP :80 (Basic 인증)──> Nginx ──> Gunicorn 127.0.0.1:5080 (jjt-web)
                                                      │  점검 실행 (스레드)
                                                      ├──SSH──> 점검 대상 서버 · 장비 (자기 자신 포함)
                                                      └──TCP 127.0.0.1:3306──> MariaDB jjt_db
```

## 준비

- Rocky Linux / RHEL 9 또는 Ubuntu 22.04 / 24.04, 인터넷 (패키지 · pip 설치)
- 이 폴더(`jjt-standalone`) 전체를 서버에 복사 (예: `scp -r jjt-standalone user@서버:~/`)

## 설치

```bash
cd ~/jjt-standalone
sudo bash deploy/install_single_server.sh
```

옵션 (환경 변수):

| 변수 | 기본값 | 의미 |
|---|---|---|
| `WEB_PORT` | 80 | 콘솔 접속 포트 |
| `ADMIN_USER` | admin | 웹 Basic 인증 사용자 |

```bash
sudo WEB_PORT=8080 ADMIN_USER=jjtadmin bash deploy/install_single_server.sh
```

스크립트가 하는 일:

1. 패키지: Python 3.11(Rocky) / python3(Ubuntu), MariaDB, Nginx
2. `jjt` 시스템 계정 생성, 소스를 `/opt/jjt` 로 복사 (코드가 부모 폴더 이름 `jjt` 를 찾으므로 경로 고정)
3. `/opt/jjt/.venv` 가상환경 + `requirements.txt`
4. MariaDB 를 127.0.0.1 에만 열고 `jjt_db` · `jjt_app@127.0.0.1` 생성 (비밀번호 무작위)
5. `/opt/jjt/local_settings.py` 작성 (권한 640)
6. systemd `jjt-web` (Gunicorn worker 1개 — 작업 상태가 프로세스 메모리에 있으므로)
7. Nginx 리버스 프록시 + Basic 인증, SELinux · 방화벽 포트 허용
8. `/api/health` 확인, 접속 정보를 `/root/jjt-credentials.txt` 에 저장 (root 만 읽기)

다시 실행해도 된다. DB 비밀번호와 웹 비밀번호는 처음 값을 유지하고 소스만 새로 복사한다.

## 사용

1. 브라우저에서 `http://<서버 IP>/` → 로그인 (`/root/jjt-credentials.txt`)
2. **대상 등록**: 호스트명 · IP · SSH 포트 · 계정 · 비밀번호 · 점검 유형
   - 이 서버 자신을 점검하려면 IP `127.0.0.1`, 유형 `unix`
   - 대상 sshd 에 비밀번호 로그인이 허용돼 있어야 한다
   - 점검 계정 권한이 낮으면 설정 파일을 못 읽어 `검토필요` · `오류` 가 늘어난다
3. **SSH 확인** → **점검 실행** → 결과 · 이력 · CSV 내보내기

## 운영 명령

```bash
systemctl status jjt-web            # 상태
journalctl -u jjt-web -f            # 로그
systemctl restart jjt-web           # 재시작
mariadb jjt_db -e "SHOW TABLES;"    # 결과 테이블 (unix_table, unix_history ...)
```

## 보안 메모

- 콘솔 자체에는 로그인이 없고, 점검 대상 SSH 비밀번호가 `jjt_targets` 테이블에 저장된다.
  그래서 Nginx Basic 인증을 앞에 두었다. 내부망에서만 쓰고 외부에 공개하지 않는다.
- Basic 인증은 HTTP 에서 평문으로 오가므로, 실습망 밖에서 쓸 때는 TLS(443) 를 붙인다.
- `/root/jjt-credentials.txt`, `/opt/jjt/local_settings.py` 는 저장소에 올리지 않는다.
