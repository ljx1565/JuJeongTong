# JJT 독립 점검 서비스

이 디렉터리만으로 주정통 보안 점검 엔진, Web API, 화면과 운영 실행 파일을 배포할 수 있다.
ALPACA의 `web/`, `alpaca_web/` 또는 프로젝트 루트 Python 모듈을 import하지 않는다.

## 구성

- `app.py`: Web 서비스 실행 진입점
- `jjt_web/`: Flask API, DB 조회·설정, 대상 관리, Background Job과 정적 화면
- `main.py`, `ssh_connection.py`, `sql_manager.py`: 점검 실행과 결과 저장
- `team_works/`: Unix, Windows, Network, PC, DBMS, 가상화, Web Application 점검기
- `requirements.txt`: 7개 점검 유형과 Web 실행에 필요한 Python 패키지
- `deploy/`: Gunicorn systemd 및 Nginx 예시
- `build_release.py`: Credential을 제외한 전달용 ZIP 생성기

## 개발 실행

Python 3.11 이상과 MariaDB가 필요하다.

```bash
cd jjt
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp local_settings.example.py local_settings.py
vi local_settings.py
.venv/bin/python app.py
```

기본 주소는 `http://127.0.0.1:5080`이다. 운영에서는 개발 서버 대신 다음처럼 실행한다.

```bash
.venv/bin/gunicorn --bind 127.0.0.1:5080 \
  --workers 1 --threads 4 --timeout 60 --access-logfile - app:app
```

작업 상태는 Process Memory에 있으므로 Gunicorn Worker는 반드시 1개로 둔다.

## MariaDB 준비

서비스는 `jjt_db`에 대상, 현재 점검 결과와 변경 이력을 저장한다. 최초 구성 계정은 Table과
Trigger를 만들 수 있어야 한다.

```sql
CREATE DATABASE jjt_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'jjt_app'@'127.0.0.1' IDENTIFIED BY '충분히-긴-비밀번호';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, TRIGGER
ON jjt_db.* TO 'jjt_app'@'127.0.0.1';
FLUSH PRIVILEGES;
```

`local_settings.py`의 `DATABASE`를 실제 접속 정보로 바꾼 뒤 `/api/health`를 확인한다.

## 대상 등록

Web 화면에서 대상을 등록할 수 있다. 초기 대상이 필요하면 `device_list.example.json`을
`device_list.json`으로 복사해 수정한다. DB의 `jjt_targets`가 비었을 때만 이 파일을 Seed로 쓴다.

대상 접속 비밀번호는 현재 `jjt_targets.password_value`에 저장된다. DB와 Web 접근을 내부망과
인증된 운영자로 제한하고, 외부에 직접 공개하지 않는다.

## 전달용 ZIP

반드시 다음 명령으로 전달본을 만든다.

```bash
python3 build_release.py
```

`dist/jjt-standalone.zip`에는 현재 운영 장비와 Credential이 들어 있는 `device_list.json`,
`local_settings.py`, 가상환경, Cache와 기존 결과 ZIP이 포함되지 않는다. 수신자는 예시 설정을
복사해 자기 환경 값을 입력해야 한다.
