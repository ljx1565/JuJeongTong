# 주정통 점검 시스템 — 환경 구축 및 대시보드 제작 요청서

## 0. 한 줄 요약

기존 관제 인프라(C&C 서버 / 웹 서버 / 로그 DB 서버)에 **주정통 취약점 점검 기능**을 얹는다.
점검 코드는 C&C 서버에서 돌고, 결과는 DB 서버의 **새 스키마 `jjt_db`** 에 쌓이며,
웹 서버에 **읽기 전용 대시보드**를 붙여 `pnjj.mg.com` 으로 접근한다.

---

## 1. 현재 환경 (이미 있는 것 — 건드리지 말 것)

| 역할 | 설명 |
|---|---|
| C&C 서버 | 서버/네트워크 관제용. 여기에 주정통 점검 코드를 배치 |
| 웹 서버 | 기존 관제 대시보드 운영 중. 주정통 대시보드를 **추가로** 붙임 |
| DB 서버 | 관제 로그 저장용. 주정통용 스키마를 **추가로** 생성 |
| DNS 서버 | 별도 장비. `pnjj.mg.com` 레코드를 여기에 등록 요청 |

**기존 로그 수집 파이프라인, 기존 대시보드, 기존 DB 스키마는 수정 대상이 아니다.**
주정통은 전부 "추가"로만 들어간다.

---

## 2. 작업 범위

### 해야 할 것

1. DB 서버에 `jjt_db` 스키마 및 테이블/트리거 생성 (§4 DDL)
2. DB 계정 2개 생성 — 쓰기용(C&C), 읽기 전용(대시보드) (§5)
3. C&C 서버에 점검 코드 배치 및 실행 환경 구성 (§6)
4. 웹 서버에 주정통 대시보드 추가 (§7)
5. DNS 서버에 `pnjj.mg.com` 등록 요청 및 웹 서버 vhost 구성 (§8)

### 하지 말 것

- 점검 로직(`team_works/*.py`) 수정 — 각 팀 담당자 소관
- 기존 관제 대시보드/로그 스키마 변경
- 대시보드에서 점검 실행 트리거 제공 (1차 범위 밖. §9 참고)

---

## 3. 데이터 흐름

```
[C&C 서버]
  main.py 실행 (수동 또는 cron)
    ├─ device_list.json 에서 대상 장비 로드
    ├─ 스레드 8개로 장비별 SSH 병렬 점검
    └─ 장비마다 결과를 배치로 INSERT
                    │
                    ▼
[DB 서버] jjt_db
    ├─ {type}_table    ← 최신 상태 (PK: ip+code, UPSERT)
    └─ {type}_history  ← 갱신 직전 값 (BEFORE UPDATE 트리거)
                    │
                    ▼ (읽기 전용 계정)
[웹 서버] 주정통 대시보드  ←── https://pnjj.mg.com
```

점검 코드는 **DB에 쓰기만** 하고, 대시보드는 **읽기만** 한다. 둘 사이에 다른 연결은 없다.

---

## 4. DB 스키마

### 생성 대상

스키마 `jjt_db` 안에 장비 타입별로 **메인 테이블 + 히스토리 테이블 + 트리거** 한 세트씩, 총 7세트.

| 타입 | 메인 테이블 | 히스토리 테이블 | 트리거 | 점검 항목 수 |
|---|---|---|---|---|
| unix | `unix_table` | `unix_history` | `before_unix_update` | 55 |
| windows | `windows_table` | `windows_history` | `before_windows_update` | 62 |
| network | `network_table` | `network_history` | `before_network_update` | 31 |
| pc | `pc_table` | `pc_history` | `before_pc_update` | 18 |
| dbms | `dbms_table` | `dbms_history` | `before_dbms_update` | 26 |
| virtual | `virtual_table` | `virtual_history` | `before_virtual_update` | 25 |
| web_application | `webapp_table` | `webapp_history` | `before_webapp_update` | 5 |

### DDL (unix 기준 — 나머지 6종은 테이블명만 치환)

```sql
CREATE DATABASE IF NOT EXISTS jjt_db
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE jjt_db;

CREATE TABLE IF NOT EXISTS unix_table (
    ip         VARCHAR(20),
    code       VARCHAR(10),
    title      VARCHAR(255),
    status     VARCHAR(10),
    reason     TEXT,
    check_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (ip, code),
    INDEX idx_status (status),
    INDEX idx_check_date (check_date)
) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS unix_history (
    seq         BIGINT AUTO_INCREMENT PRIMARY KEY,
    ip          VARCHAR(20),
    code        VARCHAR(10),
    title       VARCHAR(255),
    status      VARCHAR(10),
    reason      TEXT,
    check_date  TIMESTAMP NULL,
    archived_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ip_code_date (ip, code, check_date),
    INDEX idx_archived_at (archived_at)
) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

DROP TRIGGER IF EXISTS before_unix_update;
CREATE TRIGGER before_unix_update
BEFORE UPDATE ON unix_table
FOR EACH ROW
BEGIN
    INSERT INTO unix_history (ip, code, title, status, reason, check_date)
    VALUES (OLD.ip, OLD.code, OLD.title, OLD.status, OLD.reason, OLD.check_date);
END;
```

> 이 DDL은 `sql_manager.py` 의 `SqlManager.setup_schema()` 가 실행 시 자동으로 만든다.
> 수동 생성은 선택 사항이며, 만들어 두면 C&C가 DDL 권한 없이도 동작한다.

### 컬럼 의미

| 컬럼 | 값 | 비고 |
|---|---|---|
| `ip` | 점검 대상 장비 IP | |
| `code` | `U-01`, `W-01`, `N-01`, `D-01`, `HV-01`, `EP` 등 | KISA 가이드 항목 코드 |
| `title` | 항목 제목 | 최대 62자 관측 |
| `status` | **`양호` / `취약` / `해당없음` / `검토필요` / `오류` 5가지만** | 이외 값 없음 |
| `reason` | 판정 근거 문자열 | 빈 문자열 없음 |
| `check_date` | 마지막 갱신 시각 | UPSERT 시 자동 갱신 |

### 데이터 규모

메인 테이블 합계 **약 960행** (서버 10대 + 네트워크 10대 + DBMS/가상화/웹 기준).
PC를 점검 대상에 넣으면 **PC 1대당 18행**이 추가된다 (PC 50대면 900행).
재점검해도 메인 테이블 행 수는 변하지 않고(PK UPSERT), **히스토리에 회당 같은 양이 누적**된다.
매일 1회 실행 시 연간 수십만 행 수준 — 파티셔닝 불필요.

---

## 5. DB 계정

**계정을 반드시 2개로 분리할 것.** 대시보드가 쓰기 권한을 갖지 않게 한다.

```sql
-- C&C 서버 전용 (쓰기)
CREATE USER 'jjt_writer'@'<C&C서버IP>' IDENTIFIED BY '<암호>';
GRANT SELECT, INSERT, UPDATE, CREATE, INDEX, TRIGGER ON jjt_db.* TO 'jjt_writer'@'<C&C서버IP>';

-- 대시보드 전용 (읽기)
CREATE USER 'jjt_reader'@'<웹서버IP>' IDENTIFIED BY '<암호>';
GRANT SELECT ON jjt_db.* TO 'jjt_reader'@'<웹서버IP>';

FLUSH PRIVILEGES;
```

- 호스트를 `%` 로 열지 말 것. C&C / 웹 서버 IP로 한정.
- DB 서버의 3306 포트는 외부에 노출하지 말 것. 방화벽에서 두 IP만 허용.
- `CREATE/INDEX/TRIGGER` 권한은 `setup_schema()` 자동 생성용. §4 DDL을 수동으로 미리 만들었다면 `SELECT, INSERT, UPDATE` 만으로 충분하다.

---

## 6. C&C 서버 구성

### 배치

```
/opt/jujungtong/
├── main.py
├── ssh_connection.py
├── sql_manager.py
├── device_list.json
└── team_works/
    ├── result_spec.py
    ├── unix_server.py
    ├── windows_server.py
    ├── network_device.py
    ├── DBMS.py
    ├── virtualization_device.py
    └── web_application_jun.py
```

### device_list.json 스키마

**호스트 1대 = 항목 1개.** 한 호스트에 여러 종류의 점검이 필요하면 `checks` 배열에 나열한다.
같은 IP를 여러 항목으로 중복해서 쓰지 않는다.

```json
{
  "ip": "172.16.14.10",
  "hostname": "rocky_host",
  "role": "client",
  "checks": ["unix", "web_application"],
  "conn_info": { "port": 22, "user": "root", "password": "..." },
  "web_info": { "path": "/var/www/html", "accept_new_host_key": true }
}
```

| 필드 | 설명 |
|---|---|
| `checks` | 이 호스트에 적용할 점검 종류 배열 (`unix` `windows` `network` `pc` `dbms` `virtual` `web_application`) |
| `conn_info` | 공통 접속 정보 |
| `db_info` | `checks` 에 `dbms` 가 있을 때 필요 |
| `virt_info` | `checks` 에 `virtual` 이 있을 때 필요. `platform` 은 `esxi` \| `xenserver` 필수 |
| `web_info` | `checks` 에 `web_application` 이 있을 때 필요. `path` 필수 |
| `timeouts` | 선택. `{"connect": 15, "command": 120}` |

**한 호스트의 여러 점검은 스레드 안에서 순차 실행**된다.
같은 장비에 동시에 여러 SSH 세션을 붙이지 않기 위한 설계다.
병렬 단위는 점검 건수가 아니라 호스트 수다.

### 의존성

```
paramiko      # 유닉스/윈도우 SSH
netmiko       # 네트워크 장비 (cisco_ios)
pymysql       # 결과 DB 적재
pyVmomi       # ESXi vSphere API (virtual 타입 사용 시)
```

가상환경(`/opt/jujungtong/venv`) 사용 권장. Python 3.10 이상.

### PC 점검 전제 조건 (`checks: ["pc"]`)

PC 점검(PC-01 ~ PC-18)은 Windows 10/11 대상이며 **SSH + PowerShell** 로 동작한다.
Windows 는 OpenSSH Server 가 기본 설치가 아니므로 점검 대상 PC마다 아래가 필요하다.

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd; Set-Service -Name sshd -StartupType Automatic
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell `
  -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force
```

- `conn_info.user` 는 **관리자 그룹 계정**이어야 한다. PC-08(멀티 부팅, `bcdedit`)은 권한이 없으면 `검토필요`로 빠진다.
- **PC-09, PC-16 은 `HKCU`(접속 계정의 레지스트리)를 읽는다.** 실제 사용자 계정과 다른 계정으로 접속하면 다른 값이 나오므로, 점검 대상 사용자 계정으로 접속하거나 결과를 별도 확인해야 한다.
- PC는 수시로 꺼지고 IP도 유동적일 수 있어 실패가 잦을 수 있다. 실패한 PC는 건너뛰고 나머지가 계속 진행되므로, 대시보드에서 `check_date` 가 오래된 PC를 걸러 보는 것이 좋다.

### 실행

```bash
cd /opt/jujungtong && python3 main.py
```

실행하면 ① 점검 대상 선택(전체/개별) ② 결과 저장 DB 선택 을 대화형으로 묻고,
그 뒤로는 입력 없이 끝까지 진행한다.

### 동시성 설정 (`main.py` 상단)

```python
MAX_WORKERS = 8        # 동시 접속 장비 수
DEVICE_DEADLINE = 1800 # 장비 1대 상한(초)
```

`MAX_WORKERS` 를 8로 잡은 이유: sshd 기본값 `MaxStartups 10:30:100` 에서
인증 중 연결이 10개를 넘으면 무작위 거절이 시작되므로 여유를 뒀다.
장비를 크게 늘릴 계획이면 대상 서버의 `MaxStartups` 를 함께 조정해야 한다.

### SSH 호스트 키

`device_list.json` 에서 `strict_host_key: false` 로 둔 장비는 미등록 호스트 키를 그대로 수락한다.
이 경우 paramiko 가 매 실행마다 `UserWarning: Unknown ssh-ed25519 host key` 를 찍는데,
`main.py` 상단에서 해당 경고만 필터링해 두었다.

**운영 환경에서는 검증을 켜는 것을 권장한다.**

```bash
ssh-keyscan -H 172.16.0.50 >> ~/.ssh/known_hosts   # 지문 확인 후 등록
```

등록 후 `device_list.json` 에서 `strict_host_key` 를 `true` 로 바꾸면
paramiko 가 `RejectPolicy` 를 쓰게 되어 중간자 공격을 탐지할 수 있다.

### ⚠ 자격증명 처리 (검토 필요)

현재 `device_list.json` 에 **모든 장비의 SSH/DB 비밀번호가 평문**으로 들어 있다.
C&C 서버가 뚫리면 전체 인프라 계정이 함께 유출된다. 최소한 다음은 적용할 것.

- 파일 권한 `600`, 소유자를 실행 계정으로 한정
- git 등 형상관리에 올리지 않기 (`.gitignore` 등록)
- 가능하면 SSH 키 인증 또는 환경변수/시크릿 매니저로 전환

---

## 7. 대시보드 요구사항

### 기술 스택

기존 관제 대시보드와 동일한 스택을 쓰되, **주정통은 별도 경로/메뉴로 분리**한다.
프레임워크는 자유. 아래 화면과 쿼리만 충족하면 된다.

### 화면 1 — 전체 현황 (메인)

- 장비 타입별 카드: 총 항목 수, 취약 건수, 마지막 점검 시각
- 전체 취약률 도넛 차트 (양호/취약/해당없음/검토필요/오류 5분류)
- 최근 점검 이력 타임라인

```sql
-- 타입별 상태 집계 (테이블마다 실행 후 합치거나 UNION ALL)
SELECT 'unix' AS type, status, COUNT(*) AS cnt
FROM unix_table GROUP BY status
UNION ALL
SELECT 'windows', status, COUNT(*) FROM windows_table GROUP BY status
UNION ALL
SELECT 'network', status, COUNT(*) FROM network_table GROUP BY status;
```

### 화면 2 — 장비별 상세

- 장비 목록 (IP, 호스트명, 타입, 취약 건수, 마지막 점검 시각)
- 장비 클릭 → 해당 장비의 전체 점검 항목 표
- 표 컬럼: `code` / `title` / `status` / `reason` / `check_date`
- `status` 필터 + `code` 정렬 지원

```sql
SELECT code, title, status, reason, check_date
FROM unix_table
WHERE ip = %s
ORDER BY code;
```

### 화면 3 — 항목별 현황

- 특정 점검 항목(예: U-01)이 어느 장비에서 취약한지 가로로 비교
- "전 장비에서 취약한 항목" 상위 목록 → 우선 조치 대상 파악용

```sql
SELECT code, title, COUNT(*) AS vuln_count
FROM unix_table
WHERE status = '취약'
GROUP BY code, title
ORDER BY vuln_count DESC;
```

### 화면 4 — 변경 이력

- 특정 장비/항목의 상태 변화 추적 (양호 → 취약 전환 감지)
- 히스토리 테이블 조회

```sql
SELECT status, reason, check_date, archived_at
FROM unix_history
WHERE ip = %s AND code = %s
ORDER BY archived_at DESC
LIMIT 50;
```

### 공통 사항

- **읽기 전용.** INSERT/UPDATE/DELETE 하는 경로를 만들지 말 것
- `reason` 은 길 수 있으니 목록에서는 말줄임, 상세에서 전체 표시
- `status` 색상 규칙 통일 — 양호(초록) / 취약(빨강) / 검토필요(주황) / 해당없음(회색) / 오류(회색 테두리)
- 모든 쿼리는 **파라미터 바인딩**으로. 문자열 포매팅으로 IP나 코드를 끼워 넣지 말 것

---

## 8. 도메인 및 웹 서버

### DNS

- 별도 DNS 서버에 **`pnjj.mg.com` → 웹 서버 IP** A 레코드 등록 요청
- 내부망 전용인지 외부 공개인지 먼저 확정할 것 (아래 접근 통제와 직결)

### 웹 서버

- `pnjj.mg.com` 전용 vhost 추가 (기존 관제 대시보드 vhost와 분리)
- HTTPS 적용. 사설 도메인이므로 사내 CA 또는 자체 서명 인증서 사용
- HTTP → HTTPS 리다이렉트

### 접근 통제

점검 결과는 **인프라 전체의 취약점 목록** 이다. 유출 시 그대로 공격 지도가 된다.

- 인증 없이 열어두지 말 것 (최소 기본 인증, 가능하면 기존 관제 대시보드 인증 연동)
- 내부망 한정이면 방화벽/`allow` 대역 제한 병행
- 접근 로그를 기존 로그 파이프라인에 함께 수집

---

## 9. 이번 범위에서 제외 (추후 논의)

- 대시보드에서 점검 실행 트리거 — 웹에서 SSH 점검을 띄우는 구조는 권한 설계가 별도로 필요
- 점검 결과 알림(메일/슬랙)
- 웹 서비스 점검(`web_service.py`) — 담당자 코드 미완성
- 자동 스케줄링 — 1차는 수동 실행, 안정화 후 cron 등록

---

## 10. 인수 조건 체크리스트

- [ ] `jjt_db` 및 14개 테이블 + 7개 트리거 생성 확인
- [ ] `jjt_writer` / `jjt_reader` 계정 분리, 호스트 한정 확인
- [ ] DB 3306 포트가 C&C/웹 서버 IP에서만 접근 가능한지 확인
- [ ] C&C에서 `main.py` 실행 → 전체 점검 → DB 적재 성공
- [ ] 재실행 시 메인 테이블 행 수가 늘지 않고 히스토리에만 쌓이는지 확인
- [ ] `https://pnjj.mg.com` 접속 및 인증 동작 확인
- [ ] 대시보드 4개 화면 동작 확인
- [ ] 대시보드 계정으로 쓰기 시도 시 거부되는지 확인
- [ ] (PC 점검 시) 대상 PC에 OpenSSH Server 설치 및 관리자 계정 접속 확인

---

## 부록 — 점검 결과 규격

모든 점검 함수는 `(status, reason)` 튜플을 반환한다.

| status | 의미 |
|---|---|
| `양호` | 점검 기준 충족 |
| `취약` | 점검 기준 미충족 |
| `해당없음` | 대상 서비스/설정이 없어 점검 대상 아님 |
| `검토필요` | 자동 판정 불가, 담당자 수동 확인 필요 |
| `오류` | 명령 실행 실패 등으로 점검 자체가 불가 |

대시보드는 이 5개 외의 값을 받지 않는다고 가정해도 된다.
상세 규격은 `team_works/README_결과규격.md` 참고.
