#!/usr/bin/env bash
# JJT 주정통 점검 콘솔 — 서버 한 대에 전부 설치
#   MariaDB (jjt_db, 127.0.0.1 전용) + 점검 엔진 + Flask/Gunicorn 웹 콘솔 + Nginx (Basic 인증)
# 지원: Rocky Linux / RHEL 9, Ubuntu 22.04 / 24.04
# 사용: sudo bash deploy/install_single_server.sh          (소스 폴더 안에서 실행)
#       WEB_PORT=8080 ADMIN_USER=admin sudo -E bash deploy/install_single_server.sh
# 다시 실행해도 된다: DB 비밀번호와 웹 로그인 정보는 처음 만든 값을 유지한다.
# 점검 로직(main.py, team_works/, sql_manager.py, ssh_connection.py)은 수정하지 않고 그대로 복사한다.
set -euo pipefail

APP_DIR=/opt/jjt                      # jjt_web 이 부모 폴더의 'jjt' 를 찾으므로 이름은 jjt 고정
APP_USER=jjt
WEB_PORT="${WEB_PORT:-80}"
ADMIN_USER="${ADMIN_USER:-admin}"
DB_NAME=jjt_db
DB_USER=jjt_app
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRED_FILE=/root/jjt-credentials.txt

log()  { printf '\n\033[1;36m[JJT]\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31m[JJT 오류]\033[0m %s\n' "$*" >&2; exit 1; }
rand() { openssl rand -base64 24 | tr -d '/+=' | cut -c1-24; }

[ "$(id -u)" -eq 0 ] || die "root 로 실행하세요 (sudo bash $0)"
[ -f "$SRC_DIR/app.py" ] && [ -d "$SRC_DIR/jjt_web" ] && [ -d "$SRC_DIR/team_works" ] || die "소스 폴더를 찾지 못했습니다: $SRC_DIR"

. /etc/os-release
case "${ID}:${ID_LIKE:-}" in
  rocky:*|rhel:*|almalinux:*|*:*rhel*) OS=rhel ;;
  ubuntu:*|debian:*)                   OS=deb ;;
  *) die "지원하지 않는 OS: $PRETTY_NAME" ;;
esac
log "OS: $PRETTY_NAME"

# ---------------------------------------------------------------- 1. 패키지
log "1/8 패키지 설치"
if [ "$OS" = rhel ]; then
  dnf install -y python3.11 python3.11-pip mariadb-server nginx openssl rsync curl policycoreutils-python-utils
  PY=python3.11
  NGINX_CONF=/etc/nginx/conf.d/jjt-web.conf
else
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y python3 python3-venv python3-pip mariadb-server nginx openssl rsync curl
  PY=python3
  NGINX_CONF=/etc/nginx/sites-available/jjt-web
fi
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' || die "Python 3.10 이상이 필요합니다"

# ---------------------------------------------------------------- 2. 서비스 계정 · 소스 배치
log "2/8 서비스 계정과 소스 배치 ($APP_DIR)"
id "$APP_USER" &>/dev/null || useradd --system --home-dir "$APP_DIR" --shell /sbin/nologin "$APP_USER"
mkdir -p "$APP_DIR"
rsync -a --delete \
  --exclude '.venv/' --exclude '__pycache__/' --exclude '*.pyc' --exclude 'dist/' \
  --exclude 'local_settings.py' --exclude 'device_list.json' \
  "$SRC_DIR/" "$APP_DIR/"

# ---------------------------------------------------------------- 3. Python 가상환경
log "3/8 Python 가상환경과 패키지"
[ -x "$APP_DIR/.venv/bin/python" ] || "$PY" -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install --upgrade pip -q
"$APP_DIR/.venv/bin/pip" install -r "$APP_DIR/requirements.txt" -q
"$APP_DIR/.venv/bin/python" -m compileall -q "$APP_DIR" -x '/\.venv/' || true   # 서비스는 /opt/jjt 를 읽기 전용으로 쓴다

# ---------------------------------------------------------------- 4. MariaDB (로컬 전용)
log "4/8 MariaDB 구성 (127.0.0.1 에서만 접속)"
if [ "$OS" = rhel ]; then
  printf '[mysqld]\nbind-address = 127.0.0.1\n' > /etc/my.cnf.d/zz-jjt-bind.cnf
else
  printf '[mysqld]\nbind-address = 127.0.0.1\n' > /etc/mysql/mariadb.conf.d/99-jjt-bind.cnf
fi
systemctl enable --now mariadb
systemctl restart mariadb

if [ -f "$APP_DIR/local_settings.py" ]; then
  DB_PASS="$(cd "$APP_DIR" && .venv/bin/python -c 'import local_settings as s; print(s.DATABASE["password"])')"
  log "기존 local_settings.py 의 DB 비밀번호를 그대로 사용"
else
  DB_PASS="$(rand)"
fi
mariadb <<SQL
CREATE DATABASE IF NOT EXISTS ${DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${DB_USER}'@'127.0.0.1' IDENTIFIED BY '${DB_PASS}';
ALTER USER '${DB_USER}'@'127.0.0.1' IDENTIFIED BY '${DB_PASS}';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, TRIGGER ON ${DB_NAME}.* TO '${DB_USER}'@'127.0.0.1';
FLUSH PRIVILEGES;
SQL

# ---------------------------------------------------------------- 5. 앱 설정
log "5/8 local_settings.py"
cat > "$APP_DIR/local_settings.py" <<PYCONF
DATABASE = {
    "host": "127.0.0.1",
    "port": 3306,
    "user": "${DB_USER}",
    "password": "${DB_PASS}",
    "database": "${DB_NAME}",
    "unix_socket": None,
    "connect_timeout": 3,
}

MAX_PAGE_SIZE = 500
MAX_EXPORT_ROWS = 50000
PYCONF
chown -R root:"$APP_USER" "$APP_DIR"
chmod -R u=rwX,g=rX,o= "$APP_DIR"
chmod 640 "$APP_DIR/local_settings.py"

# 대상 테이블(jjt_targets)은 device_list.json 이 있을 때만 앱이 만든다 → 설치 때 미리 만들어 둔다
(cd "$APP_DIR" && sudo -u "$APP_USER" .venv/bin/python -c \
  "from jjt_web.config import Settings; from jjt_web.repository import make_jjt_database; from jjt_web.targets import TargetRepository; TargetRepository(make_jjt_database(Settings.load())).setup()") \
  || die "jjt_targets 테이블을 만들지 못했습니다"

# ---------------------------------------------------------------- 6. systemd (Gunicorn)
log "6/8 systemd 서비스 jjt-web (127.0.0.1:5080)"
install -m 644 "$APP_DIR/deploy/jjt-web.service.example" /etc/systemd/system/jjt-web.service
systemctl daemon-reload
systemctl enable jjt-web
systemctl restart jjt-web

# ---------------------------------------------------------------- 7. Nginx + Basic 인증
# 콘솔에는 자체 로그인이 없고 점검 대상 SSH 비밀번호를 다루므로 앞단에서 반드시 인증을 건다.
log "7/8 Nginx (포트 $WEB_PORT, Basic 인증)"
HTPASSWD=/etc/nginx/jjt.htpasswd
if [ -s "$HTPASSWD" ] && [ -f "$CRED_FILE" ]; then
  ADMIN_PASS="$(sed -n 's/^웹 비밀번호: //p' "$CRED_FILE")"
else
  ADMIN_PASS="$(rand)"
  printf '%s:%s\n' "$ADMIN_USER" "$(openssl passwd -apr1 "$ADMIN_PASS")" > "$HTPASSWD"
fi
NGINX_GROUP="$( [ "$OS" = rhel ] && echo nginx || echo www-data )"
chown root:"$NGINX_GROUP" "$HTPASSWD"; chmod 640 "$HTPASSWD"

# 기본 사이트(80, default_server)보다 우선하도록 서버 IP · 호스트명을 server_name 에 명시
SERVER_NAMES="$(hostname -I) $(hostname) localhost 127.0.0.1"
cat > "$NGINX_CONF" <<NGX
server {
    listen ${WEB_PORT};
    server_name ${SERVER_NAMES};

    auth_basic "JJT Compliance Center";
    auth_basic_user_file ${HTPASSWD};

    client_max_body_size 2m;

    location / {
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 90s;
        proxy_pass http://127.0.0.1:5080;
    }
}
NGX
if [ "$OS" = deb ]; then
  ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/jjt-web
  if [ "$WEB_PORT" = 80 ]; then rm -f /etc/nginx/sites-enabled/default; fi    # 기본 환영 페이지 비활성
fi

if [ "$OS" = rhel ] && command -v getenforce >/dev/null && [ "$(getenforce)" != Disabled ]; then
  setsebool -P httpd_can_network_connect 1
  semanage port -a -t http_port_t -p tcp "$WEB_PORT" 2>/dev/null || semanage port -m -t http_port_t -p tcp "$WEB_PORT"
fi
nginx -t
systemctl enable nginx
systemctl restart nginx

# ---------------------------------------------------------------- 8. 방화벽 · 확인
log "8/8 방화벽과 동작 확인"
if systemctl is-active --quiet firewalld; then
  firewall-cmd --permanent --add-port="${WEB_PORT}/tcp" && firewall-cmd --reload
elif command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
  ufw allow "${WEB_PORT}/tcp"
fi

ok=""
for _ in $(seq 1 20); do
  if curl -fsS http://127.0.0.1:5080/api/health >/dev/null 2>&1; then ok=1; break; fi
  sleep 1
done
[ -n "$ok" ] || { journalctl -u jjt-web -n 40 --no-pager; die "jjt-web 이 응답하지 않습니다"; }
HEALTH="$(curl -fsS -u "${ADMIN_USER}:${ADMIN_PASS}" "http://127.0.0.1:${WEB_PORT}/api/health")" || die "Nginx 를 거친 접속 실패"

umask 077
cat > "$CRED_FILE" <<CRED
JJT 주정통 점검 콘솔 접속 정보 ($(date '+%F %T'))
주소: http://$(hostname -I | awk '{print $1}'):${WEB_PORT}/
웹 사용자: ${ADMIN_USER}
웹 비밀번호: ${ADMIN_PASS}
DB: ${DB_NAME} / ${DB_USER}@127.0.0.1 (비밀번호는 ${APP_DIR}/local_settings.py)
CRED

log "설치 완료"
echo "  health : $HEALTH"
echo "  주소   : http://$(hostname -I | awk '{print $1}'):${WEB_PORT}/"
echo "  로그인 : ${ADMIN_USER} / (비밀번호는 ${CRED_FILE} 에 저장, root 만 읽기 가능)"
echo "  다음   : 웹 화면에서 점검 대상을 등록 → SSH 확인 → 점검 실행"
echo "           이 서버 자신을 점검하려면 대상 IP 를 127.0.0.1 로 등록"
