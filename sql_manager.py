import pymysql

class SqlManager:
    def __init__(self, target_ip, table_name):
        self.target_ip = target_ip
        self.table_name = table_name
        self.history_table = table_name.replace("_table", "_history")
        self.data_store = []

    def record_result(self, code, title, status, reason):
        self.data_store.append({
            'ip': self.target_ip,
            'code': code,
            'title': title,
            'status': status,
            'reason': reason
        })

    # ------------------------------------------------------------------
    # 스키마 준비는 '테이블 단위' 작업이라 장비마다 돌릴 필요가 없다.
    # 병렬 실행 시 여러 스레드가 같은 테이블에 DROP TRIGGER / CREATE TRIGGER 를
    # 동시에 던지면 트리거가 사라지거나 충돌하므로,
    # main.py 가 스레드를 만들기 전에 테이블 종류마다 한 번씩만 호출한다.
    # ------------------------------------------------------------------
    @staticmethod
    def setup_schema(db_config, table_names):
        # 1. DB 자동 생성
        admin_config = db_config.copy()
        db_name = admin_config.pop('database')

        try:
            conn = pymysql.connect(**admin_config)
            with conn.cursor() as cursor:
                cursor.execute(
                    f"CREATE DATABASE IF NOT EXISTS {db_name} "
                    f"CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
                )
            conn.commit()
            conn.close()
        except pymysql.err.OperationalError as exc:
            if exc.args[0] != 1044:
                raise

        # 2. 테이블 종류마다 메인/히스토리 테이블 + 트리거 생성
        conn = pymysql.connect(**db_config)
        with conn.cursor() as cursor:
            for table_name in sorted(set(table_names)):
                history_table = table_name.replace("_table", "_history")

                # 메인 테이블 (최신 상태 1건만 유지)
                cursor.execute(f"""
                    CREATE TABLE IF NOT EXISTS {table_name} (
                        ip VARCHAR(20),
                        code VARCHAR(10),
                        title VARCHAR(255),
                        status VARCHAR(10),
                        reason TEXT,
                        check_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        PRIMARY KEY (ip, code),
                        INDEX idx_status (status),
                        INDEX idx_check_date (check_date)
                    ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
                """)

                # 히스토리 테이블 (갱신 직전 값이 쌓임)
                cursor.execute(f"""
                    CREATE TABLE IF NOT EXISTS {history_table} (
                        seq BIGINT AUTO_INCREMENT PRIMARY KEY,
                        ip VARCHAR(20),
                        code VARCHAR(10),
                        title VARCHAR(255),
                        status VARCHAR(10),
                        reason TEXT,
                        check_date TIMESTAMP NULL,
                        archived_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        INDEX idx_ip_code_date (ip, code, check_date),
                        INDEX idx_archived_at (archived_at)
                    ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
                """)

                # 트리거: 이미 운영 중이면 다시 만들지 않는다.
                # 원격 DB의 제한 계정은 Binary Log 환경에서 CREATE TRIGGER가 막힐 수 있다.
                trigger_name = f"before_{table_name.replace('_table', '')}_update"
                cursor.execute("""
                    SELECT COUNT(*)
                    FROM information_schema.TRIGGERS
                    WHERE TRIGGER_SCHEMA = DATABASE() AND TRIGGER_NAME = %s
                """, (trigger_name,))
                if cursor.fetchone()[0]:
                    continue
                cursor.execute(f"""
                    CREATE TRIGGER {trigger_name}
                    BEFORE UPDATE ON {table_name}
                    FOR EACH ROW
                    BEGIN
                        INSERT INTO {history_table} (ip, code, title, status, reason, check_date)
                        VALUES (OLD.ip, OLD.code, OLD.title, OLD.status, OLD.reason, OLD.check_date);
                    END;
                """)
        conn.commit()
        conn.close()

    def push_to_db(self, db_config):
        if not self.data_store:
            return 0

        conn = pymysql.connect(**db_config)
        with conn.cursor() as cursor:
            sql = f"""
            INSERT INTO {self.table_name} (ip, code, title, status, reason)
            VALUES (%s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                title = VALUES(title),
                status = VALUES(status),
                reason = VALUES(reason),
                check_date = CURRENT_TIMESTAMP
            """
            data = [(d['ip'], d['code'], d['title'], d['status'], d['reason'])
                    for d in self.data_store]
            cursor.executemany(sql, data)
        conn.commit()
        conn.close()
        return len(self.data_store)
