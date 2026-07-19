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

    def setup_db(self, db_config):
        # 1. DB 자동 생성
        admin_config = db_config.copy()
        db_name = admin_config.pop('database')
        
        conn = pymysql.connect(**admin_config)
        with conn.cursor() as cursor:
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {db_name} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
            cursor.execute(f"USE {db_name}")
        conn.commit()
        conn.close()

        # 2. 메인 테이블, 히스토리 테이블, 트리거 생성
        conn = pymysql.connect(**db_config)
        with conn.cursor() as cursor:
            # 메인 테이블
            cursor.execute(f"""
                CREATE TABLE IF NOT EXISTS {self.table_name} (
                    ip VARCHAR(20),
                    code VARCHAR(10),
                    title VARCHAR(255),
                    status VARCHAR(10),
                    reason TEXT,
                    check_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (ip, code)
                ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
            """)
            
            # 히스토리 테이블
            cursor.execute(f"""
                CREATE TABLE IF NOT EXISTS {self.history_table} (
                    ip VARCHAR(20),
                    code VARCHAR(10),
                    title VARCHAR(255),
                    status VARCHAR(10),
                    reason TEXT,
                    check_date TIMESTAMP,
                    archived_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
            """)

            # 트리거 생성
            trigger_name = f"before_{self.table_name.replace('_table', '')}_update"
            cursor.execute(f"DROP TRIGGER IF EXISTS {trigger_name}")
            cursor.execute(f"""
                CREATE TRIGGER {trigger_name}
                BEFORE UPDATE ON {self.table_name}
                FOR EACH ROW
                BEGIN
                    INSERT INTO {self.history_table} (ip, code, title, status, reason, check_date)
                    VALUES (OLD.ip, OLD.code, OLD.title, OLD.status, OLD.reason, OLD.check_date);
                END;
            """)
        conn.commit()
        conn.close()

    def push_to_db(self, db_config):
        if not self.data_store: return
        
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
            data = [(d['ip'], d['code'], d['title'], d['status'], d['reason']) for d in self.data_store]
            cursor.executemany(sql, data)
        conn.commit()
        conn.close()
        print(f"  [DB] {len(self.data_store)}건 저장/갱신 완료.")
