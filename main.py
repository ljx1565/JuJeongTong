import json
from ssh_connection import SSHConnection
from sql_manager import SqlManager

from team_works.unix_server import UnixServer
#from team_works.windows_server import WindowsServer
#from team_works.web_service import Webservice
#from team_works.network_device import NetworkDevice
#from team_works.PC import PC
#from team_works.DBMS import DBMS
#from team_works.web_application import WebApplication
#from team_works.virtual_device import VirtualDevice

VALIDATOR_MAP = {
    "unix": UnixServer,
    "network": NetworkDevice
}

DB_CONFIG = {'host': '', 'user': 'admin', 'password': 'asd123!@', 'database': 'jjt_db', 'charset': 'utf8mb4'}

def main():
    with open('device_list.json', 'r', encoding='utf-8') as f:
        device_list = json.load(f)

    db_servers = [d for d in device_list if 'db' in d['hostname'].lower()]
    print("\n--- 결과 저장할 DB 서버를 선택하세요 ---")
    for idx, db in enumerate(db_servers):
        print(f"{idx + 1}. {db['hostname']} ({db['ip']})")
    
    db_choice = int(input("번호 선택: ")) - 1
    DB_CONFIG['host'] = db_servers[db_choice]['ip']
    print(f"[알림] 모든 결과는 {db_servers[db_choice]['hostname']} ({db_servers[db_choice]['ip']}) 로 저장됩니다.")

    table_map = {"unix": "unix_table", "network": "network_table"}

    for device in device_list:
        print(f"\n>>> 점검 시작: {device['hostname']} ({device['ip']})")
        
        validator_class = VALIDATOR_MAP.get(device['type'])
        if not validator_class:
            print(f"  - 지원하지 않는 타입: {device['type']}")
            continue

        conn = SSHConnection(device['ip'], device['conn_info']['port'], 
                             device['conn_info']['user'], device['conn_info']['password'],device['type'])
        conn.connect()
        print ("SSH 접속에 성공했습니다.")
        
        validator = validator_class(conn)
        sql_mgr = SqlManager(device['ip'], table_map.get(device['type'], "other_table"))
        sql_mgr.setup_db(DB_CONFIG)
        
        if hasattr(validator, 'check_list'):
            for code, meta in validator.check_list.items():
                func = getattr(validator, code, None)
                if func:
                    status, reason = func()
                    sql_mgr.record_result(code, meta['title'], status, reason)
                    print(f"  - [{code.upper()}] {meta['title']} : {status}")

        # DB 전송
        sql_mgr.push_to_db(DB_CONFIG)
        conn.disconnect()
        print("SSH 접속을 해제합니다.")

        print(sql_mgr)

if __name__ == "__main__":
    main()
