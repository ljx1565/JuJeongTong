python dbms.py \
  --ip 192.168.1.100 \
  --ssh-port 22 \
  --ssh-user ubuntu \
  --ssh-password 'SSH_PASSWORD' \
  --db-port 3306 \
  --db-user root \
  --db-password 'DB_PASSWORD'

python dbms.py \
  --ip 192.168.1.100 \
  --ssh-user ubuntu \
  --ssh-password 'SSH_PASSWORD' \
  --db-user root \
  --db-password 'DB_PASSWORD' \
  --save-results \
  --setup-result-db \
  --result-db-host 127.0.0.1 \
  --result-db-port 3306 \
  --result-db-user result_admin \
  --result-db-password 'RESULT_DB_PASSWORD' \
  --result-db-name vulnerability \
  --result-table dbms_table