from contextlib import contextmanager
from datetime import date, datetime, timezone
from decimal import Decimal
from zoneinfo import ZoneInfo

import pymysql
from pymysql.cursors import DictCursor


SEOUL_TIMEZONE = ZoneInfo("Asia/Seoul")


class Database:
    def __init__(self, settings):
        self.settings = settings

    def connect(self, autocommit=True):
        options = dict(self.settings.DATABASE)
        if not options.get("unix_socket"):
            options.pop("unix_socket", None)
        if not options.get("host"):
            options.pop("host", None)
        options.update(
            charset="utf8mb4", cursorclass=DictCursor, autocommit=autocommit,
            init_command="SET time_zone = '+09:00'"
        )
        return pymysql.connect(**options)

    @contextmanager
    def cursor(self):
        connection = self.connect()
        try:
            with connection.cursor() as cursor:
                yield cursor
        finally:
            connection.close()

    def query(self, sql, params=None):
        with self.cursor() as cursor:
            cursor.execute(sql, params or [])
            return [normalise(row) for row in cursor.fetchall()]

    def one(self, sql, params=None):
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def execute(self, sql, params=None):
        with self.cursor() as cursor:
            cursor.execute(sql, params or [])
            return cursor.rowcount

    def insert(self, sql, params=None):
        with self.cursor() as cursor:
            cursor.execute(sql, params or [])
            return cursor.lastrowid

    @contextmanager
    def transaction(self):
        connection = self.connect(autocommit=False)
        try:
            with connection.cursor() as cursor:
                yield cursor
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def health(self):
        started = datetime.now(timezone.utc)
        row = self.one("SELECT VERSION() AS version, DATABASE() AS database_name")
        elapsed = (datetime.now(timezone.utc) - started).total_seconds() * 1000
        return {**row, "latency_ms": round(elapsed, 1)}

    def table_columns(self, table):
        rows = self.query(
            "SELECT COLUMN_NAME AS name, DATA_TYPE AS data_type "
            "FROM information_schema.COLUMNS "
            "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s",
            [table],
        )
        return {row["name"]: row for row in rows}


def normalise(value):
    if isinstance(value, dict):
        return {key: normalise(item) for key, item in value.items()}
    if isinstance(value, list):
        return [normalise(item) for item in value]
    if isinstance(value, datetime):
        text = value.isoformat(timespec="microseconds")
        return text + "+09:00" if value.tzinfo is None else text
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value
