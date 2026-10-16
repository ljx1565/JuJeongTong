import re
from datetime import datetime
from zoneinfo import ZoneInfo


SEOUL_TIMEZONE = ZoneInfo("Asia/Seoul")
IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def quote(identifier):
    if not IDENTIFIER.match(identifier or ""):
        raise ValueError("invalid SQL identifier")
    return "`" + identifier + "`"


def to_database_time(value):
    parsed = parse_database_time(value)
    if not parsed:
        raise ValueError("시간 형식이 올바르지 않습니다.")
    return parsed.astimezone(SEOUL_TIMEZONE).replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S.%f")


def parse_database_time(value):
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value).strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=SEOUL_TIMEZONE)
    return parsed.astimezone(SEOUL_TIMEZONE)
