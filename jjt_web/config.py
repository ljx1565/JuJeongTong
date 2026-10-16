from copy import deepcopy


class Settings:
    DATABASE = {
        "host": "127.0.0.1",
        "port": 3306,
        "user": "jjt_app",
        "password": "",
        "database": "jjt_db",
        "unix_socket": None,
        "connect_timeout": 3,
    }
    JJT_DATABASE = None
    MAX_PAGE_SIZE = 500
    MAX_EXPORT_ROWS = 50000

    @classmethod
    def load(cls):
        values = {
            "DATABASE": deepcopy(cls.DATABASE),
            "JJT_DATABASE": deepcopy(cls.JJT_DATABASE),
            "MAX_PAGE_SIZE": cls.MAX_PAGE_SIZE,
            "MAX_EXPORT_ROWS": cls.MAX_EXPORT_ROWS,
        }
        try:
            import local_settings
        except ModuleNotFoundError as error:
            if error.name != "local_settings":
                raise
            return cls(values)

        for name in values:
            if hasattr(local_settings, name):
                values[name] = deepcopy(getattr(local_settings, name))
        return cls(values)

    def __init__(self, values=None):
        for name, value in (values or {}).items():
            setattr(self, name, value)
