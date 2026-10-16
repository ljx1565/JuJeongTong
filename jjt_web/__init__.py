from flask import Flask

from .config import Settings

from .api import api


def create_app(settings=None):
    app = Flask(__name__, static_folder="static", static_url_path="/static")
    app.config["JJT_SETTINGS"] = settings or Settings.load()
    app.register_blueprint(api)

    @app.get("/")
    def index():
        return app.send_static_file("index.html")

    @app.get("/<path:path>")
    def application_route(path):
        if path.startswith("api/"):
            return {"error": "API 경로를 찾을 수 없습니다."}, 404
        return app.send_static_file("index.html")

    return app
