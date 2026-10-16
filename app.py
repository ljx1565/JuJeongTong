import _bootstrap  # noqa: F401  필요한 패키지가 없으면 .venv 에 설치하고 다시 실행
import os

from jjt_web import create_app


app = create_app()


if __name__ == "__main__":
    # 직접 실행할 때 주소 · 포트를 바꾸려면: JJT_HOST=0.0.0.0 JJT_PORT=80 python app.py
    app.run(host=os.environ.get("JJT_HOST", "127.0.0.1"), port=int(os.environ.get("JJT_PORT", "5080")), debug=False)
