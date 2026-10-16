"""
main.py 를 실행할 때 필요한 Python 패키지가 없으면 자동으로 준비한다. (점검 로직과 무관)

1. requirements.txt 의 패키지가 모두 import 되면 아무것도 하지 않는다.
2. 하나라도 없으면 이 폴더의 .venv 가상환경을 만들고(없을 때만) requirements.txt 를 설치한 뒤,
   같은 명령을 .venv 의 python 으로 다시 실행한다. 다음부터는 .venv 를 바로 쓴다.
3. 가상환경을 만들 수 없는 시스템이면 현재 python 의 pip 로 설치를 시도한다.
"""
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV = ROOT / ".venv"
REQUIREMENTS = ROOT / "requirements.txt"
VENV_PY = VENV / ("Scripts/python.exe" if os.name == "nt" else "bin/python")

# requirements.txt 의 배포 이름 → import 이름
IMPORT_NAME = {"flask": "flask", "gunicorn": "gunicorn", "netmiko": "netmiko", "paramiko": "paramiko",
               "pymysql": "pymysql", "pyvmomi": "pyVmomi", "requests": "requests", "tzdata": "tzdata"}


def required_modules():
    names = []
    for line in REQUIREMENTS.read_text(encoding="utf-8").splitlines():
        line = line.split("#")[0].strip()
        if not line:
            continue
        dist = line.split(";")[0]
        for sep in ("==", ">=", "<=", "~=", "!=", ">", "<", "["):
            dist = dist.split(sep)[0]
        dist = dist.strip().lower()
        if os.name == "nt" and dist == "gunicorn":      # gunicorn 은 리눅스 전용
            continue
        names.append(IMPORT_NAME.get(dist, dist.replace("-", "_")))
    return names


def missing_modules():
    importlib.invalidate_caches()
    return [name for name in required_modules() if importlib.util.find_spec(name) is None]


def run(cmd):
    print("[준비] " + " ".join(str(part) for part in cmd), flush=True)
    return subprocess.call([str(part) for part in cmd]) == 0


def in_venv():
    return Path(sys.prefix).resolve() == VENV.resolve()


def relaunch(python):
    print(f"[준비] {python} 로 다시 실행합니다.\n", flush=True)
    args = [str(python), *sys.argv]
    if os.name == "nt":                                   # Windows 에는 execv 대신 자식 프로세스로
        sys.exit(subprocess.call(args))
    os.execv(str(python), args)


def ensure():
    missing = missing_modules()
    if not missing:
        return
    print(f"[준비] 없는 패키지: {', '.join(missing)}", flush=True)

    if not in_venv():
        if VENV_PY.exists():                              # 이미 만든 .venv 가 있으면 그쪽으로 넘겨서 확인
            relaunch(VENV_PY)
        else:
            if not run([sys.executable, "-m", "venv", VENV]):
                print("[준비] 가상환경을 만들지 못했습니다. "
                      "Ubuntu 는 'apt install python3-venv', Rocky 는 'dnf install python3-pip' 후 다시 실행하세요.")
                fallback_system_install()
                return
        if run([VENV_PY, "-m", "pip", "install", "-q", "--upgrade", "pip"]) and \
           run([VENV_PY, "-m", "pip", "install", "-r", REQUIREMENTS]):
            relaunch(VENV_PY)
        sys.exit("[준비] .venv 에 패키지를 설치하지 못했습니다. 네트워크와 위 오류를 확인하세요.")

    # 이미 .venv 안인데 빠진 패키지가 있을 때 (requirements.txt 가 바뀐 경우 등)
    if run([sys.executable, "-m", "pip", "install", "-r", REQUIREMENTS]):
        relaunch(sys.executable)
    sys.exit("[준비] 패키지 설치에 실패했습니다.")


def fallback_system_install():
    if run([sys.executable, "-m", "pip", "install", "-r", REQUIREMENTS]) and not missing_modules():
        return
    sys.exit("[준비] 필요한 패키지를 설치하지 못했습니다: " + ", ".join(missing_modules()))


ensure()
