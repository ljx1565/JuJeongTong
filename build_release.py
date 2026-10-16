from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "dist" / "jjt-standalone.zip"
EXCLUDED_NAMES = {
    ".git",
    ".venv",
    "__pycache__",
    "device_list.json",
    "local_settings.py",
    "dist",
}
EXCLUDED_SUFFIXES = {".pyc", ".pyo"}
EXCLUDED_PATHS = {
    Path("main.ipynb"),
    Path("team_works/web_service.py"),
}


def included(path):
    relative = path.relative_to(ROOT)
    if relative in EXCLUDED_PATHS:
        return False
    if any(part in EXCLUDED_NAMES for part in relative.parts):
        return False
    return path.suffix.lower() not in EXCLUDED_SUFFIXES


def main():
    OUTPUT.parent.mkdir(exist_ok=True)
    with ZipFile(OUTPUT, "w", ZIP_DEFLATED) as archive:
        for path in sorted(ROOT.rglob("*")):
            if path.is_file() and included(path):
                archive.write(path, Path("jjt") / path.relative_to(ROOT))
    print(OUTPUT)


if __name__ == "__main__":
    main()
