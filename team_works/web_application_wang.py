import requests
from urllib.parse import urljoin

TARGET = "https://target.example.com"

def check_directory_indexing():
    paths = [
        "/upload/",
        "/uploads/",
        "/images/",
        "/backup/",
        "/files/"
    ]

    for path in paths:
        url = urljoin(TARGET, path)

        try:
            r = requests.get(url, timeout=5)

            if "Index of /" in r.text:
                print(f"[취약] 디렉터리 인덱싱: {url}")

        except Exception:
            pass


def check_http_methods():
    try:
        r = requests.options(TARGET, timeout=5)

        allow = r.headers.get("Allow", "")

        dangerous = [
            "PUT",
            "DELETE",
            "TRACE",
            "CONNECT"
        ]

        found = [x for x in dangerous if x in allow]

        if found:
            print(f"[취약] 위험 Method 허용: {found}")
        else:
            print("[양호] Method 제한")

    except Exception as e:
        print(e)


def check_information_disclosure():
    try:
        r = requests.get(TARGET, timeout=5)

        headers = str(r.headers)

        keywords = [
            "Apache",
            "Tomcat",
            "PHP",
            "nginx"
        ]

        for keyword in keywords:
            if keyword.lower() in headers.lower():
                print(f"[의심] 서버 정보 노출: {keyword}")

    except Exception:
        pass


def check_admin_page():
    admin_paths = [
        "/admin",
        "/admin/",
        "/manager",
        "/manage",
        "/administrator"
    ]

    for path in admin_paths:
        try:
            r = requests.get(
                urljoin(TARGET, path),
                timeout=5,
                allow_redirects=False
            )

            if r.status_code == 200:
                print(f"[의심] 관리자 페이지 노출: {path}")

        except Exception:
            pass


def check_https():
    if TARGET.startswith("https://"):
        print("[양호] HTTPS 사용")
    else:
        print("[취약] HTTP 사용")


if __name__ == "__main__":
    check_https()
    check_directory_indexing()
    check_http_methods()
    check_information_disclosure()
    check_admin_page()
