import csv
import io
from datetime import datetime, timedelta, timezone

from flask import Blueprint, Response, current_app, request

from .repository import JJT_TYPE_MAP, JjtRepository, make_jjt_database
from .time_utils import parse_database_time

from .jobs import current_job, start_job
from .jobs import engine
from .targets import JJT_ROOT, TargetRepository, direct_engine_device, probe_ssh


api = Blueprint("jjt_api", __name__, url_prefix="/api")


def repository():
    settings = current_app.config["JJT_SETTINGS"]
    return settings, JjtRepository(make_jjt_database(settings))


def target_repository():
    settings = current_app.config["JJT_SETTINGS"]
    service = TargetRepository(make_jjt_database(settings))
    seed_path = JJT_ROOT / "device_list.json"
    if seed_path.is_file():
        service.seed(seed_path)
    return service


def requested_window():
    start = parse_database_time(request.args.get("from"))
    end = parse_database_time(request.args.get("to"))
    if start and end and start < end:
        return start, end
    end = datetime.now(timezone.utc)
    return end - timedelta(days=7), end


@api.errorhandler(Exception)
def api_error(error):
    current_app.logger.exception("JJT API request failed")
    return {"error": "주정통 데이터를 처리하는 중 오류가 발생했습니다."}, 500


@api.get("/health")
def health():
    _, service = repository()
    return {"status": "ok", "service": "jjt-web", "database": service.probe()}


@api.get("/check-catalog")
def check_catalog():
    types = []
    for type_id, validator in engine.VALIDATOR_MAP.items():
        items = []
        for method, meta in validator.check_list.items():
            title = meta.get("title", "")
            items.append({
                "method": method,
                "code": meta.get("code", method.upper().replace("_", "-")),
                "title": title,
                "criterion": meta.get("criterion", f"{title} 항목의 설정값이 보안 기준을 충족하는지 확인합니다."),
            })
        types.append({"id": type_id, "label": JJT_TYPE_MAP[type_id][1], "count": len(items), "items": items})
    return {"types": types}


@api.get("/targets")
def targets():
    return {"targets": target_repository().list()}


@api.post("/targets")
def create_target():
    try:
        return {"target": target_repository().create(request.get_json(silent=True) or {})}, 201
    except ValueError as exc:
        return {"error": str(exc)}, 400


@api.put("/targets/<int:target_id>")
def update_target(target_id):
    try:
        target = target_repository().update(target_id, request.get_json(silent=True) or {})
    except ValueError as exc:
        return {"error": str(exc)}, 400
    return ({"target": target}, 200) if target else ({"error": "장치를 찾을 수 없습니다."}, 404)


@api.delete("/targets/<int:target_id>")
def delete_target(target_id):
    deleted = target_repository().delete(target_id)
    return ({"deleted": True}, 200) if deleted else ({"error": "장치를 찾을 수 없습니다."}, 404)


@api.post("/targets/<int:target_id>/probe")
def probe_target(target_id):
    service = target_repository()
    target = service.get(target_id, True)
    if not target:
        return {"error": "장치를 찾을 수 없습니다."}, 404
    status, message = probe_ssh(target)
    return {"target": service.save_probe(target_id, status, message)}


@api.get("/jobs/current")
def job_status():
    return {"job": current_job()}


@api.post("/jobs")
def create_job():
    body = request.get_json(silent=True) or {}
    if body.get("confirm") != "RUN":
        return {"error": "실행 확인 값이 올바르지 않습니다."}, 400
    target_ids = body.get("targets") or []
    checks = body.get("checks") or []
    if not isinstance(target_ids, list) or not isinstance(checks, list):
        return {"error": "대상과 점검 유형 형식이 올바르지 않습니다."}, 400
    settings = current_app.config["JJT_SETTINGS"]
    database = make_jjt_database(settings)
    try:
        devices = target_repository().engine_devices()
        direct = body.get("direct_target")
        if direct:
            devices.append(direct_engine_device(direct, checks))
            target_ids = ["direct"]
        job = start_job(target_ids, checks, database.settings.DATABASE.copy(), devices)
    except ValueError as exc:
        return {"error": str(exc)}, 409
    return {"job": job}, 202


@api.get("/overview")
def overview():
    _, service = repository()
    start, end = requested_window()
    return service.overview(start, end)


@api.get("/rows")
def rows():
    settings, service = repository()
    type_id = request.args.get("type", "unix")
    if type_id not in JJT_TYPE_MAP:
        return {"error": "알 수 없는 점검 유형입니다."}, 404
    page = max(1, int(request.args.get("page", 1)))
    page_size = min(max(1, int(request.args.get("page_size", 100))), settings.MAX_PAGE_SIZE)
    return service.rows(type_id, request.args.get("status", ""), request.args.get("q", "").strip(), page, page_size)


@api.get("/results/by-date")
def results_by_date():
    settings, service = repository()
    type_id = request.args.get("type", "")
    if type_id and type_id not in JJT_TYPE_MAP:
        return {"error": "알 수 없는 점검 유형입니다."}, 404
    page = max(1, int(request.args.get("page", 1)))
    page_size = min(max(1, int(request.args.get("page_size", 100))), settings.MAX_PAGE_SIZE)
    start = parse_database_time(request.args.get("from"))
    end = parse_database_time(request.args.get("to"))
    return service.dated_rows(type_id, request.args.get("ip", ""), start, end,
                              request.args.get("status", ""), request.args.get("q", "").strip(), page, page_size)


@api.get("/export.csv")
def export_csv():
    settings, service = repository()
    type_id = request.args.get("type", "unix")
    if type_id not in JJT_TYPE_MAP:
        return {"error": "알 수 없는 점검 유형입니다."}, 404
    data = service.rows(type_id, request.args.get("status", ""), request.args.get("q", "").strip(), 1, settings.MAX_EXPORT_ROWS)
    stream = io.StringIO()
    fields = ["ip", "code", "title", "status", "reason", "check_date"]
    writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(data["rows"])
    filename = f"jjt-{type_id}-{datetime.now():%Y%m%d-%H%M%S}.csv"
    return Response("\ufeff" + stream.getvalue(), mimetype="text/csv; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="{filename}"'})
