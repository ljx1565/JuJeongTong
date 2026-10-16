import copy
import sys
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
JJT_ROOT = ROOT / "jjt"
if str(JJT_ROOT) not in sys.path:
    sys.path.insert(0, str(JJT_ROOT))

import main as engine
from sql_manager import SqlManager


_lock = threading.Lock()
_jobs = {}
_current_id = None


def start_job(target_ids, requested_checks, db_config, all_devices):
    global _current_id
    with _lock:
        current = _jobs.get(_current_id)
        if current and current["status"] in ("queued", "running"):
            raise ValueError("이미 실행 중인 점검이 있습니다.")

        known = {str(device["id"]): device for device in all_devices}
        missing = sorted(set(target_ids) - set(known))
        if missing:
            raise ValueError("알 수 없는 대상: " + ", ".join(missing))

        devices = []
        for target_id in target_ids:
            device = copy.deepcopy(known[str(target_id)])
            available = engine.get_checks(device)
            checks = [item for item in available if not requested_checks or item in requested_checks]
            if checks:
                device["checks"] = checks
                devices.append(device)
        if not devices:
            raise ValueError("실행할 대상과 점검 유형을 선택하세요.")

        job_id = uuid.uuid4().hex[:12]
        job = {
            "id": job_id, "status": "queued", "created_at": now_text(),
            "started_at": None, "finished_at": None,
            "total": len(devices), "completed": 0,
            "targets": [{"hostname": item["hostname"], "ip": item["ip"], "checks": item["checks"]} for item in devices],
            "results": [], "error": None,
        }
        _jobs[job_id] = job
        _current_id = job_id
        thread = threading.Thread(target=run_job, args=(job_id, devices, db_config), daemon=True)
        thread.start()
        return snapshot(job)


def run_job(job_id, devices, db_config):
    job = _jobs[job_id]
    try:
        job.update(status="running", started_at=now_text())
        engine.DB_CONFIG.clear()
        engine.DB_CONFIG.update(db_config)
        tables = {engine.TABLE_MAP[check] for device in devices for check in engine.get_checks(device)}
        SqlManager.setup_schema(db_config, tables)
        engine._progress.update(done=0, total=len(devices))
        workers = min(engine.MAX_WORKERS, len(devices))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(engine.check_host, device): device for device in devices}
            for future in as_completed(futures):
                device = futures[future]
                try:
                    result = future.result()
                except Exception as exc:
                    result = {"hostname": device["hostname"], "ip": device["ip"], "checks": engine.get_checks(device), "failed": engine.get_checks(device), "ok": False, "counts": {}, "elapsed": 0, "error": f"{exc.__class__.__name__}: {exc}"}
                with _lock:
                    job["results"].append(result)
                    job["completed"] += 1
        job["status"] = "completed" if all(item["ok"] for item in job["results"]) else "partial"
    except Exception as exc:
        job["status"] = "failed"
        job["error"] = f"{exc.__class__.__name__}: {exc}"
    finally:
        job["finished_at"] = now_text()


def current_job():
    with _lock:
        return snapshot(_jobs.get(_current_id)) if _current_id else None


def snapshot(job):
    return copy.deepcopy(job) if job else None


def now_text():
    return datetime.now().astimezone().isoformat(timespec="seconds")
