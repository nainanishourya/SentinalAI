import asyncio
import logging
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, File, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import config, db, scenarios, upload_scanner
from .events import broadcaster
from .pipeline import run_pipeline

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sentinelai.main")


async def _ambient_log_ticker():
    while True:
        await asyncio.sleep(config.LIVE_FEED_INTERVAL_SECONDS)
        await broadcaster.publish({"type": "ambient_log", "line": scenarios.benign_line()})


async def _autonomous_incident_loop():
    if config.AUTO_INCIDENT_INTERVAL_SECONDS <= 0:
        return
    while True:
        await asyncio.sleep(config.AUTO_INCIDENT_INTERVAL_SECONDS)
        try:
            await run_pipeline(source="autonomous")
        except Exception:
            logger.exception("autonomous pipeline run failed")


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    tasks = [
        asyncio.create_task(_ambient_log_ticker()),
        asyncio.create_task(_autonomous_incident_loop()),
    ]
    yield
    for t in tasks:
        t.cancel()


app = FastAPI(title="SentinalAI SOC", lifespan=lifespan)


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "llm_configured": bool(config.OPENROUTER_API_KEY),
        "model": config.OPENROUTER_MODEL,
    }


@app.get("/api/scenarios")
async def get_scenarios():
    return scenarios.list_scenarios()


@app.get("/api/incidents")
async def get_incidents(limit: int = 200):
    return db.list_incidents(limit)


@app.get("/api/incidents/{incident_id}")
async def get_incident(incident_id: str):
    incident = db.get_incident(incident_id)
    if not incident:
        return JSONResponse(status_code=404, content={"error": "not found"})
    return incident


@app.get("/api/uploads")
async def get_uploads():
    return db.list_upload_events()


@app.get("/api/stats")
async def get_stats():
    return db.stats()


@app.post("/api/simulate")
async def simulate(payload: dict | None = None):
    scenario_id = (payload or {}).get("scenario_id")
    asyncio.create_task(run_pipeline(scenario_id=scenario_id, source="manual-simulation"))
    return {"status": "started", "scenario_id": scenario_id}


@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...)):
    content = await file.read()
    result = upload_scanner.scan_upload(file.filename, content)
    event_id = f"UPL-{uuid.uuid4().hex[:8]}"
    now = datetime.now(timezone.utc).isoformat()

    event = {
        "id": event_id,
        "created_at": now,
        "filename": file.filename,
        "declared_ext": result["declared_ext"],
        "detected_type": result["detected_type"],
        "verdict": result["verdict"],
        "reason": result["reason"],
        "incident_id": None,
    }

    if result["verdict"] == "rejected":
        base_scenario = scenarios.generate_scenario("malicious_upload")
        base_scenario["logs"] = [
            f"[{now}] src=upload-scanner webapp: user uploaded '{file.filename}' declared-type=.{result['declared_ext'] or 'unknown'}",
            f"[{now}] src=upload-scanner upload-scanner: magic-byte inspection detected [{result['detected_type']}] content inside file declared as .{result['declared_ext'] or 'unknown'} - upload rejected. {result['reason']}",
        ]
        asyncio.create_task(_investigate_upload(base_scenario, event))
    else:
        db.save_upload_event(event)
        await broadcaster.publish({"type": "upload_event", "event": event})

    status_code = 400 if result["verdict"] == "rejected" else 200
    return JSONResponse(status_code=status_code, content={**result, "event_id": event_id, "incident": None})


async def _investigate_upload(scenario: dict, event: dict):
    incident = await run_pipeline(scenario_override=scenario, source="file-upload-scanner")
    event["incident_id"] = incident["id"] if incident else None
    db.save_upload_event(event)
    await broadcaster.publish({"type": "upload_event", "event": event})


@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    await websocket.accept()
    q = await broadcaster.subscribe()
    try:
        while True:
            msg = await q.get()
            await websocket.send_json(msg)
    except WebSocketDisconnect:
        pass
    finally:
        broadcaster.unsubscribe(q)


if config.FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(config.FRONTEND_DIR)), name="static")

    @app.get("/")
    async def index():
        return FileResponse(str(config.FRONTEND_DIR / "index.html"))
