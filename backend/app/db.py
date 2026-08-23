import json
import sqlite3
from contextlib import contextmanager

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    scenario_id TEXT,
    attack_type TEXT,
    category TEXT,
    severity TEXT,
    status TEXT,
    source TEXT,
    accuracy_score REAL,
    confidence_score REAL,
    llm_backed INTEGER,
    data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS upload_events (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    filename TEXT,
    declared_ext TEXT,
    detected_type TEXT,
    verdict TEXT,
    reason TEXT,
    incident_id TEXT
);
"""


@contextmanager
def get_conn():
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_conn() as conn:
        conn.executescript(SCHEMA)


def save_incident(incident: dict):
    with get_conn() as conn:
        conn.execute(
            """INSERT OR REPLACE INTO incidents
               (id, created_at, scenario_id, attack_type, category, severity, status, source,
                accuracy_score, confidence_score, llm_backed, data)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                incident["id"],
                incident["created_at"],
                incident.get("scenario_id"),
                incident.get("attack_type"),
                incident.get("category"),
                incident.get("severity"),
                incident.get("status", "resolved"),
                incident.get("source", "simulation"),
                incident.get("accuracy_score"),
                incident.get("confidence_score"),
                1 if incident.get("llm_backed") else 0,
                json.dumps(incident),
            ),
        )


def list_incidents(limit: int = 200):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT data FROM incidents ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [json.loads(r["data"]) for r in rows]


def get_incident(incident_id: str):
    with get_conn() as conn:
        row = conn.execute("SELECT data FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        return json.loads(row["data"]) if row else None


def save_upload_event(event: dict):
    with get_conn() as conn:
        conn.execute(
            """INSERT OR REPLACE INTO upload_events
               (id, created_at, filename, declared_ext, detected_type, verdict, reason, incident_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event["id"],
                event["created_at"],
                event.get("filename"),
                event.get("declared_ext"),
                event.get("detected_type"),
                event.get("verdict"),
                event.get("reason"),
                event.get("incident_id"),
            ),
        )


def list_upload_events(limit: int = 100):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM upload_events ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def stats():
    with get_conn() as conn:
        total = conn.execute("SELECT COUNT(*) c FROM incidents").fetchone()["c"]
        by_category = conn.execute(
            "SELECT category, COUNT(*) c FROM incidents GROUP BY category"
        ).fetchall()
        by_severity = conn.execute(
            "SELECT severity, COUNT(*) c FROM incidents GROUP BY severity"
        ).fetchall()
        avg_acc = conn.execute(
            "SELECT AVG(accuracy_score) a FROM incidents WHERE accuracy_score IS NOT NULL"
        ).fetchone()["a"]
        avg_conf = conn.execute(
            "SELECT AVG(confidence_score) a FROM incidents WHERE confidence_score IS NOT NULL"
        ).fetchone()["a"]
        recent = conn.execute(
            "SELECT created_at, accuracy_score, attack_type, severity FROM incidents ORDER BY created_at DESC LIMIT 30"
        ).fetchall()
        uploads_total = conn.execute("SELECT COUNT(*) c FROM upload_events").fetchone()["c"]
        uploads_blocked = conn.execute(
            "SELECT COUNT(*) c FROM upload_events WHERE verdict = 'rejected'"
        ).fetchone()["c"]
        return {
            "total_incidents": total,
            "by_category": [dict(r) for r in by_category],
            "by_severity": [dict(r) for r in by_severity],
            "avg_accuracy": round(avg_acc, 1) if avg_acc is not None else None,
            "avg_confidence": round(avg_conf, 1) if avg_conf is not None else None,
            "recent": [dict(r) for r in recent],
            "uploads_total": uploads_total,
            "uploads_blocked": uploads_blocked,
        }
