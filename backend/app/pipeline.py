import logging
from datetime import datetime, timezone

from . import db, scenarios
from .events import broadcaster
from .graph.workflow import GRAPH

logger = logging.getLogger("sentinelai.pipeline")


def _public_snapshot(state: dict) -> dict:
    keys = [
        "incident_id", "name", "category", "severity", "detected_category",
        "is_malicious", "detections", "incident", "analyst_findings",
        "threat_intel_report", "reconstruction", "root_cause_report", "mitre_mapping",
        "accuracy", "response_plan",
    ]
    return {k: state.get(k) for k in keys if k in state}


def _assemble_incident(state: dict) -> dict:
    accuracy = state.get("accuracy", {})
    analyst = state.get("analyst_findings") or {}
    return {
        "id": state["incident_id"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "scenario_id": state.get("scenario_id"),
        "attack_type": state.get("name"),
        "category": state.get("detected_category"),
        "true_category": state.get("category"),
        "severity": state.get("severity"),
        "status": "resolved",
        "source": state.get("source", "simulation"),
        "accuracy_score": accuracy.get("accuracy_score"),
        "confidence_score": analyst.get("analyst_confidence"),
        "llm_backed": any(t.get("llm_backed") for t in state.get("trace", []) if "llm_backed" in t),
        "raw_logs": state.get("raw_logs"),
        "detections": state.get("detections"),
        "incident": state.get("incident"),
        "analyst_findings": analyst,
        "threat_intel": state.get("threat_intel_report"),
        "reconstruction": state.get("reconstruction"),
        "root_cause": state.get("root_cause_report"),
        "mitre_mapping": state.get("mitre_mapping"),
        "accuracy": accuracy,
        "response_plan": state.get("response_plan"),
        "trace": state.get("trace"),
        "ground_truth_mitre": state.get("ground_truth_mitre"),
    }


async def run_pipeline(scenario_id: str | None = None, source: str = "simulation", scenario_override: dict | None = None):
    scenario = scenario_override or scenarios.generate_scenario(scenario_id)

    initial_state = {
        "scenario_id": scenario["scenario_id"],
        "name": scenario["name"],
        "category": scenario["category"],
        "severity": scenario["severity"],
        "source": source,
        "ground_truth_mitre": scenario["ground_truth_mitre"],
        "raw_logs": scenario["logs"],
        "trace": [],
    }

    await broadcaster.publish({
        "type": "pipeline_start",
        "scenario": scenario["name"],
        "scenario_id": scenario["scenario_id"],
        "source": source,
        "logs": scenario["logs"],
    })

    final_state = dict(initial_state)
    try:
        async for step in GRAPH.astream(initial_state):
            for node_name, update in step.items():
                if node_name == "__end__" or not isinstance(update, dict):
                    continue
                final_state.update(update)
                trace_list = update.get("trace") or []
                last_trace = trace_list[-1] if trace_list else None
                await broadcaster.publish({
                    "type": "agent_step",
                    "node": node_name,
                    "trace": last_trace,
                    "state": _public_snapshot(final_state),
                })
    except Exception:
        logger.exception("pipeline run failed for scenario %s", scenario.get("scenario_id"))
        await broadcaster.publish({"type": "pipeline_error", "scenario_id": scenario["scenario_id"]})
        return None

    if not final_state.get("is_malicious"):
        await broadcaster.publish({"type": "pipeline_benign", "incident_id": final_state.get("incident_id"), "scenario": scenario["name"]})
        return None

    incident = _assemble_incident(final_state)
    db.save_incident(incident)
    await broadcaster.publish({"type": "incident_complete", "incident": incident})
    return incident
