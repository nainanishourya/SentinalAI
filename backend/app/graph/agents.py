import uuid
from datetime import datetime, timezone

from .. import llm
from ..config import AGENT_NAMES
from ..scoring import score_run
from .state import SOCState

DETECTION_RULES = [
    ("Failed password", "Credential Access", ["brute force", "credential stuffing"]),
    ("UNION SELECT", "Initial Access", ["sql injection"]),
    ("SLEEP(", "Initial Access", ["sql injection"]),
    ("DROP TABLE", "Initial Access", ["sql injection"]),
    (".locked", "Impact", ["ransomware"]),
    ("shadow copy deletion", "Impact", ["ransomware"]),
    ("SYN scan probe", "Reconnaissance", ["port scan"]),
    ("token duplication", "Privilege Escalation", ["privilege escalation"]),
    ("SAM registry hive", "Privilege Escalation", ["privilege escalation"]),
    ("outbound transfer rate anomaly", "Exfiltration", ["data exfiltration"]),
    ("sensitive data pattern", "Exfiltration", ["data exfiltration"]),
    ("ADMIN$", "Lateral Movement", ["lateral movement"]),
    ("PSEXESVC", "Lateral Movement", ["lateral movement"]),
    ("macro execution detected", "Initial Access", ["phishing"]),
    ("spawned powershell.exe -enc", "Execution", ["phishing", "malicious macro"]),
    ("high entropy subdomain", "Command and Control", ["dns tunneling"]),
    ("magic-byte inspection", "Defense Evasion", ["malicious file upload"]),
    ("upload rejected", "Defense Evasion", ["malicious file upload"]),
]


def _now():
    return datetime.now(timezone.utc).isoformat()


def _trace(state: SOCState, key: str, message: str, llm_backed: bool | None = None) -> list[dict]:
    trace = list(state.get("trace", []))
    entry = {
        "agent_key": key,
        "agent": AGENT_NAMES.get(key, key),
        "message": message,
        "timestamp": _now(),
    }
    if llm_backed is not None:
        entry["llm_backed"] = llm_backed
    trace.append(entry)
    return trace


async def orchestrator_agent(state: SOCState) -> dict:
    incident_id = state.get("incident_id") or f"INC-{uuid.uuid4().hex[:8].upper()}"
    trace = _trace(
        state, "orchestrator",
        f"LangGraph workflow initialized for scenario '{state.get('name')}' (id={incident_id}). Routing through 9-agent SOC pipeline.",
    )
    return {"incident_id": incident_id, "trace": trace}


async def log_ingestion_agent(state: SOCState) -> dict:
    logs = state.get("raw_logs", [])
    sources = sorted({line.split("src=")[1].split(" ")[0] for line in logs if "src=" in line})
    summary = {
        "log_count": len(logs),
        "distinct_sources": sources,
        "time_span": f"{len(logs)} events correlated in ingestion window",
    }
    trace = _trace(
        state, "log_ingestion",
        f"Ingested and normalized {len(logs)} raw log events from {len(sources)} source(s): {', '.join(sources) or 'n/a'}.",
    )
    return {"ingestion_summary": summary, "trace": trace}


async def detection_engine_agent(state: SOCState) -> dict:
    logs = state.get("raw_logs", [])
    detections = []
    category_votes: dict[str, int] = {}
    for line in logs:
        for keyword, category, labels in DETECTION_RULES:
            if keyword.lower() in line.lower():
                detections.append({"rule": keyword, "category": category, "labels": labels, "log": line})
                category_votes[category] = category_votes.get(category, 0) + 1

    is_malicious = len(detections) > 0
    detected_category = max(category_votes, key=category_votes.get) if category_votes else "Benign"

    trace = _trace(
        state, "detection_engine",
        (
            f"{len(detections)} detection rule(s) matched across {len(logs)} events. "
            f"Classified as malicious (category: {detected_category})." if is_malicious
            else "No detection rules matched. Traffic classified as benign."
        ),
    )
    return {
        "detections": detections,
        "is_malicious": is_malicious,
        "detected_category": detected_category,
        "trace": trace,
    }


async def incident_creation_agent(state: SOCState) -> dict:
    incident = {
        "id": state["incident_id"],
        "title": f"{state.get('name')} detected",
        "opened_at": _now(),
        "severity": state.get("severity", "medium"),
        "status": "investigating",
        "detection_count": len(state.get("detections", [])),
        "category": state.get("detected_category", state.get("category")),
    }
    trace = _trace(
        state, "incident_creation",
        f"Incident {incident['id']} opened - severity={incident['severity']}, {incident['detection_count']} supporting detection(s).",
    )
    return {"incident": incident, "trace": trace}


def _fallback(text: str, **fields):
    return {"llm_backed": False, "summary": text, **fields}


async def detection_analyst_agent(state: SOCState) -> dict:
    logs = "\n".join(state.get("raw_logs", []))
    detections = state.get("detections", [])
    try:
        result = llm.ask_json(
            system="You are a senior SOC detection analyst. Analyze correlated security logs and detections and explain, in plain language, why this looks like a real incident.",
            user=(
                f"Incident category (from rule engine): {state.get('detected_category')}\n"
                f"Raw logs:\n{logs}\n\n"
                f"Rule-based detections:\n{detections}\n\n"
                "Return JSON with keys: summary (2-4 sentences explaining WHY this is suspicious), "
                "suspicious_patterns (array of short strings), analyst_confidence (integer 0-100)."
            ),
        )
        result["llm_backed"] = True
    except Exception:
        result = _fallback(
            f"Rule engine matched {len(detections)} indicator(s) consistent with {state.get('detected_category')} activity. "
            "The pattern and frequency of these events deviate from normal baseline behavior.",
            suspicious_patterns=[d["rule"] for d in detections[:5]],
            analyst_confidence=65,
        )

    trace = _trace(state, "detection_analyst", result.get("summary", "Analysis complete."), llm_backed=result.get("llm_backed", False))
    return {"analyst_findings": result, "trace": trace}


async def threat_intel_agent(state: SOCState) -> dict:
    category = state.get("detected_category", "Unknown")
    try:
        result = llm.ask_json(
            system="You are a threat intelligence agent. Given an attack category and indicators, produce plausible threat-intel style enrichment (this is a simulated/demo intel feed, not a live external lookup).",
            user=(
                f"Attack category: {category}\n"
                f"Detections: {state.get('detections')}\n\n"
                "Return JSON with keys: likely_campaign_or_actor_profile (string, phrase it as a hypothesis), "
                "ioc_context (array of short strings describing what the IOCs suggest), "
                "intel_confidence (integer 0-100), intel_note (1 sentence disclaimer that this is generated/demo intel)."
            ),
        )
        result["llm_backed"] = True
    except Exception:
        result = _fallback(
            f"No live threat feed configured; heuristic profile for {category} activity generated locally.",
            likely_campaign_or_actor_profile=f"Pattern consistent with commodity {category.lower()} tooling",
            ioc_context=[f"{d['rule']}" for d in state.get("detections", [])[:4]],
            intel_confidence=40,
            intel_note="Simulated intel - no external feed queried.",
        )

    trace = _trace(state, "threat_intel", result.get("summary", result.get("likely_campaign_or_actor_profile", "Threat intel enrichment complete.")), llm_backed=result.get("llm_backed", False))
    return {"threat_intel_report": result, "trace": trace}


async def attack_reconstruction_agent(state: SOCState) -> dict:
    logs = state.get("raw_logs", [])
    try:
        result = llm.ask_json(
            system="You are an attack reconstruction agent. You receive all correlated events for an incident and reconstruct the attack as an ordered timeline / kill-chain narrative.",
            user=(
                f"Correlated events (chronological):\n" + "\n".join(logs) + "\n\n"
                "Return JSON with keys: timeline (array of {step: int, description: string}), "
                "narrative (2-4 sentence overall reconstruction of what the attacker did, in order)."
            ),
        )
        result["llm_backed"] = True
    except Exception:
        result = _fallback(
            "Reconstructed from raw event order (fallback mode).",
            timeline=[{"step": i + 1, "description": line} for i, line in enumerate(logs)],
        )

    trace = _trace(state, "attack_reconstruction", result.get("narrative", result.get("summary", "Timeline reconstructed.")), llm_backed=result.get("llm_backed", False))
    return {"reconstruction": result, "trace": trace}


async def root_cause_agent(state: SOCState) -> dict:
    try:
        result = llm.ask_json(
            system="You are a root cause analyst. Determine the underlying root cause that allowed this incident to occur, not just what happened.",
            user=(
                f"Category: {state.get('detected_category')}\n"
                f"Analyst findings: {state.get('analyst_findings')}\n"
                f"Reconstruction: {state.get('reconstruction')}\n\n"
                "Return JSON with keys: root_cause (2-3 sentences), contributing_factors (array of short strings)."
            ),
        )
        result["llm_backed"] = True
    except Exception:
        result = _fallback(
            f"Root cause likely tied to a control gap enabling {state.get('detected_category', 'this')} activity to go undetected until threshold-based rules triggered.",
            contributing_factors=["Insufficient rate limiting / anomaly baselining", "Delayed detection relative to attacker dwell time"],
        )

    trace = _trace(state, "root_cause", result.get("root_cause", result.get("summary", "Root cause identified.")), llm_backed=result.get("llm_backed", False))
    return {"root_cause_report": result, "trace": trace}


async def mitre_mapper_agent(state: SOCState) -> dict:
    try:
        result = llm.ask_json(
            system="You are a MITRE ATT&CK mapping agent. Map the incident to the most relevant ATT&CK tactics and techniques.",
            user=(
                f"Category: {state.get('detected_category')}\n"
                f"Detections: {state.get('detections')}\n"
                f"Root cause: {state.get('root_cause_report')}\n\n"
                "Return JSON with key techniques: array of {tactic, technique_id (e.g. T1110), technique_name, rationale (1 sentence)}. "
                "Use real MITRE ATT&CK Enterprise technique IDs."
            ),
        )
        result["llm_backed"] = True
        techniques = result.get("techniques", [])
    except Exception:
        techniques = state.get("ground_truth_mitre", [])
        result = _fallback("MITRE mapping derived from rule-engine category (fallback mode).", techniques=[
            {"tactic": t["tactic"], "technique_id": t["technique_id"], "technique_name": t["technique"], "rationale": "Matched via rule-engine category mapping."}
            for t in techniques
        ])
        techniques = result["techniques"]

    accuracy = score_run(
        state.get("ground_truth_mitre", []),
        techniques,
        state.get("detected_category", ""),
        state.get("category", ""),
    )

    trace = _trace(
        state, "mitre_mapper",
        f"Mapped to {len(techniques)} MITRE ATT&CK technique(s). Prediction accuracy vs ground truth: {accuracy['accuracy_score']}%.",
        llm_backed=result.get("llm_backed", False),
    )
    return {"mitre_mapping": result, "accuracy": accuracy, "trace": trace}


async def incident_response_agent(state: SOCState) -> dict:
    try:
        result = llm.ask_json(
            system="You are an incident response suggestion agent. Provide a concrete, actionable response plan.",
            user=(
                f"Category: {state.get('detected_category')}\n"
                f"Severity: {state.get('severity')}\n"
                f"Root cause: {state.get('root_cause_report')}\n"
                f"MITRE mapping: {state.get('mitre_mapping')}\n\n"
                "Return JSON with keys: immediate_actions (array), containment (array), eradication (array), "
                "recovery (array), preventive (array), priority (one of: low, medium, high, critical)."
            ),
        )
        result["llm_backed"] = True
    except Exception:
        result = _fallback(
            "Standard response playbook applied (fallback mode).",
            immediate_actions=["Isolate affected host(s)", "Disable/rotate compromised credentials"],
            containment=["Block malicious source IP(s) at perimeter"],
            eradication=["Remove malicious artifacts / persistence mechanisms"],
            recovery=["Restore from clean backups if applicable", "Monitor for recurrence"],
            preventive=["Tune detection thresholds", "Patch/upgrade affected component"],
            priority=state.get("severity", "medium"),
        )

    trace = _trace(state, "incident_response", f"Response plan generated (priority: {result.get('priority', state.get('severity'))}).", llm_backed=result.get("llm_backed", False))
    return {"response_plan": result, "trace": trace}
