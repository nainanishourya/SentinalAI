from typing import Any, TypedDict


class SOCState(TypedDict, total=False):
    incident_id: str
    scenario_id: str
    name: str
    category: str
    severity: str
    source: str
    ground_truth_mitre: list[dict]
    raw_logs: list[str]

    ingestion_summary: dict
    detections: list[dict]
    is_malicious: bool
    detected_category: str

    incident: dict
    analyst_findings: dict
    threat_intel_report: dict
    reconstruction: dict
    root_cause_report: dict
    mitre_mapping: dict
    response_plan: dict

    accuracy: dict
    trace: list[dict[str, Any]]
