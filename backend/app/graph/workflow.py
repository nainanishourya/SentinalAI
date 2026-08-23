from langgraph.graph import END, StateGraph

from . import agents
from .state import SOCState


def build_graph():
    g = StateGraph(SOCState)

    g.add_node("orchestrator", agents.orchestrator_agent)
    g.add_node("log_ingestion", agents.log_ingestion_agent)
    g.add_node("detection_engine", agents.detection_engine_agent)
    g.add_node("incident_creation", agents.incident_creation_agent)
    g.add_node("detection_analyst", agents.detection_analyst_agent)
    g.add_node("threat_intel", agents.threat_intel_agent)
    g.add_node("attack_reconstruction", agents.attack_reconstruction_agent)
    g.add_node("root_cause", agents.root_cause_agent)
    g.add_node("mitre_mapper", agents.mitre_mapper_agent)
    g.add_node("incident_response", agents.incident_response_agent)

    g.set_entry_point("orchestrator")
    g.add_edge("orchestrator", "log_ingestion")
    g.add_edge("log_ingestion", "detection_engine")
    g.add_conditional_edges(
        "detection_engine",
        lambda s: "malicious" if s.get("is_malicious") else "benign",
        {"malicious": "incident_creation", "benign": END},
    )
    g.add_edge("incident_creation", "detection_analyst")
    g.add_edge("detection_analyst", "threat_intel")
    g.add_edge("threat_intel", "attack_reconstruction")
    g.add_edge("attack_reconstruction", "root_cause")
    g.add_edge("root_cause", "mitre_mapper")
    g.add_edge("mitre_mapper", "incident_response")
    g.add_edge("incident_response", END)

    return g.compile()


GRAPH = build_graph()

PIPELINE_ORDER = [
    "orchestrator", "log_ingestion", "detection_engine", "incident_creation",
    "detection_analyst", "threat_intel", "attack_reconstruction", "root_cause",
    "mitre_mapper", "incident_response",
]
