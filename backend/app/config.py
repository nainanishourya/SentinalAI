import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "nvidia/nemotron-3-super-120b-a12b:free")
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

# Free-tier OpenRouter models share upstream rate limit pools and occasionally return 429.
# The LLM client tries these in order (starting with OPENROUTER_MODEL) before falling back
# to deterministic template output, so a single busy provider never breaks the pipeline.
OPENROUTER_FALLBACK_MODELS = [
    OPENROUTER_MODEL,
    "nvidia/nemotron-3-nano-30b-a3b:free",
    "google/gemma-4-26b-a4b-it:free",
    "nvidia/nemotron-nano-9b-v2:free",
]

DB_PATH = str(Path(__file__).resolve().parent.parent / os.getenv("SENTINELAI_DB_PATH", "sentinelai.db"))
LIVE_FEED_INTERVAL_SECONDS = float(os.getenv("LIVE_FEED_INTERVAL_SECONDS", "6"))
AUTO_INCIDENT_INTERVAL_SECONDS = float(os.getenv("AUTO_INCIDENT_INTERVAL_SECONDS", "120"))

FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"

AGENT_NAMES = {
    "orchestrator": "Orchestrator (LangGraph Workflow)",
    "log_ingestion": "Log Ingestion Agent",
    "detection_engine": "Detection Engine",
    "incident_creation": "Incident Creation Agent",
    "detection_analyst": "Detection Analyst Agent",
    "threat_intel": "Threat Intelligence Agent",
    "attack_reconstruction": "Attack Reconstruction Agent",
    "root_cause": "Root Cause Analyst Agent",
    "mitre_mapper": "MITRE ATT&CK Mapper Agent",
    "incident_response": "Incident Response Suggestion Agent",
}
