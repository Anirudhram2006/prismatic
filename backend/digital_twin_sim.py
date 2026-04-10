"""
digital_twin_sim.py - Safe digital twin simulation helpers for TwinShield.
All outputs describe simulated risk inside a virtual environment.
"""

from __future__ import annotations

import json
import os
from copy import deepcopy


MOCK_DB_FILE = os.path.join(os.path.dirname(__file__), "mock_twin.json")

SIMULATION_STAGES = {
    "suspicious_login": {
        "label": "Suspicious Login",
        "description": "Someone may have entered an account in an unusual way.",
        "effect": "Potential account misuse detected in the virtual environment.",
        "impact": "A user account may be at risk of misuse.",
        "risk_level": "Medium",
        "confidence": 62,
        "eta_mins": 5,
        "next_stage": "malicious_execution",
        "predicted_outcomes": [
            {"title": "Malicious Execution", "probability": 0.58, "description": "A risky tool or script may start running next."},
            {"title": "Persistence Attempt", "probability": 0.42, "description": "The attacker may try to stay in the environment longer."}
        ],
        "recommended_action": "Reset the account password and review recent sign-ins.",
    },
    "malicious_execution": {
        "label": "Malicious Execution",
        "description": "A suspicious process may be starting inside the virtual environment.",
        "effect": "Potential harmful activity is being simulated on a device.",
        "impact": "The attacker may try to run tools that expand their reach.",
        "risk_level": "High",
        "confidence": 69,
        "eta_mins": 7,
        "next_stage": "persistence",
        "predicted_outcomes": [
            {"title": "Persistence Attempt", "probability": 0.64, "description": "The path suggests an attempt to stay in the environment."},
            {"title": "Privilege Escalation", "probability": 0.49, "description": "The next move may be an attempt to gain stronger access."}
        ],
        "recommended_action": "Inspect the affected endpoint and stop suspicious processes.",
    },
    "persistence": {
        "label": "Persistence Attempt",
        "description": "Someone may be trying to keep access over time.",
        "effect": "Potential long-term access is being simulated in the virtual environment.",
        "impact": "The path may stay active even if the first entry point is removed.",
        "risk_level": "High",
        "confidence": 73,
        "eta_mins": 9,
        "next_stage": "privilege_escalation",
        "predicted_outcomes": [
            {"title": "Privilege Escalation", "probability": 0.66, "description": "The attacker may try to gain stronger access next."},
            {"title": "Lateral Movement", "probability": 0.41, "description": "The path may branch toward nearby systems."}
        ],
        "recommended_action": "Review startup changes and isolate the affected workstation if needed.",
    },
    "privilege_escalation": {
        "label": "Privilege Escalation",
        "description": "Someone may be trying to gain higher access to the system.",
        "effect": "Potential admin-level access is being simulated safely.",
        "impact": "The attacker may gain stronger control over connected systems.",
        "risk_level": "High",
        "confidence": 81,
        "eta_mins": 12,
        "next_stage": "lateral_movement",
        "predicted_outcomes": [
            {"title": "Lateral Movement", "probability": 0.72, "description": "The path most likely expands toward connected systems."},
            {"title": "Data Access", "probability": 0.55, "description": "Sensitive systems may become reachable if access grows."}
        ],
        "recommended_action": "Reset credentials and review privilege changes immediately.",
    },
    "lateral_movement": {
        "label": "Lateral Movement",
        "description": "The simulated path is moving across nearby systems.",
        "effect": "Potential access to additional systems is being tested in the virtual environment.",
        "impact": "More business systems may become exposed if the path continues.",
        "risk_level": "High",
        "confidence": 84,
        "eta_mins": 10,
        "next_stage": "data_access",
        "predicted_outcomes": [
            {"title": "Data Access", "probability": 0.76, "description": "Sensitive data stores may become reachable next."},
            {"title": "Data Exfiltration", "probability": 0.48, "description": "Data exposure risk rises if the path is not stopped."}
        ],
        "recommended_action": "Monitor connected systems and restrict remote access paths.",
    },
    "data_access": {
        "label": "Data Access",
        "description": "Sensitive information may now be reachable inside the simulation.",
        "effect": "Potential access to customer and financial data has been simulated.",
        "impact": "Important records may be exposed if the path continues.",
        "risk_level": "Critical",
        "confidence": 88,
        "eta_mins": 8,
        "next_stage": "data_exfiltration",
        "predicted_outcomes": [
            {"title": "Data Exfiltration", "probability": 0.78, "description": "The path suggests a high chance of data leaving the environment."},
            {"title": "Expanded Data Access", "probability": 0.52, "description": "The attacker may try to reach more records before leaving."}
        ],
        "recommended_action": "Protect the affected data stores and review access patterns.",
    },
    "data_exfiltration": {
        "label": "Data Exfiltration",
        "description": "The simulation indicates data could leave the environment if nothing changes.",
        "effect": "Potential data exposure has reached the highest simulated stage.",
        "impact": "Important data may be exposed or leave the virtual environment.",
        "risk_level": "Critical",
        "confidence": 91,
        "eta_mins": 0,
        "next_stage": None,
        "predicted_outcomes": [
            {"title": "Business Impact", "probability": 0.83, "description": "If this path were real, the organization could face a serious data exposure event."}
        ],
        "recommended_action": "Contain the incident, reset access, and begin formal response review.",
    },
}


SCENARIO_STAGE_HINTS = {
    "compromised_account": "suspicious_login",
    "malware_infection": "malicious_execution",
    "insider_data_access": "data_access",
}


def load_mock_twin() -> dict:
    with open(MOCK_DB_FILE, "r", encoding="utf-8") as file_handle:
        return json.load(file_handle)


def get_stage_sequence():
    return list(SIMULATION_STAGES.keys())


def build_stage_levels(active_stage: str) -> list:
    ordered = get_stage_sequence()
    active_index = ordered.index(active_stage)
    levels = []

    for index, stage_key in enumerate(ordered, start=1):
        stage = SIMULATION_STAGES[stage_key]
        if index - 1 < active_index:
            status = "Completed"
        elif stage_key == active_stage:
            status = "Active"
        else:
            status = "Waiting"

        levels.append(
            {
                "level": index,
                "stage": stage_key,
                "title": stage["label"],
                "simple_explanation": stage["description"],
                "risk_indicator": stage["risk_level"],
                "status": status,
                "description": stage["effect"],
            }
        )

    return levels


def _systems_for_stage(stage: str, twin_data: dict) -> list:
    systems = twin_data["systems"]
    if stage in {"suspicious_login", "malicious_execution", "persistence"}:
        return [systems[1]["label"], systems[0]["label"]]
    if stage in {"privilege_escalation", "lateral_movement"}:
        return [systems[0]["label"], systems[1]["label"], systems[2]["label"]]
    return [systems[3]["label"], systems[4]["label"], systems[0]["label"]]


def _risk_score(stage: str, stage_meta: dict) -> float:
    base = {
        "Medium": 5.2,
        "High": 7.8,
        "Critical": 9.1,
    }
    score = base.get(stage_meta["risk_level"], 4.0)
    if stage in {"data_access", "data_exfiltration"}:
        score += 0.4
    return min(score, 9.8)


def simulate_stage(stage: str, incident_type: str = "Account Compromise") -> dict:
    if stage not in SIMULATION_STAGES:
        raise ValueError(f"Unknown stage: {stage}")

    stage_meta = deepcopy(SIMULATION_STAGES[stage])
    twin_data = load_mock_twin()
    levels = build_stage_levels(stage)
    affected_systems = _systems_for_stage(stage, twin_data)
    predicted_next = stage_meta["next_stage"]
    next_label = SIMULATION_STAGES[predicted_next]["label"] if predicted_next else "Containment Review"

    paths_tested = min(4 + levels[-1]["level"] + levels[[item["stage"] for item in levels].index(stage)]["level"], 18)
    high_risk_paths = max(1, len([item for item in levels if item["status"] != "Waiting" and item["risk_indicator"] in {"High", "Critical"}]))

    investigation_summary = {
        "incident_type": incident_type,
        "root_cause": "Suspicious login" if stage == "suspicious_login" else "Earlier suspicious activity in the virtual environment",
        "current_stage": stage_meta["label"],
        "predicted_outcome": next_label,
        "risk_level": stage_meta["risk_level"],
        "affected_systems": affected_systems,
        "recommended_action": stage_meta["recommended_action"],
    }

    chatbot_context = {
        "what_is_happening": (
            f"A {SIMULATION_STAGES['suspicious_login']['label'].lower()} was detected, and in our simulation "
            f"the path may now move toward {stage_meta['label'].lower()} and then {next_label.lower()}."
        ),
        "is_this_dangerous": (
            f"Yes. The current simulated risk is {stage_meta['risk_level'].lower()}, "
            "which means important systems or data could be exposed if the path continues."
        ),
        "what_should_i_do": stage_meta["recommended_action"],
        "why_did_this_happen": (
            "TwinShield grouped related warning signs into one incident and tested how they might connect inside a safe virtual environment."
        ),
    }

    return {
        "status": "simulated",
        "stage": stage,
        "stage_label": stage_meta["label"],
        "impact": stage_meta["impact"],
        "effect": stage_meta["effect"],
        "next_step": predicted_next,
        "next_step_label": next_label,
        "risk_level": stage_meta["risk_level"],
        "risk_score": _risk_score(stage, stage_meta),
        "confidence": stage_meta["confidence"],
        "timeline_levels": levels,
        "predictions": stage_meta["predicted_outcomes"],
        "simulation_summary": {
            "paths_tested": paths_tested,
            "high_risk_paths": high_risk_paths,
            "next_move_eta": f"{stage_meta['eta_mins']} min" if stage_meta["eta_mins"] else "Now",
            "confidence_level": f"{stage_meta['confidence']}%",
        },
        "security_snapshot": {
            "current_risk": stage_meta["risk_level"],
            "current_stage": stage_meta["label"],
            "likely_next_move": next_label,
            "best_first_action": stage_meta["recommended_action"],
        },
        "investigation_summary": investigation_summary,
        "chatbot_context": chatbot_context,
        "affected_systems": affected_systems,
        "mock_database": twin_data,
        "story": (
            f"TwinShield is safely simulating a path where the incident has reached {stage_meta['label'].lower()}. "
            f"From here, the most likely next move is {next_label.lower()}."
        ),
    }
