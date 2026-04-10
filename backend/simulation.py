"""
<<<<<<< HEAD
simulation.py - Rule-based attack simulation for TwinShield.
Maps incoming alerts to attack stages and predicts likely next paths.
=======
simulation.py — Rule-based attack simulation for SmokeStack
Maps incoming alert → MITRE ATT&CK stage → predicted attack paths
>>>>>>> fbfa6c73df652ef448eaa2b8b7c5810248386342
"""

from datetime import datetime, timedelta


<<<<<<< HEAD
STAGES = {
    "initial_access": {
        "order": 1,
        "label": "Initial Access",
        "color": "#f59e0b",
        "simple": "Suspicious Login",
        "icon": "key",
        "analogy": "Like someone getting through the front door with a suspicious badge swipe.",
    },
    "execution": {
        "order": 2,
        "label": "Execution",
        "color": "#f97316",
        "simple": "Malicious Action",
        "icon": "bolt",
        "analogy": "Like a hidden tool being unpacked after someone gets inside.",
    },
    "persistence": {
        "order": 3,
        "label": "Persistence",
        "color": "#ef4444",
        "simple": "Trying to Stay Inside",
        "icon": "anchor",
        "analogy": "Like leaving a spare key behind so they can return later.",
    },
    "privilege_escalation": {
        "order": 4,
        "label": "Privilege Escalation",
        "color": "#dc2626",
        "simple": "Admin Control Attempt",
        "icon": "shield",
        "analogy": "Like trying to upgrade from a visitor pass to a master key.",
    },
    "lateral_movement": {
        "order": 5,
        "label": "Lateral Movement",
        "color": "#b91c1c",
        "simple": "Moving Across Systems",
        "icon": "route",
        "analogy": "Like moving room to room inside a building after getting in.",
    },
    "collection": {
        "order": 6,
        "label": "Collection",
        "color": "#991b1b",
        "simple": "Gathering Sensitive Data",
        "icon": "database",
        "analogy": "Like pulling files together before taking them out.",
    },
    "exfiltration": {
        "order": 7,
        "label": "Exfiltration",
        "color": "#7f1d1d",
        "simple": "Data Leaving the System",
        "icon": "upload",
        "analogy": "Like carrying documents out of the building.",
    },
}


def detect_stage(alert: dict) -> str:
    """Map an alert to the most likely attack stage."""
    alert_type = alert.get("type", "").lower()
    event = alert.get("event", "").lower()
    combined = f"{alert_type} {event}"

    rules = [
        (
            [
                "brute force",
                "failed login",
                "invalid password",
                "login anomaly",
                "suspicious login",
                "credential",
            ],
            "initial_access",
        ),
        (["phishing", "malicious attachment", "macro", "payload"], "initial_access"),
        (["script exec", "powershell", "cmd.exe", "bash", "process spawn"], "execution"),
        (
            ["scheduled task", "registry", "startup", "service install", "cron", "persistence"],
            "persistence",
        ),
        (
            ["privilege", "sudo", "runas", "token", "admin escalation", "uac bypass"],
            "privilege_escalation",
        ),
        (
            ["lateral", "pass-the-hash", "rdp", "smb", "wmi", "psexec", "mimikatz"],
            "lateral_movement",
        ),
        (["data staging", "archive", "compress", "collect"], "collection"),
        (["exfil", "data transfer", "upload", "dns tunnel", "c2"], "exfiltration"),
    ]

    for keywords, stage in rules:
        if any(keyword in combined for keyword in keywords):
            return stage

    return "initial_access"


=======
# ── Attack stage catalogue ────────────────────────────────────────────────────

STAGES = {
    "initial_access":    {"order": 1, "label": "Initial Access",    "color": "#f59e0b"},
    "execution":         {"order": 2, "label": "Execution",          "color": "#f97316"},
    "persistence":       {"order": 3, "label": "Persistence",        "color": "#ef4444"},
    "privilege_escalation": {"order": 4, "label": "Privilege Escalation", "color": "#dc2626"},
    "lateral_movement":  {"order": 5, "label": "Lateral Movement",   "color": "#b91c1c"},
    "collection":        {"order": 6, "label": "Collection",         "color": "#991b1b"},
    "exfiltration":      {"order": 7, "label": "Exfiltration",       "color": "#7f1d1d"},
}


# ── Alert → stage mapping rules ──────────────────────────────────────────────

def detect_stage(alert: dict) -> str:
    """Map an alert to the most likely MITRE ATT&CK stage."""
    alert_type = alert.get("type", "").lower()
    event      = alert.get("event", "").lower()
    combined   = f"{alert_type} {event}"

    rules = [
        (["brute force", "failed login", "invalid password", "login anomaly",
          "suspicious login", "credential"],         "initial_access"),
        (["phishing", "malicious attachment", "macro", "payload"],
                                                     "initial_access"),
        (["script exec", "powershell", "cmd.exe", "bash", "process spawn"],
                                                     "execution"),
        (["scheduled task", "registry", "startup", "service install",
          "cron", "persistence"],                    "persistence"),
        (["privilege", "sudo", "runas", "token", "admin escalation",
          "uac bypass"],                             "privilege_escalation"),
        (["lateral", "pass-the-hash", "rdp", "smb", "wmi", "psexec",
          "mimikatz"],                               "lateral_movement"),
        (["data staging", "archive", "compress", "collect"],
                                                     "collection"),
        (["exfil", "data transfer", "upload", "dns tunnel", "c2"],
                                                     "exfiltration"),
    ]

    for keywords, stage in rules:
        if any(k in combined for k in keywords):
            return stage

    return "initial_access"   # default fallback


# ── Next-step generation rules ────────────────────────────────────────────────

>>>>>>> fbfa6c73df652ef448eaa2b8b7c5810248386342
ATTACK_PATHS = {
    "initial_access": [
        {
            "path_id": "PATH-A",
<<<<<<< HEAD
            "label": "Credential Harvesting -> Lateral Movement",
            "probability": 0.72,
            "steps": [
                {"stage": "execution", "action": "Deploy credential dumper", "target": "dev_laptop_alice", "eta_mins": 15},
                {"stage": "persistence", "action": "Install reverse shell backdoor", "target": "dev_laptop_alice", "eta_mins": 30},
                {"stage": "privilege_escalation", "action": "Exploit local admin token", "target": "srv_ad", "eta_mins": 45},
                {"stage": "lateral_movement", "action": "Pass the hash to Active Directory", "target": "srv_ad", "eta_mins": 60},
                {"stage": "collection", "action": "Stage sensitive finance data", "target": "db_finance", "eta_mins": 90},
                {"stage": "exfiltration", "action": "Exfiltrate through encrypted command channel", "target": "net_dmz", "eta_mins": 120},
=======
            "label": "Credential Harvesting → Lateral Movement",
            "probability": 0.72,
            "steps": [
                {"stage": "execution",            "action": "Deploy credential dumper (Mimikatz-style)", "target": "dev_laptop_alice", "eta_mins": 15},
                {"stage": "persistence",          "action": "Install reverse shell backdoor",            "target": "dev_laptop_alice", "eta_mins": 30},
                {"stage": "privilege_escalation", "action": "Exploit local admin token",                 "target": "srv_ad",           "eta_mins": 45},
                {"stage": "lateral_movement",     "action": "Pass-the-Hash to Active Directory",         "target": "srv_ad",           "eta_mins": 60},
                {"stage": "collection",           "action": "Enumerate and stage sensitive data",        "target": "db_finance",       "eta_mins": 90},
                {"stage": "exfiltration",         "action": "Exfiltrate via encrypted C2 channel",      "target": "net_dmz",          "eta_mins": 120},
>>>>>>> fbfa6c73df652ef448eaa2b8b7c5810248386342
            ],
        },
        {
            "path_id": "PATH-B",
<<<<<<< HEAD
            "label": "Phishing Pivot -> Web Server Compromise",
            "probability": 0.55,
            "steps": [
                {"stage": "execution", "action": "Run malicious macro or dropper", "target": "dev_laptop_bob", "eta_mins": 20},
                {"stage": "persistence", "action": "Create scheduled task for persistence", "target": "dev_laptop_bob", "eta_mins": 35},
                {"stage": "lateral_movement", "action": "Pivot to web server with reused credentials", "target": "srv_web", "eta_mins": 50},
                {"stage": "collection", "action": "Harvest customer database credentials", "target": "db_customer", "eta_mins": 80},
                {"stage": "exfiltration", "action": "Bulk export customer records", "target": "db_customer", "eta_mins": 100},
=======
            "label": "Phishing Pivot → Web Server Compromise",
            "probability": 0.55,
            "steps": [
                {"stage": "execution",        "action": "Execute malicious macro / dropper",    "target": "dev_laptop_bob", "eta_mins": 20},
                {"stage": "persistence",      "action": "Add scheduled task for persistence",   "target": "dev_laptop_bob", "eta_mins": 35},
                {"stage": "lateral_movement", "action": "Pivot to Web Server via SSH key",      "target": "srv_web",        "eta_mins": 50},
                {"stage": "collection",       "action": "Harvest customer DB credentials",      "target": "db_customer",    "eta_mins": 80},
                {"stage": "exfiltration",     "action": "Bulk-export customer records",         "target": "db_customer",    "eta_mins": 100},
>>>>>>> fbfa6c73df652ef448eaa2b8b7c5810248386342
            ],
        },
        {
            "path_id": "PATH-C",
<<<<<<< HEAD
            "label": "Stealth Persistence -> Finance DB Theft",
            "probability": 0.38,
            "steps": [
                {"stage": "persistence", "action": "Implant memory injector", "target": "dev_workstation", "eta_mins": 25},
                {"stage": "privilege_escalation", "action": "Exploit local privilege weakness", "target": "dev_workstation", "eta_mins": 40},
                {"stage": "lateral_movement", "action": "Move to finance workstation", "target": "dev_workstation", "eta_mins": 55},
                {"stage": "collection", "action": "Stage finance records to temp storage", "target": "db_finance", "eta_mins": 85},
                {"stage": "exfiltration", "action": "Exfiltrate through DNS tunneling", "target": "net_dmz", "eta_mins": 110},
            ],
        },
    ],
    "lateral_movement": [
        {
            "path_id": "PATH-A",
            "label": "AD Compromise -> Full Domain Takeover",
            "probability": 0.80,
            "steps": [
                {"stage": "privilege_escalation", "action": "Dump domain hashes with directory sync abuse", "target": "srv_ad", "eta_mins": 10},
                {"stage": "collection", "action": "Access file shares and sensitive databases", "target": "db_finance", "eta_mins": 30},
                {"stage": "exfiltration", "action": "Mass exfiltrate to external storage", "target": "net_dmz", "eta_mins": 60},
=======
            "label": "Stealth Persistence → Finance DB Theft",
            "probability": 0.38,
            "steps": [
                {"stage": "persistence",          "action": "Implant LSASS memory injector",          "target": "dev_workstation", "eta_mins": 25},
                {"stage": "privilege_escalation", "action": "Exploit unpatched Windows service (LPE)", "target": "dev_workstation", "eta_mins": 40},
                {"stage": "lateral_movement",     "action": "Move laterally to Finance workstation",   "target": "dev_workstation", "eta_mins": 55},
                {"stage": "collection",           "action": "Stage Finance DB records to temp folder", "target": "db_finance",      "eta_mins": 85},
                {"stage": "exfiltration",         "action": "Exfiltrate via DNS tunneling",            "target": "net_dmz",         "eta_mins": 110},
            ],
        },
    ],

    "lateral_movement": [
        {
            "path_id": "PATH-A",
            "label": "AD Compromise → Full Domain Takeover",
            "probability": 0.80,
            "steps": [
                {"stage": "privilege_escalation", "action": "DCSync attack — dump all domain hashes", "target": "srv_ad",     "eta_mins": 10},
                {"stage": "collection",           "action": "Access all file shares & databases",     "target": "db_finance", "eta_mins": 30},
                {"stage": "exfiltration",         "action": "Mass exfiltrate to external storage",   "target": "net_dmz",    "eta_mins": 60},
>>>>>>> fbfa6c73df652ef448eaa2b8b7c5810248386342
            ],
        },
        {
            "path_id": "PATH-B",
            "label": "Backup Server Ransomware",
            "probability": 0.60,
            "steps": [
<<<<<<< HEAD
                {"stage": "privilege_escalation", "action": "Gain backup operator rights", "target": "srv_backup", "eta_mins": 15},
                {"stage": "collection", "action": "Map critical backup sets", "target": "srv_backup", "eta_mins": 25},
                {"stage": "exfiltration", "action": "Encrypt backup systems with ransomware", "target": "srv_backup", "eta_mins": 45},
            ],
        },
    ],
    "privilege_escalation": [
        {
            "path_id": "PATH-A",
            "label": "Domain Admin -> Crown Jewel Access",
            "probability": 0.85,
            "steps": [
                {"stage": "lateral_movement", "action": "Move to high-value servers with admin token", "target": "srv_ad", "eta_mins": 10},
                {"stage": "collection", "action": "Collect HR, finance, and customer data", "target": "db_hr", "eta_mins": 25},
                {"stage": "exfiltration", "action": "Slow-drip exfiltration over two days", "target": "net_dmz", "eta_mins": 50},
=======
                {"stage": "privilege_escalation", "action": "Gain backup-operator privilege",         "target": "srv_backup", "eta_mins": 15},
                {"stage": "collection",           "action": "Identify and map critical backup sets",  "target": "srv_backup", "eta_mins": 25},
                {"stage": "exfiltration",         "action": "Encrypt backups — deploy ransomware",   "target": "srv_backup", "eta_mins": 45},
            ],
        },
    ],

    "privilege_escalation": [
        {
            "path_id": "PATH-A",
            "label": "Domain Admin → Crown-Jewel Access",
            "probability": 0.85,
            "steps": [
                {"stage": "lateral_movement", "action": "Move to high-value servers using DA token", "target": "srv_ad",     "eta_mins": 10},
                {"stage": "collection",       "action": "Collect HR, Finance, Customer data",        "target": "db_hr",      "eta_mins": 25},
                {"stage": "exfiltration",     "action": "Slow-drip exfil over 48 hours",             "target": "net_dmz",    "eta_mins": 50},
>>>>>>> fbfa6c73df652ef448eaa2b8b7c5810248386342
            ],
        },
    ],
}

<<<<<<< HEAD
DEFAULT_PATHS = ATTACK_PATHS["initial_access"]


def _enrich_paths(paths: list, twin: dict) -> list:
    node_map = {node["id"]: node["label"] for node in twin["nodes"]}
    enriched_paths = []

    for path in paths:
        enriched_steps = []
        for step in path["steps"]:
            stage_meta = STAGES.get(step["stage"], {})
            enriched_steps.append(
                {
                    **step,
                    "target_label": node_map.get(step["target"], step["target"]),
                    "stage_label": stage_meta.get("label", step["stage"]),
                    "stage_color": stage_meta.get("color", "#6b7280"),
                    "simple_stage": stage_meta.get("simple", step["stage"]),
                    "icon": stage_meta.get("icon", "dot"),
                }
            )
        enriched_paths.append({**path, "steps": enriched_steps})

    return enriched_paths


def _plain_english(stage: str, paths: list) -> str:
    top = sorted(paths, key=lambda path: path["probability"], reverse=True)[0]
    stage_name = STAGES.get(stage, {}).get("simple", stage)
    return (
        f"TwinShield detected {stage_name.lower()} behavior. "
        f"The most likely next route is {top['label']} with a {int(top['probability'] * 100)}% likelihood. "
        f"The first follow-up move could happen in about {top['steps'][0]['eta_mins']} minutes, so early action matters."
    )


def _story_mode(alert: dict, stage: str, paths: list) -> dict:
    top = sorted(paths, key=lambda path: path["probability"], reverse=True)[0]
    first_step = top["steps"][0]
    second_step = top["steps"][1] if len(top["steps"]) > 1 else None

    opening = (
        f"An unusual event involving {alert.get('affected_user', alert.get('user', 'a user account'))} "
        f"was detected on {alert.get('device', 'an endpoint')}."
    )
    current = (
        f"TwinShield believes this incident is in the {STAGES.get(stage, {}).get('simple', stage).lower()} phase."
    )
    next_move = (
        f"The attacker may next attempt {first_step['simple_stage'].lower()} against {first_step['target_label']} "
        f"in about {first_step['eta_mins']} minutes."
    )
    consequence = (
        f"If that succeeds, the path could continue toward {second_step['simple_stage'].lower()}."
        if second_step
        else "If nothing changes, the attacker may continue deeper into the environment."
    )

    return {
        "headline": "Here is the incident in plain language.",
        "narrative": f"{opening} {current} {next_move} {consequence}",
        "chapters": [
            {"title": "How it started", "text": alert.get("event", "Suspicious activity was reported.")},
            {"title": "What we are seeing now", "text": current},
            {"title": "What may happen next", "text": next_move},
            {"title": "Why it matters", "text": consequence},
        ],
    }


def _build_timeline(alert: dict, stage: str, paths: list) -> list:
    now = datetime.utcnow()
    stage_meta = STAGES.get(stage, {})
    timeline = [
        {
            "time": now.isoformat() + "Z",
            "stage": stage,
            "label": stage_meta.get("label", stage),
            "simple_stage": stage_meta.get("simple", stage),
            "event": alert.get("event", "Alert received"),
            "source": alert.get("source_ip", "unknown"),
            "status": "detected",
        }
    ]

    top_path = sorted(paths, key=lambda path: path["probability"], reverse=True)[0]
    for step in top_path["steps"]:
        timeline.append(
            {
                "time": (now + timedelta(minutes=step["eta_mins"])).isoformat() + "Z",
                "stage": step["stage"],
                "label": step["stage_label"],
                "simple_stage": step["simple_stage"],
                "event": step["action"],
                "target": step["target"],
                "target_label": step["target_label"],
                "status": "predicted",
            }
        )
    return timeline


=======
# Default paths when no specific rule matched
_DEFAULT_PATHS = ATTACK_PATHS["initial_access"]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _plain_english(stage: str, paths: list) -> str:
    top = sorted(paths, key=lambda p: p["probability"], reverse=True)[0]
    return (
        f"We detected suspicious activity consistent with {STAGES.get(stage, {}).get('label', stage)}. "
        f"The most likely follow-on attack ({int(top['probability']*100)}% chance) is: "
        f"\"{top['label']}\". "
        f"The attacker could complete this chain in as little as "
        f"{top['steps'][0]['eta_mins']} minutes. "
        f"Immediate action is recommended."
    )


def _build_timeline(alert: dict, stage: str, paths: list) -> list:
    """Construct a unified timeline merging the alert with the top predicted path."""
    now = datetime.utcnow()
    timeline = [
        {
            "time":   now.isoformat() + "Z",
            "stage":  stage,
            "label":  STAGES.get(stage, {}).get("label", stage),
            "event":  alert.get("event", "Alert received"),
            "source": alert.get("source_ip", "unknown"),
        }
    ]
    top_path = sorted(paths, key=lambda p: p["probability"], reverse=True)[0]
    for step in top_path["steps"]:
        timeline.append({
            "time":   (now + timedelta(minutes=step["eta_mins"])).isoformat() + "Z",
            "stage":  step["stage"],
            "label":  STAGES.get(step["stage"], {}).get("label", step["stage"]),
            "event":  step["action"],
            "target": step["target"],
        })
    return timeline


# ── Main entry point ──────────────────────────────────────────────────────────

def simulate(alert: dict, twin: dict) -> dict:
    """Run simulation and return structured prediction JSON."""

    stage = detect_stage(alert)
    paths = ATTACK_PATHS.get(stage, _DEFAULT_PATHS)

    # Enrich each path step with twin node labels
    node_map = {n["id"]: n["label"] for n in twin["nodes"]}
    enriched_paths = []
    for path in paths:
        enriched_steps = []
        for step in path["steps"]:
            enriched_steps.append({
                **step,
                "target_label": node_map.get(step["target"], step["target"]),
                "stage_label":  STAGES.get(step["stage"], {}).get("label", step["stage"]),
                "stage_color":  STAGES.get(step["stage"], {}).get("color", "#6b7280"),
            })
        enriched_paths.append({**path, "steps": enriched_steps})

    timeline = _build_timeline(alert, stage, enriched_paths)

    return {
        "incident_type":   alert.get("type", "Unknown Alert"),
        "severity":        alert.get("severity", "high"),
        "current_stage":   stage,
        "current_stage_label": STAGES.get(stage, {}).get("label", stage),
        "source_asset":    alert.get("device", "unknown"),
        "affected_user":   alert.get("user", "unknown"),
        "timestamp":       datetime.utcnow().isoformat() + "Z",
        "timeline":        timeline,
        "attack_paths":    enriched_paths,
        "plain_english":   _plain_english(stage, enriched_paths),
        "recommended_actions": _recommendations(stage),
    }


>>>>>>> fbfa6c73df652ef448eaa2b8b7c5810248386342
def _recommendations(stage: str) -> list:
    base = [
        "Isolate the affected device from the network immediately.",
        "Reset credentials for all accounts that accessed this device.",
        "Enable MFA on all privileged accounts if not already active.",
    ]
    extras = {
<<<<<<< HEAD
        "lateral_movement": [
            "Block SMB and RDP from workstations to servers.",
            "Audit Active Directory for new admin accounts.",
        ],
        "privilege_escalation": [
            "Audit sudo and local admin group memberships.",
            "Patch outstanding privilege escalation vulnerabilities.",
        ],
        "exfiltration": [
            "Block outbound traffic on non-standard ports.",
            "Enable data loss prevention rules on mail and cloud gateways.",
        ],
        "collection": [
            "Review database query logs for unusual bulk access.",
            "Enable file access auditing on sensitive shares.",
        ],
    }
    return base + extras.get(stage, [])


def _simplified_terms(stage: str, paths: list) -> list:
    terms = {stage}
    for path in paths:
        for step in path["steps"]:
            terms.add(step["stage"])

    simplified = []
    for term in sorted(terms, key=lambda item: STAGES.get(item, {}).get("order", 99)):
        meta = STAGES.get(term, {})
        simplified.append(
            {
                "term": meta.get("label", term),
                "plain_english": meta.get("simple", term),
                "analogy": meta.get("analogy", "TwinShield translates this into plain language."),
            }
        )
    return simplified


def _prediction_cards(paths: list) -> list:
    cards = []
    for path in sorted(paths, key=lambda path: path["probability"], reverse=True)[:3]:
        first_step = path["steps"][0]
        cards.append(
            {
                "title": first_step["simple_stage"],
                "technical_title": path["label"],
                "probability": path["probability"],
                "impact": "Critical" if path["probability"] >= 0.7 else "High" if path["probability"] >= 0.5 else "Medium",
                "time_window": f"Within {first_step['eta_mins']} minutes",
                "description": f"The attacker may target {first_step['target_label']} next.",
                "why": f"This route appears consistently in the twin simulation and matches the current incident pattern.",
                "next_action": f"Review activity around {first_step['target_label']} and prepare containment.",
            }
        )
    return cards


def _simulation_summary(paths: list, twin: dict) -> dict:
    top = sorted(paths, key=lambda path: path["probability"], reverse=True)[0]
    return {
        "paths_tested": len(paths),
        "high_risk_paths": len([path for path in paths if path["probability"] >= 0.5]),
        "confidence_score": int(top["probability"] * 100) + 12,
        "time_to_next_move": top["steps"][0]["eta_mins"],
        "assets_modeled": len(twin["nodes"]),
    }


def simulate(alert: dict, twin: dict) -> dict:
    """Run simulation and return structured prediction JSON."""
    stage = detect_stage(alert)
    raw_paths = ATTACK_PATHS.get(stage, DEFAULT_PATHS)
    enriched_paths = _enrich_paths(raw_paths, twin)
    timeline = _build_timeline(alert, stage, enriched_paths)
    prediction_cards = _prediction_cards(enriched_paths)
    explanation = _plain_english(stage, enriched_paths)
    story_mode = _story_mode(alert, stage, enriched_paths)

    return {
        "incident_type": alert.get("type", "Unknown Alert"),
        "severity": alert.get("severity", "high"),
        "current_stage": stage,
        "current_stage_label": STAGES.get(stage, {}).get("label", stage),
        "current_stage_simple": STAGES.get(stage, {}).get("simple", stage),
        "source_asset": alert.get("device", "unknown"),
        "affected_user": alert.get("user", "unknown"),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "timeline": timeline,
        "attack_paths": enriched_paths,
        "predictions": prediction_cards,
        "prediction_cards": prediction_cards,
        "explanation": explanation,
        "plain_english": explanation,
        "story_mode": story_mode,
        "simplified_terms": _simplified_terms(stage, enriched_paths),
        "recommended_actions": _recommendations(stage),
        "simulation_summary": _simulation_summary(enriched_paths, twin),
    }
=======
        "lateral_movement":     ["Block SMB / RDP from workstations to servers.",
                                  "Audit Active Directory for new admin accounts."],
        "privilege_escalation": ["Audit sudo / local-admin group memberships.",
                                  "Review and patch outstanding local privilege-escalation CVEs."],
        "exfiltration":         ["Block outbound traffic on non-standard ports.",
                                  "Enable DLP rules on email and cloud storage gateways."],
        "collection":           ["Audit database query logs for bulk SELECT statements.",
                                  "Enable file-access auditing on sensitive shares."],
    }
    return base + extras.get(stage, [])
>>>>>>> fbfa6c73df652ef448eaa2b8b7c5810248386342
