"""
simulation.py — Rule-based attack simulation for SmokeStack
Maps incoming alert → MITRE ATT&CK stage → predicted attack paths
"""

from datetime import datetime, timedelta


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

ATTACK_PATHS = {
    "initial_access": [
        {
            "path_id": "PATH-A",
            "label": "Credential Harvesting → Lateral Movement",
            "probability": 0.72,
            "steps": [
                {"stage": "execution",            "action": "Deploy credential dumper (Mimikatz-style)", "target": "dev_laptop_alice", "eta_mins": 15},
                {"stage": "persistence",          "action": "Install reverse shell backdoor",            "target": "dev_laptop_alice", "eta_mins": 30},
                {"stage": "privilege_escalation", "action": "Exploit local admin token",                 "target": "srv_ad",           "eta_mins": 45},
                {"stage": "lateral_movement",     "action": "Pass-the-Hash to Active Directory",         "target": "srv_ad",           "eta_mins": 60},
                {"stage": "collection",           "action": "Enumerate and stage sensitive data",        "target": "db_finance",       "eta_mins": 90},
                {"stage": "exfiltration",         "action": "Exfiltrate via encrypted C2 channel",      "target": "net_dmz",          "eta_mins": 120},
            ],
        },
        {
            "path_id": "PATH-B",
            "label": "Phishing Pivot → Web Server Compromise",
            "probability": 0.55,
            "steps": [
                {"stage": "execution",        "action": "Execute malicious macro / dropper",    "target": "dev_laptop_bob", "eta_mins": 20},
                {"stage": "persistence",      "action": "Add scheduled task for persistence",   "target": "dev_laptop_bob", "eta_mins": 35},
                {"stage": "lateral_movement", "action": "Pivot to Web Server via SSH key",      "target": "srv_web",        "eta_mins": 50},
                {"stage": "collection",       "action": "Harvest customer DB credentials",      "target": "db_customer",    "eta_mins": 80},
                {"stage": "exfiltration",     "action": "Bulk-export customer records",         "target": "db_customer",    "eta_mins": 100},
            ],
        },
        {
            "path_id": "PATH-C",
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
            ],
        },
        {
            "path_id": "PATH-B",
            "label": "Backup Server Ransomware",
            "probability": 0.60,
            "steps": [
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
            ],
        },
    ],
}

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


def _recommendations(stage: str) -> list:
    base = [
        "Isolate the affected device from the network immediately.",
        "Reset credentials for all accounts that accessed this device.",
        "Enable MFA on all privileged accounts if not already active.",
    ]
    extras = {
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
