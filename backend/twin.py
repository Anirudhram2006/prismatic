"""
twin.py — Digital Twin graph for SmokeStack
Each node represents an asset; edges represent trust/access relationships.
"""


def build_twin():
    """Return a simple graph dict representing the corporate environment."""

    nodes = [
        # ── Users ──────────────────────────────────────────────────────────
        {"id": "user_alice",  "type": "user",   "label": "Alice (Admin)",
         "risk": 0.2, "department": "IT"},
        {"id": "user_bob",    "type": "user",   "label": "Bob (Developer)",
         "risk": 0.1, "department": "Engineering"},
        {"id": "user_carol",  "type": "user",   "label": "Carol (Finance)",
         "risk": 0.1, "department": "Finance"},

        # ── Devices ────────────────────────────────────────────────────────
        {"id": "dev_laptop_alice",  "type": "device", "label": "Alice's Laptop",
         "os": "Windows 11",  "risk": 0.2},
        {"id": "dev_laptop_bob",    "type": "device", "label": "Bob's Laptop",
         "os": "macOS",        "risk": 0.1},
        {"id": "dev_workstation",   "type": "device", "label": "Finance Workstation",
         "os": "Windows 10",  "risk": 0.3},

        # ── Servers ────────────────────────────────────────────────────────
        {"id": "srv_web",    "type": "server",   "label": "Web Server",
         "ip": "10.0.1.10",  "risk": 0.4, "exposed": True},
        {"id": "srv_app",    "type": "server",   "label": "App Server",
         "ip": "10.0.1.20",  "risk": 0.3, "exposed": False},
        {"id": "srv_ad",     "type": "server",   "label": "Active Directory",
         "ip": "10.0.1.30",  "risk": 0.5, "exposed": False},
        {"id": "srv_backup", "type": "server",   "label": "Backup Server",
         "ip": "10.0.1.40",  "risk": 0.2, "exposed": False},

        # ── Databases ──────────────────────────────────────────────────────
        {"id": "db_customer", "type": "database", "label": "Customer DB",
         "sensitivity": "high",   "risk": 0.5},
        {"id": "db_finance",  "type": "database", "label": "Finance DB",
         "sensitivity": "critical","risk": 0.6},
        {"id": "db_hr",       "type": "database", "label": "HR Database",
         "sensitivity": "high",   "risk": 0.4},

        # ── Network zones ──────────────────────────────────────────────────
        {"id": "net_dmz",      "type": "network", "label": "DMZ",
         "risk": 0.4},
        {"id": "net_internal", "type": "network", "label": "Internal Network",
         "risk": 0.3},
    ]

    edges = [
        # User → Device (uses)
        {"from": "user_alice", "to": "dev_laptop_alice", "relation": "uses"},
        {"from": "user_bob",   "to": "dev_laptop_bob",   "relation": "uses"},
        {"from": "user_carol", "to": "dev_workstation",  "relation": "uses"},

        # Device → Network (connects to)
        {"from": "dev_laptop_alice", "to": "net_internal", "relation": "connects_to"},
        {"from": "dev_laptop_bob",   "to": "net_internal", "relation": "connects_to"},
        {"from": "dev_workstation",  "to": "net_internal", "relation": "connects_to"},

        # Network → Server (hosts)
        {"from": "net_dmz",      "to": "srv_web",    "relation": "hosts"},
        {"from": "net_internal", "to": "srv_app",    "relation": "hosts"},
        {"from": "net_internal", "to": "srv_ad",     "relation": "hosts"},
        {"from": "net_internal", "to": "srv_backup", "relation": "hosts"},

        # Server → Server (trust paths)
        {"from": "srv_web",  "to": "srv_app",    "relation": "trusts"},
        {"from": "srv_app",  "to": "srv_ad",     "relation": "trusts"},
        {"from": "srv_ad",   "to": "srv_backup", "relation": "trusts"},

        # Server → Database (accesses)
        {"from": "srv_app",  "to": "db_customer", "relation": "accesses"},
        {"from": "srv_app",  "to": "db_hr",       "relation": "accesses"},
        {"from": "srv_ad",   "to": "db_finance",  "relation": "accesses"},

        # User → Server (admin access)
        {"from": "user_alice", "to": "srv_ad",     "relation": "admin_access"},
        {"from": "user_alice", "to": "srv_backup", "relation": "admin_access"},
        {"from": "user_bob",   "to": "srv_app",    "relation": "ssh_access"},
        {"from": "user_carol", "to": "db_finance", "relation": "read_access"},

        # Internet → DMZ entry point
        {"from": "net_dmz",    "to": "net_internal", "relation": "gateway"},
    ]

    return {"nodes": nodes, "edges": edges}
