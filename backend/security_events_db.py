import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "security_events.db")

def setup_database():
    """
    Creates a sample SQLite database table that combines SIEM, IDS, and EDR data fields.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Create a table combining SIEM, IDS, and EDR data fields
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS combined_security_events (
        event_id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        
        -- SIEM Fields (Security Information and Event Management)
        event_type TEXT,
        source_ip TEXT,
        destination_ip TEXT,
        user_account TEXT,
        
        -- IDS Fields (Intrusion Detection System)
        ids_rule_id TEXT,
        severity_level TEXT,
        network_protocol TEXT,
        
        -- EDR Fields (Endpoint Detection and Response)
        device_id TEXT,
        process_name TEXT,
        file_hash TEXT,
        endpoint_action TEXT
    )
    ''')

    # Insert some sample mock data combining these domains
    cursor.execute('''
    INSERT INTO combined_security_events (
        event_type, source_ip, destination_ip, user_account, 
        ids_rule_id, severity_level, network_protocol, 
        device_id, process_name, file_hash, endpoint_action
    ) VALUES (
        'Suspicious Login', '185.220.101.47', '10.0.1.30', 'alice',
        'RULE-1045: Brute Force Attempt', 'High', 'TCP',
        'dev_laptop_alice', 'cmd.exe', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'Execution Allowed'
    )
    ''')

    conn.commit()
    print(f"Database created at: {DB_PATH}")
    print("Table 'combined_security_events' populated successfully.\n")
    
    # Query and display the data
    cursor.execute('SELECT * FROM combined_security_events')
    rows = cursor.fetchall()
    for row in rows:
        print("Sample Record:", row)
        
    conn.close()

if __name__ == '__main__':
    setup_database()
