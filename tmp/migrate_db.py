import sqlite3
import os

db_path = os.path.join(os.getcwd(), 'backend', 'database', 'quantumshield.db')
if os.path.exists(db_path):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        # Add the column if it doesn't exist
        cursor.execute("ALTER TABLE scan_results ADD COLUMN api_metrics_json TEXT DEFAULT '{}'")
        conn.commit()
        conn.close()
        print("Successfully added api_metrics_json to scan_results table.")
    except Exception as e:
        print(f"Migration failed (it might already exist): {str(e)}")
else:
    print(f"Database not found at {db_path}. Skipping migration.")
