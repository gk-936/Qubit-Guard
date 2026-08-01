import sqlite3
import os

db_path = "backend/database/quantumshield.db"

if not os.path.exists(db_path):
    print(f"DB not found at {db_path}")
    exit(1)

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

new_columns = [
    ("scheduled_time", "VARCHAR(10)"),
    ("email", "VARCHAR(255)"),
    ("report_type", "VARCHAR(50) DEFAULT 'executive'"),
    ("is_active", "BOOLEAN DEFAULT 1"),
    ("last_run_at", "DATETIME")
]

for col_name, col_type in new_columns:
    try:
        print(f"Adding column {col_name}...")
        cursor.execute(f"ALTER TABLE schedules ADD COLUMN {col_name} {col_type}")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e):
            print(f"Column {col_name} already exists.")
        else:
            print(f"Error adding {col_name}: {e}")

conn.commit()
conn.close()
print("Migration complete.")
