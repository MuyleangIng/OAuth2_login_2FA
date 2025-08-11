# scripts/migrate_totp_sqlite.py
import sqlite3
from pathlib import Path

DB_PATH = Path("users.db")  # change if needed

cols_to_add = [
    ("totp_secret", "TEXT"),
    ("totp_enabled", "INTEGER DEFAULT 0"),
    ("totp_verified_at", "TEXT"),
    ("totp_backup_codes", "TEXT"),
]

def column_exists(cur, table, col):
    cur.execute(f"PRAGMA table_info({table})")
    return any(r[1] == col for r in cur.fetchall())

def main():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    for col, ddl in cols_to_add:
        if not column_exists(cur, "users", col):
            cur.execute(f"ALTER TABLE users ADD COLUMN {col} {ddl}")
            print(f"Added column: {col}")
        else:
            print(f"Column exists: {col}")
    con.commit()
    con.close()
    print("Done.")

if __name__ == "__main__":
    main()
