import sqlite3

conn = sqlite3.connect("metrics.db", check_same_thread=False)
cur = conn.cursor()

cur.execute("""
            CREATE TABLE IF NOT EXISTS metrics (
                                                   key TEXT PRIMARY KEY,
                                                   value INTEGER
            )
            """)
conn.commit()

def increment(key):
    cur.execute("INSERT OR IGNORE INTO metrics VALUES (?,0)", (key,))
    cur.execute("UPDATE metrics SET value = value + 1 WHERE key=?", (key,))
    conn.commit()

def get(key):
    cur.execute("SELECT value FROM metrics WHERE key=?", (key,))
    row = cur.fetchone()
    return row[0] if row else 0
