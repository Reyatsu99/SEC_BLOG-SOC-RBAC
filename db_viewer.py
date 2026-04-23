import sqlite3
import json

def view_db():
    conn = sqlite3.connect('secure_blog.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    tables = ['users', 'posts', 'messages', 'audit_logs']
    
    for table in tables:
        print(f"\n{'='*20} {table.upper()} {'='*20}")
        try:
            cursor.execute(f"SELECT * FROM {table} LIMIT 10")
            rows = cursor.fetchall()
            if not rows:
                print("Table is empty.")
                continue
                
            for row in rows:
                data = dict(row)
                # Truncate long hashes or encrypted content for readability
                for key in data:
                    val = str(data[key])
                    if len(val) > 50:
                        data[key] = val[:47] + "..."
                print(data)
        except Exception as e:
            print(f"Error reading {table}: {e}")

    conn.close()

if __name__ == "__main__":
    view_db()
