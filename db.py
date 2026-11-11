import os
import mysql.connector


def query(sql, params=(), one=False, commit=False):
    conn = mysql.connector.connect(
        host=os.environ.get("DB_HOST", "localhost"),
        user=os.environ.get("DB_USER"),
        password=os.environ.get("DB_PASSWORD"),
        database=os.environ.get("DB_NAME"),
    )
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(sql, params)      # i %s li sostituisce il driver: mai f-string nelle query
        if commit:
            conn.commit()
            return cur.lastrowid
        rows = cur.fetchall()
        return (rows[0] if rows else None) if one else rows
    finally:
        conn.close()
