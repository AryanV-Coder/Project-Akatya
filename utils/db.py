import os
import psycopg2
from dotenv import load_dotenv
from contextlib import contextmanager

load_dotenv()

def connect_postgres():
    """Establishes and returns a direct PostgreSQL connection and cursor."""
    user = os.getenv("user")
    password = os.getenv("password")
    host = os.getenv("host")
    port = os.getenv("port")
    dbname = os.getenv("dbname")

    try:
        connection = psycopg2.connect(
            user=user,
            password=password,
            host=host,
            port=port,
            database=dbname
        )
        cursor = connection.cursor()
        return connection, cursor
    except Exception as e:
        print(f"[!] Failed to connect to PostgreSQL: {e}")
        return None, None


@contextmanager
def get_db_cursor(commit: bool = False):
    """
    Context manager for database operations.
    Automatically closes cursor and connection, and rolls back on exception.
    """
    conn, cur = connect_postgres()
    if not conn or not cur:
        raise RuntimeError("Database connection could not be established")
    
    try:
        yield cur
        if commit:
            conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()

