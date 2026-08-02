import os
import psycopg2
import psycopg2.pool
import threading
import contextlib

# Thread-safe database connection pooling
pool_lock = threading.Lock()
db_pool = None

def get_db_pool():
    global db_pool
    if db_pool is None:
        with pool_lock:
            if db_pool is None:
                database_url = os.getenv("DATABASE_URL")
                if not database_url:
                    raise ValueError("DATABASE_URL environment variable is not defined.")
                # Configure a ThreadedConnectionPool with min=1 and max=15 connections
                db_pool = psycopg2.pool.ThreadedConnectionPool(1, 15, database_url)
    return db_pool

@contextlib.contextmanager
def db_connection():
    pool = get_db_pool()
    conn = pool.getconn()
    try:
        yield conn
    except Exception:
        conn.rollback()
        raise
    else:
        conn.commit()
    finally:
        pool.putconn(conn)

def get_db_connection():
    """Retains compatibility with other modules or imports, acquiring a connection from the global pool."""
    return get_db_pool().getconn()
