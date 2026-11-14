import psycopg2
from dotenv import load_dotenv
import os

load_dotenv()

def connect_postgres():
    USER = os.getenv("user")
    PASSWORD = os.getenv("password")
    HOST = os.getenv("host")
    PORT = os.getenv("port")
    DBNAME = os.getenv("dbname")

    try:
        connection = psycopg2.connect(
            user=USER,
            password=PASSWORD,
            host=HOST,
            port=PORT,
            database=DBNAME
        )
        print("✅ PostgreSQL connection successful!")
        
        cursor = connection.cursor()
        return connection,cursor

    except Exception as e:
        print(f"Failed to connect to PostgreSQL: {e}")
        return False