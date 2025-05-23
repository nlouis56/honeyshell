import psycopg2
import os
import logging

class HoneypotDatabase:
    def __init__(self):
        dbname = os.environ.get("DB_NAME", "honeypot"),
        dbname = dbname[0] if isinstance(dbname, tuple) else dbname
        user = os.environ.get("DB_USER", "user"),
        user = user[0] if isinstance(user, tuple) else user
        password = os.environ.get("DB_PASSWORD", "password"),
        password = password[0] if isinstance(password, tuple) else password
        #host=os.environ.get("DB_HOST", "localhost"),
        #host = host[0] if isinstance(host, tuple) else host
        host = "database"  # Use the service name from docker-compose
        port = os.environ.get("DB_PORT", "5432")
        port = port[0] if isinstance(port, tuple) else port
        port = int(port) if port.isdigit() else 5432
        self._connect(dbname, user, password, host, port)

    def _connect(self, dbname, user, password, host, port):
        self.connection = psycopg2.connect(
            dbname=dbname,
            user=user,
            password=password,
            host=host,
            port=port,
        )
        self.cursor = self.connection.cursor()
        self.create_tables()
        self.connection.commit()
        logging.info("Connected to the database")

    def create_tables(self):
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS attempts (
                id SERIAL PRIMARY KEY,
                ip VARCHAR(15),
                port INT,
                username VARCHAR(50),
                password VARCHAR(50),
                method VARCHAR(20),
                result VARCHAR(20),
                time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS commands (
                id SERIAL PRIMARY KEY,
                ip VARCHAR(15),
                command TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

    def log_attempt(self, ip, port, username, password, method, result):
        self.cursor.execute("""
            INSERT INTO attempts (ip, port, username, password, method, result)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (ip, port, username, password, method, result))
        self.connection.commit()

    def log_command(self, ip, command):
        self.cursor.execute("""
            INSERT INTO commands (ip, command)
            VALUES (%s, %s)
        """, (ip, command))
        self.connection.commit()
        logging.info("Logged command from %s: %s", ip, command)
