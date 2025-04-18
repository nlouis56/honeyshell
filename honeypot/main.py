import socket
import sys
import os
import time
import random
import threading
import traceback
import logging
import paramiko
import psycopg2

BANNERS = [
    "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10",
    "SSH-2.0-OpenSSH_8.4p1 Debian-5",
    "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.5",
    "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.4",
    "SSH-2.0-OpenSSH_7.9p1 Raspbian-10+deb10u2",
    "SSH-2.0-OpenSSH_8.0",
    "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13",
    "SSH-2.0-OpenSSH_7.4",
    "SSH-2.0-OpenSSH_8.6",
    "SSH-2.0-OpenSSH_8.1",
    "SSH-2.0-OpenSSH_7.3",
    "SSH-2.0-OpenSSH_8.3",
    "SSH-2.0-OpenSSH_7.7",
    "SSH-2.0-OpenSSH_6.9",
    "SSH-2.0-OpenSSH_7.5",
    "SSH-2.0-OpenSSH_8.5",
    "SSH-2.0-OpenSSH_7.8",
    "SSH-2.0-OpenSSH_6.7",
    "SSH-2.0-OpenSSH_8.7",
    "SSH-2.0-OpenSSH_7.1",
]

MOTD = [
    "Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-72-generic x86_64)",
    "Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.0-42-generic x86_64)",
    "Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-190-generic x86_64)",
    "Welcome to Ubuntu 14.04.6 LTS (GNU/Linux 3.13.0-170-generic x86_64)",
    "Welcome to Debian GNU/Linux 10 (buster)",
    "Welcome to Debian GNU/Linux 9 (stretch)",
    "Welcome to Debian GNU/Linux 8 (jessie)",
    "Welcome to Debian GNU/Linux 7 (wheezy)",
    "Welcome to Raspbian GNU/Linux 10 (buster)",
    "Welcome to Raspbian GNU/Linux 9 (stretch)",
    "Welcome to Raspbian GNU/Linux 8 (jessie)",
    "Welcome to Raspbian GNU/Linux 7 (wheezy)",
    "Welcome to CentOS Linux 7 (Core)",
    "Welcome to CentOS Linux 8 (Core)",
    "Welcome to Fedora 32 (Workstation Edition)",
    "Welcome to Fedora 33 (Workstation Edition)",
    "Welcome to Arch Linux",
    "Welcome to Manjaro Linux",
    "Welcome to openSUSE Leap 15.2",
    "Welcome to openSUSE Leap 15.1",
    "Welcome to openSUSE Leap 15.0",
    "Welcome to openSUSE Leap 42.3",
]

class HoneypotDatabase:
    def __init__(self):
        self.connection = psycopg2.connect(
            dbname=os.environ.get("DB_NAME", "honeypot"),
            user=os.environ.get("DB_USER", "user"),
            password=os.environ.get("DB_PASSWORD", "password"),
            host=os.environ.get("DB_HOST", "localhost"),
            port=os.environ.get("DB_PORT", "5432")
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
                result VARCHAR(20)
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

class HoneypotSSHServer(paramiko.ServerInterface):
    """
    SSH server interface that logs authentication attempts.
    """
    def __init__(self, db, client_addr):
        self.event = threading.Event()
        self.db = db
        self.client_ip, self.client_port = client_addr

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        logging.info("Password auth attempt - Username: %s | Password: %s", username, password)
        randSleep: float = random.uniform(0.5, 1.5)  # Random sleep between 0.1 and 0.5 seconds
        time.sleep(randSleep)
        if random.randint(0, 10) < 3:
            result = "success"
            auth_status = paramiko.AUTH_SUCCESSFUL
            logging.info("Auth successful - Username: %s | Password: %s", username, password)
        else:
            result = "failed"
            auth_status = paramiko.AUTH_FAILED
            logging.info("Auth failed - Username: %s | Password: %s", username, password)
        self.db.log_attempt(self.client_ip, self.client_port, username, password, "password", result)
        return auth_status

    def check_auth_publickey(self, username, key):
        key_b64 = key.get_base64()
        logging.info("Public key auth attempt - Username: %s | Key: %s", username, key_b64)
        self.db.log_attempt(self.client_ip, self.client_port, username, None, "publickey", "failed")
        return paramiko.AUTH_FAILED

    def get_banner(self):
        banner = random.choice(BANNERS)
        logging.info("Sending banner: %s", banner)
        return banner, ""


def setup_server_socket(host, port):
    """
    Creates, binds, and starts listening on a server socket.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(100)
        logging.info("Honeypot listening on %s:%d", host, port)
        return sock
    except Exception as e:
        logging.error("Failed to bind socket: %s", e)
        return None


def create_transport(client, addr, key):
    """
    Creates and configures a Paramiko transport for the client.
    """
    try:
        transport = paramiko.Transport(client)
        transport.local_version = random.choice(BANNERS)
        transport.add_server_key(key)
        return transport
    except Exception as e:
        logging.error("Failed to create transport for %s:%d: %s", addr[0], addr[1], e)
        return None


def start_server_transport(transport, db, addr):
    """
    Initializes and starts the SSH server using the provided transport.
    """
    try:
        server = HoneypotSSHServer(db, addr)
        transport.start_server(server=server)
        return server
    except paramiko.SSHException as e:
        logging.error("SSH negotiation failed with %s:%d: %s", addr[0], addr[1], e)
        return None


def accept_channel(transport, addr, timeout=20):
    """
    Waits for a channel to be opened by the client.
    """
    channel = transport.accept(timeout)
    if channel is None:
        logging.warning("No channel was opened by %s:%d", addr[0], addr[1])
    return channel


def simulate_console_interaction(channel: paramiko.Channel):
    """
    Simulates console interaction with the client.
    """
    try:
        while True:
            channel.send("% ")
            data = channel.recv(1024)
            if not data:
                break
            logging.info("Received data: %s", data.decode())
            command = data.decode().strip().split()[0]
            if command == "exit":
                channel.send("Goodbye!\n")
                break
            response = f"zsh: command not found: {data}\n"
    except Exception as e:
        logging.error("Error during console interaction: %s", e)
    finally:
        channel.close()
        logging.info("Channel closed")


def handle_authenticated_channel(channel: paramiko.Channel, addr):
    """
    Handles the authenticated channel by sending the message-of-the-day.
    """
    try:
        motd = random.choice(MOTD)
        channel.send(motd + '\n')
        logging.info("Sent MOTD to %s:%d: %s", addr[0], addr[1], motd)
        simulate_console_interaction(channel)
    except paramiko.SSHException as e:
        logging.error("SSH error with %s:%d: %s", addr[0], addr[1], e)
    except socket.error as e:
        logging.error("Socket error with %s:%d: %s", addr[0], addr[1], e)
    except EOFError:
        logging.info("Client %s:%d disconnected", addr[0], addr[1])
    except Exception as e:
        logging.error("Error sending MOTD to %s:%d: %s", addr[0], addr[1], e)
    finally:
        if channel:
            channel.close()
        logging.info("Channel closed for %s:%d", addr[0], addr[1])


def process_connection(client, addr, db, rsa_key):
    """
    Processes an incoming client connection by performing transport creation,
    server startup, channel acceptance, and channel handling.
    """
    logging.info("Incoming connection from %s:%d", addr[0], addr[1])

    transport = create_transport(client, addr, rsa_key)
    if transport is None:
        return

    server = start_server_transport(transport, db, addr)
    if server is None:
        transport.close()
        return

    channel = accept_channel(transport, addr)
    if channel is None:
        transport.close()
        return

    logging.info("Client %s authenticated", addr[0])
    channel.settimeout(None)
    handle_authenticated_channel(channel, addr)
    transport.close()


def generate_rsa_key():
    """
    Generates a new RSA key pair and saves it to a file.
    """
    key = paramiko.RSAKey.generate(2048)
    with open('server.key', 'w') as key_file:
        key.write_private_key(key_file)
    logging.info("Generated new RSA key with fingerprint: %s", key.get_fingerprint().hex())
    return key


def start_honeypot_server(host='0.0.0.0', port=22):
    """
    Sets up the honeypot server, continuously accepts connections, and processes each.
    """
    db = HoneypotDatabase()
    rsa_key = generate_rsa_key()
    sock = setup_server_socket(host, port)
    if sock is None:
        sys.exit(1)

    while True:
        client, addr = sock.accept()
        try:
            threading.Thread(
                target=process_connection,
                args=(client, addr, db, rsa_key),
                daemon=True
            ).start()
            logging.info("Started thread for %s:%d", addr[0], addr[1])
        except KeyboardInterrupt:
            logging.info("Server shutting down")
        except Exception as e:
            logging.error("Exception handling connection from %s:%d: %s", addr[0], addr[1], e)
            traceback.print_exc()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    start_honeypot_server(port=2222)
