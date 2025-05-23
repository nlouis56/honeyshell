import socket
import sys
import os
import time
import random
import threading
import traceback
import logging
import paramiko

from data import HoneypotDatabase
from conn import HoneypotConnectionHandler

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
    conn_handler = HoneypotConnectionHandler(host, port, db, rsa_key)
    sock = conn_handler.setup_server_socket()
    if sock is None:
        sys.exit(1)

    while True:
        client, addr = sock.accept()
        try:
            threading.Thread(
                target=conn_handler.process_connection,
                args=(client, addr),
                daemon=True
            ).start()
            logging.info("Started thread for %s:%d", addr[0], addr[1])
        except KeyboardInterrupt:
            logging.info("Server shutting down")
        except Exception as e:
            logging.error("Exception handling connection from %s:%d: %s", addr[0], addr[1], e)
            traceback.print_exc()


if __name__ == "__main__":
    loggingLevel = os.environ.get("LOGGING_LEVEL", "INFO").upper()
    if loggingLevel not in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
        loggingLevel = "INFO"
    logging.basicConfig(level=getattr(logging, loggingLevel))
    logging.info("Starting honeypot server with logging level: %s", loggingLevel)
    port = int(os.environ.get("HONEYPOT_PORT", 22))
    if port < 1 or port > 65535:
        logging.error("Invalid port number: %d. Using default port 22.", port)
        port = 22
    logging.info("Using port: %d", port)
    start_honeypot_server(port=22)
