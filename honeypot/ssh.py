import paramiko
import threading
import time
import random
import logging

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
