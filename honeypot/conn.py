import logging
import socket
import random
import time
import paramiko

from data import HoneypotDatabase
from ssh import HoneypotSSHServer

class ConnectionAttempt:
    def __init__(self, addr, username, password, method, result):
        self.addr = addr
        self.ip, self.port = addr
        self.username = username
        self.password = password
        self.method = method
        self.result = result
        self.timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


class HoneypotConnectionHandler:

    def __init__(self, host, port, db, rsa_key):
        self.host = host
        self.port = port
        self.db = db
        self.rsa_key = rsa_key


    def setup_server_socket(self):
        """
        Creates, binds, and starts listening on a server socket.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, self.port))
            sock.listen(100)
            logging.info("Honeypot listening on %s:%d", self.host, self.port)
            return sock
        except Exception as e:
            logging.error("Failed to bind socket: %s", e)
            return None


    def create_transport(self, client, addr):
        """
        Creates and configures a Paramiko transport for the client.
        """
        try:
            transport = paramiko.Transport(client)
            transport.local_version = "SSH-2.0-OpenSSH_7.9" ## DEFINE SSH BANNER HERE
            transport.add_server_key(self.rsa_key)
            return transport
        except Exception as e:
            logging.error("Failed to create transport for %s:%d: %s", addr[0], addr[1], e)
            return None


    def start_server_transport(self, transport, addr):
        """
        Initializes and starts the SSH server using the provided transport.
        """
        try:
            server = HoneypotSSHServer(self.db, addr)
            transport.start_server(server=server)
            return server
        except paramiko.SSHException as e:
            logging.error("SSH negotiation failed with %s:%d: %s", addr[0], addr[1], e)
            return None


    def accept_channel(self, transport, addr, timeout=20):
        """
        Waits for a channel to be opened by the client.
        """
        channel = transport.accept(timeout)
        if channel is None:
            logging.info("No channel was opened by %s:%d", addr[0], addr[1])
        return channel


    def simulate_console_interaction(self, channel: paramiko.Channel):
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


    def handle_authenticated_channel(self, channel: paramiko.Channel, addr):
        """
        Handles the authenticated channel by sending the message-of-the-day.
        """
        try:
            motd = "Debian GNU/Linux 10 (buster) \n" \
                   "Kernel \r\n" \
                   "Last login: %s from %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), addr[0])
            ############## MOTD ##############
            channel.send(motd + '\n')
            logging.info("Sent MOTD to %s:%d: %s", addr[0], addr[1], motd)
            self.simulate_console_interaction(channel)
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


    def process_connection(self, client, addr):
        """
        Processes an incoming client connection by performing transport creation,
        server startup, channel acceptance, and channel handling.
        """
        logging.info("Incoming connection from %s:%d", addr[0], addr[1])

        transport = self.create_transport(client, addr)
        if transport is None:
            return

        server = self.start_server_transport(transport, addr)
        if server is None:
            transport.close()
            return

        channel = self.accept_channel(transport, addr)
        if channel is None:
            transport.close()
            return

        logging.info("Client %s authenticated", addr[0])
        channel.settimeout(None)
        self.handle_authenticated_channel(channel, addr)
        transport.close()
