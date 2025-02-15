#!/usr/bin/env python3
"""
Secure Messaging Application – Version 10/10
=============================================
Features:
  • Ephemeral end-to-end encryption using X25519 and Ed25519 keys.
  • TLS networking with certificate generation and validation.
  • Remote wipe, dead man’s switch, decoy passphrase.
  • Dummy traffic for cover messages.
  • Encoded messages embedded in text/PDF files.
  • Quick-setup wizard for client/server configuration.
  • Detailed logging and tamper-evident message log.
  • File encryption/decryption.
  
Author: Your Team Name
Date: 2025-02-15

This script has been refactored for improved modularity, error handling, and clarity.
"""

import os, sys, json, time, socket, ssl, threading, logging, datetime, base64, re, hashlib, random, traceback
from getpass import getpass
import msgpack

# Third-party cryptography libraries
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519, rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from datetime import timedelta

# ---------------------------------------------------------
# Global Configuration Constants and File Names
# ---------------------------------------------------------
LOG_FORMAT = '%(asctime)s [%(levelname)s] %(message)s'
logging.basicConfig(level=logging.DEBUG, format=LOG_FORMAT)

# File names and directories:
KEYSTORE_FILE       = "keystore.dat"
MESSAGE_LOG_FILE    = "message_log.dat"
COUNTER_STATE_FILE  = "counter_state.json"
SETUP_CONFIG_FILE   = "setup_config.json"

SERVER_KEY_FILE     = "server_key.pem"
SERVER_CERT_FILE    = "server_cert.pem"
CLIENT_KEY_FILE     = "client_key.pem"
CLIENT_CERT_FILE    = "client_cert.pem"
TRUSTED_SERVER_FILE = "trusted_server_cert.pem"
TRUSTED_CLIENT_FILE = "trusted_client_cert.pem"
TRUSTED_CLIENTS_DIR = "trusted_clients"

# Default network parameters:
DEFAULT_PORT        = 5000
BUFFER_SIZE         = 4096
CONFIG_PEM_PASSWORD = "P3M!n!t!@l"

# Special Passphrases:
DEADMAN_PASSWORD    = "1234567890"  # triggers local data wipe immediately
DECOY_PASSWORD      = "decoy9876"   # triggers decoy mode at startup

# Additional passwords for key export/display:
EXPORT_KEYS_PASSWORD  = "G3tP3m!!!"
DISPLAY_KEYS_PASSWORD = "S3cur3M3$$!!!"

# ---------------------------------------------------------
# Utility Functions and Crypto Helpers
# ---------------------------------------------------------
class CryptoUtils:
    """Provides helper functions for key derivation, symmetric encryption and HMAC."""
    @staticmethod
    def derive_key(passphrase: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
        )
        return kdf.derive(passphrase.encode())

    @staticmethod
    def encrypt_data(data: bytes, passphrase: str) -> bytes:
        salt = os.urandom(16)
        key  = CryptoUtils.derive_key(passphrase, salt)
        # Compute HMAC for integrity
        h = HMAC(key, hashes.SHA256())
        h.update(data)
        hmac_digest = h.finalize()
        combined = data + hmac_digest
        aead = ChaCha20Poly1305(key)
        nonce = os.urandom(12)
        ciphertext = aead.encrypt(nonce, combined, None)
        return salt + nonce + ciphertext

    @staticmethod
    def decrypt_data(enc: bytes, passphrase: str) -> bytes:
        salt  = enc[:16]
        nonce = enc[16:28]
        ciph  = enc[28:]
        key   = CryptoUtils.derive_key(passphrase, salt)
        aead  = ChaCha20Poly1305(key)
        plain = aead.decrypt(nonce, ciph, None)
        data, hmac_recv = plain[:-32], plain[-32:]
        h2 = HMAC(key, hashes.SHA256())
        h2.update(data)
        h2.verify(hmac_recv)
        return data

    @staticmethod
    def compute_log_hash(msg: dict, prev_hash: str = "") -> str:
        combo = (prev_hash + json.dumps(msg, sort_keys=True)).encode()
        return hashlib.sha256(combo).hexdigest()

# ---------------------------------------------------------
# Certificate Management
# ---------------------------------------------------------
class CertManager:
    """Generates self-signed certificates for TLS using RSA keys."""
    @staticmethod
    def generate_self_signed_cert(cert_file: str, key_file: str, common_name: str) -> None:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        now = datetime.datetime.now(datetime.timezone.utc)
        expire = now + timedelta(days=365)
        serial = x509.random_serial_number()
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([ x509.NameAttribute(NameOID.COMMON_NAME, common_name) ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(serial)
            .not_valid_before(now)
            .not_valid_after(expire)
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                critical=False
            )
            .sign(key, hashes.SHA256())
        )
        try:
            with open(key_file, "wb") as f:
                f.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            with open(cert_file, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            logging.info(f"Generated certificate and key for CN={common_name}")
        except Exception as e:
            logging.error(f"Failed to generate certificate: {e}")

# ---------------------------------------------------------
# Data Wipe and Fake Log Generation
# ---------------------------------------------------------
def wipe_local_data():
    """Remove all local data files and keys to reset the application."""
    files_to_remove = [
        KEYSTORE_FILE, MESSAGE_LOG_FILE, COUNTER_STATE_FILE,
        SETUP_CONFIG_FILE, TRUSTED_SERVER_FILE, TRUSTED_CLIENT_FILE
    ]
    for fname in files_to_remove:
        if os.path.exists(fname):
            try:
                os.remove(fname)
                logging.info(f"Wiped file: {fname}")
            except Exception as e:
                logging.warning(f"Error wiping {fname}: {e}")
    for fname in [SERVER_KEY_FILE, SERVER_CERT_FILE, CLIENT_KEY_FILE, CLIENT_CERT_FILE]:
        if os.path.exists(fname):
            try:
                os.remove(fname)
                logging.info(f"Wiped key/cert file: {fname}")
            except Exception:
                pass

def create_fake_log_entries():
    """Return a list of fake log entries for decoy mode."""
    return [
        {
            "id": 1,
            "sender": "HQ",
            "counter": 999,
            "timestamp": "2025-01-01T12:00:00",
            "message": "GRID REF: 1234 5678. Prepare to move."
        },
        {
            "id": 2,
            "sender": "CO",
            "counter": 1000,
            "timestamp": "2025-01-01T12:05:00",
            "message": "EXECUTE. Rendezvous in 5 mins."
        }
    ]

# ---------------------------------------------------------
# Application Core Classes
# ---------------------------------------------------------
class KeyStore:
    """Manages local ephemeral keys (X25519 & Ed25519) in an encrypted keystore."""
    def __init__(self):
        self.passphrase = None
        self.private_key_x25519 = None
        self.public_key_x25519 = None
        self.private_key_ed25519 = None
        self.public_key_ed25519 = None

    def initial_setup(self):
        """Create a new keystore by prompting for a strong passphrase and generating keys."""
        while True:
            p1 = getpass("Set a strong passphrase (>=20 chars with mixed case, digits & symbols): ")
            if not self.validate_passphrase(p1):
                print("Passphrase complexity insufficient. Try again.")
                continue
            p2 = getpass("Confirm passphrase: ")
            if p1 != p2:
                print("Passphrase mismatch. Try again.")
                continue
            self.passphrase = p1
            break
        self.generate_keys()
        self.save_keys()

    @staticmethod
    def validate_passphrase(passphrase: str) -> bool:
        if len(passphrase) < 20:
            return False
        if not re.search(r'[A-Z]', passphrase):
            return False
        if not re.search(r'[a-z]', passphrase):
            return False
        if not re.search(r'[0-9]', passphrase):
            return False
        if not re.search(r'[\W_]', passphrase):
            return False
        return True

    def generate_keys(self):
        """Generate new ephemeral key pairs."""
        self.private_key_x25519 = x25519.X25519PrivateKey.generate()
        self.public_key_x25519  = self.private_key_x25519.public_key()
        self.private_key_ed25519 = ed25519.Ed25519PrivateKey.generate()
        self.public_key_ed25519  = self.private_key_ed25519.public_key()
        logging.info("Ephemeral keys generated.")

    def save_keys(self):
        """Serialize and encrypt the keys to a file."""
        try:
            data = {
                "private_key_x25519": self.private_key_x25519.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode(),
                "public_key_x25519": self.public_key_x25519.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode(),
                "private_key_ed25519": self.private_key_ed25519.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode(),
                "public_key_ed25519": self.public_key_ed25519.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode()
            }
            enc = CryptoUtils.encrypt_data(json.dumps(data).encode(), self.passphrase)
            with open(KEYSTORE_FILE, "wb") as f:
                f.write(enc)
            logging.info("Keystore saved successfully.")
        except Exception as e:
            logging.error(f"Keystore saving failed: {e}")

    def load_keys(self):
        """Load the keys from the keystore, checking for special passphrases."""
        if not os.path.exists(KEYSTORE_FILE):
            self.initial_setup()
            return
        self.passphrase = getpass("Enter local keystore passphrase: ")
        if self.passphrase == DEADMAN_PASSWORD:
            print("Dead man’s switch triggered! Wiping all local data.")
            wipe_local_data()
            sys.exit(0)
        elif self.passphrase == DECOY_PASSWORD:
            print("***** Decoy mode activated. Real data hidden. *****")
            return
        try:
            with open(KEYSTORE_FILE, "rb") as f:
                data = f.read()
            dec = CryptoUtils.decrypt_data(data, self.passphrase)
            d = json.loads(dec.decode())
            self.private_key_x25519 = serialization.load_pem_private_key(
                d["private_key_x25519"].encode(), password=None)
            self.public_key_x25519 = self.private_key_x25519.public_key()
            self.private_key_ed25519 = serialization.load_pem_private_key(
                d["private_key_ed25519"].encode(), password=None)
            self.public_key_ed25519 = self.private_key_ed25519.public_key()
            logging.info("Keystore loaded successfully.")
        except Exception as e:
            logging.error(f"Error loading keystore: {e}")
            sys.exit(1)

    def get_identity_fingerprint(self) -> str:
        """Returns a short fingerprint of the Ed25519 public key."""
        try:
            pub_raw = self.private_key_ed25519.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            return hashlib.sha256(pub_raw).hexdigest()[:8]
        except Exception as e:
            logging.error(f"Fingerprint generation error: {e}")
            return "unknownfp"

class MessageLog:
    """Stores encrypted messages and ensures tamper-evident logging."""
    def __init__(self, keystore: KeyStore):
        self.keystore = keystore
        self.decoy_mode = (self.keystore.passphrase == DECOY_PASSWORD)
        self.messages = []
        self.load_log()

    def load_log(self):
        if self.decoy_mode:
            self.messages = create_fake_log_entries()
            logging.info("Decoy message log loaded.")
            return
        if os.path.exists(MESSAGE_LOG_FILE):
            try:
                with open(MESSAGE_LOG_FILE, "rb") as f:
                    enc = f.read()
                dec = CryptoUtils.decrypt_data(enc, self.keystore.passphrase)
                self.messages = json.loads(dec.decode())
                logging.info("Message log loaded.")
            except Exception as e:
                logging.error(f"Failed to load message log: {e}")
                self.messages = []

    def save_log(self):
        if self.decoy_mode:
            return
        try:
            prev_hash = ""
            for m in self.messages:
                m["prev_hash"] = prev_hash
                h = CryptoUtils.compute_log_hash(m, prev_hash)
                m["log_hash"] = h
                prev_hash = h
            enc = CryptoUtils.encrypt_data(json.dumps(self.messages).encode(), self.keystore.passphrase)
            with open(MESSAGE_LOG_FILE, "wb") as f:
                f.write(enc)
            logging.debug("Message log saved.")
        except Exception as e:
            logging.error(f"Error saving message log: {e}")

    def add_message(self, msg: dict):
        self.messages.append(msg)
        self.save_log()

    def delete_message(self, msg_id: int):
        self.messages = [m for m in self.messages if m.get("id") != msg_id]
        self.save_log()

    def purge_messages(self):
        self.messages = []
        self.save_log()

class CounterState:
    """Tracks message counters to prevent replay attacks."""
    def __init__(self, keystore: KeyStore):
        self.keystore = keystore
        self.decoy_mode = (self.keystore.passphrase == DECOY_PASSWORD)
        self.last_counter = 0
        self.seen_counters = set()
        self.load_state()

    def load_state(self):
        if self.decoy_mode:
            self.last_counter = 999
            self.seen_counters = set()
            return
        if os.path.exists(COUNTER_STATE_FILE):
            try:
                with open(COUNTER_STATE_FILE, "r") as f:
                    d = json.load(f)
                self.last_counter = d.get("last_counter", 0)
                self.seen_counters = set(d.get("seen_counters", []))
                logging.info("Counter state loaded.")
            except Exception as e:
                logging.error(f"Counter state load error: {e}")

    def save_state(self):
        if self.decoy_mode:
            return
        try:
            with open(COUNTER_STATE_FILE, "w") as f:
                json.dump({
                    "last_counter": self.last_counter,
                    "seen_counters": list(self.seen_counters)
                }, f)
        except Exception as e:
            logging.error(f"Error saving counter state: {e}")

# ---------------------------------------------------------
# TLS and Network Manager
# ---------------------------------------------------------
class TLSManager:
    """Creates TLS server and client connections."""
    def __init__(self, config: dict):
        self.config = config  # expects keys: node_role, port, max_clients, etc.

    def create_tls_server_context(self, is_server: bool) -> ssl.SSLContext:
        # Choose proper certificate files based on role.
        if is_server:
            cert_file = SERVER_CERT_FILE
            key_file  = SERVER_KEY_FILE
        else:
            cert_file = CLIENT_CERT_FILE
            key_file  = CLIENT_KEY_FILE

        if not (os.path.exists(cert_file) and os.path.exists(key_file)):
            raise RuntimeError("TLS certificate or key not found. Run quick-setup.")

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if is_server else ssl.PROTOCOL_TLS_CLIENT)
        if is_server:
            ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
            # Server may require client certificates if available:
            if os.path.exists(TRUSTED_CLIENT_FILE):
                ctx.verify_mode = ssl.CERT_REQUIRED
                ctx.load_verify_locations(TRUSTED_CLIENT_FILE)
            else:
                ctx.verify_mode = ssl.CERT_OPTIONAL
        else:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_REQUIRED
            if not os.path.exists(TRUSTED_SERVER_FILE):
                raise RuntimeError("Trusted server certificate not found. Please import it.")
            ctx.load_verify_locations(TRUSTED_SERVER_FILE)
            ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
        return ctx

    def create_tls_client_socket(self, host: str, port: int) -> ssl.SSLSocket:
        ctx = self.create_tls_server_context(is_server=False)
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(self.config.get("network_timeout", 10))
        tls_sock = ctx.wrap_socket(raw_sock, server_hostname="PinnedServer")
        logging.debug(f"Connecting to TLS server at {host}:{port}...")
        tls_sock.connect((host, port))
        logging.info(f"TLS connection established to {host}:{port}")
        return tls_sock

# ---------------------------------------------------------
# Main Messaging Application Class
# ---------------------------------------------------------
class MessagingApp:
    """The central class that brings together keystore, messaging, TLS, and command processing."""
    def __init__(self):
        # Load or initialize keystore
        self.keystore = KeyStore()
        self.keystore.load_keys()

        # Initialize message log and counter state
        self.msg_log = MessageLog(self.keystore)
        self.counter_state = CounterState(self.keystore)

        # Load configuration
        self.config = {
            "self_destruct_mode": "none",     # Options: none, after_read, time_based
            "self_destruct_timer": 300,
            "network_timeout": 10,
            "dummy_traffic_enabled": False,
            "dummy_traffic_peer": None
        }
        self.setup_config = {
            "node_role": "unknown",
            "display_name": "Unknown",
            "port": DEFAULT_PORT,
            "max_clients": 5,
            "active_client_count": 0
        }
        self.load_setup_config()

        # Dictionary to hold peer info: { peer_id: (ip, port) }
        self.peers = {}

        # Trusted ephemeral keys from peers: { peer_id: {"x25519": str, "ed25519": str} }
        self.trusted_keys = {}

        # TLS manager for networking operations
        self.tls_manager = TLSManager(self.setup_config)

        # Start background threads: TLS server, auto-delete, dummy traffic
        self.server_thread = threading.Thread(target=self.start_tls_server, daemon=True)
        self.server_thread.start()

        self.auto_delete_thread = threading.Thread(target=self.auto_delete_messages, daemon=True)
        self.auto_delete_thread.start()

        self.dummy_thread_stop = threading.Event()
        self.dummy_thread = threading.Thread(target=self.send_dummy_traffic, daemon=True)
        self.dummy_thread.start()

        if self.keystore.passphrase == DECOY_PASSWORD:
            logging.warning("Running in decoy mode: real data is hidden.")

    # ----------------------- Setup Config -----------------------
    def load_setup_config(self):
        if os.path.exists(SETUP_CONFIG_FILE):
            try:
                with open(SETUP_CONFIG_FILE, "r") as f:
                    cfg = json.load(f)
                self.setup_config.update(cfg)
                logging.info("Setup configuration loaded.")
            except Exception as e:
                logging.error(f"Error loading setup config: {e}")

    def save_setup_config(self):
        try:
            with open(SETUP_CONFIG_FILE, "w") as f:
                json.dump(self.setup_config, f, indent=2)
            logging.debug("Setup configuration saved.")
        except Exception as e:
            logging.error(f"Error saving setup config: {e}")

    # ----------------------- TLS Server -----------------------
    def start_tls_server(self):
        role = self.setup_config.get("node_role", "unknown")
        is_server = role in ["fs", "sa"]
        port = self.setup_config.get("port", 0)
        if port <= 0:
            logging.info("Server port not set. Skipping TLS server startup.")
            return
        try:
            ctx = self.tls_manager.create_tls_server_context(is_server=is_server)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("", port))
            sock.listen()
            logging.info(f"TLS server listening on port {port} as role '{role}'")
            while True:
                client_sock, addr = sock.accept()
                if is_server and (self.setup_config["active_client_count"] >= self.setup_config.get("max_clients", 5)):
                    logging.warning("Max clients reached. Dropping connection.")
                    client_sock.close()
                    continue
                try:
                    tls_conn = ctx.wrap_socket(client_sock, server_side=True)
                    if is_server:
                        self.setup_config["active_client_count"] += 1
                        self.save_setup_config()
                    threading.Thread(target=self.handle_tls_connection, args=(tls_conn, addr), daemon=True).start()
                except Exception as e:
                    logging.error(f"TLS server error: {e}")
        except Exception as e:
            logging.error(f"Failed to start TLS server: {e}")

    def handle_tls_connection(self, tls_conn: ssl.SSLSocket, addr):
        logging.debug(f"Incoming TLS connection from {addr}")
        role = self.setup_config.get("node_role", "unknown")
        is_server = role in ["fs", "sa"]
        try:
            data = b""
            with tls_conn:
                while True:
                    chunk = tls_conn.recv(BUFFER_SIZE)
                    if not chunk:
                        break
                    data += chunk
            if not data:
                return
            msg_dict = msgpack.unpackb(data, raw=False)
            # Check for remote wipe command
            if msg_dict.get("cmd") == "remote-wipe":
                target = msg_dict.get("target", "")
                if target == self.setup_config.get("display_name"):
                    self.remote_wipe_local()
                return
            # Replay protection:
            counter = msg_dict.get("counter")
            if counter is not None:
                if counter in self.counter_state.seen_counters:
                    logging.warning("Replay attack detected. Dropping message.")
                    return
                self.counter_state.seen_counters.add(counter)
                self.counter_state.save_state()
            sender = msg_dict.get("sender")
            # Verify signature if sender is trusted:
            if sender in self.trusted_keys:
                ed_pub_pem = self.trusted_keys[sender]["ed25519"]
                sign_input = (msg_dict.get("ephemeral_pub", "") +
                              msg_dict.get("nonce", "") +
                              msg_dict.get("ciphertext", "")).encode()
                signature = base64.b64decode(msg_dict.get("signature", ""))
                if not self.verify_signature(sign_input, signature, ed_pub_pem):
                    logging.error("Signature verification failed.")
                    return
            else:
                logging.warning(f"Message received from unknown sender {sender}")
            # Decrypt the message:
            payload = self.decrypt_message(msg_dict)
            if not payload:
                logging.error("Failed to decrypt message.")
                return
            # Store message in log:
            msg_entry = {
                "id": len(self.msg_log.messages) + 1,
                "sender": sender,
                "counter": payload.get("counter"),
                "timestamp": payload.get("timestamp"),
                "message": payload.get("message")
            }
            self.msg_log.add_message(msg_entry)
            logging.info(f"Message received from {sender}")
            if self.config["self_destruct_mode"] == "after_read":
                self.msg_log.delete_message(msg_entry["id"])
        except Exception as e:
            logging.error(f"Error handling TLS connection: {traceback.format_exc()}")
        finally:
            if is_server:
                self.setup_config["active_client_count"] = max(0, self.setup_config["active_client_count"] - 1)
                self.save_setup_config()

    # ----------------------- Ephemeral Encryption -----------------------
    def encrypt_message(self, plaintext: str, peer_id: str) -> dict:
        """Encrypts a message using ephemeral E2E key exchange."""
        if peer_id not in self.trusted_keys:
            logging.error(f"No trusted keys for peer {peer_id}.")
            return None
        try:
            recip_pub = serialization.load_pem_public_key(self.trusted_keys[peer_id]["x25519"].encode())
        except Exception as e:
            logging.error(f"Error loading recipient public key: {e}")
            return None
        eph_priv = x25519.X25519PrivateKey.generate()
        eph_pub = eph_priv.public_key()
        eph_pub_bytes = eph_pub.public_bytes(encoding=serialization.Encoding.Raw,
                                               format=serialization.PublicFormat.Raw)
        shared = eph_priv.exchange(recip_pub)
        derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                       info=b"ephemeral handshake").derive(shared)
        aead = ChaCha20Poly1305(derived)
        nonce = os.urandom(12)
        self.counter_state.last_counter += 1
        self.counter_state.save_state()
        payload = {
            "counter": self.counter_state.last_counter,
            "timestamp": datetime.datetime.now().isoformat(),
            "message": plaintext
        }
        ciphertext = aead.encrypt(nonce, json.dumps(payload).encode(), None)
        return {
            "ephemeral_pub": base64.b64encode(eph_pub_bytes).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode()
        }

    def decrypt_message(self, msgd: dict) -> dict:
        """Decrypts an incoming ephemeral message."""
        try:
            eph_pub_bytes = base64.b64decode(msgd["ephemeral_pub"])
            nonce = base64.b64decode(msgd["nonce"])
            ciphertext = base64.b64decode(msgd["ciphertext"])
            ephemeral_pub = x25519.X25519PublicKey.from_public_bytes(eph_pub_bytes)
            shared = self.keystore.private_key_x25519.exchange(ephemeral_pub)
            derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                           info=b"ephemeral handshake").derive(shared)
            aead = ChaCha20Poly1305(derived)
            decrypted_json = aead.decrypt(nonce, ciphertext, None).decode()
            return json.loads(decrypted_json)
        except Exception as e:
            logging.error(f"Decryption error: {e}")
            return None

    def sign_message(self, data: bytes) -> bytes:
        try:
            return self.keystore.private_key_ed25519.sign(data)
        except Exception as e:
            logging.error(f"Signing error: {e}")
            return b""

    def verify_signature(self, data: bytes, sig: bytes, ed_pub_pem: str) -> bool:
        try:
            pk = serialization.load_pem_public_key(ed_pub_pem.encode())
            pk.verify(sig, data)
            return True
        except Exception as e:
            logging.error(f"Signature verification error: {e}")
            return False

    # ----------------------- Auto Delete and Dummy Traffic -----------------------
    def auto_delete_messages(self):
        """Background thread for time-based auto-deletion of messages."""
        while True:
            if self.config["self_destruct_mode"] == "time_based":
                now = datetime.datetime.now()
                new_list = []
                for m in self.msg_log.messages:
                    try:
                        dt = datetime.datetime.fromisoformat(m.get("timestamp", ""))
                        if (now - dt).total_seconds() > self.config["self_destruct_timer"]:
                            logging.info(f"Auto-deleting message {m['id']}.")
                            continue
                    except Exception:
                        pass
                    new_list.append(m)
                if len(new_list) != len(self.msg_log.messages):
                    self.msg_log.messages = new_list
                    self.msg_log.save_log()
            time.sleep(10)

    def send_dummy_traffic(self):
        """Background thread to send periodic dummy messages if enabled."""
        while True:
            if self.config.get("dummy_traffic_enabled") and self.config.get("dummy_traffic_peer"):
                dummy_msg = f"CoverTraffic-{random.randint(1000, 9999)}"
                peer_id = self.config["dummy_traffic_peer"]
                if peer_id in self.peers:
                    ip, port = self.peers[peer_id]
                    enc = self.encrypt_message(dummy_msg, peer_id)
                    if enc:
                        sign_data = (enc["ephemeral_pub"] + enc["nonce"] + enc["ciphertext"]).encode()
                        signature = self.sign_message(sign_data)
                        msg = {
                            "sender": self.keystore.get_identity_fingerprint(),
                            "counter": self.counter_state.last_counter,
                            "ephemeral_pub": enc["ephemeral_pub"],
                            "nonce": enc["nonce"],
                            "ciphertext": enc["ciphertext"],
                            "signature": base64.b64encode(signature).decode(),
                            "timestamp": datetime.datetime.now().isoformat(),
                            "dummy_traffic": True
                        }
                        packed = msgpack.packb(msg, use_bin_type=True)
                        try:
                            conn = self.tls_manager.create_tls_client_socket(ip, port)
                            with conn:
                                conn.sendall(packed)
                            logging.info(f"Dummy traffic sent to {ip}:{port}")
                        except Exception as e:
                            logging.warning(f"Dummy traffic send error: {e}")
            time.sleep(30)

    # ----------------------- Command Processing -----------------------
    def run(self):
        print(f"Secure Messaging Application. Role: {self.setup_config.get('node_role')} (type 'help' for commands)")
        while True:
            try:
                line = input("> ").strip()
                if not line:
                    continue
                # Dead man’s switch during runtime:
                if line == DEADMAN_PASSWORD:
                    print("Dead man's switch activated. Wiping all local data.")
                    wipe_local_data()
                    sys.exit(0)
                elif line == DECOY_PASSWORD:
                    print("Cannot switch to decoy mode mid-session.")
                    continue

                parts = line.split()
                cmd = parts[0].lower()
                args = parts[1:]
                if cmd in ["exit", "quit"]:
                    print("Exiting application.")
                    break
                elif cmd == "help":
                    self.print_help()
                elif cmd == "quick-setup":
                    self.command_quick_setup(args)
                elif cmd == "server-config":
                    self.command_server_config(args)
                elif cmd == "client-config":
                    self.command_client_config(args)
                elif cmd == "send":
                    self.command_send(args)
                elif cmd == "list":
                    self.command_list(args)
                elif cmd == "delete":
                    self.command_delete(args)
                elif cmd == "purge":
                    self.command_purge(args)
                elif cmd == "getkeys":
                    self.command_getkeys(args)
                elif cmd == "recallkeys":
                    self.command_recallkeys(args)
                elif cmd == "bind":
                    self.command_bind(args)
                elif cmd == "trust":
                    self.command_trust(args)
                elif cmd == "remote-wipe":
                    self.command_remote_wipe(args)
                elif cmd == "encrypt-file":
                    self.command_encrypt_file(args)
                elif cmd == "decrypt-file":
                    self.command_decrypt_file(args)
                elif cmd == "dummy-traffic":
                    self.command_dummy_traffic(args)
                elif cmd == "instructions":
                    self.command_instructions(args)
                else:
                    print("Unknown command. Type 'help' for a list.")
            except Exception as e:
                logging.error(f"Command processing error: {traceback.format_exc()}")

    # ----------------------- Command Implementations -----------------------
    def print_help(self):
        help_text = """
Available Commands:
  quick-setup             - Run quick-setup wizard.
  server-config g|e|i     - Manage server TLS certificates (generate/export/import).
  client-config g|e|i     - Manage client TLS certificates (generate/export/import).
  send <peer_id> <msg>    - Send a secure message to a bound peer.
  list                    - List received messages.
  delete <msg_id>         - Delete a specific message.
  purge                   - Purge all messages.
  getkeys                 - Export ephemeral public keys (password required).
  recallkeys              - Display ephemeral public keys (password required).
  bind <peer_id> <ip:port> - Bind a peer identifier to an IP address.
  trust <peer_id> [manual|import] - Add trusted ephemeral keys for a peer.
  remote-wipe <target>    - Send a remote wipe command to a peer.
  encrypt-file <peer_id> <file_path> - Encrypt a local file.
  decrypt-file <file_path> - Decrypt an encrypted file.
  dummy-traffic start <peer_id> | stop - Enable/disable dummy traffic.
  instructions            - Show usage instructions.
  help                    - Display this help text.
  exit/quit               - Exit the application.
  
SPECIAL PASSCODES:
  - '1234567890' triggers dead man's switch.
  - 'decoy9876'  triggers decoy mode at startup.
"""
        print(help_text)

    def command_quick_setup(self, args: list):
        if self.setup_config.get("node_role") != "unknown":
            confirm = input(f"Existing role '{self.setup_config['node_role']}' detected. Overwrite? (y/n): ").strip().lower()
            if confirm != "y":
                print("Quick-setup aborted.")
                return
        while True:
            role = input("Choose your role: [fc]=Field Client, [fs]=Field Server, [sa]=Static Anchor: ").strip().lower()
            if role in ["fc", "fs", "sa"]:
                self.setup_config["node_role"] = role
                break
            print("Invalid role. Please enter 'fc', 'fs', or 'sa'.")
        dn = input(f"Enter display name (default: {self.setup_config['display_name']}): ").strip()
        if dn:
            self.setup_config["display_name"] = dn
        p_input = input(f"Enter listening port (0 for none, default: {DEFAULT_PORT}): ").strip()
        self.setup_config["port"] = int(p_input) if p_input.isdigit() else DEFAULT_PORT

        if self.setup_config["node_role"] == "fc":
            self.quicksetup_client_flow()
        else:
            self.quicksetup_server_flow(is_anchor=(self.setup_config["node_role"] == "sa"))

        adv = input("Advanced config? Enable auto-delete? (y/n): ").strip().lower()
        if adv == "y":
            sdm = input("Set self_destruct_mode (none/after_read/time_based): ").strip().lower()
            if sdm in ["none", "after_read", "time_based"]:
                self.config["self_destruct_mode"] = sdm
                if sdm == "time_based":
                    st = input(f"Auto-delete timer in seconds (default {self.config['self_destruct_timer']}): ").strip()
                    if st.isdigit():
                        self.config["self_destruct_timer"] = int(st)
        self.save_setup_config()
        print("Quick-setup complete. (Restart application if port configuration changed.)")

    def quicksetup_client_flow(self):
        print(f"--- Client Quick-Setup: {self.setup_config['display_name']} ---")
        if not (os.path.exists(CLIENT_CERT_FILE) and os.path.exists(CLIENT_KEY_FILE)):
            print("Generating client certificate/key...")
            CertManager.generate_self_signed_cert(CLIENT_CERT_FILE, CLIENT_KEY_FILE, self.setup_config["display_name"])
        else:
            print("Client certificate/key already exist; skipping generation.")
        ex = input("Export client certificate to USB now? (y/n): ").strip().lower()
        if ex == "y":
            pwd = getpass("Enter config password: ")
            if pwd == CONFIG_PEM_PASSWORD:
                dst = "D:/my_client_cert.pem"
                try:
                    with open(CLIENT_CERT_FILE, "rb") as src, open(dst, "wb") as dstf:
                        dstf.write(src.read())
                    print(f"Client certificate exported to {dst}")
                except Exception as e:
                    print(f"Export error: {e}")
            else:
                print("Incorrect config password. Skipping export.")
        done = input("Is the server configured? (y/n): ").strip().lower()
        if done == "y":
            print("Place server cert on USB as D:/import_server_cert.pem then press Enter.")
            input("Press Enter when ready...")
            if os.path.exists("D:/import_server_cert.pem"):
                try:
                    with open("D:/import_server_cert.pem", "rb") as src, open(TRUSTED_SERVER_FILE, "wb") as dstf:
                        dstf.write(src.read())
                    print("Server certificate imported successfully.")
                    os.remove("D:/import_server_cert.pem")
                except Exception as e:
                    print(f"Import error: {e}")
            else:
                print("Server certificate not found on USB.")
        else:
            print("Please complete server configuration later using 'client-config import'.")

    def quicksetup_server_flow(self, is_anchor: bool):
        role_name = "STATIC ANCHOR SERVER" if is_anchor else "FIELD SERVER"
        print(f"--- Server Quick-Setup: {self.setup_config['display_name']} ---")
        mc = input(f"Enter maximum clients (default: {self.setup_config['max_clients']}): ").strip()
        if mc.isdigit():
            self.setup_config["max_clients"] = int(mc)
        if not (os.path.exists(SERVER_CERT_FILE) and os.path.exists(SERVER_KEY_FILE)):
            print("Generating server certificate/key...")
            CertManager.generate_self_signed_cert(SERVER_CERT_FILE, SERVER_KEY_FILE, self.setup_config["display_name"])
        else:
            print("Server certificate/key exist; skipping generation.")
        if not os.path.exists(TRUSTED_CLIENTS_DIR):
            os.makedirs(TRUSTED_CLIENTS_DIR, exist_ok=True)
        num_clients = input("Number of client .pem files to import from USB: ").strip()
        try:
            n = int(num_clients)
        except:
            n = 0
        for i in range(n):
            src = f"D:/import_client_cert{i+1}.pem"
            if os.path.exists(src):
                try:
                    dst = os.path.join(TRUSTED_CLIENTS_DIR, f"client{i+1}.pem")
                    with open(src, "rb") as s, open(dst, "wb") as d:
                        d.write(s.read())
                    os.remove(src)
                    print(f"Imported client cert {i+1}.")
                except Exception as e:
                    print(f"Import error for client {i+1}: {e}")
            else:
                print(f"File {src} not found; skipping.")
        ex2 = input("Export server certificate to USB? (y/n): ").strip().lower()
        if ex2 == "y":
            pwd = getpass("Enter config password: ")
            if pwd == CONFIG_PEM_PASSWORD:
                dst2 = "D:/my_server_cert.pem"
                try:
                    with open(SERVER_CERT_FILE, "rb") as s, open(dst2, "wb") as d:
                        d.write(s.read())
                    print(f"Server certificate exported to {dst2}")
                except Exception as e:
                    print(f"Export error: {e}")
            else:
                print("Incorrect password; skipping export.")
        combined_path = TRUSTED_CLIENT_FILE
        try:
            with open(combined_path, "wb") as out:
                for fname in os.listdir(TRUSTED_CLIENTS_DIR):
                    if fname.lower().endswith(".pem"):
                        with open(os.path.join(TRUSTED_CLIENTS_DIR, fname), "rb") as f:
                            out.write(f.read())
            logging.info(f"Combined client certificates into {combined_path}")
        except Exception as e:
            logging.warning(f"Error combining client certificates: {e}")

    def command_server_config(self, args: list):
        if len(args) < 1:
            print("Usage: server-config [generate|export|import]")
            return
        sub = args[0].lower()
        if sub == "generate":
            pwd = getpass("Enter config password: ")
            if pwd != CONFIG_PEM_PASSWORD:
                print("Incorrect password.")
                return
            CertManager.generate_self_signed_cert(SERVER_CERT_FILE, SERVER_KEY_FILE, self.setup_config["display_name"])
            print("Server certificate/key generated.")
        elif sub == "export":
            pwd = getpass("Enter config password: ")
            if pwd != CONFIG_PEM_PASSWORD:
                print("Incorrect password.")
                return
            if not os.path.exists(SERVER_CERT_FILE):
                print("Server certificate not found.")
                return
            dst = "D:/my_server_cert.pem"
            with open(SERVER_CERT_FILE, "rb") as s, open(dst, "wb") as d:
                d.write(s.read())
            print(f"Server certificate exported to {dst}")
        elif sub == "import":
            pwd = getpass("Enter config password: ")
            if pwd != CONFIG_PEM_PASSWORD:
                print("Incorrect password.")
                return
            src = "D:/import_server_cert.pem"
            if not os.path.exists(src):
                print(f"No file at {src}")
                return
            with open(src, "rb") as s, open(TRUSTED_SERVER_FILE, "wb") as d:
                d.write(s.read())
            print("Server certificate imported successfully.")
        else:
            print("Invalid subcommand. Use generate|export|import.")

    def command_client_config(self, args: list):
        if len(args) < 1:
            print("Usage: client-config [generate|export|import]")
            return
        sub = args[0].lower()
        if sub == "generate":
            pwd = getpass("Enter config password: ")
            if pwd != CONFIG_PEM_PASSWORD:
                print("Incorrect password.")
                return
            CertManager.generate_self_signed_cert(CLIENT_CERT_FILE, CLIENT_KEY_FILE, self.setup_config["display_name"])
            print("Client certificate/key generated.")
        elif sub == "export":
            pwd = getpass("Enter config password: ")
            if pwd != CONFIG_PEM_PASSWORD:
                print("Incorrect password.")
                return
            if not os.path.exists(CLIENT_CERT_FILE):
                print("Client certificate not found.")
                return
            dst = "D:/my_client_cert.pem"
            with open(CLIENT_CERT_FILE, "rb") as s, open(dst, "wb") as d:
                d.write(s.read())
            print(f"Client certificate exported to {dst}")
        elif sub == "import":
            pwd = getpass("Enter config password: ")
            if pwd != CONFIG_PEM_PASSWORD:
                print("Incorrect password.")
                return
            src = "D:/import_client_cert.pem"
            if not os.path.exists(src):
                print(f"No file at {src}")
                return
            with open(src, "rb") as s, open(TRUSTED_CLIENT_FILE, "wb") as d:
                d.write(s.read())
            print("Client certificate imported successfully.")
        else:
            print("Invalid subcommand. Use generate|export|import.")

    def command_getkeys(self, args: list):
        pwd = getpass("Enter password for key export: ")
        if pwd != EXPORT_KEYS_PASSWORD:
            print("Incorrect password.")
            return
        try:
            x255 = self.keystore.public_key_x25519.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)
            ed25 = self.keystore.public_key_ed25519.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)
            with open("D:/my_x25519_public.pem", "wb") as fx, open("D:/my_ed25519_public.pem", "wb") as fe:
                fx.write(x255)
                fe.write(ed25)
            print("Ephemeral public keys exported to USB (D:/my_x25519_public.pem, D:/my_ed25519_public.pem).")
        except Exception as e:
            print(f"Error exporting keys: {e}")

    def command_recallkeys(self, args: list):
        pwd = getpass("Enter password for key display: ")
        if pwd != DISPLAY_KEYS_PASSWORD:
            print("Incorrect password.")
            return
        try:
            x255 = self.keystore.public_key_x25519.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()
            ed25 = self.keystore.public_key_ed25519.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()
            print("X25519 Public Key:\n", x255)
            print("Ed25519 Public Key:\n", ed25)
        except Exception as e:
            print(f"Error displaying keys: {e}")

    def command_bind(self, args: list):
        if len(args) != 2:
            print("Usage: bind <peer_id> <ip:port>")
            return
        peer_id = args[0]
        try:
            ip, port_str = args[1].split(":")
            port = int(port_str)
        except:
            print("Invalid IP:port format.")
            return
        self.peers[peer_id] = (ip, port)
        print(f"Peer '{peer_id}' bound to {ip}:{port}")

    def command_trust(self, args: list):
        if len(args) < 1:
            print("Usage: trust <peer_id> [manual <x25519_pub> <ed25519_pub>] or import")
            return
        peer_id = args[0]
        if len(args) == 1:
            sub = input("Choose subcommand (manual/import): ").strip().lower()
            if sub == "manual":
                x255 = input("Enter peer's X25519 public key (PEM): ")
                ed25 = input("Enter peer's Ed25519 public key (PEM): ")
                self.trusted_keys[peer_id] = {"x25519": x255, "ed25519": ed25}
                print(f"Trusted keys for {peer_id} added.")
            elif sub == "import":
                self.handle_trust_import(peer_id)
            else:
                print("Invalid subcommand.")
        else:
            if args[1] == "manual" and len(args) >= 4:
                self.trusted_keys[peer_id] = {"x25519": args[2], "ed25519": args[3]}
                print(f"Trusted keys for {peer_id} added.")
            elif args[1] == "import":
                self.handle_trust_import(peer_id)
            else:
                print("Invalid usage. Use 'manual' or 'import'.")

    def handle_trust_import(self, peer_id: str):
        x255_path = "D:/my_x25519_public.pem"
        ed25_path = "D:/my_ed25519_public.pem"
        if not os.path.exists(x255_path) or not os.path.exists(ed25_path):
            print("Peer key files not found on USB.")
            return
        try:
            with open(x255_path, "r") as fx:
                x255_data = fx.read()
            with open(ed25_path, "r") as fe:
                ed25_data = fe.read()
            os.remove(x255_path)
            os.remove(ed25_path)
            self.trusted_keys[peer_id] = {"x25519": x255_data, "ed25519": ed25_data}
            print(f"Trusted keys for peer '{peer_id}' imported and USB files removed.")
        except Exception as e:
            print(f"Error importing trusted keys: {e}")

    def command_remote_wipe(self, args: list):
        if len(args) != 1:
            print("Usage: remote-wipe <target_display_name>")
            return
        target = args[0]
        if not self.peers:
            print("No peers bound. Use 'bind' first.")
            return
        print("Select a peer to send the remote wipe command:")
        for peer in self.peers.keys():
            print(f" - {peer}")
        chosen = input("Enter peer ID: ").strip()
        if chosen not in self.peers or chosen not in self.trusted_keys:
            print("Invalid or untrusted peer. Use 'bind' and 'trust' first.")
            return
        ip, port = self.peers[chosen]
        payload = json.dumps({"cmd": "remote-wipe", "target": target})
        enc = self.encrypt_message(payload, chosen)
        if not enc:
            print("Encryption error.")
            return
        sign_data = (enc["ephemeral_pub"] + enc["nonce"] + enc["ciphertext"]).encode()
        signature = self.sign_message(sign_data)
        msg = {
            "sender": self.keystore.get_identity_fingerprint(),
            "counter": self.counter_state.last_counter,
            "ephemeral_pub": enc["ephemeral_pub"],
            "nonce": enc["nonce"],
            "ciphertext": enc["ciphertext"],
            "signature": base64.b64encode(signature).decode(),
            "timestamp": datetime.datetime.now().isoformat(),
            "cmd": "remote-wipe"
        }
        packed = msgpack.packb(msg, use_bin_type=True)
        try:
            conn = self.tls_manager.create_tls_client_socket(ip, port)
            with conn:
                conn.sendall(packed)
            print(f"Remote wipe command sent to peer '{chosen}' for target '{target}'.")
        except Exception as e:
            print(f"Error sending remote wipe: {e}")

    def command_encrypt_file(self, args: list):
        if len(args) != 2:
            print("Usage: encrypt-file <peer_id> <file_path>")
            return
        peer_id, filepath = args
        if not os.path.isfile(filepath):
            print("Invalid file path.")
            return
        if peer_id not in self.trusted_keys:
            print("Peer not trusted. Use 'trust' first.")
            return
        try:
            with open(filepath, "rb") as f:
                file_data = f.read()
        except Exception as e:
            print(f"File read error: {e}")
            return
        # Encrypt file contents (treating bytes as latin-1 string for compatibility)
        enc = self.encrypt_message(file_data.decode('latin-1', errors='replace'), peer_id)
        if not enc:
            print("Encryption error.")
            return
        sign_data = (enc["ephemeral_pub"] + enc["nonce"] + enc["ciphertext"]).encode()
        signature = self.sign_message(sign_data)
        ephemeral_dict = {
            "sender": self.keystore.get_identity_fingerprint(),
            "counter": self.counter_state.last_counter,
            "ephemeral_pub": enc["ephemeral_pub"],
            "nonce": enc["nonce"],
            "ciphertext": enc["ciphertext"],
            "signature": base64.b64encode(signature).decode(),
            "timestamp": datetime.datetime.now().isoformat(),
            "file_name": os.path.basename(filepath)
        }
        packed = msgpack.packb(ephemeral_dict, use_bin_type=True)
        try:
            with open(filepath, "wb") as f:
                f.write(packed)
            print(f"File encrypted and overwritten: {filepath}")
        except Exception as e:
            print(f"Error writing encrypted file: {e}")

    def command_decrypt_file(self, args: list):
        if len(args) != 1:
            print("Usage: decrypt-file <file_path>")
            return
        filepath = args[0]
        if not os.path.isfile(filepath):
            print("Invalid file path.")
            return
        try:
            with open(filepath, "rb") as f:
                data = f.read()
            ephemeral_dict = msgpack.unpackb(data, raw=False)
        except Exception as e:
            print(f"Error reading encrypted file: {e}")
            return
        dec_obj = self.decrypt_message(ephemeral_dict)
        if not dec_obj:
            print("Decryption failed.")
            return
        try:
            file_bytes = dec_obj["message"].encode('latin-1', 'replace')
            with open(filepath, "wb") as f:
                f.write(file_bytes)
            print(f"File decrypted: {filepath}")
        except Exception as e:
            print(f"Error writing decrypted file: {e}")

    def command_dummy_traffic(self, args: list):
        if len(args) < 1:
            print("Usage: dummy-traffic start <peer_id> OR dummy-traffic stop")
            return
        sub = args[0].lower()
        if sub == "start":
            if len(args) != 2:
                print("Usage: dummy-traffic start <peer_id>")
                return
            peer_id = args[1]
            if peer_id not in self.peers:
                print("Unknown peer. Use 'bind' first.")
                return
            self.config["dummy_traffic_enabled"] = True
            self.config["dummy_traffic_peer"] = peer_id
            print(f"Dummy traffic enabled for peer '{peer_id}'.")
        elif sub == "stop":
            self.config["dummy_traffic_enabled"] = False
            self.config["dummy_traffic_peer"] = None
            print("Dummy traffic disabled.")
        else:
            print("Invalid dummy-traffic command.")

    def command_instructions(self, args: list):
        instructions = """
*** Secure Messaging Application – User Guide ***

1. INITIAL SETUP:
   - On first run, you will be prompted to create a keystore passphrase.
   - Use 'quick-setup' to select your role:
       • fc = Field Client
       • fs = Field Server
       • sa = Static Anchor Server
   - The quick-setup wizard will guide you through certificate generation and binding.

2. KEYS & TRUST:
   - Use 'getkeys' (password required) to export your ephemeral public keys for E2E encryption.
   - Use 'trust <peer_id>' to import or manually add a peer’s ephemeral keys.
   - Use 'bind <peer_id> <ip:port>' to map a peer’s identifier to its network address.

3. MESSAGING:
   - Send messages using: send <peer_id> <message>
   - Received messages are stored and can be viewed with 'list'.
   - Use 'delete <message_id>' or 'purge' to manage stored messages.

4. FILE ENCRYPTION:
   - Encrypt files for a peer using: encrypt-file <peer_id> <file_path>
   - Decrypt using: decrypt-file <file_path>

5. SPECIAL FEATURES:
   - Remote Wipe: Send a remote wipe command with 'remote-wipe <target>'.
   - Dummy Traffic: Start dummy cover messages using 'dummy-traffic start <peer_id>'.
   - Self-Destruct: Configure message auto-deletion using 'self-destruct' (feature may be added in future updates).

6. SECURITY:
   - Dead Man’s Switch: Typing '1234567890' wipes all local data immediately.
   - Decoy Mode: Use passphrase 'decoy9876' at startup to load decoy data.
   - All communications use TLS and ephemeral E2E encryption.

Type 'help' to see the command list.
"""
        print(instructions)

# ---------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------
if __name__ == "__main__":
    try:
        app = MessagingApp()
        app.run()
    except KeyboardInterrupt:
        print("\nExiting application.")
        sys.exit(0)
