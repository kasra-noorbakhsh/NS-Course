###############################################################################
# 
# messenger.py
# ______________
# Please implement the functions below according to the assignment spec
###############################################################################
from lib import (
    gen_random_salt,
    generate_eg,
    compute_dh,
    verify_with_ecdsa,
    hmac_to_aes_key,
    hmac_to_hmac_key,
    hkdf,
    encrypt_with_gcm,
    decrypt_with_gcm,
    kdf_ck,
)
import socket
import struct


class MessengerClient:
    def __init__(self, cert_authority_public_key: bytes):
        """
        The certificate authority DSA public key is used to
        verify the authenticity and integrity of certificates
        of other users (see handout and receive_certificate)
        """
        # Feel free to store data as needed in the objects below
        # and modify their structure as you see fit.
        self.ca_public_key = cert_authority_public_key
        self.conns = {}  # data for each active connection
        self.certs = {}  # certificates of other users


    def generate_certificate(self, username: str) -> dict:
        """
        Generate a certificate to be stored with the certificate authority.
        The certificate must contain the field "username".

        Inputs:
            username: str

        Returns:
            certificate: dict
        """
        self.username = username
        self.eg_keypair = generate_eg()  # Save private for later DH steps
        certificate = {
            "username": username,
            "eg_pub": self.eg_keypair["public"]
        }
        return certificate


    def receive_certificate(self, certificate: dict, signature: bytes) -> None:
        """
        Receive and store another user's certificate.

        Inputs:
            certificate: dict
            signature: bytes

        Returns:
            None
        """
        if not verify_with_ecdsa(self.ca_public_key, str(certificate), signature):
            raise ValueError("Tampering detected!")

        name = certificate["username"]
        self.certs[name] = certificate
        peer_pub = certificate["eg_pub"]

        # Establish shared root key using own private and their public
        shared_secret = compute_dh(self.eg_keypair["private"], peer_pub)
        salt = b"initial_ratchet_salt"
        root_key, send_chain_key = hkdf(shared_secret, salt, "ratchet")

        self.conns[name] = {
            "root_key": root_key,
            "send_ck": send_chain_key,
            "recv_ck": None,  # not known yet
            "DHs": self.eg_keypair,
            "DHr": peer_pub,
            "Ns": 0, "Nr": 0, "PN": 0,
            "skipped_keys": {}  # (dh_pub, msg_num) -> key
        }


    def send_message(self, name: str, plaintext: str) -> tuple[dict, tuple[bytes, bytes]]:
        """
        Generate the message to be sent to another user.

        Inputs:
            name: str
            plaintext: str

        Returns:
            (header, ciphertext): tuple(dict, tuple(bytes, bytes))
        """
        import random

        conn = self.conns[name]

        # DH ratchet with 10% chance
        include_dh = False
        if random.random() < 0.1 or conn["Ns"] == 0:  # Force DH ratchet for first message
            include_dh = True
            conn["PN"] = conn["Ns"]
            conn["DHs"] = generate_eg()
            dh_secret = compute_dh(conn["DHs"]["private"], conn["DHr"])
            conn["root_key"], conn["send_ck"] = hkdf(dh_secret, conn["root_key"] or b"initial_ratchet_salt", "ratchet")
            conn["Ns"] = 0  # Reset Ns after DH ratchet

        # Derive message key
        mk, conn["send_ck"] = kdf_ck(conn["send_ck"])
        iv = gen_random_salt()

        ciphertext = encrypt_with_gcm(mk, plaintext, iv)

        # Construct header
        header = {
            "pn": conn["PN"],
            "n": conn["Ns"],
            "iv": iv
        }
        if include_dh:
            header["dh"] = conn["DHs"]["public"]

        conn["Ns"] += 1
        return header, ciphertext


    def receive_message(self, name: str, message: tuple[dict, tuple[bytes, bytes]]) -> str:
        """
        Decrypt a message received from another user.

        Inputs:
            name: str
            message: tuple(dict, tuple(bytes, bytes))

        Returns:
            plaintext: str
        """
        header, ciphertext_info = message
        iv = header["iv"]
        conn = self.conns.get(name)

        if conn is None:
            if name not in self.certs:
                raise ValueError("Missing certificate for user")
            peer_cert = self.certs[name]
            peer_pub = peer_cert["eg_pub"]
            conn = {
                "root_key": None,
                "send_ck": None,
                "recv_ck": None,
                "DHs": self.eg_keypair,
                "DHr": peer_pub,
                "Ns": 0, "Nr": 0, "PN": 0,
                "skipped_keys": {}
            }
            self.conns[name] = conn

        # Handle DH ratchet if new public key is provided
        if "dh" in header and header["dh"] != conn["DHr"]:
            # Store previous chain state for skipped messages
            if conn["recv_ck"] is not None:
                # Save message keys for any skipped messages in the previous chain
                for i in range(conn["Nr"], header["pn"]):
                    mk, conn["recv_ck"] = kdf_ck(conn["recv_ck"])
                    conn["skipped_keys"][(conn["DHr"], i)] = mk
            # Update DH public key and reset chain state
            conn["PN"] = conn["Ns"]
            conn["Ns"] = 0
            conn["Nr"] = 0
            conn["DHr"] = header["dh"]
            # Perform DH key exchange
            dh_secret = compute_dh(conn["DHs"]["private"], conn["DHr"])
            # Derive new root key and receive chain key
            conn["root_key"], conn["recv_ck"] = hkdf(dh_secret, conn["root_key"] or b"initial_ratchet_salt", "ratchet")
        elif conn["recv_ck"] is None:
            # Initial setup for first message if no DH key provided
            dh_secret = compute_dh(conn["DHs"]["private"], conn["DHr"])
            conn["root_key"], conn["recv_ck"] = hkdf(dh_secret, b"initial_ratchet_salt", "ratchet")

        n = header["n"]
        sk_key = (conn["DHr"], n)

        if sk_key in conn["skipped_keys"]:
            mk = conn["skipped_keys"].pop(sk_key)
        else:
            if n < conn["Nr"]:
                raise ValueError("Message replay detected")
            if n - conn["Nr"] > 10:
                raise ValueError("Too many skipped messages")
            # Derive message keys for skipped messages
            while conn["Nr"] < n:
                mk, conn["recv_ck"] = kdf_ck(conn["recv_ck"])
                conn["skipped_keys"][(conn["DHr"], conn["Nr"])] = mk
                conn["Nr"] += 1
            # Derive the message key for the current message
            mk, conn["recv_ck"] = kdf_ck(conn["recv_ck"])
            conn["Nr"] += 1

        plaintext = decrypt_with_gcm(mk, ciphertext_info, iv)
        return plaintext


###################################
# Simulated IPsec Transport Layer #
###################################

STATIC_IPSEC_KEY = hmac_to_aes_key(b"session_psk", "ipsec")

def send_via_simulated_ipsec(dest_ip: str, dest_port: int, data: bytes):
    """
    Encrypt data using AES-GCM and send it over UDP to the destination.

    Inputs:
        dest_ip: str - Destination IP address
        dest_port: int - Destination port
        data: bytes - Data to encrypt and send

    Returns:
        None
    """
    # Generate random IV
    iv = gen_random_salt()
    
    # Encrypt data with AES-GCM
    ciphertext, auth_tag = encrypt_with_gcm(STATIC_IPSEC_KEY, data, iv)
    
    # Serialize packet: IV length (4 bytes), IV, ciphertext, auth_tag
    iv_len = len(iv)
    packet = struct.pack('!I', iv_len) + iv + ciphertext + auth_tag
    
    # Send over UDP
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(packet, (dest_ip, dest_port))

def receive_via_simulated_ipsec(bind_ip: str, bind_port: int) -> bytes:
    """
    Listen on the given IP and port, receive a UDP packet, and decrypt it.

    Inputs:
        bind_ip: str - IP address to bind to
        bind_port: int - Port to bind to

    Returns:
        plaintext: bytes - Decrypted data
    """
    # Create UDP socket and bind to address
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((bind_ip, bind_port))
        
        # Receive packet
        packet, _ = sock.recvfrom(65535)  # Buffer size for UDP
        
        # Deserialize packet: IV length (4 bytes), IV, ciphertext, auth_tag
        iv_len = struct.unpack('!I', packet[:4])[0]
        iv = packet[4:4+iv_len]
        ciphertext = packet[4+iv_len:-16]  # Last 16 bytes are auth_tag
        auth_tag = packet[-16:]
        
        # Decrypt with AES-GCM
        plaintext = decrypt_with_gcm(STATIC_IPSEC_KEY, (ciphertext, auth_tag), iv)
        return plaintext
