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
        salt = gen_random_salt()
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
        if random.random() < 0.1:
            include_dh = True
            conn["PN"] = conn["Ns"]
            conn["DHs"] = generate_eg()
            dh_secret = compute_dh(conn["DHs"]["private"], conn["DHr"])
            conn["root_key"], conn["send_ck"] = hkdf(dh_secret, conn["root_key"], "ratchet")

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
            shared_secret = compute_dh(self.eg_keypair["private"], peer_pub)
            salt = gen_random_salt()
            root_key, recv_ck = hkdf(shared_secret, salt, "ratchet")
            conn = self.conns[name] = {
                "root_key": root_key,
                "send_ck": None,
                "recv_ck": recv_ck,
                "DHs": self.eg_keypair,
                "DHr": peer_pub,
                "Ns": 0, "Nr": 0, "PN": 0,
                "skipped_keys": {}
            }

        if "dh" in header and header["dh"] != conn["DHr"]:
            if conn["Nr"] < header["pn"]:
                for skipped in range(conn["Nr"], min(header["pn"], conn["Nr"] + 10)):
                    if conn["recv_ck"] is None:
                        break
                    mk, conn["recv_ck"] = kdf_ck(conn["recv_ck"])
                    conn["skipped_keys"][(conn["DHr"], skipped)] = mk
            conn["PN"] = conn["Ns"]
            conn["Nr"] = 0
            conn["DHr"] = header["dh"]
            dh_secret = compute_dh(conn["DHs"]["private"], conn["DHr"])
            conn["root_key"], conn["recv_ck"] = hkdf(dh_secret, conn["root_key"], "ratchet")

        n = header["n"]
        mk = None
        sk_key = (conn["DHr"], n)

        if sk_key in conn["skipped_keys"]:
            mk = conn["skipped_keys"].pop(sk_key)
        else:
            if conn["recv_ck"] is None:
                # Attempt deriving recv_ck from DHs/private and current DHr
                dh_secret = compute_dh(conn["DHs"]["private"], conn["DHr"])
                conn["root_key"], conn["recv_ck"] = hkdf(dh_secret, conn["root_key"], "ratchet")
            if n - conn["Nr"] > 10:
                raise ValueError("Too many skipped messages")
            while conn["Nr"] < n:
                _, conn["recv_ck"] = kdf_ck(conn["recv_ck"])
                conn["Nr"] += 1
            mk, conn["recv_ck"] = kdf_ck(conn["recv_ck"])
            conn["Nr"] += 1

        plaintext = decrypt_with_gcm(mk, ciphertext_info, iv)
        return plaintext


###################################
# Simulated IPsec Transport Layer #
###################################

STATIC_IPSEC_KEY = hmac_to_aes_key(b"session_psk", "ipsec")

def send_via_simulated_ipsec(dest_ip: str, dest_port: int, data: bytes):
    iv = {}
    # TO DO

def receive_via_simulated_ipsec(bind_ip: str, bind_port: int) -> bytes:
    # TO DO
    plaintext = {}
    return plaintext
