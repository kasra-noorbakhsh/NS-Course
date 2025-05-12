###############################################################################
# Cryptographic Primitives
#
# All of the cryptographic functions you need for this assignment are contained
# within this library.
#
# For your convenience, we have abstracted away all of the pesky underlying 
# data types so that you can focus on building the messenger without getting 
# caught up with conversions.
#
# Keys, hash outputs, ciphertexts, and signatures are all in bytes, and input
# plaintexts are strings.
# 
# 
# lib.py
# Adapted into Python by Ari Glenn
# Edited by Abolfazl Eslami
###############################################################################
from typing import Tuple

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256, SHA384
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Random import get_random_bytes
from Crypto.Protocol.DH import key_agreement
from Crypto.Protocol.KDF import HKDF
import functools



def generate_eg() -> dict:
    """
    Generates an El Gamal key pair

    Returns:
        pair of ElGamal keys as an object
            public: bytes
            private: bytes
    """
    key = ECC.generate(curve="P-384")
    # Export keys in binary
    return {"public": key.public_key().export_key(format="DER"), "private": key.export_key(format="DER")}

def gen_random_salt(length: int = 16) -> bytes:
    """
    Generates a random salt/IV

    Inputs:
        length: int (default to 16)

    Returns:
        random byte string of specified length: bytes
    """
    return get_random_bytes(length)

def verify_with_ecdsa(public_key: bytes, message: str, signature: bytes) -> bool:
    """
    Verifies an ECDSA signature

    Inputs:
        public_key: bytes
        message: string
        signature: bytes

    Returns:
        verification: bool
    """
    # Convert key to ECC key object
    public_key = ECC.import_key(public_key)
    # Create cryptographic hash object and hash message
    h = SHA384.new(str_to_bytes(message))
    # Digital signature standard
    verifier = DSS.new(public_key, "fips-186-3")
    try:
        verifier.verify(h, signature)
        return True
    except ValueError:
        return False
    
def encrypt_with_gcm(key: bytes, plaintext: str, iv: bytes, authenticated_data: str = "") -> Tuple[bytes, bytes]:
    """
    Encrypts using AES-GCM

    Inputs:
        key (to encrypt with): bytes
        plaintext (str to be encrypted): string
        iv (nonce generated from gen_random_salt()): bytes
        authenticated_data (optional string): string

    Returns:
        ciphertext_info: tuple of [ciphertext, tag]
    """
    # Create cipher from key and iv
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    # Convert authenticated_data to bytes
    cipher.update(str_to_bytes(authenticated_data))
    # Convert plaintext to bytes
    if type(plaintext) == str:
        plaintext = str_to_bytes(plaintext)
    # Encrypt plaintext
    ciphertext_info = cipher.encrypt_and_digest(plaintext)
    return ciphertext_info

def decrypt_with_gcm(key: bytes, ciphertext_info: Tuple[bytes, bytes], iv: bytes, authenticated_data: str = "", decode_bytes: bool = True) -> str | bytes:
    """
    Decrypts using AES-GCM

    Inputs:
        key: bytes
        ciphertext_info: tuple of [ciphertext, tag] (the output from encrypt_with_gcm())
        iv (used to encrypt): bytes
        authenticated_data (optional string): string
        decode_bytes (This is for test_messenger, you should NOT need to set this to False.
            If False, returns plaintext in bytes instead of string): bool

    Returns:
        plaintext: string (or byte string if decode_bytes set to False)
    """
    # Create cipher from key and iv
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    # Convert authenticated_data to bytes
    cipher.update(str_to_bytes(authenticated_data))
    # Decrypt ciphertext
    plaintext = cipher.decrypt_and_verify(*ciphertext_info)
    # Convert bytes to string
    if decode_bytes:
        return plaintext.decode("utf-8")
    return plaintext

def compute_dh(my_private_key: str, their_public_key: str) -> bytes:
    """
    Computes Diffie-Hellman key exchange for an EG private key and EG public key

    Inputs:
        my_private_key: should be private key from generate_eg()
        their_public_key: should be public key from generate_eg()
        NOTE: my_private_key and their_public_key should be from different calls to generate_eg()

    Returns:
        shared secret result of DH exchange: bytes
    """
    # Convert keys to ECC key objects
    my_private_key = ECC.import_key(my_private_key)
    their_public_key = ECC.import_key(their_public_key)
    # Define KDF to be used for DH key agreement
    kdf = functools.partial(HKDF, key_len=32, salt=b"nonce", hashmod=SHA256)
    # Return shared secret
    return key_agreement(static_priv=my_private_key, static_pub=their_public_key, kdf=kdf)

def hmac_to_hmac_key(key: bytes, data: str) -> bytes:
    """
    Performs HMAC to derive a new key with the HMAC algorithm

    Inputs:
        key: bytes
        data: string

    Returns:
        hmac_output: bytes
    """
    # Compute HMAC output
    h = HMAC.new(key, digestmod=SHA256)
    h.update(str_to_bytes(data))
    hmac_output = h.digest()
    return hmac_output

def hmac_to_aes_key(key: bytes, data: str) -> bytes:
    """
    Derives an AES key using HMAC

    Inputs:
        key: bytes
        data: string

    Returns:
        aes_derived_key: bytes
    """
    # Compute HMAC output
    h = HMAC.new(key, digestmod=SHA256)
    h.update(str_to_bytes(data))
    hmac_output = h.digest()
    # Create AES key from the HMAC output (256 bit)
    aes_derived_key = hmac_output
    # Return AES key bytes
    return aes_derived_key

def hkdf(input_key: bytes, salt: bytes, info_str: str) -> Tuple[bytes, bytes]:
    """
    Calculates HKDF outputs

    Inputs:
        input_key: bytes
        salt: bytes
        info_str: string

    Returns:
        hkdf_out1: bytes
        hkdf_out2: bytes
    """
    # Derive an initial key using HMAC on input_key with arbitrary constant
    hmac = HMAC.new(input_key, msg=b"0", digestmod=SHA256)
    input_key_hkdf = hmac.digest()
    # Generate salts for derive_key calls
    salt1_hmac = HMAC.new(salt, msg=b"salt1", digestmod=SHA256).digest()
    salt2_hmac = HMAC.new(salt, msg=b"salt2", digestmod=SHA256).digest()
    # Calculate first HKDF output with salt1
    hkdf_out1 = HKDF(
        master=input_key_hkdf,
        key_len=len(input_key_hkdf), # with len 32
        salt=salt1_hmac,
        hashmod=SHA256,
        context=info_str.encode()
    )
    # Calculate second HKDF output with salt2
    hkdf_out2 = HKDF(
        master=input_key_hkdf,
        key_len=len(input_key_hkdf), # with len 32
        salt=salt2_hmac,
        hashmod=SHA256,
        context=info_str.encode()
    )
    return hkdf_out1, hkdf_out2



def kdf_ck(ck: bytes) -> Tuple[bytes, bytes]:
    """
    Implements KDF_CK as per Double Ratchet spec.

    Inputs:
        ck: bytes (current chain key)

    Returns:
        (message_key, next_chain_key)
    """
    # Message key = HMAC(ck, 0x01)
    hmac1 = HMAC.new(ck, digestmod=SHA256)
    hmac1.update(b'\x01')
    message_key = hmac1.digest()

    # Next chain key = HMAC(ck, 0x02)
    hmac2 = HMAC.new(ck, digestmod=SHA256)
    hmac2.update(b'\x02')
    next_chain_key = hmac2.digest()

    return message_key, next_chain_key


###############################################################################
# Addtional functions for test_messenger.py
#
# YOU DO NOT NEED THESE FUNCTIONS FOR MESSENGER.PY
#
# ... but they may be helpful if you want to write additional tests for certificate
# signatures in test_messenger.py
###############################################################################

def generate_ecdsa() -> dict:
    """
    Generates an ECDSA key pair

    Returns:
        pair of ECDSA keys as an object
            public: bytes
            private: bytes
    """
    key = ECC.generate(curve="P-384")
    return {"public": key.public_key().export_key(format="DER"), "private": key.export_key(format="DER")}

def sign_with_ecdsa(private_key: bytes, message: str) -> bytes:
    """
    Signs a message with ECDSA

    Inputs:
        private_key: bytes
        message: string

    Returns:
        signature: bytes
    """
    # Convert key to ECC key object
    private_key = ECC.import_key(private_key)
    h = SHA384.new(str_to_bytes(message))
    signer = DSS.new(private_key, "fips-186-3")
    return signer.sign(h)

def str_to_bytes(s: str) -> bytes:
    """
    Converts string to bytes

    Inputs:
        s: string

    Returns:
        byte string
    """
    return s.encode("utf-8")
