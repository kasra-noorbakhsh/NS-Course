###############################################################################
# 
# question_4_code.py
# ______________
# Code to help answer Question 4 in the short-answer questions
###############################################################################
import time
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from lib import (generate_ecdsa, sign_with_ecdsa, verify_with_ecdsa, str_to_bytes)

def ecdsa_test(message):
    print("====================================================")
    print(f"Testing ECDSA on message: \"{message}\"")
    print("----------------------------------------------------")
    
    # Generate ECDSA key
    start_time = time.time()
    key_pair = generate_ecdsa()
    elapsed_time = time.time() - start_time
    print(f"ECDSA Key Generation Total Time: {elapsed_time*1000:.2f} ms")
    
    # Sign with ECDSA key
    start_time = time.time()
    signature = sign_with_ecdsa(key_pair["private"], message)
    elapsed_time = time.time() - start_time
    print(f"ECDSA Signing Total Time: {elapsed_time*1000:.2f} ms")

    # Verify with ECDSA key
    start_time = time.time()
    verified = verify_with_ecdsa(key_pair["public"], message, signature)
    elapsed_time = time.time() - start_time
    print(f"ECDSA Verifying Total Time: {elapsed_time*1000:.2f} ms")
    # Ensure verification succeeded
    if not verified:
        raise Exception("Verification function failed")
    
    print("ECDSA Signature Byte Length", len(signature))
    print("====================================================")


def rsa_test(message):
    print("====================================================")
    print(f"Testing RSA on message: \"{message}\"")
    print("----------------------------------------------------")
    
    # Generate RSA key
    start_time = time.time()
    private_key = RSA.generate(4096)
    public_key = private_key.public_key()
    elapsed_time = time.time() - start_time
    print(f"RSA Key Generation Total Time: {elapsed_time*1000:.2f} ms")
    
    # Sign with RSA key
    start_time = time.time()
    h = SHA256.new(str_to_bytes(message))
    signature = pss.new(private_key).sign(h)
    elapsed_time = time.time() - start_time
    print(f"RSA Signing Total Time: {elapsed_time*1000:.2f} ms")

    # Verify with RSA key
    start_time = time.time()
    verifier = pss.new(public_key)
    try:
        verifier.verify(h, signature)
        verified = True
    except (ValueError):
        verified = False
    elapsed_time = time.time() - start_time
    print(f"RSA Verifying Total Time: {elapsed_time*1000:.2f} ms")
    # Ensure verification succeeded
    if not verified:
        raise Exception("Verification function failed")
    
    print("RSA Signature Byte Length", len(signature))
    print("====================================================")


# Run ECDSA and RSA tests
message = "using cryptography correctly is very important"
ecdsa_test(message)
rsa_test(message)
