## Double Ratchet Analysis

This document analyzes several aspects of a hypothetical messaging protocol employing the Double Ratchet algorithm, comparing its security properties and performance characteristics of underlying cryptographic primitives (ECDSA and RSA).

### a: If Alice and Bob Never Update Their DH Key (Break-in Recovery and Forward Secrecy)

- **Break-in Recovery**:
    - Without Diffie-Hellman (DH) key updates, no new randomness is introduced into the session.
    - If the current session keys are compromised, an attacker can decrypt all subsequent messages.
    - **Result**: No break-in recovery is provided in this scenario.

- **Forward Secrecy**:
    - The symmetric ratchet (`kdf_ck`) derives unique message keys, which are updated after each message using a one-way Hash-based Message Authentication Code (HMAC).
    - Even if keys are compromised in the future, past message keys remain secure because the chain key is updated unidirectionally.
    - **Result**: Forward secrecy is maintained despite the lack of DH updates.

### b: Longest Sending Chain for Alice and Bob

- **Conversation Breakdown**:
    1. **A**: "Hey Bob, can you send me the locker combo" (Alice's sending chain length: 1)
    2. **A**: "I need to get my laptop" (Alice's sending chain length: 2)
    3. **B**: "Sure, it's 1234" (Bob's sending chain length: 1)
    4. **A**: "Great, thanks!..." (Alice's sending chain length: 1 - *resets after receiving a message*)
    5. **B**: "Did it work" (Bob's sending chain length: 1 - *resets after receiving a message*)

- **Longest Consecutive Sending Chain**:
    - **Alice**: 2 messages (Messages 1 and 2).
    - **Bob**: 1 message (no instance of consecutive sending).

### c: Security Feature Preventing Access to Locker Combination

- **Feature**: Forward Secrecy, provided by the Double Ratchet algorithm.

- **Mechanism**:
    - The symmetric ratchet (`kdf_ck`) generates a unique message key specifically for Message 3: "Sure, it's 1234" using HMAC-SHA256.
    - After each sent or received message, the chain key is updated. This one-way update ensures that previous message keys cannot be derived from the current or future chain keys.
    - Consequently, an attacker who might have compromised keys *before* Message 3 cannot decrypt this message because the specific message key used for it is lost after the `send_ck` is updated.

### d: RSA and ECDSA Comparison

This section compares the performance and characteristics of Elliptic Curve Digital Signature Algorithm (ECDSA) and Rivest–Shamir–Adleman (RSA) as implemented in `question_4_code.py`.

#### ECDSA

Implemented using the P-384 curve, ECDSA demonstrates high efficiency across various cryptographic operations.

- **Key Generation**: Fast, typically taking between 2-20 ms. Tests show an average of **2.35 ms**. This speed is attributed to the computationally lightweight nature of elliptic curve key pair generation (`lib.py`, line 258).
- **Signature Generation**: Quick, generally ranging from 3-10 ms. Testing yielded an average of **3.24 ms**. This involves hashing with SHA384 and elliptic curve signing (`lib.py`, lines 271-275).
- **Signature Length**: Compact and fixed at **96 bytes** for the P-384 curve, as observed in the test output.
- **Verification**: Moderately fast, usually between 3-15 ms. Tests averaged **3.58 ms**, requiring a hash operation and elliptic curve computations (`lib.py`, lines 48-60).

ECDSA's efficiency makes it particularly well-suited for resource-constrained environments.

#### RSA

Implemented with a 4096-bit key, RSA operations are generally more computationally intensive compared to ECDSA in this context.

- **Key Generation**: Slow, ranging from 500-3000 ms. Tests averaged a significantly higher **680.22 ms**. This is due to the complex process of finding and verifying large prime numbers (`question_4_code.py`, lines 44-45).
- **Signature Generation**: Takes between 8-100 ms. Testing resulted in an average of **8.01 ms**, involving SHA256 hashing and Probabilistic Signature Scheme (PSS) signing with the large key (`question_4_code.py`, lines 50-52).
- **Signature Length**: Fixed at **512 bytes**, directly corresponding to the 4096-bit key size, as confirmed in the tests.
- **Verification**: Faster compared to its other operations, typically between 1-10 ms. Tests showed an average of **1.17 ms**, utilizing a single public-key operation (`question_4_code.py`, lines 55-62).

While RSA's overall performance is slower than ECDSA in these tests, its faster verification time can be an advantage in certain applications.

#### Test Results

The following results were obtained from testing both algorithms on the message: "using cryptography correctly is very important".

| Metric                  | ECDSA (P-384) | RSA (4096-bit) |
| ----------------------- | ------------- | -------------- |
| Key Generation Time     | 2.35 ms       | 680.22 ms      |
| Signing Time            | 3.24 ms       | 8.01 ms        |
| Verifying Time          | 3.58 ms       | 1.17 ms        |
| Signature Byte Length | 96 bytes      | 512 bytes      |

#### Comparison Summary

- **Key Generation Time**: RSA is significantly slower (500-3000 ms) than ECDSA (2-20 ms) due to the fundamental differences in their key generation processes (prime generation vs. elliptic curve operations).
- **Signature Generation Time**: RSA (8-100 ms) is generally slower than ECDSA (3-10 ms) due to the larger key size and the complexity of the PSS signing scheme.
- **Signature Length**: RSA produces much longer signatures (512 bytes) compared to ECDSA (96 bytes), as RSA signature length scales with the key size, while ECDSA's output is fixed for a given curve.
- **Verification Time**: RSA (1-10 ms) demonstrates a slightly faster verification time compared to ECDSA (3-15 ms), as RSA verification involves a single modular exponentiation, while ECDSA involves more complex elliptic curve computations.
