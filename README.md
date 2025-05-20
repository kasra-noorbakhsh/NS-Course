# NS-Course: Cryptographic Messenger Project

This repository is for the Network Security course and hosts the Cryptographic Messenger Project, which implements a secure messaging system using cryptographic primitives, featuring a `MessengerClient` class for end-to-end encrypted communication and IPsec simulation.

---

## 📌 Project Overview

* **src**:

  * `lib.py`: Provides cryptographic primitives including El Gamal key generation, AES-GCM encryption/decryption, Diffie-Hellman key exchange, HMAC, and HKDF functions.
  * `messenger.py`: Implements the `MessengerClient` class for generating certificates, sending/receiving encrypted messages, and simulating IPsec communication.
  * `question_4_code.py`: Contains code to compare ECDSA and RSA performance for signing and verifying messages, aiding in answering Question 4.

* **tests**:

  * `test_messenger.py`: Comprehensive tests for the `MessengerClient`, covering certificate exchange, message encryption/decryption, replay attacks, and multi-party conversations.
  * `test_ipsec.py`: Unit tests for the IPsec simulation, verifying send/receive functionality with various data sizes and conditions.

---

## 🧰 Tools Used

* [Python 3](https://www.python.org/) for implementation
* [PyCryptoDome](https://pycryptodome.readthedocs.io/) for cryptographic operations
* [socket](https://docs.python.org/3/library/socket.html) for UDP-based IPsec simulation
* [unittest](https://docs.python.org/3/library/unittest.html) for testing framework

---

## 🚀 How to Run

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/kasra-noorbakhsh/NS-Course.git
   cd NS-Course
   ```

2. **Install Dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

3. **Run the tests**:

   ```bash
   cd tests
   python3 test_messenger.py
   cd src
   python3 test_ipsec.py
   ```

4. **Output**:

   * Programs output results to `stdout`, including test pass/fail messages and performance metrics.

---

## 📬 Contact

Made by **Kasra Noorbakhsh** And **Kourosh Sajjadi**


📧 Feel free to connect or provide feedback!

---

## ❓ Questions

1. **If Alice and Bob never update their DH key, what are the effects on break-in recovery and forward secrecy?**
2. **What is the longest consecutive sending chain for Alice and Bob in the provided conversation?**
3. **Which security feature prevents an attacker from accessing the locker combination message?**
4. **How do RSA and ECDSA compare in terms of performance and characteristics based on the provided tests?**

---

## 📝 Answers

### a. If Alice and Bob Never Update Their DH Key (Break-in Recovery and Forward Secrecy)

* **Break-in Recovery**:

  * Without Diffie-Hellman (DH) key updates, no new randomness is introduced into the session.
  * If the current session keys are compromised, an attacker can decrypt all subsequent messages.
  * **Result**: No break-in recovery is provided in this scenario.

* **Forward Secrecy**:

  * The symmetric ratchet (`kdf_ck`) derives unique message keys, which are updated after each message using a one-way Hash-based Message Authentication Code (HMAC).
  * Even if keys are compromised in the future, past message keys remain secure because the chain key is updated unidirectionally.
  * **Result**: Forward secrecy is maintained despite the lack of DH updates.

### b. Longest Sending Chain for Alice and Bob

* **Conversation Breakdown**:

  1. **A**: "Hey Bob, can you send me the locker combo" (Alice's sending chain length: 1)
  2. **A**: "I need to get my laptop" (Alice's sending chain length: 2)
  3. **B**: "Sure, it's 1234" (Bob's sending chain length: 1)
  4. **A**: "Great, thanks!..." (Alice's sending chain length: 1 - *resets after receiving a message*)
  5. **B**: "Did it work" (Bob's sending chain length: 1 - *resets after receiving a message*)

* **Longest Consecutive Sending Chain**:

  * **Alice**: 2 messages (Messages 1 and 2).
  * **Bob**: 1 message (no instance of consecutive sending).

### c. Security Feature Preventing Access to Locker Combination

* **Feature**: Forward Secrecy, provided by the Double Ratchet algorithm.

* **Mechanism**:

  * The symmetric ratchet (`kdf_ck`) generates a unique message key specifically for Message 3: "Sure, it's 1234" using HMAC-SHA256.
  * After each sent or received message, the chain key is updated. This one-way update ensures that previous message keys cannot be derived from the current or future chain keys.
  * Consequently, an attacker who might have compromised keys *before* Message 3 cannot decrypt this message because the specific message key used for it is lost after the `send_ck` is updated.

### d. RSA and ECDSA Comparison

This section compares the performance and characteristics of Elliptic Curve Digital Signature Algorithm (ECDSA) and Rivest–Shamir–Adleman (RSA) as implemented in `question_4_code.py`.

#### ECDSA

* **Key Generation**: Fast, typically taking between 2-20 ms. Tests show an average of **2.35 ms**.
* **Signature Generation**: Quick, generally ranging from 3-10 ms. Testing yielded an average of **3.24 ms**.
* **Signature Length**: Compact and fixed at **96 bytes** for the P-384 curve.
* **Verification**: Moderately fast, usually between 3-15 ms. Tests averaged **3.58 ms**.

ECDSA's efficiency makes it particularly well-suited for resource-constrained environments.

#### RSA

* **Key Generation**: Slow, ranging from 500-3000 ms. Tests averaged **680.22 ms**.
* **Signature Generation**: Takes between 8-100 ms. Testing resulted in an average of **8.01 ms**.
* **Signature Length**: Fixed at **512 bytes**, directly corresponding to the 4096-bit key size.
* **Verification**: Faster compared to its other operations, typically between 1-10 ms. Tests showed an average of **1.17 ms**.

While RSA's overall performance is slower than ECDSA in these tests, its faster verification time can be advantageous in certain applications.

#### Test Results

| Metric                | ECDSA (P-384) | RSA (4096-bit) |
| --------------------- | ------------- | -------------- |
| Key Generation Time   | 2.35 ms       | 680.22 ms      |
| Signing Time          | 3.24 ms       | 8.01 ms        |
| Verifying Time        | 3.58 ms       | 1.17 ms        |
| Signature Byte Length | 96 bytes      | 512 bytes      |

#### Comparison Summary

* **Key Generation Time**: RSA is significantly slower than ECDSA due to prime generation vs. elliptic curve operations.
* **Signature Generation Time**: RSA is generally slower than ECDSA due to larger key size and complexity.
* **Signature Length**: RSA produces much longer signatures compared to ECDSA for equivalent security levels.
* **Verification Time**: RSA shows slightly faster verification compared to ECDSA, owing to a single modular exponentiation vs. elliptic curve computations.
