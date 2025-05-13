# 🗝️ Cryptographic Messenger Project

This project implements a secure messaging system using cryptographic primitives, featuring a `MessengerClient` class for end-to-end encrypted communication and IPsec simulation. The codebase includes source files in the `src` directory and test files in the `tests` directory, demonstrating the use of elliptic curve cryptography (ECC), Diffie-Hellman (DH) key exchange, and AES-GCM encryption.

---

## 📌 Project Overview

- **src**:
  - `lib.py`: Provides cryptographic primitives including El Gamal key generation, AES-GCM encryption/decryption, Diffie-Hellman key exchange, HMAC, and HKDF functions.
  - `messenger.py`: Implements the `MessengerClient` class for generating certificates, sending/receiving encrypted messages, and simulating IPsec communication.
  - `question_4_code.py`: Contains code to compare ECDSA and RSA performance for signing and verifying messages, aiding in answering Question 4.

- **tests**:
  - `test_messenger.py`: Comprehensive tests for the `MessengerClient`, covering certificate exchange, message encryption/decryption, replay attacks, and multi-party conversations.
  - `test_ipsec.py`: Unit tests for the IPsec simulation, verifying send/receive functionality with various data sizes and conditions.
---

## 🧰 Tools Used

- [Python 3](https://www.python.org/) for implementation
- [PyCryptoDome](https://pycryptodome.readthedocs.io/) for cryptographic operations
- [socket](https://docs.python.org/3/library/socket.html) for UDP-based IPsec simulation
- [unittest](https://docs.python.org/3/library/unittest.html) for testing framework

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

3. **Run the test for Messenger**:
   ```bash
   cd tests
   python3 test_messenger.py
   ```

4. **Run the test for IPSec**:
   ```bash
   cd src
   python3 test_ipsec.py
   ```

6. **Output**:
   - Programs output results to `stdout`, including test pass/fail messages and performance metrics.

---

## 📬 Contact

Made by **Kasra Noorbakhsh**  
📧 Feel free to connect or provide feedback!
