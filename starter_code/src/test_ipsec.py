import unittest
import threading
import time
import struct
import socket
from messenger import MessengerClient, send_via_simulated_ipsec, receive_via_simulated_ipsec
from lib import gen_random_salt, encrypt_with_gcm, hmac_to_aes_key

class CustomTestResult(unittest.TestResult):
    def __init__(self, stream=None, descriptions=None, verbosity=None):
        super().__init__(stream, descriptions, verbosity)
        self.test_number = 0

    def startTest(self, test):
        self.test_number += 1
        print(f"{self.test_number}) Testing: {test._testMethodDoc.strip()}")
        super().startTest(test)

    def addSuccess(self, test):
        super().addSuccess(test)
        print(f"{self.test_number}) Test passed: {test._testMethodDoc.strip()}")

    def addFailure(self, test, err):
        super().addFailure(test, err)
        print(f"{self.test_number}) Test failed: {test._testMethodDoc.strip()}")
        print(f"Error: {err[1]}")

    def addError(self, test, err):
        super().addError(test, err)
        print(f"{self.test_number}) Test errored: {test._testMethodDoc.strip()}")
        print(f"Error: {err[1]}")

class CustomTestRunner(unittest.TextTestRunner):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, resultclass=CustomTestResult, **kwargs)

class TestIPsec(unittest.TestCase):
    def setUp(self):
        """Initialize test environment with client and network settings."""
        self.client = MessengerClient(b"dummy_ca_key")
        self.bind_ip = "127.0.0.1"
        self.dest_ip = "127.0.0.1"
        # Assign unique ports for each test
        self.ports = {
            'test_send_receive_ipsec': self._find_available_port(),
            'test_large_data_ipsec': self._find_available_port(),
            'test_multiple_messages_ipsec': self._find_available_port(),
            'test_invalid_data_ipsec': self._find_available_port()
        }

    def _find_available_port(self):
        """Find an available port by binding and releasing a socket."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(('127.0.0.1', 0))  # Let OS assign a free port
            return s.getsockname()[1]

    def test_send_receive_ipsec(self):
        """Send and receive a single message over simulated IPsec."""
        test_data = b"Hello, IPsec!"
        received_data = [None]
        port = self.ports['test_send_receive_ipsec']
        def receive():
            try:
                received_data[0] = receive_via_simulated_ipsec(self.bind_ip, port)
            except Exception as e:
                received_data[0] = e

        receiver_thread = threading.Thread(target=receive)
        receiver_thread.daemon = True
        receiver_thread.start()
        time.sleep(0.1)
        send_via_simulated_ipsec(self.dest_ip, port, test_data)
        receiver_thread.join(timeout=2.0)

        self.assertIsNotNone(received_data[0], "No data received")
        self.assertNotIsInstance(received_data[0], Exception, f"Receiver raised an exception: {received_data[0]}")
        self.assertEqual(received_data[0], test_data, "Received data does not match sent data")

    def test_large_data_ipsec(self):
        """Send and receive a 1KB message over simulated IPsec."""
        test_data = b"A" * 1000  # 1KB to avoid UDP fragmentation
        received_data = [None]
        port = self.ports['test_large_data_ipsec']
        def receive():
            try:
                received_data[0] = receive_via_simulated_ipsec(self.bind_ip, port)
            except Exception as e:
                received_data[0] = e

        receiver_thread = threading.Thread(target=receive)
        receiver_thread.daemon = True
        receiver_thread.start()
        time.sleep(0.1)
        send_via_simulated_ipsec(self.dest_ip, port, test_data)
        receiver_thread.join(timeout=3.0)

        self.assertIsNotNone(received_data[0], "No data received")
        self.assertNotIsInstance(received_data[0], Exception, f"Receiver raised an exception: {received_data[0]}")
        self.assertEqual(received_data[0], test_data, "Received large data does not match sent data")

    def test_multiple_messages_ipsec(self):
        """Send and receive three sequential messages over simulated IPsec."""
        test_data_list = [b"Message 1", b"Message 2", b"Message 3"]
        received_data_list = [None] * 3
        port = self.ports['test_multiple_messages_ipsec']
        def receive_multiple():
            try:
                for i in range(3):
                    received_data_list[i] = receive_via_simulated_ipsec(self.bind_ip, port)
            except Exception as e:
                received_data_list[i] = e

        receiver_thread = threading.Thread(target=receive_multiple)
        receiver_thread.daemon = True
        receiver_thread.start()
        time.sleep(0.1)
        for data in test_data_list:
            send_via_simulated_ipsec(self.dest_ip, port, data)
            time.sleep(0.05)  # Small delay to ensure sequential delivery

        receiver_thread.join(timeout=3.0)

        for i, (received, expected) in enumerate(zip(received_data_list, test_data_list)):
            self.assertIsNotNone(received, f"No data received for message {i+1}")
            self.assertNotIsInstance(received, Exception, f"Receiver raised an exception for message {i+1}: {received}")
            self.assertEqual(received, expected, f"Received data for message {i+1} does not match sent data")

    def test_invalid_data_ipsec(self):
        """Send corrupted data and verify it fails decryption."""
        test_data = b"Hello, IPsec!"
        received_data = [None]
        port = self.ports['test_invalid_data_ipsec']
        def receive():
            try:
                received_data[0] = receive_via_simulated_ipsec(self.bind_ip, port)
            except Exception as e:
                received_data[0] = e

        receiver_thread = threading.Thread(target=receive)
        receiver_thread.daemon = True
        receiver_thread.start()
        time.sleep(0.1)
        
        # Create corrupted packet using a wrong key
        wrong_key = hmac_to_aes_key(b"wrong_psk", "ipsec")  # Same derivation but different input
        iv = gen_random_salt()
        ciphertext, auth_tag = encrypt_with_gcm(wrong_key, test_data, iv)
        packet = struct.pack('!I', len(iv)) + iv + ciphertext + auth_tag
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(packet, (self.dest_ip, port))

        receiver_thread.join(timeout=2.0)

        self.assertIsNotNone(received_data[0], "No data received")
        self.assertIsInstance(received_data[0], ValueError, "Expected ValueError for corrupted data")
        self.assertIn("MAC check failed", str(received_data[0]), "Expected MAC check failure")

if __name__ == '__main__':
    unittest.main(testRunner=CustomTestRunner(verbosity=2))
