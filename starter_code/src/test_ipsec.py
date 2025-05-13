import unittest
import threading
import time
from messenger import MessengerClient, send_via_simulated_ipsec, receive_via_simulated_ipsec

class TestIPsec(unittest.TestCase):
    def setUp(self):
        # Initialize a dummy MessengerClient instance
        self.client = MessengerClient(b"dummy_ca_key")
        self.bind_ip = "127.0.0.1"
        self.bind_port = 12345
        self.dest_ip = "127.0.0.1"
        self.dest_port = 12345

    def test_send_receive_ipsec(self):
        # Test data to send
        test_data = b"Hello, IPsec!"
        
        # Create a thread to run the receiver
        received_data = [None]  # Store received data
        def receive():
            try:
                received_data[0] = receive_via_simulated_ipsec(self.bind_ip, self.bind_port)
            except Exception as e:
                received_data[0] = e

        receiver_thread = threading.Thread(target=receive)
        receiver_thread.daemon = True
        receiver_thread.start()

        # Wait briefly to ensure receiver is listening
        time.sleep(0.1)

        # Send the data
        send_via_simulated_ipsec(self.dest_ip, self.dest_port, test_data)

        # Wait for receiver to complete
        receiver_thread.join(timeout=2.0)

        # Check if data was received correctly
        self.assertIsNotNone(received_data[0], "No data received")
        self.assertNotIsInstance(received_data[0], Exception, f"Receiver raised an exception: {received_data[0]}")
        self.assertEqual(received_data[0], test_data, "Received data does not match sent data")

if __name__ == '__main__':
    unittest.main()
