#!/usr/bin/python3
import unittest
import socket
import threading
import time
from src.inputs.tcp_connector import TcpConnector

class TcpConnectorTests(unittest.TestCase):

    def test_invalid_argument_formatting(self):
        with self.assertRaises(ValueError):
            TcpConnector("invalid_no_colon")

        with self.assertRaises(ValueError):
            TcpConnector("127.0.0.1:abc")

    def test_tcp_connector_reconnect_failure(self):
        # Connecting to a non-existent port should handle connection failure cleanly
        connector = TcpConnector("127.0.0.1:59999")
        connector.max_reconnect_attempts = 1
        connector.reconnect_delay = 0.05
        self.assertFalse(connector._reconnect())

    def test_tcp_connector_mock_server(self):
        # Start a local TCP echo mock server
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('127.0.0.1', 0))
        server.listen(1)
        port = server.getsockname()[1]

        def handle_client():
            conn, _ = server.accept()
            # Send HDLC framed DIAG dummy packet (opcode 0x00) with CRC and trailer 0x7E
            hdlc_frame = b'\x7e\x00\x00\x00\x7e'
            conn.sendall(hdlc_frame)
            time.sleep(0.1)
            conn.close()
            server.close()

        server_thread = threading.Thread(target=handle_client)
        server_thread.daemon = True
        server_thread.start()

        connector = TcpConnector(f"127.0.0.1:{port}")
        self.assertIsNotNone(connector.socket)

        # Run read loop in a short background step
        read_thread = threading.Thread(target=connector.read_loop)
        read_thread.daemon = True
        read_thread.start()

        time.sleep(0.3)
        connector.program_is_terminating = True
        connector.dispose()

if __name__ == '__main__':
    unittest.main()
