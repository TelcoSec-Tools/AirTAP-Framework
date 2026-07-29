#!/usr/bin/python3
#-*- encoding: Utf-8 -*-
from socket import socket, AF_INET, SOCK_STREAM, timeout as SocketTimeout
from logging import debug, error, info, warning
from time import sleep

from ._hdlc_mixin import HdlcMixin
from ._base_input import BaseInput

"""
    This class implements reading Qualcomm DIAG data from a remote TCP service.
"""

class TcpConnector(HdlcMixin, BaseInput):
    
    def __init__(self, args: str):
        super().__init__()
        
        self.address = None
        self.port = None
        self.socket = None
        self.received_first_packet = False
        self.packet_buffer = b''
        self.max_reconnect_attempts = 5
        self.reconnect_delay = 2.0
        
        self._parse_args(args)
        self._connect()
        
    def _parse_args(self, args: str):
        if not args or ':' not in args:
            error('Invalid TCP address format. Expected IP_ADDRESS:TCP_PORT (e.g., 127.0.0.1:9999)')
            raise ValueError('Invalid TCP connector argument')

        parts = args.split(':')
        if len(parts) != 2 or not parts[1].isdigit():
            error('Invalid TCP port specified. Port must be a valid integer.')
            raise ValueError('Invalid TCP connector port')

        self.address = parts[0].strip()
        self.port = int(parts[1])

    def _connect(self) -> bool:
        if self.socket:
            try:
                self.socket.close()
            except Exception:
                pass

        self.socket = socket(AF_INET, SOCK_STREAM)
        self.socket.settimeout(5.0)

        try:
            info('Connecting to remote DIAG TCP service at %s:%d...' % (self.address, self.port))
            self.socket.connect((self.address, self.port))
            info('Successfully connected to DIAG TCP service at %s:%d' % (self.address, self.port))
            return True
        except Exception as e:
            warning('Failed to connect to %s:%d: %s' % (self.address, self.port, str(e)))
            return False

    def send_request(self, packet_type, packet_payload):
        if not self.socket:
            error('Cannot send request: TCP socket is not connected.')
            return

        raw_payload = self.hdlc_encapsulate(bytes([packet_type]) + packet_payload)
        try:
            self.socket.sendall(raw_payload)
        except (BrokenPipeError, OSError) as e:
            error('Error sending DIAG request over TCP: %s' % str(e))
    
    def read_loop(self):
        while not self.program_is_terminating:
            try:
                while self.TRAILER_CHAR not in self.packet_buffer:
                    if self.program_is_terminating:
                        return

                    try:
                        socket_read = self.socket.recv(1024 * 1024)
                    except SocketTimeout:
                        continue
                    except (OSError, ConnectionResetError) as e:
                        warning('TCP read error: %s' % str(e))
                        socket_read = b''

                    if not socket_read:
                        # Remote side closed connection or socket read error
                        if not self._reconnect():
                            error('TCP connection lost and reconnect failed. Exiting read loop.')
                            return
                        continue

                    self.packet_buffer += socket_read

                while self.TRAILER_CHAR in self.packet_buffer:
                    raw_payload, self.packet_buffer = self.packet_buffer.split(self.TRAILER_CHAR, 1)

                    try:
                        unframed_message = self.hdlc_decapsulate(
                            payload = raw_payload + self.TRAILER_CHAR
                        )
                    except self.InvalidFrameError:
                        continue
                    finally:
                        self.received_first_packet = True

                    self.dispatch_received_diag_packet(unframed_message)

            except Exception as e:
                if self.program_is_terminating:
                    return
                error('Unexpected exception in TCP read loop: %s' % str(e))
                if not self._reconnect():
                    return

    def _reconnect(self) -> bool:
        for attempt in range(1, self.max_reconnect_attempts + 1):
            if self.program_is_terminating:
                return False
            info('Attempting TCP reconnect (%d/%d)...' % (attempt, self.max_reconnect_attempts))
            if self._connect():
                return True
            sleep(self.reconnect_delay)

        return False

    def dispose(self, disposing=True):
        if self.socket:
            try:
                self.socket.close()
            except Exception:
                pass
            self.socket = None

    def __del__(self):
        self.dispose(disposing=False)

    
