#!/usr/bin/python3
#-*- encoding: utf-8 -*-
from struct import pack, unpack, unpack_from, calcsize
from logging import debug, info, warning, error
from crcmod import mkCrcFun
from time import time

from ..protocol.messages import get_message_name

"""
    This class implements the pseudo-HDLC framing using for the Qualcomm Diag
    protocol.
"""

class HdlcMixin:

    ESCAPE_CHAR = b'\x7d'
    TRAILER_CHAR = b'\x7e'

    ESC_ESC = b'\x7d\x5d'
    ESC_TRAILER = b'\x7d\x5e'

    ccitt_crc16 = staticmethod(
        mkCrcFun(0x11021, initCrc=0, xorOut=0xffff)
    )

    """
        Utility function to add CRC + escape the message + add the trailer
        
        :param payload: A raw payload to be encapsulated
    """

    def hdlc_encapsulate(self, payload: bytes) -> bytes:
        if payload:
            debug('[>] Sending request %s of length %d: %s' % (get_message_name(payload[0]), len(payload[1:]), payload[1:]))
        
        # Calculate and append CRC16
        crc_payload = payload + pack('<H', self.ccitt_crc16(payload))
        
        # Fast byte replacement using pre-compiled constants
        escaped_payload = crc_payload.replace(self.ESCAPE_CHAR, self.ESC_ESC).replace(self.TRAILER_CHAR, self.ESC_TRAILER)
        
        return escaped_payload + self.TRAILER_CHAR

    """
        Utility function to decode the reverse way
        
        :param payload: An encapsulated payload to be made raw
        :raises InvalidFrameError: Used to signal to the caller through
            an Exception that a packet that is too short or with an invalid
            CRC-16 was received, along with a warning
    """

    def hdlc_decapsulate(self, payload: bytes) -> bytes:
        if len(payload) < 3:
            error('Too short Diag frame received')
            raise self.InvalidFrameError
        
        # Remove trailer if present
        if payload[-1:] == self.TRAILER_CHAR:
            payload = payload[:-1]
        
        # Fast byte unescaping using pre-compiled constants
        raw_message = payload.replace(self.ESC_TRAILER, self.TRAILER_CHAR).replace(self.ESC_ESC, self.ESCAPE_CHAR)
        
        if len(raw_message) < 2:
            error('Too short Diag frame received')
            raise self.InvalidFrameError

        calculated_crc = self.ccitt_crc16(raw_message[:-2])
        received_crc = unpack('<H', raw_message[-2:])[0]
        
        if received_crc != calculated_crc:
            warning('Ignoring (partial?) frame: Wrong CRC: %s (is: %04x, should be: %04x)' % (
                repr(raw_message[:-2]),
                received_crc,
                calculated_crc
            ))
            raise self.InvalidFrameError

        return raw_message[:-2]
    
    class InvalidFrameError(Exception):
        
        pass


