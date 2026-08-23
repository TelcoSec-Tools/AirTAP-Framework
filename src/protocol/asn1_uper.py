#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AirTAP ASN.1 UPER / PER Bit-Stream Engine
==========================================
Fast, pure-Python bit-level stream parser for 3GPP ASN.1 Unaligned Packed
Encoding Rules (UPER - ITU-T X.691 / ISO/IEC 8825-2) used in:
- 5G NR RRC (3GPP TS 38.331)
- 4G LTE RRC (3GPP TS 36.331)
- 3GPP Positioning Protocol (LPP - 3GPP TS 37.355)
- C-V2X PC5 Direct Sidelink RRC
"""

from typing import Tuple, List, Dict, Any, Optional

class BitStream:
    """Bit-level stream reader for ASN.1 UPER decoding."""
    
    def __init__(self, data: bytes):
        self.data = data
        self.byte_len = len(data)
        self.bit_len = self.byte_len * 8
        self.bit_offset = 0

    @property
    def remaining_bits(self) -> int:
        return max(0, self.bit_len - self.bit_offset)

    @property
    def has_bits(self) -> bool:
        return self.bit_offset < self.bit_len

    def read_bit(self) -> int:
        """Reads a single bit (0 or 1)."""
        if self.bit_offset >= self.bit_len:
            return 0
        byte_idx = self.bit_offset >> 3
        bit_idx = 7 - (self.bit_offset & 7)
        self.bit_offset += 1
        return (self.data[byte_idx] >> bit_idx) & 1

    def read_bits(self, n: int) -> int:
        """Reads n bits as an unsigned integer (MSB first). Clamped to remaining bits and max 64 bits."""
        if n <= 0 or not self.has_bits:
            return 0
        n_safe = min(n, 64, self.remaining_bits)
        val = 0
        for _ in range(n_safe):
            val = (val << 1) | self.read_bit()
        return val

    def read_bytes(self, n_bytes: int) -> bytes:
        """Reads n bytes from current bit position."""
        if n_bytes <= 0 or not self.has_bits:
            return b""
        safe_bytes = min(n_bytes, 4096, self.remaining_bits // 8)
        res = bytearray()
        for _ in range(safe_bytes):
            res.append(self.read_bits(8))
        return bytes(res)

    def read_constrained_int(self, min_val: int, max_val: int) -> int:
        """Decodes constrained whole number [min_val .. max_val]."""
        range_val = max_val - min_val
        if range_val <= 0:
            return min_val
        
        # Calculate number of bits required for range_val
        bits_needed = min(64, (range_val).bit_length())
        val = self.read_bits(bits_needed)
        return min_val + val

    def read_semi_constrained_int(self, min_val: int) -> int:
        """Decodes semi-constrained whole number [min_val .. infinity]."""
        length = min(self.read_length(), 8)
        val = self.read_bits(length * 8)
        return min_val + val

    def read_unconstrained_int(self) -> int:
        """Decodes unconstrained 2's complement integer."""
        length = min(self.read_length(), 8)
        if length <= 0:
            return 0
        raw = self.read_bits(length * 8)
        # Sign extend
        if raw & (1 << (length * 8 - 1)):
            raw -= (1 << (length * 8))
        return raw

    def read_enumerated(self, num_root_values: int, is_extensible: bool = False) -> Tuple[int, bool]:
        """
        Decodes ASN.1 ENUMERATED type.
        Returns: (enum_index, is_extension)
        """
        if is_extensible:
            ext_bit = self.read_bit()
            if ext_bit == 1:
                # Extension addition present
                ext_val = self.read_small_int()
                return (min(ext_val + num_root_values, 128), True)
        
        if num_root_values <= 1:
            return (0, False)
        
        bits_needed = min(32, (num_root_values - 1).bit_length())
        val = self.read_bits(bits_needed)
        return (min(val, num_root_values - 1), False)

    def read_choice_index(self, num_root_choices: int, is_extensible: bool = False) -> Tuple[int, bool]:
        """Decodes CHOICE selection index."""
        if is_extensible:
            ext_bit = self.read_bit()
            if ext_bit == 1:
                ext_idx = self.read_small_int()
                return (min(ext_idx + num_root_choices, 128), True)
        
        if num_root_choices <= 1:
            return (0, False)
        
        bits_needed = min(32, (num_root_choices - 1).bit_length())
        return (min(self.read_bits(bits_needed), 128), False)

    def read_length(self) -> int:
        """Decodes unconstrained length determinant in UPER."""
        first_bit = self.read_bit()
        if first_bit == 0:
            return self.read_bits(7)
        second_bit = self.read_bit()
        if second_bit == 0:
            return min(((first_bit << 6) | self.read_bits(6)) << 8 | self.read_bits(8), 4096)
        # Large length chunking (>= 16k)
        return min(self.read_bits(6) * 16384, 65536)

    def read_small_int(self) -> int:
        """Decodes normally small non-negative whole number."""
        bit = self.read_bit()
        if bit == 0:
            return self.read_bits(6)
        else:
            length = min(self.read_length(), 4)
            return self.read_bits(length * 8)

    def read_bit_string(self, fixed_length: Optional[int] = None) -> str:
        """Decodes BIT STRING as binary string '0101...'."""
        length = fixed_length if fixed_length is not None else self.read_length()
        bits = []
        for _ in range(min(length, self.remaining_bits)):
            bits.append(str(self.read_bit()))
        return "".join(bits)

    def read_octet_string(self, min_len: int = 0, max_len: Optional[int] = None) -> bytes:
        """Decodes OCTET STRING."""
        if max_len is not None and min_len == max_len and max_len <= 2:
            return self.read_bytes(max_len)
        length = self.read_length()
        return self.read_bytes(length)
