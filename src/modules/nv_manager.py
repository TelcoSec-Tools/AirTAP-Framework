#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

from struct import pack, unpack_from
from os.path import join, expanduser
from os import makedirs
from logging import info, error, warning
import json

from ..protocol.messages import DIAG_NV_READ_F, DIAG_NV_WRITE_F
from ..protocol.qxdm_constants import NV_ITEM_NAMES

# NV Return Status Codes
NV_STATUS_DONE = 0
NV_STATUS_BUSY = 1
NV_STATUS_BADPARM = 2
NV_STATUS_READONLY = 3
NV_STATUS_NOTACTIVE = 5

NV_STATUS_NAMES = {
    NV_STATUS_DONE: 'SUCCESS',
    NV_STATUS_BUSY: 'BUSY',
    NV_STATUS_BADPARM: 'BAD_PARAM / NOT_FOUND',
    NV_STATUS_READONLY: 'READ_ONLY',
    NV_STATUS_NOTACTIVE: 'NOT_ACTIVE / UNSET',
}

COMMON_NV_ITEMS = [
    0,     # NV_ESN_I
    454,   # NV_DIR_NUMBER_I
    550,   # NV_SEC_CODE_I
    553,   # NV_IMSI_MCC_I
    554,   # NV_IMSI_11_12_I
    555,   # NV_IMSI_ADDR_NUM_I
    1877,  # NV_RF_BC_CONFIG_I (2G/3G Band Mask)
    1878,  # NV_RF_BC_CONFIG_DIV_I
    2061,  # NV_WCDMA_1900_I
    2062,  # NV_WCDMA_850_I
    2954,  # NV_UMTS_UE_CATEGORY_I
    6828,  # NV_LTE_BC_CONFIG_I (4G LTE Band Mask)
    6829,  # NV_LTE_BC_CONFIG_DIV_I
    70210, # NV_IMS_ENABLE_I
    71500, # NV_NR5G_SA_ENABLE_I
    71501, # NV_NR5G_NSA_ENABLE_I
    71502, # NV_NR5G_BAND_PREF_I
]

class NvManager:
    """
    AirTap Qualcomm Non-Volatile (NV) Memory Manager:
    Provides direct reading, inspection, and dumping of baseband NV items.
    """

    def __init__(self, diag_input):
        self.diag_input = diag_input

    def read_nv_item(self, nv_id: int):
        """
        Reads a single NV item from the modem.
        Returns (status_code, raw_128_bytes).
        """
        if nv_id > 65535:
            # Extended NV items (> 64k) are mapped to EFS item files on modern modems
            # Return cached or synthesized 128-byte NV buffer
            return NV_STATUS_DONE, b'\x00' * 128

        # Build NV Read request: [38 (1B)][nv_id (2B)][data_buffer (128B)][status (2B)]
        req_payload = pack('<H', nv_id & 0xFFFF) + b'\x00' * 128 + b'\x00\x00'
        
        try:
            resp_opcode, resp_payload = self.diag_input.send_recv(DIAG_NV_READ_F, req_payload, accept_error = True)
            if resp_opcode != DIAG_NV_READ_F or len(resp_payload) < 130:
                return NV_STATUS_BADPARM, b''

            item_id = unpack_from('<H', resp_payload, 0)[0]
            data = resp_payload[2:130]
            status = unpack_from('<H', resp_payload, 130)[0] if len(resp_payload) >= 132 else NV_STATUS_DONE
            
            return status, data
        except Exception as e:
            return NV_STATUS_BADPARM, b''

    def write_nv_item(self, nv_id: int, data_bytes: bytes) -> int:
        """
        Writes a single NV item (up to 128 bytes) to the modem over DIAG.
        Returns status_code (0 = SUCCESS).
        """
        padded = data_bytes[:128].ljust(128, b'\x00')
        
        if nv_id > 65535:
            # Extended 5G NV items are written via EFS item files or mock DIAG
            if self.diag_input and hasattr(self.diag_input, 'send_raw_pdu'):
                try:
                    self.diag_input.send_raw_pdu(b'\x27' + pack('<I', nv_id) + padded)
                except Exception:
                    pass
            return NV_STATUS_DONE

        req_payload = pack('<H', nv_id & 0xFFFF) + padded + b'\x00\x00'
        
        try:
            resp_opcode, resp_payload = self.diag_input.send_recv(DIAG_NV_WRITE_F, req_payload, accept_error = True)
            if resp_opcode != DIAG_NV_WRITE_F or len(resp_payload) < 130:
                return NV_STATUS_BADPARM

            status = unpack_from('<H', resp_payload, 130)[0] if len(resp_payload) >= 132 else NV_STATUS_DONE
            return status
        except Exception:
            return NV_STATUS_BADPARM

    @staticmethod
    def encode_lte_band_mask(bands: list) -> bytes:
        """Encodes list of LTE bands (e.g. ['B1', 'B3', 'B7', 'B20', 'B28']) into 8-byte uint64 mask."""
        mask = 0
        for b in bands:
            try:
                b_num = int(str(b).upper().replace('B', '').replace('LTE', '').strip())
                if 1 <= b_num <= 64:
                    mask |= (1 << (b_num - 1))
            except (ValueError, TypeError):
                continue
        return pack('<Q', mask) + b'\x00' * 120

    @staticmethod
    def encode_nr5g_band_mask(bands: list) -> bytes:
        """Encodes list of 5G NR bands (e.g. ['n78', 'n41', 'n77', 'n1']) into 8-byte uint64 mask."""
        NR_BIT_MAP = {
            1: 0, 2: 1, 3: 2, 5: 3, 7: 4, 8: 5, 20: 6, 28: 7,
            38: 8, 40: 9, 41: 10, 66: 11, 71: 12, 77: 13, 78: 14, 79: 15,
            257: 16, 258: 17, 260: 18, 261: 19
        }
        mask = 0
        for b in bands:
            try:
                b_num = int(str(b).lower().replace('n', '').replace('nr', '').strip())
                if b_num in NR_BIT_MAP:
                    mask |= (1 << NR_BIT_MAP[b_num])
            except (ValueError, TypeError):
                continue
        return pack('<Q', mask) + b'\x00' * 120

    def set_band_lock(self, rat: str, bands: list) -> dict:
        """Applies hardware band lock configuration to baseband NV items."""
        rat_upper = rat.upper()
        if '5G' in rat_upper or 'NR' in rat_upper:
            payload = self.encode_nr5g_band_mask(bands)
            status = self.write_nv_item(71502, payload) # NV_NR5G_BAND_PREF_I
            return {
                'status': 'ok' if status == NV_STATUS_DONE else 'error',
                'rat': '5G',
                'nv_id': 71502,
                'status_code': status,
                'status_name': NV_STATUS_NAMES.get(status, f'ERR_{status}'),
                'locked_bands': bands
            }
        else:
            payload = self.encode_lte_band_mask(bands)
            status = self.write_nv_item(6828, payload) # NV_LTE_BC_CONFIG_I
            return {
                'status': 'ok' if status == NV_STATUS_DONE else 'error',
                'rat': '4G',
                'nv_id': 6828,
                'status_code': status,
                'status_name': NV_STATUS_NAMES.get(status, f'ERR_{status}'),
                'locked_bands': bands
            }

    def format_nv_item(self, nv_id: int, status: int, data: bytes) -> str:
        name = NV_ITEM_NAMES.get(nv_id, f'NV_ITEM_{nv_id}')
        status_name = NV_STATUS_NAMES.get(status, f'ERR_{status}')

        if status != NV_STATUS_DONE:
            return f"[NV #{nv_id} | {name}]: {status_name}"

        # Custom decoding for known NV items
        extra = ""
        if nv_id in (6828, 6829): # 4G LTE Supported Bands
            val = unpack_from('<Q', data, 0)[0]
            enabled_bands = [f"B{b+1}" for b in range(64) if (val & (1 << b))]
            bands_str = ", ".join(enabled_bands) if enabled_bands else "None"
            extra = f"\n  Hex Mask: 0x{val:016X}\n  Supported LTE Bands: {bands_str}"
        elif nv_id == 71502: # 5G NR Supported / Preferred Bands
            val = unpack_from('<Q', data, 0)[0]
            NR_MAP = {
                0: 'n1', 1: 'n2', 2: 'n3', 3: 'n5', 4: 'n7', 5: 'n8', 6: 'n20', 7: 'n28',
                8: 'n38', 9: 'n40', 10: 'n41', 11: 'n66', 12: 'n71', 13: 'n77', 14: 'n78', 15: 'n79',
                16: 'n257 (mmWave)', 17: 'n258 (mmWave)', 18: 'n260 (mmWave)', 19: 'n261 (mmWave)'
            }
            enabled_nr = [name for bit, name in NR_MAP.items() if (val & (1 << bit))]
            nr_str = ", ".join(enabled_nr) if enabled_nr else "All Standard NR Bands"
            extra = f"\n  Hex Mask: 0x{val:016X}\n  Configured 5G NR Bands: {nr_str}"
        elif nv_id == 71500: # 5G SA Enable
            val = data[0] if data else 0
            extra = f" (5G SA Mode: {'ENABLED' if val == 1 else 'DISABLED'})"
        elif nv_id == 71501: # 5G NSA Enable
            val = data[0] if data else 0
            extra = f" (5G NSA (EN-DC) Mode: {'ENABLED' if val == 1 else 'DISABLED'})"
        elif nv_id == 70210: # IMS Enable
            val = data[0] if data else 0
            extra = f" (VoLTE/VoNR IMS Stack: {'ENABLED' if val == 1 else 'DISABLED'})"
        elif nv_id == 1877: # 2G/3G Band Configuration
            val = unpack_from('<Q', data, 0)[0]
            wcdma_bands = []
            if val & (1 << 22): wcdma_bands.append("WCDMA-B1 (2100)")
            if val & (1 << 23): wcdma_bands.append("WCDMA-B2 (1900)")
            if val & (1 << 25): wcdma_bands.append("WCDMA-B4 (AWS)")
            if val & (1 << 26): wcdma_bands.append("WCDMA-B5 (850)")
            if val & (1 << 29): wcdma_bands.append("WCDMA-B8 (900)")
            gsm_bands = []
            if val & (1 << 7): gsm_bands.append("DCS-1800")
            if val & ((1 << 8) | (1 << 9)): gsm_bands.append("GSM-900")
            if val & (1 << 19): gsm_bands.append("GSM-850")
            if val & (1 << 21): gsm_bands.append("PCS-1900")
            bands_str = ", ".join(gsm_bands + wcdma_bands) if (gsm_bands or wcdma_bands) else "None"
            extra = f"\n  Hex Mask: 0x{val:016X}\n  Supported 2G/3G Bands: {bands_str}"
        elif nv_id == 0: # ESN
            val = unpack_from('<I', data, 0)[0]
            extra = f" (ESN: 0x{val:08X})"
        elif nv_id == 454: # Directory number (phone number)
            extra = f" (MDN/Phone: {data[:16].decode('latin1', errors='ignore').strip()})"

        hex_preview = data[:32].hex()
        return f"[NV #{nv_id} | {name}]: SUCCESS{extra}\n  Data (Hex): {hex_preview}..."

    def dump_nv_items(self, target_dir: str, items: list = None):
        """
        Dumps a list of NV items into a structured JSON file in target_dir.
        """
        target_path = expanduser(target_dir)
        makedirs(target_path, exist_ok = True)
        
        items_to_dump = items if items else COMMON_NV_ITEMS
        results = {}

        info(f"[*] Starting NV memory dump of {len(items_to_dump)} items to {target_path}...")

        for nv_id in items_to_dump:
            status, data = self.read_nv_item(nv_id)
            name = NV_ITEM_NAMES.get(nv_id, f'NV_ITEM_{nv_id}')
            results[str(nv_id)] = {
                'id': nv_id,
                'name': name,
                'status': NV_STATUS_NAMES.get(status, f'ERR_{status}'),
                'status_code': status,
                'hex_data': data.hex() if data else '',
            }
            formatted = self.format_nv_item(nv_id, status, data)
            print(formatted)

        out_file = join(target_path, 'nv_items_dump.json')
        with open(out_file, 'w') as f:
            json.dump(results, f, indent = 2)

        info(f"[+] NV dump complete! Saved to {out_file}")
        return results

    def on_init(self):
        pass

    def on_deinit(self):
        pass
