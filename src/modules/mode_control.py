#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

from struct import pack
from logging import info, error

from ..protocol.messages import DIAG_CONTROL_F

MODE_OFFLINE_D_F = 1
MODE_RESET_F = 2
MODE_POWER_OFF_F = 4

MODE_NAMES = {
    MODE_OFFLINE_D_F: 'OFFLINE',
    MODE_RESET_F: 'RESET',
    MODE_POWER_OFF_F: 'POWER_OFF',
}

class ModeController:
    """
    AirTap Qualcomm Baseband Mode Controller:
    Sends hardware control commands (Offline, Reset, Power Off) to the modem.
    """

    def __init__(self, diag_input):
        self.diag_input = diag_input

    def switch_mode(self, mode: int):
        mode_name = MODE_NAMES.get(mode, f'MODE_{mode}')
        info(f"[*] Sending baseband mode command: {mode_name} (opcode 41, mode {mode})...")

        req_payload = pack('<H', mode)
        try:
            resp_opcode, resp_payload = self.diag_input.send_recv(DIAG_CONTROL_F, req_payload, accept_error = True)
            if resp_opcode == DIAG_CONTROL_F:
                info(f"[+] Baseband successfully switched to {mode_name} mode.")
                return True
            else:
                error(f"[-] Baseband rejected mode command {mode_name} (resp opcode: {resp_opcode})")
                return False
        except Exception as e:
            error(f"[-] Failed to execute mode command: {e}")
            return False

    def on_init(self):
        pass

    def on_deinit(self):
        pass
