#!/usr/bin/python3
#-*- encoding: Utf-8 -*-
from struct import pack, unpack_from, calcsize
from logging import warning, info
from ..protocol.log_types import *
from ..protocol.messages import *
from time import sleep

"""
    This module exposes a class from which a module may inherit in order to
    enable logging packets.
"""

"""
    Definitions:

    * A "log" is a packet containing debugging information sent asynchronously
      through Diag by the baseband, as a raw binary structure, at the condition
      that the user has registered interest for this log or category of logs.

    * A "log code" is a 16-bit value referencing a specific binary structure
      that may be send through a log. Example: WCDMA_SIGNALLING_MESSAGE (0x412f)
      contains raw 3G signalling packets, with a small proprietary header.
    
    * A "log type" is the made up of the high 4-bits of the "log code", and
      encompass a broad range of logs. Example: WCDMA (0x4) for 3G-related logs.
    
    The user may register interest in log codes using a large bit mask, that
    is what this module does.
"""

LOG_CONFIG_RETRIEVE_ID_RANGES_OP = 1
LOG_CONFIG_SET_MASK_OP = 3

LOG_CONFIG_SUCCESS_S = 0

"""
    The following list enumerate log types used by the --pcap-dump and
    --json-geo-dump modules, and is used to restrict the quantity of logs
    that AirTap registers to the baseband device (otherwise the volume of
    logs could be huge and it would be good to avoid potential performance
    impact on untested environment).

    Before you add a new start using a new log type in this module, be sure
    to add it to the list below.
"""

TYPES_FOR_RAW_PACKET_LOGGING = [
    # 2G (GSM & GPRS):
    LOG_GSM_RR_SIGNALING_MESSAGE_C,       # 0x512f
    LOG_GSM_SACCH_C,                      # 0x5134
    LOG_GSM_CELL_BROADCAST_C,             # 0x5130
    LOG_GPRS_MAC_SIGNALLING_MESSAGE_C,    # 0x5226
    LOG_GPRS_RLC_UL_COMMAND_C,            # 0x520a
    LOG_GPRS_RLC_DL_COMMAND_C,            # 0x520b
    LOG_GPRS_LLC_ME_LOG_PACKET_C,         # 0x5215
    LOG_GPRS_SNDCP_PDU_C,                 # 0x521e
    LOG_SIM_APDU_LOG_C,                   # 0x1188

    # 3G (UMTS & WCDMA):
    WCDMA_SIGNALLING_MESSAGE,             # 0x412f
    LOG_UMTS_CELL_BROADCAST_C,            # 0x4130
    LOG_UMTS_NAS_OTA_MESSAGE_LOG_PACKET_C,# 0x713a
    LOG_WCDMA_CELL_ID_C,                  # 0x4005

    # 4G (LTE):
    LOG_LTE_RRC_OTA_MSG_LOG_C,            # 0xb0c0
    LOG_LTE_RRC_RADIO_RESOURCE_CONFIG_C,  # 0xb0c1
    LOG_LTE_RRC_ETWS_CMAS_LOG_C,          # 0xb0c4
    LOG_LTE_CALEA_TRACE_LOG_C,            # 0xb0c3
    LOG_LTE_NAS_ESM_OTA_IN_MSG_LOG_C,     # 0xb0e0
    LOG_LTE_NAS_ESM_OTA_OUT_MSG_LOG_C,    # 0xb0e1
    LOG_LTE_NAS_EMM_OTA_IN_MSG_LOG_C,     # 0xb0e2
    LOG_LTE_NAS_EMM_OTA_OUT_MSG_LOG_C,    # 0xb0e3
    LOG_LTE_NAS_EMM_SEC_OTA_IN_MSG_LOG_C, # 0xb0ec
    LOG_LTE_NAS_EMM_SEC_OTA_OUT_MSG_LOG_C,# 0xb0ed
    LOG_LTE_SERVING_CELL_INFO_C,          # 0xb193
    LOG_LTE_ML1_SERVING_CELL_MEAS_C,      # 0xb173

    # 5G (NR):
    LOG_NR_RRC_OTA_MSG_LOG_C,             # 0xb821
    LOG_NR_RRC_RADIO_RESOURCE_CONFIG_C,   # 0xb822
    LOG_NR_RRC_ETWS_CMAS_LOG_C,           # 0xb825
    LOG_NR_CALEA_TRACE_LOG_C,             # 0xb830
    LOG_NR_NAS_5GMM_OTA_IN_MSG_LOG_C,     # 0xb800
    LOG_NR_NAS_5GMM_OTA_OUT_MSG_LOG_C,     # 0xb801
    LOG_NR_NAS_5GSM_OTA_IN_MSG_LOG_C,     # 0xb802
    LOG_NR_NAS_5GSM_OTA_OUT_MSG_LOG_C,     # 0xb803
    LOG_NR_MAC_PDU_LOG_C,                 # 0xb808
    LOG_NR_MAC_RACH_TRIGGER_LOG_C,        # 0xb80a
    LOG_NR_SDAP_PDU_LOG_C,                # 0xb826
    LOG_NR_ML1_SERVING_CELL_BEAM_C,       # 0xb97f

    # IMS / SIP Signaling:
    LOG_LTE_IMS_SIP_MSG_C,                # 0x156e
    LOG_NR_IMS_SIP_MSG_C,                 # 0xb832
    LOG_IMS_SIP_MSG_C,                    # 0x1570
    LOG_IMS_REGISTRATION_C,               # 0x156f
    LOG_IMS_CONFIG_C,                     # 0x1570

    # User Plane IP Data:
    LOG_DATA_PROTOCOL_LOGGING_C           # 0x11eb
]

RAT_TO_LOG_CODES = {
    '2g': [
        LOG_GSM_RR_SIGNALING_MESSAGE_C,
        LOG_GSM_SACCH_C,
        LOG_GSM_CELL_BROADCAST_C,
        LOG_GPRS_MAC_SIGNALLING_MESSAGE_C,
        LOG_GPRS_RLC_UL_COMMAND_C,
        LOG_GPRS_RLC_DL_COMMAND_C,
        LOG_GPRS_LLC_ME_LOG_PACKET_C,
        LOG_GPRS_SNDCP_PDU_C,
    ],
    '3g': [
        WCDMA_SIGNALLING_MESSAGE,
        LOG_UMTS_CELL_BROADCAST_C,
        LOG_UMTS_NAS_OTA_MESSAGE_LOG_PACKET_C,
    ],
    '4g': [
        LOG_LTE_RRC_OTA_MSG_LOG_C,
        LOG_LTE_RRC_RADIO_RESOURCE_CONFIG_C,
        LOG_LTE_RRC_ETWS_CMAS_LOG_C,
        LOG_LTE_CALEA_TRACE_LOG_C,
        LOG_LTE_NAS_ESM_OTA_IN_MSG_LOG_C,
        LOG_LTE_NAS_ESM_OTA_OUT_MSG_LOG_C,
        LOG_LTE_NAS_EMM_OTA_IN_MSG_LOG_C,
        LOG_LTE_NAS_EMM_OTA_OUT_MSG_LOG_C,
    ],
    '5g': [
        LOG_NR_RRC_OTA_MSG_LOG_C,
        LOG_NR_RRC_RADIO_RESOURCE_CONFIG_C,
        LOG_NR_RRC_ETWS_CMAS_LOG_C,
        LOG_NR_SDAP_PDU_LOG_C,
        LOG_NR_CALEA_TRACE_LOG_C,
        LOG_NR_MAC_PDU_LOG_C,
        LOG_NR_MAC_RACH_TRIGGER_LOG_C,
        LOG_NR_NAS_5GMM_OTA_IN_MSG_LOG_C,
        LOG_NR_NAS_5GMM_OTA_OUT_MSG_LOG_C,
        LOG_NR_NAS_5GSM_OTA_IN_MSG_LOG_C,
        LOG_NR_NAS_5GSM_OTA_OUT_MSG_LOG_C,
    ],
}
RAT_TO_LOG_CODES['gsm'] = RAT_TO_LOG_CODES['2g']
RAT_TO_LOG_CODES['umts'] = RAT_TO_LOG_CODES['3g']
RAT_TO_LOG_CODES['wcdma'] = RAT_TO_LOG_CODES['3g']
RAT_TO_LOG_CODES['lte'] = RAT_TO_LOG_CODES['4g']
RAT_TO_LOG_CODES['nr'] = RAT_TO_LOG_CODES['5g']

class EnableLogMixin:
    
    def on_init(self):
        
        # Apply filters if specified on diag_input or self
        filter_rat = getattr(self.diag_input, 'filter_rat', None) or getattr(self, 'filter_rat', None)
        filter_logs = getattr(self.diag_input, 'filter_logs', None) or getattr(self, 'filter_logs', None)

        # Avoid redundant reconfiguration if another module has already configured the log mask
        if getattr(self.diag_input, '_active_log_mask_configured', False) and not filter_logs and not filter_rat:
            return
        if self.diag_input is not None:
            setattr(self.diag_input, '_active_log_mask_configured', True)

        if filter_logs:
            allowed = set(filter_logs)
            if hasattr(self, 'limit_registered_logs'):
                self.limit_registered_logs = [x for x in self.limit_registered_logs if x in allowed]
            else:
                self.limit_registered_logs = list(allowed)
        elif filter_rat:
            allowed = set()
            for rat in filter_rat:
                allowed.update(RAT_TO_LOG_CODES.get(str(rat).lower().strip(), []))
            if hasattr(self, 'limit_registered_logs'):
                self.limit_registered_logs = [x for x in self.limit_registered_logs if x in allowed]
            else:
                self.limit_registered_logs = list(allowed)

        self.log_type_to_mask_bitsize = {}
        
        # Send the message for receiving the highest valid log code for
        # each existing log type (see defintions above).
        
        opcode, payload = self.diag_input.send_recv(DIAG_LOG_CONFIG_F, pack('<3xI', LOG_CONFIG_RETRIEVE_ID_RANGES_OP))
        
        header_spec = '<3xII'
        operation, status = unpack_from(header_spec, payload)
        
        assert operation == LOG_CONFIG_RETRIEVE_ID_RANGES_OP
        
        if status != LOG_CONFIG_SUCCESS_S:
            
            warning('Warning: log operation %d resulted in status %d' % (operation, status))
        
        log_masks = unpack_from('<16I', payload, calcsize(header_spec))
        
        # Iterate on information contained in the packet for each log type
        
        log_types = {
            0x1: '1X',
            0x4: 'WCDMA',
            0x5: 'GSM',
            0x6: 'LBS',
            0x7: 'UMTS',
            0x8: 'TDMA',
            0xA: 'DTV',
            0xB: 'APPS/LTE/WIMAX',
            0xC: 'DSP',
            0xD: 'TDSCDMA',
            0xF: 'TOOLS'
        }
        
        information_string = 'Enabled logging for: '
        
        for log_type, log_mask_bitsize in enumerate(log_masks):
            
            # Register logging for each supported log type
            
            if log_mask_bitsize:
                
                self.log_type_to_mask_bitsize[log_type] = log_mask_bitsize
                
                log_mask = self._fill_log_mask(log_type, log_mask_bitsize)
                
                opcode, payload = self.diag_input.send_recv(DIAG_LOG_CONFIG_F, pack('<3xIII',
                    LOG_CONFIG_SET_MASK_OP,
                    log_type,
                    log_mask_bitsize
                ) + log_mask)

                operation, status = unpack_from(header_spec, payload)
                
                assert operation == LOG_CONFIG_SET_MASK_OP
                
                if status != LOG_CONFIG_SUCCESS_S:
                    
                    warning('Warning: log operation %d resulted in status %d' % (operation, status))
                
                information_string += '%s (%d), ' % (log_types.get(log_type, 'UNKNOWN'), log_type)
        
        info(information_string.strip(', '))
    
    def _fill_log_mask(self, log_type, num_bits, bit_value = 1):
        
        log_mask = b''
        
        current_byte = 0
        num_bits_written = 0
        
        for i in range(num_bits):
            
            enable_this_log_type = True
            
            # limit_registered_logs: When set by a module inheriting this
            # class, this attribute may instruct to limit the logs to register
            # interest for a restricted set of log codes, in order to limit the
            # bulk of data sent from the device to the Diag client.
            
            if (hasattr(self, 'limit_registered_logs') and
                ((log_type << 12) | i) not in self.limit_registered_logs):
                
                enable_this_log_type = False
            
            current_byte |= (bit_value & enable_this_log_type) << num_bits_written
            num_bits_written += 1
            
            if num_bits_written == 8 or i == num_bits - 1:
                
                log_mask += bytes([current_byte])
                
                current_byte = 0
                num_bits_written = 0
        
        return log_mask
    
    def on_deinit(self):
        
        try:
            for log_type, log_mask_bitsize in getattr(self, 'log_type_to_mask_bitsize', {}).items():
                
                log_mask = self._fill_log_mask(log_type, log_mask_bitsize, bit_value = 0)
                
                self.diag_input.send_recv(DIAG_LOG_CONFIG_F, pack('<3xIII',
                    LOG_CONFIG_SET_MASK_OP,
                    log_type,
                    log_mask_bitsize
                ) + log_mask, accept_error = True)
        except Exception:
            pass

