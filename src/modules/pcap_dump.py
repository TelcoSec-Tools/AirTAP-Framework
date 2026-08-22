#!/usr/bin/python3
#-*- encoding: Utf-8 -*-
import os
from struct import pack, unpack, unpack_from, calcsize
from subprocess import Popen, PIPE, DEVNULL, STDOUT
from os.path import expandvars, dirname, realpath, join, exists
from os import makedirs, getenv, listdir, walk
from traceback import print_exc
from shutil import copy2, which
from logging import warning
from sys import platform
from glob import glob
import gzip

from ..modules._enable_log_mixin import EnableLogMixin, TYPES_FOR_RAW_PACKET_LOGGING
from ..modules.decoded_sibs_dump import DecodedSibsDumper

MODULES_DIR = realpath(dirname(__file__))
SRC_WIRESHARK_PLUGIN_DIR = realpath(MODULES_DIR + '/wireshark_plugin')


try:
    from os import setpgrp, getenv, setresgid, setresuid, setgroups, getgrouplist
    from pwd import getpwuid
    IS_UNIX = True

except Exception:
    IS_UNIX = False

from ..protocol.log_types import *
from ..protocol.gsmtap import *

"""
    This module registers various diag LOG events, and tries to generate a
    PCAP of GSMTAP 2G, 3G, 4G or 5G frames from it.
    
    5G frames shall be decoded from a .PCAP or .DLF file only if
    the AirTap Wireshark plugin is installed or loaded.
"""

class PcapDumper(DecodedSibsDumper):
    
    def __init__(self, diag_input, pcap_file, reassemble_sibs = True, decrypt_nas = True, include_ip_traffic = True):
        
        self.pcap_file = pcap_file
        
        """
            Write a PCAP file header - https://wiki.wireshark.org/Development/LibpcapFileFormat#File_Format
        """
        
        if not getattr(self.pcap_file, 'appending_to_file', False):
            
            self.pcap_file.write(pack('<IHHi4xII',
                0xa1b2c3d4, # PCAP Magic
                2, 4, # Version
                0, # Timezone
                65535, # Max packet length
                228 # LINKTYPE_IPV4 (for GSMTAP)
            ))

            self.pcap_file.flush()

        self.packets_since_flush = 0

        self.diag_input = diag_input
        
        self.limit_registered_logs = TYPES_FOR_RAW_PACKET_LOGGING
        
        self.current_rat = None # Radio access technology: "2g", "3g", "4g", "5g"
        
        self.reassemble_sibs = reassemble_sibs
        self.decrypt_nas = decrypt_nas
        self.include_ip_traffic = include_ip_traffic
        
        # Install the AirTap Lua Wireshark plug-in, except if the
        # corresponding environment variable is set.
        
        self.install_wireshark_plugin()
    
    def install_wireshark_plugin(self):
        
        # See: https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html
        # See: https://docs.python.org/3/library/os.path.html#os.path.expandvars
        # See: https://docs.python.org/3/library/sys.html#sys.platform
        
        if getenv('DONT_INSTALL_WIRESHARK_PLUGIN'):
            
            return
        
        if platform in ('win32', 'cygwin'):
            
            DST_WIRESHARK_PLUGIN_DIR = expandvars('%APPDATA%\\Wireshark\\plugins')
        
        else:
            
            DST_WIRESHARK_PLUGIN_DIR = expandvars('$HOME/.local/lib/wireshark/plugins')
        
        if '%' in DST_WIRESHARK_PLUGIN_DIR or '$' in DST_WIRESHARK_PLUGIN_DIR:
            return # Variable expansion did not work
        
        try:
            makedirs(DST_WIRESHARK_PLUGIN_DIR, exist_ok = True)
            
            # Clean old loose root .lua files to prevent duplicate loading
            for f in listdir(DST_WIRESHARK_PLUGIN_DIR):
                if f.endswith('.lua'):
                    try:
                        os.remove(join(DST_WIRESHARK_PLUGIN_DIR, f))
                    except Exception:
                        pass

            telcosec_dst = join(DST_WIRESHARK_PLUGIN_DIR, 'telcosec')
            makedirs(telcosec_dst, exist_ok=True)
            
            for file_name in listdir(SRC_WIRESHARK_PLUGIN_DIR):
                if file_name.endswith('.lua'):
                    copy2(join(SRC_WIRESHARK_PLUGIN_DIR, file_name),
                          join(telcosec_dst, file_name))
        except OSError:
            return # Could not create or write to the Wireshark plug-in directory, non-fatal
        
    
    """
        Process a single log packet containing raw signalling or data traffic,
        to be encapsulated into GSMTAP and append to the PCAP
    """
    
    def on_log(self, log_type, log_payload, log_header, timestamp = 0):
        
        packet = None
        
        if log_type == WCDMA_SIGNALLING_MESSAGE: # 0x412f
            
            self.current_rat = '3g'
            
            (channel_type, radio_bearer, length), signalling_message = unpack('<BBH', log_payload[:4]), log_payload[4:]
            
            is_uplink = channel_type in (
                RRCLOG_SIG_UL_CCCH,
                RRCLOG_SIG_UL_DCCH
            )
            
            # GSMTAP definition:
            # - https://github.com/wireshark/wireshark/blob/wireshark-2.5.0/epan/dissectors/packet-gsmtap.h
            # - http://osmocom.org/projects/baseband/wiki/GSMTAP
            
            # RRC channel types:
            # - https://github.com/fgsect/scat/blob/0e1d3a4/parsers/qualcomm/diagwcdmalogparser.py#L259
            
            if channel_type in (254, 255, 0x89, 0xF0, RRCLOG_EXTENSION_SIB, RRCLOG_SIB_CONTAINER):
                return # Frames containing only a MIB or extension SIB, as already present in RRC frames, ignoring
            
            if channel_type >= 0x80: # We are in presence of an explicit ARFCN/PSC
                channel_type -= 0x80
                signalling_message = signalling_message[4:]
            
            packet = signalling_message[:length]
            
            gsmtap_channel_type = {
                RRCLOG_SIG_UL_CCCH: GSMTAP_RRC_SUB_UL_CCCH_Message,
                RRCLOG_SIG_UL_DCCH: GSMTAP_RRC_SUB_UL_DCCH_Message,
                RRCLOG_SIG_DL_CCCH: GSMTAP_RRC_SUB_DL_CCCH_Message,
                RRCLOG_SIG_DL_DCCH: GSMTAP_RRC_SUB_DL_DCCH_Message,
                RRCLOG_SIG_DL_BCCH_BCH: GSMTAP_RRC_SUB_BCCH_BCH_Message,
                RRCLOG_SIG_DL_BCCH_FACH: GSMTAP_RRC_SUB_BCCH_FACH_Message,
                RRCLOG_SIG_DL_PCCH: GSMTAP_RRC_SUB_PCCH_Message,
                RRCLOG_SIG_DL_MCCH: GSMTAP_RRC_SUB_MCCH_Message,
                RRCLOG_SIG_DL_MSCH: GSMTAP_RRC_SUB_MSCH_Message
            }.get(channel_type)
            
            if gsmtap_channel_type is None:
                
                warning('Unknown log type received for WCDMA_SIGNALLING_MESSAGE: %d' % channel_type)
                return
            
            packet = build_gsmtap_ip(GSMTAP_TYPE_UMTS_RRC, gsmtap_channel_type, packet, is_uplink)
        
        elif log_type == LOG_GSM_RR_SIGNALING_MESSAGE_C: # 0x512f
            
            self.current_rat = '2g'
            
            (channel_type, message_type, length), signalling_message = unpack('<BBB', log_payload[:3]), log_payload[3:]
            
            packet = signalling_message[:length]
            
            is_uplink = not bool(channel_type & 0x80)
            
            # GSMTAP definition:
            # - https://github.com/wireshark/wireshark/blob/wireshark-2.5.0/epan/dissectors/packet-gsmtap.h
            # - http://osmocom.org/projects/baseband/wiki/GSMTAP
            
            gsmtap_channel_type = {
                DCCH: GSMTAP_CHANNEL_SDCCH,
                BCCH: GSMTAP_CHANNEL_BCCH,
                L2_RACH: GSMTAP_CHANNEL_RACH,
                CCCH: GSMTAP_CHANNEL_CCCH,
                SACCH: GSMTAP_CHANNEL_SDCCH | GSMTAP_CHANNEL_ACCH,
                SDCCH: GSMTAP_CHANNEL_SDCCH,
                FACCH_F: GSMTAP_CHANNEL_TCH_F | GSMTAP_CHANNEL_ACCH,
                FACCH_H: GSMTAP_CHANNEL_TCH_F | GSMTAP_CHANNEL_ACCH,
                L2_RACH_WITH_NO_DELAY: GSMTAP_CHANNEL_RACH
            }.get(channel_type & 0x7f)
            
            if gsmtap_channel_type is None:
                
                warning('Unknown log type received for LOG_GSM_RR_SIGNALING_MESSAGE_C: %d' % channel_type)
                return
            
            # Diag is delivering us L3 data, but GSMTAP will want L2 for most
            # channels (including a LAPDm header that we don't have), the
            # workaround for this is to set the interface type to A-bis.
            
            # Other channels that include just a L2 pseudo length before their
            # protocol discriminator will have it removed.
            
            interface_type = GSMTAP_TYPE_ABIS
            
            if gsmtap_channel_type in (GSMTAP_CHANNEL_BCCH, GSMTAP_CHANNEL_CCCH):
                
                packet = packet[1:]
            
            packet = build_gsmtap_ip(interface_type, gsmtap_channel_type, packet, is_uplink)

        elif log_type == LOG_GSM_SACCH_C: # 0x5134 - GSM SACCH
            self.current_rat = '2g'
            is_uplink = False
            packet = build_gsmtap_ip(GSMTAP_TYPE_UM, GSMTAP_CHANNEL_SDCCH | GSMTAP_CHANNEL_ACCH, log_payload, is_uplink)
        
        elif log_type in (
            LOG_GPRS_RLC_UL_COMMAND_C,
            LOG_GPRS_RLC_DL_COMMAND_C,
            LOG_GPRS_LLC_ME_LOG_PACKET_C,
            LOG_GPRS_SNDCP_PDU_C
        ): # 0x520a, 0x520b, 0x5215, 0x521e - GPRS RLC/LLC/SNDCP
            self.current_rat = '2g'
            is_uplink = log_type == LOG_GPRS_RLC_UL_COMMAND_C
            payload = log_payload[4:] if len(log_payload) >= 4 else log_payload
            packet = build_gsmtap_ip(GSMTAP_TYPE_GPRS_LLC if log_type == LOG_GPRS_LLC_ME_LOG_PACKET_C else GSMTAP_TYPE_UM, GSMTAP_CHANNEL_PACCH, payload, is_uplink)
        
        elif log_type == LOG_GPRS_MAC_SIGNALLING_MESSAGE_C: # 0x5226
            
            (channel_type, message_type, length), signalling_message = unpack('<BBB', log_payload[:3]), log_payload[3:]
            
            if message_type == PACKET_CHANNEL_REQUEST:
                return # "Internal use", discard
            
            # This contains the whole RLC/MAC header
            
            PAYLOAD_TYPE_CTRL_NO_OPT_OCTET = 1 # Protocol constant from Wireshark
            packet = bytes([PAYLOAD_TYPE_CTRL_NO_OPT_OCTET << 6, *signalling_message[:length]])
            
            is_uplink = not bool(channel_type & 0x80)
            
            # Normalize GPRS MAC channel type
            # 0x01/0x81: PACCH DL/UL, 0x02/0x82: PDTCH, 0x03/0x83: PACCH RRBP, 0x04/0x84: PACCH UL/DL
            norm_ch = channel_type & 0x7F
            if norm_ch in (0x01, 0x02, 0x03, 0x04):
                gsmtap_channel_type = GSMTAP_CHANNEL_PACCH
            elif norm_ch == 0x00:
                gsmtap_channel_type = GSMTAP_CHANNEL_PBCCH if hasattr(sys.modules.get('src.protocol.gsmtap'), 'GSMTAP_CHANNEL_PBCCH') else GSMTAP_CHANNEL_PACCH
            else:
                gsmtap_channel_type = GSMTAP_CHANNEL_PACCH
            
            packet = build_gsmtap_ip(GSMTAP_TYPE_UM, gsmtap_channel_type, packet, is_uplink)
        
        elif log_type == LOG_LTE_RRC_OTA_MSG_LOG_C: # 0xb0c0
            
            self.current_rat = '4g'
            
            # Interesting structures are defined:
            # - By MobileInsight here: https://github.com/mobile-insight/mobileinsight-core/blob/v3.2.0/dm_collector_c/log_packet.h#L200
            # - By Moiji diag-parser here: https://github.com/moiji-mobile/diag-parser/blob/master/diag_input.c#L206
            
            # Parse base header
            
            (ext_header_ver, rrc_rel, rrc_ver, bearer_id, phy_cellid), ext_header = unpack('<BBBBH', log_payload[:6]), log_payload[6:]
            
            if ext_header_ver >= 25: # Handle post-NR releases
                (ext_header_ver, rrc_rel, rrc_ver, nc_rrc_rel, bearer_id, phy_cellid), ext_header = unpack('<BBBHBH', log_payload[:8]), log_payload[8:]
            
            # Parse extended header
            
            freq_type = 'H' if ext_header_ver < 8 else 'I'
            
            header_spec = '<' + freq_type + 'HBH'
            
            if unpack_from('<H', ext_header, calcsize(header_spec) - 2)[0] != len(ext_header) - calcsize(header_spec): # SIB mask is present
                
                header_spec = '<' + freq_type + 'HB4xH'
            
            (freq, sfn, channel_type, length), packet = unpack_from(header_spec, ext_header), ext_header[calcsize(header_spec):]
            
            # GSMTAP definition:
            # - https://github.com/wireshark/wireshark/blob/wireshark-2.5.0/epan/dissectors/packet-gsmtap.h
            # - http://osmocom.org/projects/baseband/wiki/GSMTAP
            
            if channel_type in (254, 255):
                return # Frames containing only a MIB or extension SIB, as already present in RRC frames, ignoring
            
            if LTE_UL_DCCH_NB < channel_type <= LTE_UL_DCCH_NB + 9:
                channel_type -= 9

            
            # See here for LTE channel constants (they heavily depend on baseband
            # versions): https://github.com/fgsect/scat/blob/01d5b81/parsers/qualcomm/diagltelogparser.py#L1207
            
            channel_lookup_table = {
                LTE_BCCH_BCH_NB: GSMTAP_LTE_RRC_SUB_BCCH_BCH_Message_NB,
                LTE_BCCH_DL_SCH_NB: GSMTAP_LTE_RRC_SUB_BCCH_DL_SCH_Message_NB,
                LTE_PCCH_NB: GSMTAP_LTE_RRC_SUB_PCCH_Message_NB,
                LTE_DL_CCCH_NB: GSMTAP_LTE_RRC_SUB_DL_CCCH_Message_NB,
                LTE_DL_DCCH_NB: GSMTAP_LTE_RRC_SUB_DL_DCCH_Message_NB,
                LTE_UL_CCCH_NB: GSMTAP_LTE_RRC_SUB_UL_CCCH_Message_NB,
                LTE_UL_DCCH_NB: GSMTAP_LTE_RRC_SUB_UL_DCCH_Message_NB,
            }
            
            # The v9 channel type values don't overlap a lot with other
            # existing values as they start at "8", so handle these in
            # all case and allow these to be erased with other values
            # subsequently
                        
            channel_lookup_table.update({
                LTE_BCCH_BCH_v9: GSMTAP_LTE_RRC_SUB_BCCH_BCH_Message,
                LTE_BCCH_DL_SCH_v9: GSMTAP_LTE_RRC_SUB_BCCH_DL_SCH_Message,
                LTE_MCCH_v9: GSMTAP_LTE_RRC_SUB_MCCH_Message,
                LTE_PCCH_v9: GSMTAP_LTE_RRC_SUB_PCCH_Message,
                LTE_DL_CCCH_v9: GSMTAP_LTE_RRC_SUB_DL_CCCH_Message,
                LTE_DL_DCCH_v9: GSMTAP_LTE_RRC_SUB_DL_DCCH_Message,
                LTE_UL_CCCH_v9: GSMTAP_LTE_RRC_SUB_UL_CCCH_Message,
                LTE_UL_DCCH_v9: GSMTAP_LTE_RRC_SUB_UL_DCCH_Message,
            })
        
            if ext_header_ver in (14, 15, 16, 20, 24, 25):

                channel_lookup_table.update({
                    LTE_BCCH_BCH_v14: GSMTAP_LTE_RRC_SUB_BCCH_BCH_Message,
                    LTE_BCCH_DL_SCH_v14: GSMTAP_LTE_RRC_SUB_BCCH_DL_SCH_Message,
                    LTE_MCCH_v14: GSMTAP_LTE_RRC_SUB_MCCH_Message,
                    LTE_PCCH_v14: GSMTAP_LTE_RRC_SUB_PCCH_Message,
                    LTE_DL_CCCH_v14: GSMTAP_LTE_RRC_SUB_DL_CCCH_Message,
                    LTE_DL_DCCH_v14: GSMTAP_LTE_RRC_SUB_DL_DCCH_Message,
                    LTE_UL_CCCH_v14: GSMTAP_LTE_RRC_SUB_UL_CCCH_Message,
                    LTE_UL_DCCH_v14: GSMTAP_LTE_RRC_SUB_UL_DCCH_Message,
                })
            
            elif ext_header_ver == 19 or ext_header_ver >= 26:
                
                channel_lookup_table.update({
                    LTE_BCCH_BCH_v19: GSMTAP_LTE_RRC_SUB_BCCH_BCH_Message,
                    LTE_BCCH_DL_SCH_v19: GSMTAP_LTE_RRC_SUB_BCCH_DL_SCH_Message,
                    LTE_MCCH_v19: GSMTAP_LTE_RRC_SUB_MCCH_Message,
                    LTE_PCCH_v19: GSMTAP_LTE_RRC_SUB_PCCH_Message,
                    LTE_DL_CCCH_v19: GSMTAP_LTE_RRC_SUB_DL_CCCH_Message,
                    LTE_DL_DCCH_v19: GSMTAP_LTE_RRC_SUB_DL_DCCH_Message,
                    LTE_UL_CCCH_v19: GSMTAP_LTE_RRC_SUB_UL_CCCH_Message,
                    LTE_UL_DCCH_v19: GSMTAP_LTE_RRC_SUB_UL_DCCH_Message,
                })

            elif ext_header_ver not in (9, 12):
            
                channel_lookup_table.update({
                    LTE_BCCH_BCH_v0: GSMTAP_LTE_RRC_SUB_BCCH_BCH_Message,
                    LTE_BCCH_DL_SCH_v0: GSMTAP_LTE_RRC_SUB_BCCH_DL_SCH_Message,
                    LTE_MCCH_v0: GSMTAP_LTE_RRC_SUB_MCCH_Message,
                    LTE_PCCH_v0: GSMTAP_LTE_RRC_SUB_PCCH_Message,
                    LTE_DL_CCCH_v0: GSMTAP_LTE_RRC_SUB_DL_CCCH_Message,
                    LTE_DL_DCCH_v0: GSMTAP_LTE_RRC_SUB_DL_DCCH_Message,
                    LTE_UL_CCCH_v0: GSMTAP_LTE_RRC_SUB_UL_CCCH_Message,
                    LTE_UL_DCCH_v0: GSMTAP_LTE_RRC_SUB_UL_DCCH_Message,
                })
                
            gsmtap_channel_type = channel_lookup_table.get(channel_type)
            
            is_uplink = gsmtap_channel_type in (
                GSMTAP_LTE_RRC_SUB_UL_CCCH_Message,
                GSMTAP_LTE_RRC_SUB_UL_DCCH_Message,
                GSMTAP_LTE_RRC_SUB_UL_CCCH_Message_NB,
                GSMTAP_LTE_RRC_SUB_UL_DCCH_Message_NB,
            )
            
            if gsmtap_channel_type is None:
                
                warning('Unknown log type received for LOG_LTE_RRC_OTA_MSG_LOG_C version %d: %d' % (
                    ext_header_ver, channel_type))
                return
            
            packet = build_gsmtap_ip(GSMTAP_TYPE_LTE_RRC, gsmtap_channel_type, packet, is_uplink)
        
        elif self.decrypt_nas and log_type in (
            LOG_LTE_NAS_ESM_OTA_IN_MSG_LOG_C,
            LOG_LTE_NAS_ESM_OTA_OUT_MSG_LOG_C,
            LOG_LTE_NAS_EMM_OTA_IN_MSG_LOG_C,
            LOG_LTE_NAS_EMM_OTA_OUT_MSG_LOG_C,
            LOG_LTE_NAS_EMM_SEC_OTA_IN_MSG_LOG_C,
            LOG_LTE_NAS_EMM_SEC_OTA_OUT_MSG_LOG_C
        ): # 4G LTE NAS (ESM, EMM, and Security-Protected EMM)
            self.current_rat = '4g'
            
            # Header source: https://github.com/mobile-insight/mobileinsight-core/blob/v3.2.0/dm_collector_c/log_packet.h#L274
            (ext_header_ver, rrc_rel, rrc_ver_minor, rrc_ver_major), signalling_message = unpack('<BBBB', log_payload[:4]), log_payload[4:]
            
            is_uplink = log_type in (
                LOG_LTE_NAS_ESM_OTA_OUT_MSG_LOG_C,
                LOG_LTE_NAS_EMM_OTA_OUT_MSG_LOG_C,
                LOG_LTE_NAS_EMM_SEC_OTA_OUT_MSG_LOG_C
            )
            
            # Detect Security Header:
            # - Explicit security OTA log codes (0xB0EC / 0xB0ED)
            # - Or non-zero security header type in byte 0
            is_sec_header = False
            if log_type in (LOG_LTE_NAS_EMM_SEC_OTA_IN_MSG_LOG_C, LOG_LTE_NAS_EMM_SEC_OTA_OUT_MSG_LOG_C):
                is_sec_header = True
            elif signalling_message and len(signalling_message) >= 6:
                sec_hdr_type = (signalling_message[0] >> 4) & 0x0F
                proto_disc = signalling_message[0] & 0x0F
                if sec_hdr_type in (1, 2, 3, 4) and proto_disc == 0x07:
                    is_sec_header = True
            
            nas_sub_type = GSMTAP_LTE_NAS_SEC_HEADER if is_sec_header else GSMTAP_LTE_NAS_PLAIN
            packet = build_gsmtap_ip(GSMTAP_TYPE_LTE_NAS, nas_sub_type, signalling_message, is_uplink)
        
        elif self.include_ip_traffic and log_type == LOG_DATA_PROTOCOL_LOGGING_C: # 0x11eb - IPv4 user-plane data
            
            packet = log_payload[8:]
        
        elif log_type == LOG_UMTS_NAS_OTA_MESSAGE_LOG_PACKET_C: # 0x713a - 2G/3G DTAP from NAS
            
            if self.current_rat != '2g': # Not needed in 3G, where this is already embedded in RRC
                
                return
            
            # Header source: https://github.com/mobile-insight/mobileinsight-core/blob/v3.2.0/dm_collector_c/log_packet.h#L274
            
            (is_uplink, length), signalling_message = unpack('<BI', log_payload[:5]), log_payload[5:]
            
            packet = signalling_message[:length]
            
            is_uplink = bool(is_uplink)
            
            packet = build_gsmtap_ip(GSMTAP_TYPE_ABIS, GSMTAP_CHANNEL_SDCCH, signalling_message, is_uplink)
        
        elif log_type == LOG_NR_RRC_OTA_MSG_LOG_C: # 0xb821 - 5G NR RRC
            
            self.current_rat = '5g'
            
            try:
                (version,), ext_header = unpack('<B', log_payload[:1]), log_payload[1:]
                
                if version >= 1:
                    sfn, slot, channel_type, pdu_len = unpack_from('<HHHH', ext_header)
                    signalling_message = ext_header[8:8 + pdu_len]
                else:
                    channel_type, pdu_len = unpack_from('<HH', ext_header)
                    signalling_message = ext_header[4:4 + pdu_len]
                
                nr_channel_map = {
                    NR_BCCH_BCH: GSMTAP_NR_RRC_SUB_BCCH_BCH,
                    NR_BCCH_DL_SCH: GSMTAP_NR_RRC_SUB_BCCH_DL_SCH,
                    NR_DL_CCCH: GSMTAP_NR_RRC_SUB_DL_CCCH,
                    NR_DL_DCCH: GSMTAP_NR_RRC_SUB_DL_DCCH,
                    NR_UL_CCCH: GSMTAP_NR_RRC_SUB_UL_CCCH,
                    NR_UL_CCCH1: GSMTAP_NR_RRC_SUB_UL_CCCH1,
                    NR_UL_DCCH: GSMTAP_NR_RRC_SUB_UL_DCCH,
                    NR_PCCH: GSMTAP_NR_RRC_SUB_PCCH,
                }
                
                gsmtap_channel_type = nr_channel_map.get(channel_type)
                if gsmtap_channel_type is not None and signalling_message:
                    is_uplink = gsmtap_channel_type in (
                        GSMTAP_NR_RRC_SUB_UL_CCCH,
                        GSMTAP_NR_RRC_SUB_UL_CCCH1,
                        GSMTAP_NR_RRC_SUB_UL_DCCH
                    )
                    packet = build_gsmtap_ip(GSMTAP_TYPE_NR_RRC, gsmtap_channel_type, signalling_message, is_uplink)
                else:
                    packet = build_nr_rrc_log_ip(log_payload)
            except Exception:
                packet = build_nr_rrc_log_ip(log_payload)

        elif log_type in (
            LOG_NR_NAS_5GMM_OTA_IN_MSG_LOG_C,
            LOG_NR_NAS_5GMM_OTA_OUT_MSG_LOG_C,
            LOG_NR_NAS_5GSM_OTA_IN_MSG_LOG_C,
            LOG_NR_NAS_5GSM_OTA_OUT_MSG_LOG_C
        ): # 0xb800, 0xb801, 0xb802, 0xb803 - 5G NAS
            
            self.current_rat = '5g'
            is_uplink = log_type in (LOG_NR_NAS_5GMM_OTA_OUT_MSG_LOG_C, LOG_NR_NAS_5GSM_OTA_OUT_MSG_LOG_C)
            
            try:
                packet = build_nr_nas_log_ip(log_payload)
            except Exception:
                packet = build_nr_nas_log_ip(log_payload)

        elif log_type in (
            LOG_NR_MAC_PDU_LOG_C,
            LOG_NR_MAC_RACH_TRIGGER_LOG_C,
            LOG_NR_SDAP_PDU_LOG_C,
            LOG_NR_RRC_ETWS_CMAS_LOG_C,
            LOG_NR_CALEA_TRACE_LOG_C,
            LOG_NR_RRC_RADIO_RESOURCE_CONFIG_C
        ): # 0xb808, 0xb80a, 0xb826, 0xb825, 0xb830, 0xb822 - 5G MAC, SDAP, ETWS, CALEA, RC
            self.current_rat = '5g'
            is_uplink = False
            try:
                payload = log_payload[4:] if len(log_payload) >= 4 else log_payload
                packet = build_gsmtap_ip(GSMTAP_TYPE_NR_MAC, GSMTAP_CHANNEL_UNKNOWN, payload, is_uplink)
            except Exception:
                packet = build_gsmtap_ip(GSMTAP_TYPE_NR_MAC, GSMTAP_CHANNEL_UNKNOWN, log_payload, is_uplink)

        elif log_type in (
            LOG_LTE_IMS_SIP_MSG_C,
            LOG_NR_IMS_SIP_MSG_C,
            LOG_IMS_SIP_MSG_C,
            LOG_IMS_REGISTRATION_C,
            LOG_IMS_CONFIG_C
        ): # 0x156e, 0x156f, 0x1570, 0xb0e0, 0xb832 - IMS SIP
            self.current_rat = '5g' if log_type == LOG_NR_IMS_SIP_MSG_C else '4g'
            is_uplink = False
            try:
                # Find start of text message (SIP/2.0 or request methods)
                sip_start = -1
                for marker in (b'SIP/2.0', b'INVITE ', b'REGISTER ', b'ACK ', b'BYE ', b'CANCEL ', b'OPTIONS ', b'MESSAGE ', b'NOTIFY ', b'SUBSCRIBE '):
                    pos = log_payload.find(marker)
                    if pos != -1 and (sip_start == -1 or pos < sip_start):
                        sip_start = pos
                
                if sip_start != -1:
                    sip_payload = log_payload[sip_start:]
                    packet = build_sip_udp_ip(sip_payload, is_uplink)
                else:
                    payload = log_payload[4:] if len(log_payload) >= 4 else log_payload
                    packet = build_sip_udp_ip(payload, is_uplink)
            except Exception:
                packet = build_sip_udp_ip(log_payload, is_uplink)

        elif log_type == LOG_SIM_APDU_LOG_C: # 0x1188 - SIM APDU
            self.current_rat = '2g'
            is_uplink = False
            try:
                payload = log_payload[4:] if len(log_payload) >= 4 else log_payload
                packet = build_gsmtap_ip(GSMTAP_TYPE_SIM, GSMTAP_CHANNEL_UNKNOWN, payload, is_uplink)
            except Exception:
                packet = build_gsmtap_ip(GSMTAP_TYPE_SIM, GSMTAP_CHANNEL_UNKNOWN, log_payload, is_uplink)
            
        if packet:
            
            try:
                
                self.pcap_file.write(pack('<IIII',
                    int(timestamp),
                    int((timestamp * 1000000) % 1000000),
                    len(packet),
                    len(packet)
                ) + packet)

                self.flush_periodically()

            except (BrokenPipeError, OSError):

                self.diag_input.remove_module(self)

        # Also write a reassembled 3G SIB if present
        
        if self.reassemble_sibs:
            DecodedSibsDumper.on_log(self, log_type, log_payload, log_header, timestamp)
    
    """
        Callback to the be called by the inherited "DecodedSibsDumper" class
        if the user has passed the --reassemble-sibs argument.
        
        The --reassemble-sibs argument will reassemble SIBs into individual
        GSMTAP packets so that Wireshark can process them (it currently
        can't when embedded into RRC frames).
    """
    
    def on_decoded_sib(self, sib_type, sib_dict, sib_bytes, rrc_sfn, timestamp):
        
        packet = sib_bytes
        
        is_uplink = False
        
        gsmtap_channel_type = {
            'masterInformationBlock': GSMTAP_RRC_SUB_MasterInformationBlock,
            'systemInformationBlockType1': GSMTAP_RRC_SUB_SysInfoType1,
            'systemInformationBlockType2': GSMTAP_RRC_SUB_SysInfoType2,
            'systemInformationBlockType3': GSMTAP_RRC_SUB_SysInfoType3,
            'systemInformationBlockType4': GSMTAP_RRC_SUB_SysInfoType4,
            'systemInformationBlockType5': GSMTAP_RRC_SUB_SysInfoType5,
            'systemInformationBlockType6': GSMTAP_RRC_SUB_SysInfoType6,
            'systemInformationBlockType7': GSMTAP_RRC_SUB_SysInfoType7,
            'systemInformationBlockType11': GSMTAP_RRC_SUB_SysInfoType11,
            'systemInformationBlockType12': GSMTAP_RRC_SUB_SysInfoType12,
            'systemInformationBlockType13': GSMTAP_RRC_SUB_SysInfoType13,
            'systemInformationBlockType13-1': GSMTAP_RRC_SUB_SysInfoType13_1,
            'systemInformationBlockType13-2': GSMTAP_RRC_SUB_SysInfoType13_2,
            'systemInformationBlockType13-3': GSMTAP_RRC_SUB_SysInfoType13_3,
            'systemInformationBlockType13-4': GSMTAP_RRC_SUB_SysInfoType13_4,
            'systemInformationBlockType14': GSMTAP_RRC_SUB_SysInfoType14,
            'systemInformationBlockType15': GSMTAP_RRC_SUB_SysInfoType15,
            'systemInformationBlockType15-1': GSMTAP_RRC_SUB_SysInfoType15_1,
            'systemInformationBlockType15-2': GSMTAP_RRC_SUB_SysInfoType15_2,
            'systemInformationBlockType15-3': GSMTAP_RRC_SUB_SysInfoType15_3,
            'systemInformationBlockType16': GSMTAP_RRC_SUB_SysInfoType16,
            'systemInformationBlockType17': GSMTAP_RRC_SUB_SysInfoType17,
            'systemInformationBlockType15-4': GSMTAP_RRC_SUB_SysInfoType15_4,
            'systemInformationBlockType18': GSMTAP_RRC_SUB_SysInfoType18,
            'schedulingBlock1': GSMTAP_RRC_SUB_SysInfoTypeSB1,
            'schedulingBlock2': GSMTAP_RRC_SUB_SysInfoTypeSB2,
            'systemInformationBlockType15-5': GSMTAP_RRC_SUB_SysInfoType15_5,
            'systemInformationBlockType5bis': GSMTAP_RRC_SUB_SysInfoType5bis,
            'systemInfoType11bis': GSMTAP_RRC_SUB_SysInfoType11bis,
            'systemInfoType15bis': GSMTAP_RRC_SUB_SysInfoType15bis,
            'systemInfoType15-1bis': GSMTAP_RRC_SUB_SysInfoType15_1bis,
            'systemInfoType15-2bis': GSMTAP_RRC_SUB_SysInfoType15_2bis,
            'systemInfoType15-3bis': GSMTAP_RRC_SUB_SysInfoType15_3bis,
            'systemInfoType15-6': GSMTAP_RRC_SUB_SysInfoType15_6,
            'systemInfoType15-7': GSMTAP_RRC_SUB_SysInfoType15_7,
            'systemInfoType15-8': GSMTAP_RRC_SUB_SysInfoType15_8,
            'systemInfoType19': GSMTAP_RRC_SUB_SysInfoType19,
            'systemInfoType15-2ter': GSMTAP_RRC_SUB_SysInfoType15_2ter,
            'systemInfoType20': GSMTAP_RRC_SUB_SysInfoType20,
            'systemInfoType21': GSMTAP_RRC_SUB_SysInfoType21,
            'systemInfoType22': GSMTAP_RRC_SUB_SysInfoType22
        }[sib_type]
            
        packet = build_gsmtap_ip(GSMTAP_TYPE_UMTS_RRC, gsmtap_channel_type, packet, is_uplink)
        
        assert len(packet) <= 65535
        
        try:
        
            self.pcap_file.write(pack('<IIII',
                int(timestamp),
                int((timestamp * 1000000) % 1000000),
                len(packet),
                len(packet)
            ) + packet)

            self.flush_periodically()

        except (BrokenPipeError, OSError):

            self.diag_input.remove_module(self)

    def on_sib_decoding_error(self, decoding_error):

        pass

    """
        A capture normally ends through Ctrl-C, an unplugged device or a killed
        process, not a clean return, so nothing can be counted on to run at
        exit - self.pcap_file is block-buffered and __del__ may never fire.
        Flushing every FLUSH_EVERY_N_PACKETS records bounds what a hard stop
        can take with it to a fraction of a buffer, for a cost that is
        negligible next to building the packet in the first place.
    """

    FLUSH_EVERY_N_PACKETS = 32

    def flush_periodically(self):

        self.packets_since_flush += 1

        if self.packets_since_flush >= self.FLUSH_EVERY_N_PACKETS:

            self.packets_since_flush = 0

            self.pcap_file.flush()

    def __del__(self):
        
        if getattr(self, 'pcap_file', None):
            self.pcap_file.close()


"""
    This is the same module, except that il will launch directly a FIFO to
    Wireshark rather than write the PCAP to a file
"""

class WiresharkLive(PcapDumper):

    def __init__(self, diag_input, reassemble_sibs = True, decrypt_nas = True, include_ip_traffic = True):
        
        wireshark = (
            which('C:\\Program Files\\Wireshark\\Wireshark.exe') or
            which('C:\\Program Files (x86)\\Wireshark\\Wireshark.exe') or
            which('wireshark') or
            which('wireshark-gtk')
        )
        
        if not wireshark:
            raise Exception('Could not find Wireshark in $PATH')
        
        if not IS_UNIX:
            self.detach_process = None

        # Wireshark automatically loads all plugins from %APPDATA%/Wireshark/plugins/telcosec
        cmd = [wireshark, '-k', '-i', '-']
        wireshark_pipe = Popen(cmd,
            stdin = PIPE, stdout = DEVNULL, stderr = STDOUT,
            preexec_fn = self.detach_process,
            bufsize = 0
        ).stdin
        
        wireshark_pipe.appending_to_file = False
        
        super().__init__(diag_input, wireshark_pipe, reassemble_sibs, decrypt_nas, include_ip_traffic)
    
    """
        Executed when we launch a Wireshark process, after fork()
    """
    
    def detach_process(self):
        
        try:
            
            # Don't be hit by CTRL+C
            
            setpgrp()
            
            # Drop privileges if needed
            
            uid, gid = getenv('SUDO_UID'), getenv('SUDO_GID')
            
            if uid and gid:
                
                uid, gid = int(uid), int(gid)

                setgroups(getgrouplist(getpwuid(uid).pw_name, gid))

                setresgid(gid, gid, -1)
                
                setresuid(uid, uid, -1)
        
        except Exception:
            
            print_exc()

