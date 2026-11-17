#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

"""
    AirTap - Interactive Session Replay Engine
    Powered by TelcoSec.net (https://telcosec.net)

    Supports unified sub-millisecond precision replay, timeline scrubbing,
    pause/resume, and variable speed (0.5x to 10x, and unthrottled maximum)
    across:
    1. Standard and Nanosecond PCAP captures (GSMTAP, UDP, Ethernet, Raw IP).
    2. Qualcomm Diag Log File (DLF) captures.
    3. Qualcomm QMDL container captures.
    4. Newline-delimited JSON / GeoJSON diagnostic streams.
"""

from datetime import datetime
from struct import unpack, unpack_from, pack
import time
import threading
import json
import os

from ._base_input import BaseInput
from ..protocol.log_types import (
    LOG_GSM_RR_SIGNALING_MESSAGE_C,
    WCDMA_SIGNALLING_MESSAGE,
    LOG_LTE_RRC_OTA_MSG_LOG_C,
    LOG_LTE_NAS_ESM_OTA_IN_MSG_LOG_C,
    LOG_LTE_NAS_EMM_OTA_IN_MSG_LOG_C,
    LOG_NR_RRC_OTA_MSG_LOG_C,
    LOG_NR_NAS_5GMM_OTA_IN_MSG_LOG_C,
    LOG_IMS_SIP_MSG_C,
    LOG_SIM_APDU_LOG_C,
    LOG_DATA_PROTOCOL_LOGGING_C,
    LOG_GNSS_POSITION_REPORT_C,
    LOG_GNSS_NMEA_REPORT_C,
    LOG_CG_LCS_POSITION_ESTIMATE_C,
)
from ..protocol.gsmtap import (
    GSMTAP_TYPE_UM,
    GSMTAP_TYPE_UMTS_RRC,
    GSMTAP_TYPE_LTE_RRC,
    GSMTAP_TYPE_LTE_NAS,
    GSMTAP_TYPE_NR_RRC,
    GSMTAP_TYPE_NR_NAS,
    GSMTAP_PORT,
    NR_RRC_UDP_PORT,
)


class ReplayFrame:
    """Represents an individual captured diagnostic frame in memory."""
    def __init__(self, log_type: int, log_data: bytes, log_header: bytes, timestamp: float, metadata: dict = None):
        self.log_type = log_type
        self.log_data = log_data
        self.log_header = log_header
        self.timestamp = timestamp
        self.metadata = metadata or {}


class SessionReplayer(BaseInput):
    """
    High-performance multi-format diagnostic session replayer.
    Provides pause, seek, step, speed control, and timeline events.
    """

    STATE_IDLE = 'IDLE'
    STATE_PLAYING = 'PLAYING'
    STATE_PAUSED = 'PAUSED'
    STATE_COMPLETED = 'COMPLETED'

    def __init__(self, file_path: str = None, raw_bytes: bytes = None, on_event_callback = None):
        self.file_path = file_path
        self.raw_bytes = raw_bytes
        self.on_event_callback = on_event_callback

        self.frames = []
        self.current_idx = 0
        self.state = self.STATE_IDLE
        self.speed = 1.0  # 1.0 = real-time, 2.0 = 2x, 0 = unthrottled
        self.loop = False

        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._pause_event.set() # Unpaused by default
        self._lock = threading.Lock()
        self._worker_thread = None

        super().__init__()

        if file_path or raw_bytes:
            self.load()

    def load(self, file_path: str = None, raw_bytes: bytes = None):
        """Loads and indexes all frames from file or memory buffer."""
        with self._lock:
            if file_path:
                self.file_path = file_path
            if raw_bytes:
                self.raw_bytes = raw_bytes

            data = self.raw_bytes
            if not data and self.file_path and os.path.exists(self.file_path):
                with open(self.file_path, 'rb') as f:
                    data = f.read()

            if not data:
                return False

            self.frames = self._parse_frames(data)
            self.current_idx = 0
            self.state = self.STATE_PAUSED if self.frames else self.STATE_IDLE
            self._notify_event('loaded', {
                'total_frames': len(self.frames),
                'duration_sec': self.get_duration(),
                'start_ts': self.frames[0].timestamp if self.frames else 0,
                'end_ts': self.frames[-1].timestamp if self.frames else 0,
            })
            return True

    def _parse_frames(self, data: bytes) -> list:
        """Auto-detects format from magic bytes and parses frames into memory."""
        if len(data) < 4:
            return []

        magic = unpack('<I', data[:4])[0]

        # 1. PCAP format (Standard or Nanosecond, Little/Big Endian)
        if magic in (0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1):
            return self._parse_pcap(data)

        # 2. QMDL Qualcomm Container format ('QMDL' magic: 0x4c444d51)
        if magic == 0x4c444d51 or data[:4] == b'QMDL':
            return self._parse_qmdl(data)

        # 3. JSON / GeoJSON Stream (starts with '{' or '[')
        first_char = data.strip()[:1]
        if first_char in (b'{', b'['):
            return self._parse_json(data)

        # 4. Fallback: Diag Log File (DLF) format
        return self._parse_dlf(data)

    def _parse_pcap(self, data: bytes) -> list:
        frames = []
        if len(data) < 24:
            return frames

        magic, ver_maj, ver_min, thiszone, sigfigs, snaplen, linktype = unpack('<IHHiIII', data[:24])
        is_be = (magic in (0xd4c3b2a1, 0x4d3cb2a1))
        is_nano = (magic in (0xa1b23c4d, 0x4d3cb2a1))
        pkt_hdr_fmt = '>IIII' if is_be else '<IIII'

        offset = 24
        while offset + 16 <= len(data):
            ts_sec, ts_usec, incl_len, orig_len = unpack_from(pkt_hdr_fmt, data, offset)
            offset += 16
            if offset + incl_len > len(data):
                break

            pkt_bytes = data[offset:offset + incl_len]
            offset += incl_len
            ts = ts_sec + (ts_usec / 1e9 if is_nano else ts_usec / 1e6)

            # Strip Ethernet / IP / UDP encapsulation
            payload = pkt_bytes
            if linktype == 1 and len(payload) > 14:  # Ethernet
                payload = payload[14:]

            if len(payload) >= 20 and (payload[0] >> 4) == 4:  # IPv4
                ihl = (payload[0] & 0x0f) * 4
                protocol = payload[9]
                if protocol == 17 and len(payload) >= ihl + 8:  # UDP
                    src_port, dst_port, udp_len = unpack_from('>HHH', payload, ihl)
                    udp_data = payload[ihl + 8:ihl + udp_len]

                    if src_port == GSMTAP_PORT or dst_port == GSMTAP_PORT:
                        f = self._decode_gsmtap_payload(udp_data, ts)
                        if f: frames.append(f)
                    elif src_port == NR_RRC_UDP_PORT or dst_port == NR_RRC_UDP_PORT:
                        hdr = pack('<HHQ', len(udp_data) + 12, LOG_NR_RRC_OTA_MSG_LOG_C, int(ts))
                        frames.append(ReplayFrame(LOG_NR_RRC_OTA_MSG_LOG_C, udp_data, hdr, ts))
                    elif src_port == 5060 or dst_port == 5060:
                        hdr = pack('<HHQ', len(udp_data) + 12, LOG_IMS_SIP_MSG_C, int(ts))
                        frames.append(ReplayFrame(LOG_IMS_SIP_MSG_C, udp_data, hdr, ts))
                    else:
                        hdr = pack('<HHQ', len(payload) + 12, LOG_DATA_PROTOCOL_LOGGING_C, int(ts))
                        frames.append(ReplayFrame(LOG_DATA_PROTOCOL_LOGGING_C, payload, hdr, ts))
            elif len(payload) >= 16 and payload[0] == 2:  # Raw GSMTAP header
                f = self._decode_gsmtap_payload(payload, ts)
                if f: frames.append(f)

        return frames

    def _decode_gsmtap_payload(self, gsmtap_data: bytes, ts: float) -> ReplayFrame:
        if len(gsmtap_data) < 16:
            return None
        version, hdr_len, gsmtap_type = unpack_from('>BBB', gsmtap_data, 0)
        raw_payload = gsmtap_data[hdr_len * 4:]

        type_map = {
            GSMTAP_TYPE_UM: LOG_GSM_RR_SIGNALING_MESSAGE_C,
            GSMTAP_TYPE_UMTS_RRC: WCDMA_SIGNALLING_MESSAGE,
            GSMTAP_TYPE_LTE_RRC: LOG_LTE_RRC_OTA_MSG_LOG_C,
            GSMTAP_TYPE_LTE_NAS: LOG_LTE_NAS_ESM_OTA_IN_MSG_LOG_C,
            GSMTAP_TYPE_NR_RRC: LOG_NR_RRC_OTA_MSG_LOG_C,
            GSMTAP_TYPE_NR_NAS: LOG_NR_NAS_5GMM_OTA_IN_MSG_LOG_C,
        }
        log_type = type_map.get(gsmtap_type, LOG_DATA_PROTOCOL_LOGGING_C)
        hdr = pack('<HHQ', len(raw_payload) + 12, log_type, int(ts))
        return ReplayFrame(log_type, raw_payload, hdr, ts)

    def _parse_dlf(self, data: bytes) -> list:
        frames = []
        offset = 0
        TIMESTAMP_OFFSET = datetime(1980, 1, 6).timestamp()

        while offset + 12 <= len(data):
            log_header = data[offset:offset + 12]
            log_length, log_type, log_time = unpack('<HHQ', log_header)

            if log_length < 12 or offset + log_length > len(data):
                break

            log_data = data[offset + 12:offset + log_length]
            offset += log_length

            # Qualcomm 54-bit timestamp decoding
            ts = (log_time >> 20) / 50.0 + TIMESTAMP_OFFSET + ((log_time & 0xfffff) / 0x100000)
            frames.append(ReplayFrame(log_type, log_data, log_header, ts))

        return frames

    def _parse_qmdl(self, data: bytes) -> list:
        frames = []
        offset = 0

        # Skip QMDL file header if present
        if data[:4] == b'QMDL':
            offset = 12 if len(data) >= 12 else 4

        TIMESTAMP_OFFSET = datetime(1980, 1, 6).timestamp()

        while offset + 8 <= len(data):
            # QMDL item header: [length(2B), type(2B), timestamp(8B)]
            if offset + 12 > len(data):
                break
            length, log_type = unpack_from('<HH', data, offset)
            if length < 8 or offset + length > len(data):
                offset += 1
                continue

            item_data = data[offset + 4:offset + length]
            offset += length

            if len(item_data) >= 8:
                log_time = unpack_from('<Q', item_data, 0)[0]
                ts = (log_time >> 20) / 50.0 + TIMESTAMP_OFFSET + ((log_time & 0xfffff) / 0x100000)
                payload = item_data[8:]
                hdr = pack('<HHQ', len(payload) + 12, log_type, int(ts))
                frames.append(ReplayFrame(log_type, payload, hdr, ts))

        return frames

    def _parse_json(self, data: bytes) -> list:
        from base64 import b64decode
        frames = []
        text = data.decode('utf-8', errors='ignore')

        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                log_type = obj.get('log_type', LOG_DATA_PROTOCOL_LOGGING_C)
                ts = float(obj.get('timestamp', time.time()))
                raw_frame = obj.get('log_frame')
                if raw_frame:
                    raw_bytes = b64decode(raw_frame)
                    hdr = raw_bytes[:12] if len(raw_bytes) >= 12 else pack('<HHQ', len(raw_bytes) + 12, log_type, int(ts))
                    payload = raw_bytes[12:] if len(raw_bytes) >= 12 else raw_bytes
                else:
                    payload = b''
                    hdr = pack('<HHQ', 12, log_type, int(ts))

                meta = {k: v for k, v in obj.items() if k not in ('log_type', 'log_frame', 'timestamp')}
                frames.append(ReplayFrame(log_type, payload, hdr, ts, metadata=meta))
            except Exception:
                continue

        return frames

    # ─── Playback Control API ────────────────────────────────────────────────

    def play(self):
        """Resumes or starts playback loop in background worker thread."""
        with self._lock:
            if not self.frames:
                return False
            self.state = self.STATE_PLAYING
            self._pause_event.set()

            if not self._worker_thread or not self._worker_thread.is_alive():
                self._stop_event.clear()
                self._worker_thread = threading.Thread(target=self._run_replay, daemon=True)
                self._worker_thread.start()

            self._notify_event('playing', {'index': self.current_idx, 'speed': self.speed})
            return True

    def pause(self):
        """Pauses the playback loop."""
        with self._lock:
            self.state = self.STATE_PAUSED
            self._pause_event.clear()
            self._notify_event('paused', {'index': self.current_idx})

    def step(self):
        """Advances single frame while paused."""
        with self._lock:
            if self.current_idx < len(self.frames):
                frame = self.frames[self.current_idx]
                self._dispatch_frame(frame)
                self.current_idx += 1
                self._notify_event('stepped', {'index': self.current_idx, 'progress': self.get_progress()})
                if self.current_idx >= len(self.frames):
                    self.state = self.STATE_COMPLETED

    def seek_to_index(self, index: int):
        """Seeks directly to a frame index."""
        with self._lock:
            self.current_idx = max(0, min(len(self.frames) - 1, index))
            if self.frames:
                self.timestamp = self.frames[self.current_idx].timestamp
            self._notify_event('seeked', {'index': self.current_idx, 'progress': self.get_progress()})

    def seek_to_percentage(self, percent: float):
        """Seeks using a 0.0 - 100.0 percentage."""
        if not self.frames:
            return
        idx = int((percent / 100.0) * len(self.frames))
        self.seek_to_index(idx)

    def set_speed(self, multiplier: float):
        """Sets playback speed multiplier (0 = max unthrottled, 1.0 = real-time, 2.0 = 2x, etc.)."""
        with self._lock:
            self.speed = max(0.0, float(multiplier))
            self._notify_event('speed_changed', {'speed': self.speed})

    def stop(self):
        """Terminates replay loop and resets index."""
        self._stop_event.set()
        self._pause_event.set()
        with self._lock:
            self.state = self.STATE_IDLE
            self.current_idx = 0

    def get_progress(self) -> float:
        """Returns replay progress percentage (0.0 to 100.0)."""
        if not self.frames:
            return 0.0
        return round((self.current_idx / len(self.frames)) * 100.0, 2)

    def get_duration(self) -> float:
        """Returns capture duration in seconds."""
        if len(self.frames) < 2:
            return 0.0
        return round(self.frames[-1].timestamp - self.frames[0].timestamp, 3)

    def get_status(self) -> dict:
        """Returns comprehensive replay status metadata."""
        cur_ts = self.frames[self.current_idx].timestamp if self.frames and self.current_idx < len(self.frames) else 0
        start_ts = self.frames[0].timestamp if self.frames else 0
        elapsed = max(0.0, cur_ts - start_ts) if start_ts else 0.0

        return {
            'state': self.state,
            'current_index': self.current_idx,
            'total_frames': len(self.frames),
            'progress_percent': self.get_progress(),
            'speed': self.speed,
            'elapsed_sec': round(elapsed, 2),
            'total_duration_sec': self.get_duration(),
            'file_name': os.path.basename(self.file_path) if self.file_path else 'Memory Capture',
        }

    # ─── BaseInput Integration (CLI: airtap -r FILE) ─────────────────────────

    def read_loop(self):
        """
        Entry point used by BaseInput._read_thread() when the replayer is the
        CLI input source. The GUI drives play()/pause() itself and never goes
        through here.

        load() leaves the replayer PAUSED, so start playback explicitly, then
        block until the worker finishes (or stop() is called). Returning early
        would end BaseInput.run() and tear the modules down before any frame
        was dispatched.
        """
        if not self.frames and not self.load():
            return

        if not self.play():
            return

        worker = self._worker_thread
        while worker is not None and worker.is_alive() and not self._stop_event.is_set():
            worker.join(0.2)

    # ─── Internal Worker Loop ────────────────────────────────────────────────

    def _run_replay(self):
        last_frame_ts = None

        while not self._stop_event.is_set() and self.current_idx < len(self.frames):
            self._pause_event.wait()
            if self._stop_event.is_set():
                break

            with self._lock:
                frame = self.frames[self.current_idx]
                self.current_idx += 1

            # Dispatch frame to all active modules & GUI
            self._dispatch_frame(frame)

            # Timing & delay calculations for smooth realistic replay
            if self.speed > 0 and self.current_idx < len(self.frames):
                next_ts = self.frames[self.current_idx].timestamp
                delta = max(0.0, next_ts - frame.timestamp)
                if delta > 0:
                    delay = delta / self.speed
                    # Cap excessive idle gap delays to 2 seconds
                    delay = min(delay, 2.0)
                    time.sleep(delay)

        with self._lock:
            if self.current_idx >= len(self.frames):
                self.state = self.STATE_COMPLETED
                self._notify_event('completed', self.get_status())

    def _dispatch_frame(self, frame: ReplayFrame):
        self.timestamp = frame.timestamp
        self.dispatch_diag_log(frame.log_type, frame.log_data, frame.log_header, frame.timestamp)

    def _notify_event(self, event_type: str, data: dict):
        if self.on_event_callback:
            try:
                self.on_event_callback(event_type, data)
            except Exception:
                pass
