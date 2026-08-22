#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

from argparse import ArgumentParser, _SubParsersAction, Namespace
from struct import pack, unpack, calcsize
from typing import List, Tuple, Optional
import re

from ._base_efs_shell_command import BaseEfsShellCommand
from ...protocol.subsystems import *
from ...protocol.messages import *
from ...protocol.efs2 import *


class GrepCommand(BaseEfsShellCommand):

    def get_argument_parser(self, subparsers_object: _SubParsersAction) -> ArgumentParser:
        argument_parser = subparsers_object.add_parser(
            'grep',
            description='Search for text strings or hex byte patterns within files in EFS recursively.'
        )
        argument_parser.add_argument('pattern', help='String or regex pattern to search for')
        argument_parser.add_argument('path', nargs='?', default='/', help='EFS path or directory to search (default: /)')
        argument_parser.add_argument('-i', '--ignore-case', action='store_true', help='Perform case-insensitive matching')
        argument_parser.add_argument('-n', '--line-number', action='store_true', help='Prefix each line of output with the 1-based line number')
        argument_parser.add_argument('-x', '--hex', action='store_true', help='Treat pattern as hex bytes (e.g., "0829" or "deadbeef")')

        return argument_parser

    def execute_command(self, diag_input, args: Namespace):
        remote_path = args.path.rstrip('/') or '/'
        pattern_str = args.pattern
        is_hex = getattr(args, 'hex', False)
        ignore_case = getattr(args, 'ignore_case', False)
        show_line_no = getattr(args, 'line_number', False)

        if is_hex:
            pattern_bytes = bytes.fromhex(pattern_str.replace(' ', ''))
        else:
            flags = re.IGNORECASE if ignore_case else 0
            regex = re.compile(pattern_str.encode('utf-8', errors='ignore'), flags)

        self._grep_path(diag_input, remote_path, regex if not is_hex else pattern_bytes, is_hex, show_line_no)

    def _grep_path(self, diag_input, current_path: str, pattern, is_hex: bool, show_line_no: bool):
        # Open directory or test if it is a directory
        opcode, payload = diag_input.send_recv(
            DIAG_SUBSYS_CMD_F,
            pack('<BH', DIAG_SUBSYS_FS, EFS2_DIAG_OPENDIR) + current_path.encode('latin1') + b'\x00',
            accept_error=True
        )

        is_dir = False
        dir_fd = None
        if opcode == DIAG_SUBSYS_CMD_F and len(payload) >= 11:
            _, _, dir_fd, err = unpack('<BHIi', payload[:11])
            if err == 0:
                is_dir = True

        if is_dir:
            entries = []
            try:
                sequence_number = 1
                while True:
                    opcode, payload = diag_input.send_recv(
                        DIAG_SUBSYS_CMD_F,
                        pack('<BHIi', DIAG_SUBSYS_FS, EFS2_DIAG_READDIR, dir_fd, sequence_number),
                        accept_error=False
                    )
                    readdir_struct = '<BHI8i'
                    if len(payload) < calcsize(readdir_struct):
                        break

                    (cmd_subsystem_id, subcommand_code,
                     dir_fd, sequence_number, err,
                     entry_type, mode, size,
                     atime, mtime, ctime) = unpack(readdir_struct, payload[:calcsize(readdir_struct)])

                    entry_name_bytes = payload[calcsize(readdir_struct):].rstrip(b'\x00')
                    if not entry_name_bytes:
                        break

                    entry_name = entry_name_bytes.decode('latin1', errors='replace')
                    if entry_name not in ('.', '..'):
                        entries.append((entry_name, entry_type, mode))

                    sequence_number += 1
            finally:
                diag_input.send_recv(
                    DIAG_SUBSYS_CMD_F,
                    pack('<BHi', DIAG_SUBSYS_FS, EFS2_DIAG_CLOSEDIR, dir_fd)
                )

            for entry_name, entry_type, mode in entries:
                sub_path = current_path.rstrip('/') + '/' + entry_name
                self._grep_path(diag_input, sub_path, pattern, is_hex, show_line_no)

        else:
            # It's a file, read and grep
            self._grep_file(diag_input, current_path, pattern, is_hex, show_line_no)

    def _grep_file(self, diag_input, file_path: str, pattern, is_hex: bool, show_line_no: bool):
        file_bytes = self._read_efs_file(diag_input, file_path)
        if not file_bytes:
            return

        if is_hex:
            if pattern in file_bytes:
                idx = file_bytes.find(pattern)
                print(f"{file_path}: match found at offset 0x{idx:X}")
        else:
            lines = file_bytes.splitlines()
            for line_idx, line in enumerate(lines, start=1):
                if pattern.search(line):
                    line_str = line.decode('utf-8', errors='replace').strip()
                    line_prefix = f":{line_idx}:" if show_line_no else ":"
                    print(f"{file_path}{line_prefix}{line_str}")

    def _read_efs_file(self, diag_input, file_path: str) -> bytes:
        opcode, payload = diag_input.send_recv(
            DIAG_SUBSYS_CMD_F,
            pack('<BHii', DIAG_SUBSYS_FS, EFS2_DIAG_OPEN, 0x0, 0) + file_path.encode('latin1') + b'\x00',
            accept_error=True
        )

        if opcode != DIAG_SUBSYS_CMD_F or len(payload) < 11:
            return b''

        _, _, file_fd, errno = unpack('<BHIi', payload[:11])
        if errno != 0:
            return b''

        bytes_read = b''
        read_struct = '<BHiIii'
        struct_len = calcsize(read_struct)

        try:
            while True:
                opcode, payload = diag_input.send_recv(
                    DIAG_SUBSYS_CMD_F,
                    pack('<BHiII', DIAG_SUBSYS_FS, EFS2_DIAG_READ, file_fd, 1024, len(bytes_read)),
                    accept_error=False
                )
                if opcode != DIAG_SUBSYS_CMD_F or len(payload) < struct_len:
                    break

                (cmd_subsystem_id, subcommand_code,
                 file_fd, offset, num_bytes_read,
                 errno) = unpack(read_struct, payload[:struct_len])

                if errno != 0:
                    break

                chunk = payload[struct_len:]
                if not chunk:
                    break
                bytes_read += chunk
                if len(chunk) < 1024:
                    break
        finally:
            diag_input.send_recv(
                DIAG_SUBSYS_CMD_F,
                pack('<BHi', DIAG_SUBSYS_FS, EFS2_DIAG_CLOSE, file_fd)
            )

        return bytes_read
