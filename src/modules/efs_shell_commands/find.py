#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

from argparse import ArgumentParser, _SubParsersAction, Namespace
from struct import pack, unpack, calcsize
from typing import List, Optional
from fnmatch import fnmatch
from os import strerror

from ._base_efs_shell_command import BaseEfsShellCommand
from ...inputs._base_input import message_id_to_name
from ...protocol.subsystems import *
from ...protocol.messages import *
from ...protocol.efs2 import *

class FindCommand(BaseEfsShellCommand):

    def get_argument_parser(self, subparsers_object: _SubParsersAction) -> ArgumentParser:
        argument_parser = subparsers_object.add_parser(
            'find',
            description='Search for files and directories matching a pattern in the EFS.'
        )
        argument_parser.add_argument('path', nargs='?', default='/', help='Root path to start searching from (default: /)')
        argument_parser.add_argument('-name', '--name', dest='name_pattern', default='*', help='Filename pattern to search for (glob style, e.g. "*.nv" or "item_*")')

        return argument_parser

    def execute_command(self, diag_input, args: Namespace):
        root_path = args.path.rstrip('/') or '/'
        pattern = args.name_pattern

        self._find_recursive(diag_input, root_path, pattern)

    def _find_recursive(self, diag_input, remote_dir: str, pattern: str):
        remote_dir_clean = remote_dir.rstrip('/') or '/'

        opcode, payload = diag_input.send_recv(
            DIAG_SUBSYS_CMD_F,
            pack('<BH', DIAG_SUBSYS_FS, EFS2_DIAG_OPENDIR) + remote_dir_clean.encode('latin1') + b'\x00',
            accept_error=True
        )

        if opcode != DIAG_SUBSYS_CMD_F:
            return

        cmd_subsystem_id, subcommand_code, dir_fd, err = unpack('<BHIi', payload)
        if err:
            return

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
            full_path = (remote_dir.rstrip('/') + '/' + entry_name)
            is_directory = (entry_type == 0x01) or ((mode & 0o170000) == 0o040000)

            if fnmatch(entry_name, pattern) or fnmatch(full_path, pattern):
                print(full_path + ('/' if is_directory else ''))

            if is_directory:
                self._find_recursive(diag_input, full_path, pattern)
