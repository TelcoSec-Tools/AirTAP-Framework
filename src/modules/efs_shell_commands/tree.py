#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

from argparse import ArgumentParser, _SubParsersAction, Namespace
from struct import pack, unpack, calcsize
from typing import List, Tuple

from ._base_efs_shell_command import BaseEfsShellCommand
from ...protocol.subsystems import *
from ...protocol.messages import *
from ...protocol.efs2 import *


class TreeCommand(BaseEfsShellCommand):

    def get_argument_parser(self, subparsers_object: _SubParsersAction) -> ArgumentParser:
        argument_parser = subparsers_object.add_parser(
            'tree',
            description='Display a graphical tree representation of directories and files in EFS.'
        )
        argument_parser.add_argument('path', nargs='?', default='/', help='Root directory to list (default: /)')
        argument_parser.add_argument('-d', '--dirs-only', action='store_true', help='List directories only')
        argument_parser.add_argument('-L', '--max-level', type=int, default=10, help='Max display depth of the directory tree (default: 10)')
        argument_parser.add_argument('-s', '--size', action='store_true', help='Print the size in bytes of each file')

        return argument_parser

    def execute_command(self, diag_input, args: Namespace):
        root_path = args.path.rstrip('/') or '/'
        print(root_path)

        dir_count, file_count = self._render_tree(
            diag_input, root_path, prefix='', current_level=1,
            max_level=args.max_level, dirs_only=args.dirs_only, show_size=args.size
        )

        print(f"\n{dir_count} directories" + (f", {file_count} files" if not args.dirs_only else ""))

    def _render_tree(self, diag_input, remote_dir: str, prefix: str, current_level: int,
                     max_level: int, dirs_only: bool, show_size: bool) -> Tuple[int, int]:
        if current_level > max_level:
            return (0, 0)

        entries = self._list_dir_entries(diag_input, remote_dir)
        if not entries:
            return (0, 0)

        if dirs_only:
            entries = [e for e in entries if e[1] == 0x01 or (e[2] & 0o170000) == 0o040000]

        dir_count = 0
        file_count = 0

        total_entries = len(entries)
        for i, (entry_name, entry_type, mode, size) in enumerate(entries):
            is_last = (i == total_entries - 1)
            connector = "\\-- " if is_last else "|-- "
            sub_prefix = "    " if is_last else "|   "

            is_dir = (entry_type == 0x01) or ((mode & 0o170000) == 0o040000)
            full_path = (remote_dir.rstrip('/') + '/' + entry_name)

            size_str = f" [{size} B]" if show_size and not is_dir else ""
            type_indicator = "/" if is_dir else ""
            print(f"{prefix}{connector}{entry_name}{type_indicator}{size_str}")

            if is_dir:
                dir_count += 1
                sub_dirs, sub_files = self._render_tree(
                    diag_input, full_path, prefix + sub_prefix, current_level + 1,
                    max_level, dirs_only, show_size
                )
                dir_count += sub_dirs
                file_count += sub_files
            else:
                file_count += 1

        return (dir_count, file_count)

    def _list_dir_entries(self, diag_input, remote_dir: str) -> List[Tuple[str, int, int, int]]:
        remote_dir_clean = remote_dir.rstrip('/') or '/'

        opcode, payload = diag_input.send_recv(
            DIAG_SUBSYS_CMD_F,
            pack('<BH', DIAG_SUBSYS_FS, EFS2_DIAG_OPENDIR) + remote_dir_clean.encode('latin1') + b'\x00',
            accept_error=True
        )

        if opcode != DIAG_SUBSYS_CMD_F or len(payload) < 11:
            return []

        cmd_subsystem_id, subcommand_code, dir_fd, err = unpack('<BHIi', payload[:11])
        if err:
            return []

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
                    entries.append((entry_name, entry_type, mode, size))

                sequence_number += 1
        finally:
            diag_input.send_recv(
                DIAG_SUBSYS_CMD_F,
                pack('<BHi', DIAG_SUBSYS_FS, EFS2_DIAG_CLOSEDIR, dir_fd)
            )

        return entries
