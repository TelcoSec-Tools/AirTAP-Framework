#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

from argparse import ArgumentParser, _SubParsersAction, Namespace
from struct import pack, unpack, calcsize
from typing import Optional
from os import strerror

from ._base_efs_shell_command import BaseEfsShellCommand
from ...inputs._base_input import message_id_to_name
from ...protocol.subsystems import *
from ...protocol.messages import *
from ...protocol.efs2 import *


class StatfsCommand(BaseEfsShellCommand):

    def get_argument_parser(self, subparsers_object: _SubParsersAction) -> ArgumentParser:
        argument_parser = subparsers_object.add_parser(
            'statfs',
            description='Display filesystem partition capacity, block counts, and free space (similar to df).'
        )
        argument_parser.add_argument('path', nargs='?', default='/', help='EFS path on the filesystem to query (default: /)')
        argument_parser.add_argument('-H', '--human-readable', action='store_true', help='Print sizes in human-readable powers of 1024 (e.g., 10MB, 2GB)')

        return argument_parser

    def execute_command(self, diag_input, args: Namespace):
        remote_path = args.path.rstrip('/') or '/'
        human_readable = getattr(args, 'human_readable', False)

        # Send EFS2_DIAG_STATFS (19) or EFS2_DIAG_STATVFS_V2 (42)
        opcode, payload = diag_input.send_recv(
            DIAG_SUBSYS_CMD_F,
            pack('<BH', DIAG_SUBSYS_FS, EFS2_DIAG_STATFS) + remote_path.encode('latin1') + b'\x00',
            accept_error=True
        )

        if opcode != DIAG_SUBSYS_CMD_F or len(payload) < 8:
            print(f"Error executing STATFS: unexpected response opcode {message_id_to_name.get(opcode, opcode)}")
            return

        cmd_subsystem_id, subcommand_code, err = unpack('<BHI', payload[:7])
        if err != 0:
            err_name = EFS2_ERROR_CODES.get(err, strerror(err) if err < 256 else f'Error #{err}')
            print(f"Error querying STATFS for '{remote_path}': {err_name}")
            return

        # Expected payload struct: <BHI i i i i i i i i (f_type, f_bsize, f_blocks, f_bfree, f_bavail, f_files, f_ffree, f_favail)
        statfs_fmt = '<BHI8i'
        if len(payload) >= calcsize(statfs_fmt):
            (cmd_subsystem_id, subcommand_code, err,
             f_type, f_bsize, f_blocks, f_bfree, f_bavail,
             f_files, f_ffree, f_favail) = unpack(statfs_fmt, payload[:calcsize(statfs_fmt)])

            f_bsize = max(f_bsize, 512)
            total_bytes = f_blocks * f_bsize
            free_bytes = f_bfree * f_bsize
            used_bytes = max(total_bytes - free_bytes, 0)
            use_percent = round((used_bytes / total_bytes * 100.0), 1) if total_bytes > 0 else 0.0

            def fmt_size(num_bytes: int) -> str:
                if not human_readable:
                    return f"{num_bytes} B"
                for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
                    if abs(num_bytes) < 1024.0:
                        return f"{num_bytes:.1f} {unit}"
                    num_bytes /= 1024.0
                return f"{num_bytes:.1f} PB"

            fs_types = {
                0x0000: 'EFS2 Flash Filesystem',
                0xEF53: 'EXT2/EXT3/EXT4 Linux Filesystem',
                0x4D44: 'FAT / FAT32 Filesystem',
                0x5846: 'XFS Filesystem',
            }
            fs_name = fs_types.get(f_type, f"EFS2 Type 0x{f_type:04X}")

            print(f"Filesystem:        {fs_name}")
            print(f"Mount / Path:      {remote_path}")
            print(f"Block Size:        {f_bsize} bytes")
            print(f"Total Capacity:    {fmt_size(total_bytes)} ({f_blocks} blocks)")
            print(f"Used Space:        {fmt_size(used_bytes)} ({use_percent}%)")
            print(f"Free Space:        {fmt_size(free_bytes)} ({f_bfree} blocks available)")
            print(f"Total Inodes/Files:{f_files}")
            print(f"Free Inodes/Files: {f_ffree}")
        else:
            print(f"STATFS executed successfully on '{remote_path}' (raw response {len(payload)} bytes).")
