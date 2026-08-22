#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

from os.path import basename, realpath, dirname, expanduser, exists, isdir, join
from argparse import ArgumentParser, _SubParsersAction, Namespace
from struct import pack, unpack, calcsize
from typing import List, Dict, Optional
from os import strerror, getcwd, makedirs
from datetime import datetime

from ._base_efs_shell_command import BaseEfsShellCommand
from ...inputs._base_input import message_id_to_name
from ...protocol.subsystems import *
from ...protocol.messages import *
from ...protocol.efs2 import *

class GetCommand(BaseEfsShellCommand):

    def get_argument_parser(self, subparsers_object: _SubParsersAction) -> ArgumentParser:
        argument_parser = subparsers_object.add_parser(
            'get',
            description="Read a file or directory in the EFS and download it to the disk."
        )
        argument_parser.add_argument('-r', '--recursive', action='store_true', help='Download directories recursively')
        argument_parser.add_argument('remote_src', help='Remote source path in EFS')
        argument_parser.add_argument('local_dst', nargs='?', help='Local destination path')

        return argument_parser

    def execute_command(self, diag_input, args: Namespace):
        remote_src: str = args.remote_src
        local_dst: str = expanduser(args.local_dst or (getcwd() + '/' + basename(remote_src.rstrip('/'))))

        if args.recursive:
            self._get_recursive(diag_input, remote_src, local_dst)
        else:
            self._get_single_file(diag_input, remote_src, local_dst)

    def _get_single_file(self, diag_input, remote_src: str, local_dst: str):
        if exists(local_dst) and isdir(local_dst):
            local_dst = join(local_dst, basename(remote_src))

        local_dir = realpath(dirname(local_dst))
        if not exists(local_dir):
            try:
                makedirs(local_dir, exist_ok=True)
            except Exception as e:
                print(f'Error creating directory "{local_dir}": {e}')
                return

        opcode, payload = diag_input.send_recv(DIAG_SUBSYS_CMD_F, pack('<BHii',
            DIAG_SUBSYS_FS,
            EFS2_DIAG_OPEN,
            0x0,
            0,
        ) + remote_src.encode('latin1').decode('unicode_escape').encode('latin1') + b'\x00', accept_error=True)

        if opcode != DIAG_SUBSYS_CMD_F:
            print('Error executing OPEN: %s received with payload "%s"' % (message_id_to_name.get(opcode, opcode), repr(payload)))
            return

        (cmd_subsystem_id, subcommand_code, file_fd, errno) = unpack('<BHIi', payload)
        if errno:
            print('Error executing OPEN: %s' % (EFS2_ERROR_CODES.get(errno) or strerror(errno)))
            return

        try:
            BYTES_TO_READ = 1024
            with open(local_dst, 'wb') as output_file:
                while True:
                    opcode, payload = diag_input.send_recv(DIAG_SUBSYS_CMD_F, pack('<BHiII',
                        DIAG_SUBSYS_FS,
                        EFS2_DIAG_READ,
                        file_fd,
                        BYTES_TO_READ,
                        output_file.tell()
                    ))

                    read_struct = '<BHiIii'
                    if len(payload) < calcsize(read_struct):
                        break

                    (cmd_subsystem_id, subcommand_code,
                     file_fd, offset, num_bytes_read,
                     errno) = unpack(read_struct, payload[:calcsize(read_struct)])

                    read_data: bytes = payload[calcsize(read_struct):]
                    output_file.write(read_data)

                    if errno:
                        print('Error executing READ: %s' % (EFS2_ERROR_CODES.get(errno) or strerror(errno)))
                        return

                    if len(read_data) < BYTES_TO_READ:
                        break
        finally:
            opcode, payload = diag_input.send_recv(DIAG_SUBSYS_CMD_F, pack('<BHi',
                DIAG_SUBSYS_FS,
                EFS2_DIAG_CLOSE,
                file_fd
            ))

    def _get_recursive(self, diag_input, remote_dir: str, local_dir: str):
        makedirs(local_dir, exist_ok=True)
        remote_dir_clean = remote_dir.rstrip('/') or '/'

        opcode, payload = diag_input.send_recv(
            DIAG_SUBSYS_CMD_F,
            pack('<BH', DIAG_SUBSYS_FS, EFS2_DIAG_OPENDIR) + remote_dir_clean.encode('latin1') + b'\x00',
            accept_error=True
        )

        if opcode != DIAG_SUBSYS_CMD_F:
            # Maybe it's a file, fallback to single file
            self._get_single_file(diag_input, remote_dir, local_dir)
            return

        cmd_subsystem_id, subcommand_code, dir_fd, err = unpack('<BHIi', payload)
        if err:
            # Fallback to single file if not a directory
            self._get_single_file(diag_input, remote_dir, local_dir)
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
            remote_subpath = (remote_dir.rstrip('/') + '/' + entry_name)
            local_subpath = join(local_dir, entry_name)
            is_directory = (entry_type == 0x01) or ((mode & 0o170000) == 0o040000)

            if is_directory:
                self._get_recursive(diag_input, remote_subpath, local_subpath)
            else:
                self._get_single_file(diag_input, remote_subpath, local_subpath)
