#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

from os.path import realpath, expanduser, join, isdir
from struct import pack, unpack, calcsize
from logging import error, warning, info
from os import makedirs, strerror
import os

from ..inputs._base_input import message_id_to_name
from ..protocol.subsystems import *
from ..protocol.messages import *
from ..protocol.efs2 import *

class EfsDumper:

    """
        This module recursively dumps the entire EFS filesystem of the device
        to a specified local output directory.
    """

    def __init__(self, diag_input, output_dir: str):
        self.diag_input = diag_input
        self.output_dir = realpath(expanduser(output_dir))
        self.total_files = 0
        self.total_dirs = 0
        self.total_bytes = 0

    def on_init(self):
        print(f'[*] Starting recursive EFS dump to: {self.output_dir}')
        makedirs(self.output_dir, exist_ok=True)

        try:
            self._dump_directory('/', self.output_dir)
            print(f'[+] EFS dump complete!')
            print(f'[+] Dumped {self.total_files} file(s) across {self.total_dirs} directory/ies ({self.total_bytes} bytes total).')
        except Exception as e:
            error(f'Error during EFS dump: {e}')
        finally:
            with self.diag_input.shutdown_event:
                self.diag_input.shutdown_event.notify()

    def _dump_directory(self, remote_dir: str, local_dir: str):
        self.total_dirs += 1
        makedirs(local_dir, exist_ok=True)

        remote_dir_encoded = remote_dir.rstrip('/')
        if not remote_dir_encoded:
            remote_dir_encoded = '/'

        opcode, payload = self.diag_input.send_recv(
            DIAG_SUBSYS_CMD_F,
            pack('<BH', DIAG_SUBSYS_FS, EFS2_DIAG_OPENDIR) + remote_dir_encoded.encode('latin1') + b'\x00',
            accept_error=True
        )

        if opcode != DIAG_SUBSYS_CMD_F:
            warning(f'Could not open remote directory {remote_dir}: opcode {message_id_to_name.get(opcode, opcode)}')
            return

        cmd_subsystem_id, subcommand_code, dir_fd, err = unpack('<BHIi', payload)
        if err:
            warning(f'Could not open remote directory {remote_dir}: {EFS2_ERROR_CODES.get(err) or strerror(err)}')
            return

        entries = []
        try:
            sequence_number = 1
            while True:
                opcode, payload = self.diag_input.send_recv(
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
            self.diag_input.send_recv(
                DIAG_SUBSYS_CMD_F,
                pack('<BHi', DIAG_SUBSYS_FS, EFS2_DIAG_CLOSEDIR, dir_fd)
            )

        for entry_name, entry_type, mode, size in entries:
            remote_path = (remote_dir.rstrip('/') + '/' + entry_name)
            local_path = join(local_dir, entry_name)

            is_directory = (entry_type == 0x01) or ((mode & 0o170000) == 0o040000)

            if is_directory:
                print(f'  [DIR]  {remote_path}')
                self._dump_directory(remote_path, local_path)
            else:
                print(f'  [FILE] {remote_path} ({size} bytes)')
                self._dump_file(remote_path, local_path)

    def _dump_file(self, remote_file: str, local_file: str):
        opcode, payload = self.diag_input.send_recv(
            DIAG_SUBSYS_CMD_F,
            pack('<BHii', DIAG_SUBSYS_FS, EFS2_DIAG_OPEN, 0x0, 0) + remote_file.encode('latin1') + b'\x00',
            accept_error=True
        )

        if opcode != DIAG_SUBSYS_CMD_F:
            warning(f'Could not open remote file {remote_file}')
            return

        cmd_subsystem_id, subcommand_code, file_fd, err = unpack('<BHIi', payload)
        if err:
            warning(f'Error opening {remote_file}: {EFS2_ERROR_CODES.get(err) or strerror(err)}')
            return

        bytes_read_total = 0
        BYTES_CHUNK = 1024

        try:
            with open(local_file, 'wb') as out_f:
                while True:
                    opcode, payload = self.diag_input.send_recv(
                        DIAG_SUBSYS_CMD_F,
                        pack('<BHiII', DIAG_SUBSYS_FS, EFS2_DIAG_READ, file_fd, BYTES_CHUNK, out_f.tell())
                    )

                    read_struct = '<BHiIii'
                    if len(payload) < calcsize(read_struct):
                        break

                    (cmd_subsystem_id, subcommand_code,
                     file_fd, offset, num_bytes_read,
                     err) = unpack(read_struct, payload[:calcsize(read_struct)])

                    read_data = payload[calcsize(read_struct):]
                    out_f.write(read_data)
                    bytes_read_total += len(read_data)

                    if err or len(read_data) < BYTES_CHUNK:
                        break

            self.total_files += 1
            self.total_bytes += bytes_read_total
        except Exception as e:
            warning(f'Failed writing {local_file}: {e}')
        finally:
            self.diag_input.send_recv(
                DIAG_SUBSYS_CMD_F,
                pack('<BHi', DIAG_SUBSYS_FS, EFS2_DIAG_CLOSE, file_fd)
            )

    def on_deinit(self):
        pass
