#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

from unittest import TestCase, main
from unittest.mock import MagicMock
from argparse import Namespace
from tempfile import TemporaryDirectory
from struct import pack
from os.path import join, exists

from src.modules.efs_shell_commands.find import FindCommand
from src.modules.efs_shell_commands.get import GetCommand
from src.protocol.messages import DIAG_SUBSYS_CMD_F
from src.protocol.subsystems import DIAG_SUBSYS_FS
from src.protocol.efs2 import EFS2_DIAG_OPENDIR, EFS2_DIAG_READDIR, EFS2_DIAG_CLOSEDIR, EFS2_DIAG_OPEN, EFS2_DIAG_READ, EFS2_DIAG_CLOSE

class TestEfsShellCommands(TestCase):

    def setUp(self):
        self.diag_input = MagicMock()

        readdir_struct = '<BHI8i'

        # Entry 1: nv (directory)
        self.entry_dir = pack(readdir_struct,
            DIAG_SUBSYS_FS, EFS2_DIAG_READDIR,
            1, 1, 0,
            0x01, 0o040755, 0, 0, 0, 0
        ) + b'nv\x00'

        # Entry 2: config.nv (file)
        self.entry_file = pack(readdir_struct,
            DIAG_SUBSYS_FS, EFS2_DIAG_READDIR,
            1, 2, 0,
            0x00, 0o100644, 5, 0, 0, 0
        ) + b'config.nv\x00'

        self.empty_entry = pack(readdir_struct,
            DIAG_SUBSYS_FS, EFS2_DIAG_READDIR,
            1, 3, 0,
            0x00, 0, 0, 0, 0, 0
        ) + b'\x00'

        current_dir_path = ['/']

        def mock_send_recv(opcode, payload, accept_error=False):
            if opcode == DIAG_SUBSYS_CMD_F:
                subsys_id, subcmd = payload[0], payload[1] | (payload[2] << 8) if len(payload) >= 3 else (0, 0)
                if subcmd == EFS2_DIAG_OPENDIR:
                    path_str = payload[3:].rstrip(b'\x00').decode('latin1', errors='replace')
                    current_dir_path[0] = path_str or '/'
                    return DIAG_SUBSYS_CMD_F, pack('<BHIi', DIAG_SUBSYS_FS, EFS2_DIAG_OPENDIR, 1, 0)
                elif subcmd == EFS2_DIAG_READDIR:
                    seq = payload[7] if len(payload) > 7 else 1
                    if current_dir_path[0] == '/':
                        if seq == 1:
                            return DIAG_SUBSYS_CMD_F, self.entry_dir
                        elif seq == 2:
                            return DIAG_SUBSYS_CMD_F, self.entry_file
                        else:
                            return DIAG_SUBSYS_CMD_F, self.empty_entry
                    else:
                        return DIAG_SUBSYS_CMD_F, self.empty_entry
                elif subcmd == EFS2_DIAG_CLOSEDIR:
                    return DIAG_SUBSYS_CMD_F, pack('<BHi', DIAG_SUBSYS_FS, EFS2_DIAG_CLOSEDIR, 0)
                elif subcmd == EFS2_DIAG_OPEN:
                    return DIAG_SUBSYS_CMD_F, pack('<BHIi', DIAG_SUBSYS_FS, EFS2_DIAG_OPEN, 1, 0)
                elif subcmd == EFS2_DIAG_READ:
                    read_resp = '<BHiIii'
                    return DIAG_SUBSYS_CMD_F, pack(read_resp, DIAG_SUBSYS_FS, EFS2_DIAG_READ, 1, 0, 5, 0) + b'hello'
                elif subcmd == EFS2_DIAG_CLOSE:
                    return DIAG_SUBSYS_CMD_F, pack('<BHi', DIAG_SUBSYS_FS, EFS2_DIAG_CLOSE, 0)
            return DIAG_SUBSYS_CMD_F, b''

        self.diag_input.send_recv.side_effect = mock_send_recv

    def test_find_command(self):
        find_cmd = FindCommand()
        args = Namespace(path='/', name_pattern='*.nv')
        # Execute without raising exceptions
        find_cmd.execute_command(self.diag_input, args)

    def test_get_recursive_command(self):
        get_cmd = GetCommand()
        with TemporaryDirectory() as temp_dir:
            dst = join(temp_dir, 'out_dir')
            args = Namespace(remote_src='/', local_dst=dst, recursive=True)
            get_cmd.execute_command(self.diag_input, args)
            self.assertTrue(exists(dst))

if __name__ == '__main__':
    main()
