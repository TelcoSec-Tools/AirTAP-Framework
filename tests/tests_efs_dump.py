#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

from unittest import TestCase, main
from unittest.mock import MagicMock
from tempfile import TemporaryDirectory
from struct import pack, calcsize
from os.path import join, exists, isdir
import os

from src.modules.efs_dump import EfsDumper
from src.protocol.messages import DIAG_SUBSYS_CMD_F
from src.protocol.subsystems import DIAG_SUBSYS_FS
from src.protocol.efs2 import EFS2_DIAG_OPENDIR, EFS2_DIAG_READDIR, EFS2_DIAG_CLOSEDIR, EFS2_DIAG_OPEN, EFS2_DIAG_READ, EFS2_DIAG_CLOSE

class TestEfsDumper(TestCase):

    def test_efs_dump_traversal_and_file_writing(self):
        diag_input = MagicMock()
        diag_input.shutdown_event = MagicMock()

        # Build mock readdir payload for root directory containing 1 dir ('nv') and 1 file ('test.txt')
        readdir_struct = '<BHI8i'

        dir_entry = pack(readdir_struct,
            DIAG_SUBSYS_FS, EFS2_DIAG_READDIR,
            1, 1, 0,
            0x01, 0o040755, 0, 0, 0, 0
        ) + b'nv\x00'

        file_entry = pack(readdir_struct,
            DIAG_SUBSYS_FS, EFS2_DIAG_READDIR,
            1, 2, 0,
            0x00, 0o100644, 11, 0, 0, 0
        ) + b'test.txt\x00'

        empty_entry = pack(readdir_struct,
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
                            return DIAG_SUBSYS_CMD_F, dir_entry
                        elif seq == 2:
                            return DIAG_SUBSYS_CMD_F, file_entry
                        else:
                            return DIAG_SUBSYS_CMD_F, empty_entry
                    else:
                        return DIAG_SUBSYS_CMD_F, empty_entry
                elif subcmd == EFS2_DIAG_CLOSEDIR:
                    return DIAG_SUBSYS_CMD_F, pack('<BHi', DIAG_SUBSYS_FS, EFS2_DIAG_CLOSEDIR, 0)
                elif subcmd == EFS2_DIAG_OPEN:
                    return DIAG_SUBSYS_CMD_F, pack('<BHIi', DIAG_SUBSYS_FS, EFS2_DIAG_OPEN, 2, 0)
                elif subcmd == EFS2_DIAG_READ:
                    read_resp_struct = '<BHiIii'
                    data = b'hello world'
                    return DIAG_SUBSYS_CMD_F, pack(read_resp_struct, DIAG_SUBSYS_FS, EFS2_DIAG_READ, 2, 0, len(data), 0) + data
                elif subcmd == EFS2_DIAG_CLOSE:
                    return DIAG_SUBSYS_CMD_F, pack('<BHi', DIAG_SUBSYS_FS, EFS2_DIAG_CLOSE, 0)

            return DIAG_SUBSYS_CMD_F, b''

        diag_input.send_recv.side_effect = mock_send_recv

        with TemporaryDirectory() as temp_dir:
            dump_dir = join(temp_dir, 'dump')
            dumper = EfsDumper(diag_input, dump_dir)
            dumper.on_init()

            self.assertTrue(exists(dump_dir))
            self.assertTrue(exists(join(dump_dir, 'test.txt')))
            with open(join(dump_dir, 'test.txt'), 'rb') as f:
                self.assertEqual(f.read(), b'hello world')
            self.assertGreaterEqual(dumper.total_files, 1)

if __name__ == '__main__':
    main()
