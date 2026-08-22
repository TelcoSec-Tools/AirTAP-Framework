#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

import unittest
from unittest.mock import MagicMock
from struct import pack
from argparse import ArgumentParser
import io
import sys

from src.protocol.subsystems import DIAG_SUBSYS_FS
from src.protocol.messages import DIAG_SUBSYS_CMD_F
from src.protocol.efs2 import EFS2_DIAG_OPENDIR, EFS2_DIAG_READDIR, EFS2_DIAG_CLOSEDIR, EFS2_DIAG_STATFS, EFS2_DIAG_OPEN, EFS2_DIAG_READ, EFS2_DIAG_CLOSE, EFS2_DIAG_MD5SUM
from src.modules.efs_shell_commands.tree import TreeCommand
from src.modules.efs_shell_commands.statfs import StatfsCommand
from src.modules.efs_shell_commands.grep import GrepCommand
from src.modules.efs_shell_commands.md5sum import Md5sumCommand
from src.modules.efs_shell import EfsShell


class TestEfsCommands(unittest.TestCase):

    def setUp(self):
        self.diag_input = MagicMock()

    def test_efs_shell_registers_all_commands(self):
        shell = EfsShell(self.diag_input)
        command_names = shell.sub_parser_command_name_to_command_object.keys()
        self.assertIn('tree', command_names)
        self.assertIn('statfs', command_names)
        self.assertIn('grep', command_names)
        self.assertIn('find', command_names)
        self.assertIn('cat', command_names)
        self.assertIn('md5sum', command_names)

    def test_statfs_command_execution(self):
        # Mock STATFS response:
        # <BHI 8i: subsystem(19), subcommand(19), err(0), f_type(0), f_bsize(4096), f_blocks(1000), f_bfree(600), f_bavail(600), f_files(500), f_ffree(300), f_favail(300)
        resp_payload = pack('<BHI8i', DIAG_SUBSYS_FS, EFS2_DIAG_STATFS, 0, 0, 4096, 1000, 600, 600, 500, 300, 300)
        self.diag_input.send_recv.return_value = (DIAG_SUBSYS_CMD_F, resp_payload)

        cmd = StatfsCommand()
        subparsers = ArgumentParser().add_subparsers()
        parser = cmd.get_argument_parser(subparsers)
        args = parser.parse_args(['/nv', '-H'])

        # Capture output
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            cmd.execute_command(self.diag_input, args)
            out = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout

        self.assertIn('EFS2 Flash Filesystem', out)
        self.assertIn('4096 bytes', out)
        self.assertIn('3.9 MB', out) # 1000 * 4096 = 4096000 B ~ 3.9 MB
        self.assertIn('40.0%', out) # 400 used / 1000 total = 40%

    def test_tree_command_execution(self):
        # Mock OPENDIR and READDIR
        opendir_resp = pack('<BHIi', DIAG_SUBSYS_FS, EFS2_DIAG_OPENDIR, 1, 0)
        
        # Entry 1: 'item_file.nv' (regular file, size 128)
        readdir_1 = pack('<BHI8i', DIAG_SUBSYS_FS, EFS2_DIAG_READDIR, 1, 1, 0, 0, 0o100644, 128, 0, 0, 0) + b'item_file.nv\x00'
        # Entry 2: empty to terminate
        readdir_2 = pack('<BHI8i', DIAG_SUBSYS_FS, EFS2_DIAG_READDIR, 1, 2, 0, 0, 0, 0, 0, 0, 0)

        closedir_resp = pack('<BHi', DIAG_SUBSYS_FS, EFS2_DIAG_CLOSEDIR, 0)

        self.diag_input.send_recv.side_effect = [
            (DIAG_SUBSYS_CMD_F, opendir_resp),
            (DIAG_SUBSYS_CMD_F, readdir_1),
            (DIAG_SUBSYS_CMD_F, readdir_2),
            (DIAG_SUBSYS_CMD_F, closedir_resp),
        ]

        cmd = TreeCommand()
        subparsers = ArgumentParser().add_subparsers()
        parser = cmd.get_argument_parser(subparsers)
        args = parser.parse_args(['/nv', '-s'])

        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            cmd.execute_command(self.diag_input, args)
            out = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout

        self.assertIn('item_file.nv', out)
        self.assertIn('128 B', out)
        self.assertIn('1 files', out)

    def test_grep_command_text_match(self):
        # Mock OPENDIR failing (it's a file), then OPEN, READ, CLOSE
        opendir_err = pack('<BHIi', DIAG_SUBSYS_FS, EFS2_DIAG_OPENDIR, 0, 1)
        open_resp = pack('<BHIi', DIAG_SUBSYS_FS, EFS2_DIAG_OPEN, 2, 0)
        match_data = b"carrier_apn=internet.telecom.net\nother_param=123\n"
        read_resp = pack('<BHiIii', DIAG_SUBSYS_FS, EFS2_DIAG_READ, 2, 0, len(match_data), 0) + match_data
        close_resp = pack('<BHi', DIAG_SUBSYS_FS, EFS2_DIAG_CLOSE, 0)

        self.diag_input.send_recv.side_effect = [
            (DIAG_SUBSYS_CMD_F, opendir_err),
            (DIAG_SUBSYS_CMD_F, open_resp),
            (DIAG_SUBSYS_CMD_F, read_resp),
            (DIAG_SUBSYS_CMD_F, close_resp),
        ]

        cmd = GrepCommand()
        subparsers = ArgumentParser().add_subparsers()
        parser = cmd.get_argument_parser(subparsers)
        args = parser.parse_args(['carrier_apn', '/nv/item_file.nv', '-n'])

        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            cmd.execute_command(self.diag_input, args)
            out = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout

        self.assertIn('/nv/item_file.nv:1:carrier_apn=internet.telecom.net', out)

    def test_md5sum_command_execution(self):
        # Mock MD5SUM response (<BHHi 16B hash)
        expected_hash = bytes.fromhex('5d41402abc4b2a76b9719d911017c592')
        md5_resp = pack('<BHHi', DIAG_SUBSYS_FS, EFS2_DIAG_MD5SUM, 1, 0) + expected_hash
        self.diag_input.send_recv.return_value = (DIAG_SUBSYS_CMD_F, md5_resp)

        cmd = Md5sumCommand()
        subparsers = ArgumentParser().add_subparsers()
        parser = cmd.get_argument_parser(subparsers)
        args = parser.parse_args(['/nv/item_file.nv'])

        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            cmd.execute_command(self.diag_input, args)
            out = sys.stdout.getvalue().strip()
        finally:
            sys.stdout = old_stdout

        self.assertEqual(out, '5d41402abc4b2a76b9719d911017c592')


if __name__ == '__main__':
    unittest.main()
