#!/usr/bin/env python3
#-*- encoding: utf-8 -*-

"""
    Tests that malformed or truncated data received from a modem is dropped
    with a diagnostic, rather than raising out of the dispatch path and
    killing a running capture.

    A Diag device is an untrusted source as far as AirTap is concerned: a
    buggy or unusual baseband can emit short frames, unknown log types and
    unknown EFS file modes. None of those should be fatal.
"""

from unittest import TestCase
from struct import pack, calcsize, error as struct_error
from logging import getLogger, WARNING
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.inputs._base_input import BaseInput
from src.protocol.messages import DIAG_LOG_F, DIAG_MULTI_RADIO_CMD_F, DIAG_MSG_F


class RecordingModule:
    """
    A module test double that records the callbacks it receives, standing in
    for a real module such as PcapDumper.
    """

    def __init__(self):
        self.logs = []
        self.messages = []
        self.events = []

    def on_log(self, log_type, log_payload, log_header, timestamp):
        self.logs.append((log_type, log_payload, log_header))

    def on_message(self, opcode, payload):
        self.messages.append((opcode, payload))

    def on_event(self, event_id, event_payload, timestamp):
        self.events.append((event_id, event_payload))


class ExplodingModule:
    """
    A module test double whose callbacks raise the kinds of exception a real
    module's struct-parsing code raises on a truncated payload.
    """

    def __init__(self, exception):
        self._exception = exception
        self.call_count = 0

    def on_log(self, log_type, log_payload, log_header, timestamp):
        self.call_count += 1
        raise self._exception

    def on_message(self, opcode, payload):
        self.call_count += 1
        raise self._exception

    def on_event(self, event_id, event_payload, timestamp):
        self.call_count += 1
        raise self._exception


def make_input():
    """
    Build a bare BaseInput. Its constructor performs no I/O and starts no
    threads, so it can be exercised directly.
    """

    return BaseInput()


def well_formed_diag_log_packet(log_type = 0x412f, log_payload = b'\xaa\xbb'):
    """
    Build a complete DIAG_LOG_F packet: opcode, outer header ('<BH'), inner
    header ('<HHQ'), then the inner payload.
    """

    inner = pack('<HHQ', calcsize('<HHQ') + len(log_payload), log_type, 0) + log_payload

    return bytes([DIAG_LOG_F]) + pack('<BH', 0, len(inner)) + inner


class DispatchRobustnessTests(TestCase):

    # --- Sanity checks: well-formed input must still be dispatched ---

    def test_well_formed_log_packet_is_dispatched_to_modules(self):
        diag_input = make_input()
        module = RecordingModule()
        diag_input.add_module(module)

        diag_input.dispatch_received_diag_packet(well_formed_diag_log_packet(
            log_type = 0x412f, log_payload = b'\xaa\xbb'))

        self.assertEqual(1, len(module.logs))
        log_type, log_payload, log_header = module.logs[0]
        self.assertEqual(0x412f, log_type)
        self.assertEqual(b'\xaa\xbb', log_payload)
        self.assertEqual(calcsize('<HHQ'), len(log_header))

    # --- Truncated frames ---

    def test_empty_diag_packet_is_dropped_without_raising(self):
        diag_input = make_input()
        module = RecordingModule()
        diag_input.add_module(module)

        diag_input.dispatch_received_diag_packet(b'')

        self.assertEqual([], module.logs)

    def test_log_packet_truncated_in_outer_header_is_dropped_without_raising(self):
        diag_input = make_input()
        module = RecordingModule()
        diag_input.add_module(module)

        # DIAG_LOG_F opcode with only one byte where '<BH' (3 bytes) is needed
        diag_input.dispatch_received_diag_packet(bytes([DIAG_LOG_F]) + b'\x00')

        self.assertEqual([], module.logs)

    def test_log_packet_truncated_in_inner_header_is_dropped_without_raising(self):
        diag_input = make_input()
        module = RecordingModule()
        diag_input.add_module(module)

        # Outer header complete, inner header ('<HHQ', 12 bytes) truncated to 4
        packet = bytes([DIAG_LOG_F]) + pack('<BH', 0, 4) + b'\x01\x02\x03\x04'

        diag_input.dispatch_received_diag_packet(packet)

        self.assertEqual([], module.logs)

    def test_truncated_log_packet_logs_a_warning(self):
        diag_input = make_input()

        with self.assertLogs(getLogger(), level = WARNING) as captured:
            diag_input.dispatch_received_diag_packet(bytes([DIAG_LOG_F]) + b'\x00')

        self.assertTrue(
            any('truncated' in line.lower() or 'malformed' in line.lower()
                for line in captured.output),
            'expected a warning naming the frame as truncated/malformed, got: %r'
                % captured.output)

    def test_multi_radio_packet_with_no_inner_payload_is_dropped_without_raising(self):
        diag_input = make_input()
        module = RecordingModule()
        diag_input.add_module(module)

        # DIAG_MULTI_RADIO_CMD_F strips 7 bytes before recursing; supply fewer,
        # so the recursive call would receive an empty packet.
        diag_input.dispatch_received_diag_packet(bytes([DIAG_MULTI_RADIO_CMD_F]) + b'\x00\x01')

        self.assertEqual([], module.logs)

    # --- Module callbacks that raise must not kill the capture ---

    def test_module_raising_struct_error_on_log_does_not_propagate(self):
        diag_input = make_input()
        diag_input.add_module(ExplodingModule(struct_error('unpack requires more bytes')))

        # Must not raise
        diag_input.dispatch_received_diag_packet(well_formed_diag_log_packet())

    def test_module_raising_on_log_does_not_prevent_later_modules(self):
        diag_input = make_input()
        exploding = ExplodingModule(struct_error('unpack requires more bytes'))
        recording = RecordingModule()
        diag_input.add_module(exploding)
        diag_input.add_module(recording)

        diag_input.dispatch_received_diag_packet(well_formed_diag_log_packet())

        self.assertEqual(1, exploding.call_count)
        self.assertEqual(1, len(recording.logs),
            'a parse failure in one module must not stop dispatch to the others')

    def test_module_raising_key_error_on_log_does_not_propagate(self):
        diag_input = make_input()
        diag_input.add_module(ExplodingModule(KeyError(0o170000)))

        diag_input.dispatch_received_diag_packet(well_formed_diag_log_packet())

    def test_module_raising_on_message_does_not_propagate(self):
        diag_input = make_input()
        exploding = ExplodingModule(struct_error('bad'))
        recording = RecordingModule()
        diag_input.add_module(exploding)
        diag_input.add_module(recording)

        diag_input.dispatch_received_diag_packet(bytes([DIAG_MSG_F]) + b'\x01\x02')

        self.assertEqual(1, len(recording.messages))

    def test_module_raising_on_event_does_not_propagate(self):
        diag_input = make_input()
        exploding = ExplodingModule(struct_error('bad'))
        recording = RecordingModule()
        diag_input.add_module(exploding)
        diag_input.add_module(recording)

        diag_input.dispatch_received_diag_packet(bytes([0x60]) + pack('<H', 0x1234) + b'\x09')

        self.assertEqual(1, len(recording.events))

    def test_module_failure_logs_a_warning_naming_the_module(self):
        diag_input = make_input()
        diag_input.add_module(ExplodingModule(struct_error('unpack requires more bytes')))

        with self.assertLogs(getLogger(), level = WARNING) as captured:
            diag_input.dispatch_received_diag_packet(well_formed_diag_log_packet())

        self.assertTrue(
            any('ExplodingModule' in line for line in captured.output),
            'expected the failing module to be named in the warning, got: %r'
                % captured.output)

    def test_keyboard_interrupt_from_module_is_not_swallowed(self):
        """
        The guard must not turn Ctrl-C into a warning; only data-parsing
        failures are recoverable.
        """

        diag_input = make_input()
        diag_input.add_module(ExplodingModule(KeyboardInterrupt()))

        with self.assertRaises(KeyboardInterrupt):
            diag_input.dispatch_received_diag_packet(well_formed_diag_log_packet())

    def test_broken_output_sink_is_not_swallowed(self):
        """
        A dead output sink (Wireshark closed its pipe) fails identically for
        every subsequent packet. Swallowing it would log a traceback per packet
        forever instead of shutting the capture down.
        """

        diag_input = make_input()
        diag_input.add_module(ExplodingModule(BrokenPipeError('the pipe is gone')))

        with self.assertRaises(BrokenPipeError):
            diag_input.dispatch_received_diag_packet(well_formed_diag_log_packet())

    def test_full_disk_on_output_is_not_swallowed(self):
        from errno import ENOSPC

        diag_input = make_input()
        diag_input.add_module(ExplodingModule(OSError(ENOSPC, 'No space left on device')))

        with self.assertRaises(OSError):
            diag_input.dispatch_received_diag_packet(well_formed_diag_log_packet())


class EfsShellCommandRobustnessTests(TestCase):
    """
    An EFS shell command parses a reply the modem composed. A malformed reply
    must end that one command with a diagnostic and return the user to the
    prompt, not tear down the interactive shell.
    """

    def make_shell(self):
        from src.modules.efs_shell import EfsShell

        # EfsShell.__init__ only builds argument parsers - no I/O, no device
        return EfsShell(diag_input = None)

    def test_command_raising_struct_error_returns_to_the_prompt(self):
        shell = self.make_shell()

        class ExplodingCommand:
            def execute_command(self, diag_input, args):
                raise struct_error('unpack requires a buffer of 12 bytes')

        # Must not raise
        shell._run_efs_command(ExplodingCommand(), None)

    def test_command_raising_key_error_returns_to_the_prompt(self):
        shell = self.make_shell()

        class ExplodingCommand:
            def execute_command(self, diag_input, args):
                raise KeyError(0o170000)

        shell._run_efs_command(ExplodingCommand(), None)

    def test_command_failure_is_reported_to_the_user(self):
        shell = self.make_shell()

        class ExplodingCommand:
            def execute_command(self, diag_input, args):
                raise struct_error('unpack requires a buffer of 12 bytes')

        with self.assertLogs(getLogger(), level = WARNING) as captured:
            shell._run_efs_command(ExplodingCommand(), None)

        self.assertTrue(any('ExplodingCommand' in line for line in captured.output),
            'expected the failing command to be named, got: %r' % captured.output)

    def test_local_file_error_is_not_blamed_on_the_modem(self):
        """
        "put /nonexistent /efs/x" fails in the local open(), before the modem
        is ever contacted. Reporting that as a bad device reply sends the user
        looking in entirely the wrong place.
        """

        shell = self.make_shell()

        class LocalFileCommand:
            def execute_command(self, diag_input, args):
                raise FileNotFoundError(2, 'No such file or directory', 'local_src.bin')

        with self.assertLogs(getLogger(), level = WARNING) as captured:
            shell._run_efs_command(LocalFileCommand(), None)

        joined = '\n'.join(captured.output)
        self.assertIn('LocalFileCommand', joined)
        self.assertIn('local_src.bin', joined,
            'the offending local path should be shown, got: %r' % captured.output)
        self.assertNotIn('device', joined.lower(),
            'a local file error must not be attributed to the device, got: %r'
                % captured.output)

    def test_systemexit_from_command_is_still_absorbed(self):
        """
        argparse and the command bodies use SystemExit as flow control; the
        pre-existing behaviour of swallowing it must be preserved.
        """

        shell = self.make_shell()

        class ExitingCommand:
            def execute_command(self, diag_input, args):
                raise SystemExit(2)

        shell._run_efs_command(ExitingCommand(), None)

    def test_keyboard_interrupt_from_command_is_not_swallowed(self):
        shell = self.make_shell()

        class InterruptedCommand:
            def execute_command(self, diag_input, args):
                raise KeyboardInterrupt()

        with self.assertRaises(KeyboardInterrupt):
            shell._run_efs_command(InterruptedCommand(), None)

    def test_successful_command_is_executed_with_the_diag_input(self):
        shell = self.make_shell()

        class RecordingCommand:
            def __init__(self):
                self.calls = []

            def execute_command(self, diag_input, args):
                self.calls.append((diag_input, args))

        command = RecordingCommand()
        sentinel_args = object()
        shell.diag_input = 'the-diag-input'

        shell._run_efs_command(command, sentinel_args)

        self.assertEqual([('the-diag-input', sentinel_args)], command.calls)


class ReadLoopErrorReportingTests(TestCase):
    """
    read_loop() reports why it is giving up. A genuine disconnect and an
    unexpected bug in the frame reader are different events and must not be
    reported with the same message - "the serial port was closed" sends
    someone chasing cables when the real cause is in the code.
    """

    def make_reader(self, exception):
        from src.inputs.usb_modem_pyserial import UsbModemPyserialConnector

        class ReadLoopUnderTest(UsbModemPyserialConnector):
            def __init__(self):
                # Deliberately skips the real constructor: it probes for
                # devices and spawns helper processes.
                self._exception = exception

            def _read_frame(self):
                raise self._exception

        return ReadLoopUnderTest()

    def test_disconnect_is_reported_as_a_closed_port(self):
        reader = self.make_reader(ConnectionError('Serial port returned no data'))

        with self.assertLogs(getLogger(), level = WARNING) as captured:
            with self.assertRaises(SystemExit):
                reader.read_loop()

        self.assertTrue(any('closed or preempted' in line for line in captured.output),
            'expected the disconnect message, got: %r' % captured.output)

    def test_unexpected_error_is_not_reported_as_a_closed_port(self):
        reader = self.make_reader(ValueError('a bug in the frame reader'))

        with self.assertLogs(getLogger(), level = WARNING) as captured:
            with self.assertRaises(SystemExit):
                reader.read_loop()

        joined = '\n'.join(captured.output)

        self.assertNotIn('closed or preempted', joined,
            'an unexpected exception must not be blamed on the serial port')

    def test_unexpected_error_reports_the_underlying_exception(self):
        reader = self.make_reader(ValueError('a bug in the frame reader'))

        with self.assertLogs(getLogger(), level = WARNING) as captured:
            with self.assertRaises(SystemExit):
                reader.read_loop()

        joined = '\n'.join(captured.output)

        self.assertIn('a bug in the frame reader', joined,
            'the real exception must be visible for diagnosis')


class Efs2FileTypeTests(TestCase):

    def test_known_file_type_is_named(self):
        from src.protocol.efs2 import efs2_file_type_name, EFS2_FILE_TYPES

        known_mode = next(iter(EFS2_FILE_TYPES))

        self.assertEqual(EFS2_FILE_TYPES[known_mode],
            efs2_file_type_name(known_mode))

    def test_unknown_file_type_returns_placeholder_instead_of_raising(self):
        from src.protocol.efs2 import efs2_file_type_name, EFS2_FILE_TYPES

        # Find a non-zero file-type value that the table does not define. Zero
        # would make the assertion below vacuous, since '0' appears in any
        # zero-padded octal rendering.
        unknown_mode = next(candidate for candidate in range(0o10000, 0o200000, 0o10000)
            if candidate not in EFS2_FILE_TYPES)

        result = efs2_file_type_name(unknown_mode)

        # The placeholder must show the type bits the way EFS2_FILE_TYPES
        # spells them, so the value can be looked up against the table
        self.assertIn('%06o' % unknown_mode, result,
            'the unknown type value should appear in the placeholder as-is')

    def test_only_the_file_type_bits_are_considered(self):
        from src.protocol.efs2 import efs2_file_type_name, EFS2_FILE_TYPES

        known_mode = next(iter(EFS2_FILE_TYPES))

        # Permission bits set alongside the type bits must not change the name
        self.assertEqual(efs2_file_type_name(known_mode),
            efs2_file_type_name(known_mode | 0o777))
