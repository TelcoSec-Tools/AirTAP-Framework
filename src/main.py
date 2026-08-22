#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

from logging import DEBUG, INFO, basicConfig, error, info, debug, warning
from argparse import RawTextHelpFormatter, ArgumentParser, SUPPRESS, Action
from os.path import expanduser, splitext
from pathlib import Path
import sys

from .modules.json_geo_dump import JsonGeoDumper
from .modules.memory_dump import MemoryDumper
from .modules.cli import CommandLineInterface
from .modules.dlf_dump import DlfDumper
from .modules.info import InfoRetriever
from .modules._utils import FileType

from .inputs.json_geo_read import JsonGeoReader
from .inputs.usb_modem_pyserial import UsbModemPyserialConnector
from .inputs.usb_modem_pyusb import UsbModemPyusbConnector
from .inputs.usb_modem_pyusb_devfinder import PyusbDevInterface, PyusbDevNotFoundReason
from .inputs.usb_modem_argparser import UsbModemArgParser, UsbModemArgType
from .inputs.dlf_read import DlfReader
from .inputs.adb import AdbConnector
from .inputs.adb_wsl2 import AdbWsl2Connector
from .inputs.tcp_connector import TcpConnector

from . import __version__

def build_parser(advanced = False):
    """
    Build argument parser. If advanced=False, low-level forensic and deep protocol
    flags are hidden from the standard help screen to keep the CLI concise and professional.
    """
    epilog_standard = """Quickstart Examples:
  airtap -l -s                        Live stream to Wireshark with real-time telemetry
  airtap -o capture.pcap -s           Capture cellular traffic to PCAP file + stats
  airtap -m auto -l                   Auto-detect USB modem and stream to Wireshark
  airtap -a -l                        Capture from rooted Android phone over ADB
  airtap -t 127.0.0.1:2500 -l         Capture from remote TCP DIAG service
  airtap -r capture.pcap -s           Replay a recorded PCAP trace into telemetry
  airtap --gui                        Launch Visual Operations Suite (Web GUI)
  airtap --install-plugins            Deploy Wireshark Lua dissectors
  airtap --shell                      Launch interactive baseband EFS filesystem shell
  airtap --info                       Query modem model, firmware revision & chip ID

Use '--help-advanced' to display all expert, forensic, and low-level protocol options.
"""

    epilog_advanced = """Advanced & Forensic Examples:
  airtap -a -o capture.pcap --reassemble-sibs --decrypt-nas --include-ip
  airtap -a --dump-fs /tmp/efs_backup
  airtap -m auto --dump-mem /tmp/mem --start 0x00000000 --stop 0x0fffffff
  airtap --benchmark --benchmark-pkts 2000
  airtap --fuzz --fuzz-template nr_rrc_reconfig --fuzz-pcap fuzz.pcap
  airtap -m auto --at-cmd "AT+COPS?"
  airtap -a --sibs --rat 4g,5g
  airtap -a --json trace.json
  airtap -w /mnt/c/platform-tools/adb.exe -l
"""

    parser = ArgumentParser(
        prog = 'airtap',
        description = 'AirTap - Cellular Baseband Diagnostics & Radio Packet Capture Tool (v%s)' % __version__,
        formatter_class = RawTextHelpFormatter,
        epilog = epilog_advanced if advanced else epilog_standard,
        add_help = False
    )

    # General Options
    general = parser.add_argument_group(title = 'General Options')
    general.add_argument('-h', '--help', action = 'store_true', help = 'Show standard help message and exit.')
    general.add_argument('-H', '--help-advanced', '--help-all', dest = 'help_advanced', action = 'store_true',
                         help = 'Show advanced forensic, memory, and protocol options.')
    general.add_argument('--version', action = 'version', version = 'AirTap ' + __version__)
    general.add_argument('-v', '--verbose', action = 'store_true', help = 'Enable verbose debug logging for all DIAG frames.')

    # Primary Actions & Modules
    actions = parser.add_argument_group(
        title = 'Capture Actions & Analysis Modes',
        description = 'Select one or more actions to perform on the DIAG data stream.'
    )
    actions.add_argument('-g', '--gui', dest = 'gui', action = 'store_true',
                         help = 'Launch the AirTap Visual Operations Suite (Web-powered real-time GUI).')
    actions.add_argument('-l', '--live', '--wireshark-live', dest = 'wireshark_live', action = 'store_true',
                         help = 'Spawn a live Wireshark session for real-time packet analysis.')
    actions.add_argument('-s', '--stats', '--telemetry', dest = 'stats', action = 'store_true',
                         help = 'Display real-time telemetry: packet rates, RAT breakdown & RF signal quality (RSRP/RSRQ/PCI).')
    actions.add_argument('-o', '--pcap', '--pcap-dump', dest = 'pcap_dump', metavar = 'FILE', type = FileType('ab'),
                         help = 'Save captured GSMTAP 2G/3G/4G/5G radio frames to a PCAP file.')
    actions.add_argument('-q', '--qmdl', '--qmdl-dump', dest = 'qmdl_dump', metavar = 'FILE', type = FileType('ab'),
                         help = 'Export raw frames into a QMDL2 container compatible with QXDM Professional.')
    actions.add_argument('-i', '--info', dest = 'info', action = 'store_true',
                         help = 'Retrieve baseband hardware revision, firmware build ID, and chip info.')
    actions.add_argument('--audit', '--sec-audit', dest = 'sec_audit', action = 'store_true',
                         help = 'Perform real-time radio security auditing (detect null ciphering, FBS lures, IMSI harvesting).')
    actions.add_argument('--audit-log', dest = 'audit_log', metavar = 'FILE',
                         help = 'Save structured security audit findings to a JSON file.' if advanced else SUPPRESS)
    actions.add_argument('--install-plugins', '--install-wireshark-plugins', dest = 'install_plugins', action = 'store_true',
                         help = 'Deploy AirTap Wireshark Lua dissectors to the standard Wireshark plugins directory.')
    actions.add_argument('--benchmark', dest = 'benchmark', action = 'store_true',
                         help = 'Execute baseband throughput and dissection latency benchmark stress test.')
    actions.add_argument('--fuzz', '--fuzz-campaign', dest = 'fuzz', action = 'store_true',
                         help = 'Execute 3GPP protocol fuzzing campaign and generate mutated test vectors.')
    actions.add_argument('--shell', '--efs-shell', dest = 'efs_shell', action = 'store_true',
                         help = 'Launch an interactive shell to explore the baseband EFS filesystem.')
    actions.add_argument('--apn-audit', dest = 'apn_audit', metavar = 'APN',
                         help = 'Execute 3GPP/GSMA security audit on cellular APN or 5G Data Network Name (DNN).')
    actions.add_argument('--cli', dest = 'cli', action = 'store_true',
                         help = 'Launch an interactive command prompt for dynamic module management.')

    # Advanced Forensic & Export Actions
    actions.add_argument('--benchmark-pkts', dest = 'benchmark_pkts', metavar = 'COUNT', type = int, default = 1000,
                         help = 'Number of synthetic 3GPP frames for benchmark (default: 1000).' if advanced else SUPPRESS)
    actions.add_argument('--benchmark-rate', dest = 'benchmark_rate', metavar = 'RATE', type = int, default = 2000,
                         help = 'Target packet injection rate in pkts/s (default: 2000).' if advanced else SUPPRESS)
    actions.add_argument('--fuzz-template', dest = 'fuzz_template', metavar = 'NAME', default = 'nr_rrc_reconfig',
                         help = 'Fuzzing template (nr_rrc_reconfig, lte_nas_smc, lte_rrc_reconfig, lte_sib1, sim_apdu_auth).' if advanced else SUPPRESS)
    actions.add_argument('--fuzz-strategy', dest = 'fuzz_strategy', metavar = 'STRAT', default = 'byte_boundary',
                         help = 'Mutation strategy (bit_flip, byte_boundary, length_tamper, truncation, ie_injection, asn1_tag_corrupt).' if advanced else SUPPRESS)
    actions.add_argument('--fuzz-count', dest = 'fuzz_count', metavar = 'COUNT', type = int, default = 10,
                         help = 'Number of mutated test vectors to generate (default: 10).' if advanced else SUPPRESS)
    actions.add_argument('--fuzz-pcap', dest = 'fuzz_pcap', metavar = 'FILE',
                         help = 'Export generated fuzz vectors into a GSMTAP PCAP file.' if advanced else SUPPRESS)
    actions.add_argument('--at-cmd', dest = 'at_cmd', metavar = 'CMD',
                         help = 'Execute a single 3GPP/Qualcomm AT or DIAG command (e.g. "AT+COPS?", "DIAG:00").' if advanced else SUPPRESS)
    actions.add_argument('--at-macro', dest = 'at_macro', metavar = 'NAME',
                         help = 'Execute a predefined diagnostic macro sequence (full_audit, rf_scan, sim_audit, diag_probe).' if advanced else SUPPRESS)
    actions.add_argument('--sibs', '--decoded-sibs-dump', dest = 'decoded_sibs_dump', action = 'store_true',
                         help = 'Decode and stream 3G/4G/5G System Information Blocks (SIBs) to stdout.' if advanced else SUPPRESS)
    actions.add_argument('--messages', '--f3', dest = 'messages', action = 'store_true',
                         help = 'Stream Qualcomm F3 internal debug messages (with subsystem name, file & line numbers).' if advanced else SUPPRESS)
    actions.add_argument('--events', dest = 'events', action = 'store_true',
                         help = 'Stream Qualcomm asynchronous modem event reports (RRC state changes, handovers, RACH).' if advanced else SUPPRESS)
    actions.add_argument('--dump-fs', '--efs-dump', dest = 'efs_dump', metavar = 'DIR',
                         help = 'Recursively dump the internal modem EFS filesystem to a local directory.' if advanced else SUPPRESS)
    actions.add_argument('--dump-mem', '--memory-dump', dest = 'memory_dump', metavar = 'DIR',
                         help = 'Dump baseband memory ranges to a local directory.' if advanced else SUPPRESS)
    actions.add_argument('--apn-pdp', dest = 'apn_pdp', metavar = 'TYPE', default = 'IPv4v6',
                         help = 'PDP / PDU Session Type for APN audit (IPv4, IPv6, IPv4v6).' if advanced else SUPPRESS)
    actions.add_argument('--apn-restr', dest = 'apn_restr', metavar = 'LEVEL', type = int, default = 0,
                         help = '3GPP APN Restriction Level (0-4).' if advanced else SUPPRESS)
    actions.add_argument('--apn-sst', dest = 'apn_sst', metavar = 'SST', type = int, default = None,
                         help = '5G Slice Service Type (1=eMBB, 2=URLLC, 3=MIoT, 4=V2X).' if advanced else SUPPRESS)
    actions.add_argument('--apn-proxy', dest = 'apn_proxy', metavar = 'HOST:PORT', default = None,
                         help = 'Audited HTTP/WAP proxy address.' if advanced else SUPPRESS)
    actions.add_argument('--dlf', '--dlf-dump', dest = 'dlf_dump', metavar = 'FILE', type = FileType('ab'),
                         help = 'Save raw frames into a Qualcomm DLF file.' if advanced else SUPPRESS)
    actions.add_argument('--json', '--json-geo-dump', dest = 'json_geo_dump', metavar = 'FILE', type = FileType('a'),
                         help = 'Save raw frames and GPS geolocation coordinates to a JSON file.' if advanced else SUPPRESS)

    # QXDM NV Memory & Baseband Control
    actions.add_argument('--nv-read', dest = 'nv_read', metavar = 'ID', type = int,
                         help = 'Read a specific baseband Non-Volatile (NV) item (e.g. 1877 for band mask).' if advanced else SUPPRESS)
    actions.add_argument('--nv-dump', dest = 'nv_dump', metavar = 'DIR',
                         help = 'Dump standard baseband NV items to a directory / JSON file.' if advanced else SUPPRESS)
    actions.add_argument('--dmc', dest = 'dmc', metavar = 'FILE',
                         help = 'Load Qualcomm QXDM Item Configuration (.dmc) mask file.' if advanced else SUPPRESS)
    actions.add_argument('--offline', dest = 'offline', action = 'store_true',
                         help = 'Put baseband modem into digital offline mode.' if advanced else SUPPRESS)
    actions.add_argument('--reset', dest = 'reset', action = 'store_true',
                         help = 'Trigger a soft reset / reboot of the baseband modem processor.' if advanced else SUPPRESS)

    # Input Sources
    inputs = parser.add_argument_group(
        title = 'Input Sources (auto-detected if omitted)',
        description = 'Specify the source of DIAG data. If omitted, AirTap auto-detects connected devices.'
    )
    inputs.add_argument('-a', '--adb', dest = 'adb', action = 'store_true',
                        help = 'Capture from a rooted Android phone over ADB.')
    inputs.add_argument('-m', '--modem', '--usb-modem', dest = 'usb_modem', metavar = 'DEV', nargs = '?', const = 'auto',
                        help = 'Connect to a USB modem or COM/tty port (default: "auto").')
    inputs.add_argument('-t', '--tcp', dest = 'tcp', metavar = 'IP:PORT',
                        help = 'Connect to a remote TCP DIAG service.')
    inputs.add_argument('-r', '--replay', dest = 'replay', metavar = 'FILE', type = FileType('rb'),
                        help = 'Replay a recorded file (.pcap, .dlf, or .json).')

    # Advanced / Environment Inputs
    inputs.add_argument('-w', '--wsl2', '--adb-wsl2', dest = 'adb_wsl2', metavar = 'PATH', default = None,
                        help = 'Path to Windows adb.exe for WSL2 environment.' if advanced else SUPPRESS)
    inputs.add_argument('--shannon-read', dest = 'shannon_read', metavar = 'FILE', type = FileType('rb'),
                        help = 'Read Samsung Shannon (Exynos) diagnostic capture file.' if advanced else SUPPRESS)
    inputs.add_argument('--mtk-read', dest = 'mtk_read', metavar = 'FILE', type = FileType('rb'),
                        help = 'Read MediaTek (Dimensity / Helio) baseband trace capture file.' if advanced else SUPPRESS)
    inputs.add_argument('--replay-speed', dest = 'replay_speed', metavar = 'SPEED', type = float, default = 1.0,
                        help = 'Playback speed multiplier for session replay (e.g. 1.0, 2.0, 5.0, or 0 for max speed).' if advanced else SUPPRESS)
    inputs.add_argument('--pcap-read', dest = 'pcap_read', metavar = 'FILE', type = FileType('rb'), help = SUPPRESS)
    inputs.add_argument('--dlf-read', dest = 'dlf_read', metavar = 'FILE', type = FileType('rb'), help = SUPPRESS)
    inputs.add_argument('--json-geo-read', dest = 'json_geo_read', metavar = 'FILE', type = FileType('r'), help = SUPPRESS)

    # Filtering & Protocol Options
    filters = parser.add_argument_group(
        title = 'Filters & Protocol Options',
        description = 'Fine-tune captured technologies, log codes, and protocol options.'
    )
    filters.add_argument('--rat', '--filter-rat', dest = 'filter_rat', metavar = 'RATS',
                         help = 'Comma-separated list of RATs to capture (e.g., "4g,5g" or "2g,3g").')
    filters.add_argument('--logs', '--filter-logs', dest = 'filter_logs', metavar = 'CODES',
                         help = 'Comma-separated list of hex log codes (e.g., "0xb0c0,0xb821").')

    # Advanced Protocol & Memory Options
    filters.add_argument('--reassemble-sibs', dest = 'reassemble_sibs', action = 'store_true', default = True,
                         help = 'Reassemble fragmented UMTS SIBs into standalone GSMTAP frames (enabled by default).' if advanced else SUPPRESS)
    filters.add_argument('--no-reassemble-sibs', dest = 'reassemble_sibs', action = 'store_false',
                         help = 'Disable UMTS SIB reassembly.' if advanced else SUPPRESS)

    filters.add_argument('--decrypt-nas', dest = 'decrypt_nas', action = 'store_true', default = True,
                         help = 'Include unencrypted LTE/5G NAS signaling frames (enabled by default).' if advanced else SUPPRESS)
    filters.add_argument('--no-decrypt-nas', dest = 'decrypt_nas', action = 'store_false',
                         help = 'Disable plain NAS extraction.' if advanced else SUPPRESS)

    filters.add_argument('--include-ip', '--include-ip-traffic', dest = 'include_ip_traffic', action = 'store_true', default = True,
                         help = 'Capture raw user-plane IPv4 traffic (enabled by default).' if advanced else SUPPRESS)
    filters.add_argument('--no-ip', '--no-ip-traffic', dest = 'include_ip_traffic', action = 'store_false',
                         help = 'Exclude user-plane IPv4 traffic.' if advanced else SUPPRESS)

    filters.add_argument('--start', dest = 'start', metavar = 'ADDR', default = '00000000',
                         help = 'Memory dump start offset in hex (default: 00000000).' if advanced else SUPPRESS)
    filters.add_argument('--stop', dest = 'stop', metavar = 'ADDR', default = 'ffffffff',
                         help = 'Memory dump stop offset in hex (default: ffffffff).' if advanced else SUPPRESS)

    return parser


def print_application_banner():
    banner = (
        "\033[1;36m    _    _     _____            \033[0m\n"
        "\033[1;36m   / \\  (_)_ _|_   _|_ _ _ __   \033[0m\n"
        "\033[1;36m  / _ \\ | | '__|| |/ _` | '_ \\  \033[0m\n"
        "\033[1;36m / ___ \\| | |   | | (_| | |_) | \033[0m\n"
        "\033[1;36m/_/   \\_\\_|_|   |_|\\__,_| .__/  \033[0m\n"
        "\033[1;36m                        |_|     \033[0m\n"
        f"\033[1;37m AirTap v{__version__}\033[0m - \033[0;37mCellular Baseband Diagnostics & Radio Security Framework\033[0m\n"
        "\033[1;35m [*] TelcoSec Platform\033[0m - Telecom Security Intelligence | \033[1;34mhttps://telcosec.net\033[0m\n"
        "\033[1;32m [🎓] TelcoSec Academy\033[0m - Hands-on Cellular Security & 5G Training | \033[1;36mhttps://app.telcosec.net\033[0m\n"
    )
    try:
        print(banner, file=sys.stderr, flush=True)
    except Exception:
        pass


def main():
    # Handle help requests
    is_advanced_help = any(arg in sys.argv for arg in ('-H', '--help-advanced', '--help-all', '--advanced-help'))
    is_standard_help = any(arg in sys.argv for arg in ('-h', '--help'))
    has_no_args = (len(sys.argv) == 1)

    if is_advanced_help:
        print_application_banner()
        parser = build_parser(advanced = True)
        parser.print_help()
        return 0

    if is_standard_help or has_no_args:
        print_application_banner()
        parser = build_parser(advanced = False)
        parser.print_help()
        return 0

    # Build full parser for execution
    parser = build_parser(advanced = True)
    args = parser.parse_args()

    basicConfig(stream = sys.stderr, level = DEBUG if args.verbose else INFO,
                format = '[%(asctime)s | %(levelname)s @ %(filename)s:%(lineno)d ] %(message)s',
                force = True, datefmt = '%H:%M:%S')

    print_application_banner()

    # Standalone utilities (do not require an active modem/capture source)
    if args.install_plugins:
        from .modules.wireshark_plugin.install_plugins import install
        res = install()
        if res["status"] == "ok":
            info(f"[+] Successfully installed {res['total_dissectors']} Wireshark Lua dissectors to: {res['target_dir']}")
            return 0
        else:
            error(f"[-] Installation failed: {res.get('message')}")
            return 1

    if args.benchmark:
        from .modules.benchmark_engine import BenchmarkEngine
        b_engine = BenchmarkEngine()
        info(f"[*] Starting AirTap Dissection & Streaming Latency Benchmark ({args.benchmark_pkts} packets)...")
        res = b_engine.run_benchmark(packet_count=args.benchmark_pkts, target_rate=args.benchmark_rate)
        if res['status'] == 'ok':
            print("\n" + "="*60)
            print(" AirTap Performance & Latency Benchmark Results")
            print("="*60)
            print(f" Packets Processed: {res['packets_processed']}")
            print(f" Total Duration:    {res['total_duration_sec']}s")
            print(f" Throughput:        {res['throughput_pkts_per_sec']} pkts/sec")
            print(f" Average Latency:   {res['latency_stats_ms']['avg']} ms")
            print(f" p50 Latency:       {res['latency_stats_ms']['p50']} ms")
            print(f" p95 Latency:       {res['latency_stats_ms']['p95']} ms")
            print(f" p99 Latency:       {res['latency_stats_ms']['p99']} ms")
            print(f" Max Latency:       {res['latency_stats_ms']['max']} ms")
            print(f" Pipeline Status:   {res['pipeline_status']}")
            print("="*60 + "\n")
            return 0
        else:
            error(f"Benchmark failed: {res.get('message')}")
            return 1

    if args.fuzz:
        from .modules.protocol_fuzzer import ProtocolFuzzerEngine
        fuzzer = ProtocolFuzzerEngine()
        campaign = fuzzer.generate_campaign(
            template_key=args.fuzz_template,
            count=args.fuzz_count,
            strategy=args.fuzz_strategy
        )
        info(f"[*] Generated 3GPP Fuzz Campaign: {campaign['campaign_count']} mutated vectors (Template: {args.fuzz_template}, Strategy: {args.fuzz_strategy})")
        print("\n" + "="*70)
        print(f" AirTap 3GPP Protocol Fuzz Campaign: {args.fuzz_template}")
        print("="*70)
        for idx, v in enumerate(campaign['vectors'], 1):
            print(f"[{idx:02d}] {v['id']} ({v['rat']}) -> {v['description']}")
            print(f"     Orig: {v['original_hex']}")
            print(f"     Fuzz: {v['mutated_hex']}")
            print(f"     Diag Status: {v['baseband_status']}")
        print("="*70 + "\n")
        if args.fuzz_pcap:
            pcap_bytes, _, fname = fuzzer.export_fuzz_pcap(campaign['vectors'])
            with open(args.fuzz_pcap, 'wb') as f:
                f.write(pcap_bytes)
            info(f"[+] Exported fuzzing vectors to GSMTAP PCAP: {args.fuzz_pcap}")
        return 0

    if getattr(args, 'apn_audit', None):
        from .modules.apn_sec_audit import ApnSecurityAuditor
        auditor = ApnSecurityAuditor()
        proxy_host = None
        proxy_port = None
        if getattr(args, 'apn_proxy', None):
            parts = args.apn_proxy.split(':')
            proxy_host = parts[0]
            if len(parts) > 1 and parts[1].isdigit():
                proxy_port = int(parts[1])
        res = auditor.audit_apn(
            apn_name=args.apn_audit,
            pdn_type=getattr(args, 'apn_pdp', 'IPv4v6'),
            restriction_level=getattr(args, 'apn_restr', 0),
            sst=getattr(args, 'apn_sst', None),
            proxy_host=proxy_host,
            proxy_port=proxy_port
        )
        print(auditor.format_cli_report(res))
        return 0

    def resolve_usb_connector(usb_modem: PyusbDevInterface):
        if usb_modem.chardev_if_mounted:
            return UsbModemPyserialConnector(usb_modem.chardev_if_mounted)
        return UsbModemPyusbConnector(usb_modem)

    # Resolve input source
    diag_input = None

    # 1. Replay file input
    if args.replay:
        from .inputs.session_replay import SessionReplayer
        file_path = getattr(args.replay, 'name', None)
        diag_input = SessionReplayer(file_path=file_path)
        diag_input.set_speed(args.replay_speed)
    elif args.shannon_read:
        from .inputs.shannon_read import ShannonReader
        diag_input = ShannonReader(args.shannon_read)
    elif args.mtk_read:
        from .inputs.mtk_read import MediaTekReader
        diag_input = MediaTekReader(args.mtk_read)
    elif args.pcap_read:
        from .inputs.pcap_read import PcapReader
        diag_input = PcapReader(args.pcap_read)
    elif args.dlf_read:
        diag_input = DlfReader(args.dlf_read)
    elif args.json_geo_read:
        diag_input = JsonGeoReader(args.json_geo_read)
    elif args.adb_wsl2:
        win_adb_path = Path(args.adb_wsl2).resolve()
        if not win_adb_path.is_file():
            error("--adb-wsl2 is not a valid path to Windows adb executable")
            return 1
        diag_input = AdbWsl2Connector(f'{win_adb_path}')
        if diag_input.usb_modem and not diag_input.usb_modem.not_found_reason:
            diag_input = resolve_usb_connector(diag_input.usb_modem)
    elif args.adb:
        diag_input = AdbConnector()
        if diag_input.usb_modem and not diag_input.usb_modem.not_found_reason:
            diag_input = resolve_usb_connector(diag_input.usb_modem)
    elif args.tcp:
        diag_input = TcpConnector(args.tcp)
    elif args.usb_modem:
        usb_arg = UsbModemArgParser(args.usb_modem)
        if not usb_arg.arg_type:
            error("Invalid value for --modem argument. Please see --help.")
            return 1
        elif usb_arg.arg_type == UsbModemArgType.pyserial_dev:
            diag_input = UsbModemPyserialConnector(usb_arg.pyserial_device)
        else:
            dev_intf = PyusbDevInterface.from_arg(usb_arg)
            if dev_intf.not_found_reason:
                error('No Qualcomm DIAG interface was found matching the criteria.')
                return 1
            else:
                diag_input = resolve_usb_connector(dev_intf)

    # 2. Auto-detection fallback if no input explicitly provided
    if diag_input is None:
        debug('No input specified, probing for connected DIAG sources...')
        try:
            dev_intf = PyusbDevInterface.auto_find()
            if not dev_intf.not_found_reason:
                info('Auto-detected Qualcomm USB DIAG device.')
                diag_input = resolve_usb_connector(dev_intf)
        except Exception:
            pass

        if diag_input is None:
            try:
                diag_input = AdbConnector()
                if diag_input.usb_modem and not diag_input.usb_modem.not_found_reason:
                    diag_input = resolve_usb_connector(diag_input.usb_modem)
            except Exception:
                pass

        if diag_input is None:
            error('No DIAG input device specified and auto-detection found no active modem or ADB device.\n' +
                  'Please specify an input (e.g. -a for ADB, -m auto for USB modem, -t for TCP, or -r for replay).')
            return 1

    # 1. Load DMC Mask Configuration if specified
    if args.dmc:
        from .protocol.dmc_parser import DmcParser
        dmc_cfg = DmcParser(args.dmc).parse()
        info(f"[*] Loaded DMC mask: {len(dmc_cfg['log_codes'])} log codes, {len(dmc_cfg['event_ids'])} event IDs")
        if dmc_cfg['log_codes']:
            diag_input.filter_logs = (diag_input.filter_logs or []) + dmc_cfg['log_codes']

    # 2. Handle immediate AT terminal commands / macros
    if args.at_cmd or args.at_macro:
        from .modules.at_terminal import AtTerminalEngine
        term = AtTerminalEngine(diag_input)
        if args.at_cmd:
            res = term.execute_command(args.at_cmd)
            print(f">>> {res['cmd']}\n{res['output']}")
        elif args.at_macro:
            res = term.execute_macro(args.at_macro)
            print(f"[*] Macro '{res['macro']}' finished ({res['total_commands']} commands in {res['total_duration_ms']}ms):")
            for r in res.get('results', []):
                print(f"\n>>> {r['cmd']}\n{r['output']}")
        diag_input.dispose()
        return 0

    # 3. Handle immediate QXDM control actions
    if args.offline:
        from .modules.mode_control import ModeController, MODE_OFFLINE_D_F
        ctl = ModeController(diag_input)
        ctl.switch_mode(MODE_OFFLINE_D_F)
        diag_input.dispose()
        return 0

    if args.reset:
        from .modules.mode_control import ModeController, MODE_RESET_F
        ctl = ModeController(diag_input)
        ctl.switch_mode(MODE_RESET_F)
        diag_input.dispose()
        return 0

    if args.nv_read is not None:
        from .modules.nv_manager import NvManager
        nvm = NvManager(diag_input)
        status, data = nvm.read_nv_item(args.nv_read)
        print(nvm.format_nv_item(args.nv_read, status, data))
        diag_input.dispose()
        return 0

    if args.nv_dump:
        from .modules.nv_manager import NvManager
        nvm = NvManager(diag_input)
        nvm.dump_nv_items(args.nv_dump)
        diag_input.dispose()
        return 0

    # Apply filters
    if args.filter_rat:
        diag_input.filter_rat = [r.strip().lower() for r in args.filter_rat.split(',') if r.strip()]
    if args.filter_logs:
        diag_input.filter_logs = [int(h.strip(), 16) for h in args.filter_logs.split(',') if h.strip()]

    # Module instantiation
    def parse_modules_args(args):
        if args.memory_dump:
            diag_input.add_module(MemoryDumper(diag_input, expanduser(args.memory_dump), int(args.start, 16), int(args.stop, 16)))
        if args.pcap_dump:
            from .modules.pcap_dump import PcapDumper
            diag_input.add_module(PcapDumper(diag_input, args.pcap_dump, args.reassemble_sibs, args.decrypt_nas, args.include_ip_traffic))
        if args.wireshark_live:
            from .modules.pcap_dump import WiresharkLive
            diag_input.add_module(WiresharkLive(diag_input, args.reassemble_sibs, args.decrypt_nas, args.include_ip_traffic))
        if args.json_geo_dump:
            diag_input.add_module(JsonGeoDumper(diag_input, args.json_geo_dump))
        if args.decoded_sibs_dump:
            from .modules.decoded_sibs_dump import DecodedSibsDumper
            diag_input.add_module(DecodedSibsDumper(diag_input))
        if args.messages or args.events:
            from .modules.qxdm_streamer import QxdmStreamer
            diag_input.add_module(QxdmStreamer(diag_input, show_messages = args.messages, show_events = args.events))
        if args.info:
            diag_input.add_module(InfoRetriever(diag_input))
        if args.dlf_dump:
            diag_input.add_module(DlfDumper(diag_input, args.dlf_dump))
        if args.qmdl_dump:
            from .modules.qmdl_dump import QmdlDumper
            diag_input.add_module(QmdlDumper(diag_input, args.qmdl_dump))
        if args.efs_dump:
            from .modules.efs_dump import EfsDumper
            diag_input.add_module(EfsDumper(diag_input, args.efs_dump))
        if args.stats:
            from .modules.stats_dump import StatsDumper
            diag_input.add_module(StatsDumper(diag_input))
        if getattr(args, 'sec_audit', False) or getattr(args, 'audit_log', None):
            from .modules.sec_audit import SecurityAuditor
            diag_input.add_module(SecurityAuditor(diag_input, audit_log_path = args.audit_log))
        if getattr(args, 'gui', False):
            from .modules.gui_server import GuiServer
            diag_input.add_module(GuiServer(diag_input))

    parse_modules_args(args)

    if args.cli:
        if diag_input.modules or args.efs_shell:
            error('You cannot specify both CLI and a standalone module.')
            return 1
        diag_input.add_module(CommandLineInterface(diag_input, parser, parse_modules_args))

    if args.efs_shell:
        if diag_input.modules:
            error('You cannot specify both EFS shell and a standalone module.')
            return 1
        from .modules.efs_shell import EfsShell
        diag_input.add_module(EfsShell(diag_input))

    if not diag_input.modules:
        parser.print_help()
        error('You must specify at least one action (e.g. -l for live Wireshark, -s for stats, -o for PCAP, or --shell).')
        return 1

    # Enter main loop
    try:
        diag_input.run()
    finally:
        diag_input.dispose()

    return 0
