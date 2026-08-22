#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
    AirTap - Wireshark Lua Dissectors Installer & Manager
    Copyright (C) TelcoSec.net - Telecom Security Intelligence & Research

    Automatically detects the Wireshark plugins directory across Windows, Linux, and macOS,
    and deploys all AirTap cellular radio and security dissectors.
"""

import os
import sys
import shutil
import platform
from typing import List, Optional, Tuple, Dict
from logging import info, error, warning


def get_wireshark_plugin_dir() -> str:
    """
    Determines the standard user plugins directory for the active operating system.
    """
    system = platform.system()

    if system == "Windows":
        appdata = os.environ.get("APPDATA")
        if appdata:
            return os.path.join(appdata, "Wireshark", "plugins")
        return os.path.expanduser(os.path.join("~", "AppData", "Roaming", "Wireshark", "plugins"))

    elif system == "Darwin": # macOS
        return os.path.expanduser(os.path.join("~", "Library", "Application Support", "Wireshark", "plugins"))

    else: # Linux / FreeBSD / Unix
        # Check standard XDG data home or fallback to ~/.local/lib/wireshark/plugins
        xdg_data = os.environ.get("XDG_DATA_HOME")
        if xdg_data:
            return os.path.join(xdg_data, "wireshark", "plugins")
        return os.path.expanduser(os.path.join("~", ".local", "lib", "wireshark", "plugins"))


def get_plugin_source_dir() -> str:
    """Returns the directory where AirTap Lua dissectors are stored in the package."""
    return os.path.dirname(os.path.abspath(__file__))


def list_dissectors() -> List[str]:
    """Returns a sorted list of all available Lua dissectors."""
    src_dir = get_plugin_source_dir()
    if not os.path.isdir(src_dir):
        return []
    return sorted([f for f in os.listdir(src_dir) if f.endswith(".lua")])


def install(dest_dir: Optional[str] = None, overwrite: bool = True, dry_run: bool = False) -> Dict[str, any]:
    """
    Installs all AirTap Wireshark Lua dissectors into the target directory.

    :param dest_dir: Destination directory. Defaults to standard Wireshark plugin dir.
    :param overwrite: If True, overwrite existing dissector files.
    :param dry_run: If True, simulate installation without copying files.
    :return: Dictionary with installation summary and list of installed files.
    """
    target = dest_dir or get_wireshark_plugin_dir()
    src_dir = get_plugin_source_dir()
    lua_files = list_dissectors()

    if not lua_files:
        return {
            "status": "error",
            "message": f"No Lua dissector files found in source directory: {src_dir}",
            "target_dir": target,
            "installed": []
        }

    installed_files = []

    if not dry_run:
        os.makedirs(target, exist_ok=True)

    for fname in lua_files:
        src_path = os.path.join(src_dir, fname)
        dst_path = os.path.join(target, fname)

        if not dry_run:
            if overwrite or not os.path.exists(dst_path):
                shutil.copy2(src_path, dst_path)
        installed_files.append(dst_path)

    return {
        "status": "ok",
        "target_dir": target,
        "total_dissectors": len(lua_files),
        "installed": installed_files,
        "dry_run": dry_run
    }


def main():
    import argparse
    parser = argparse.ArgumentParser(
        prog="install_plugins",
        description="AirTap Wireshark Lua Dissectors Installer"
    )
    parser.add_argument("-d", "--dest", help="Custom destination directory for Wireshark plugins")
    parser.add_argument("--dry-run", action="store_true", help="Simulate installation without writing files")
    parser.add_argument("-l", "--list", action="store_true", help="List all available Lua dissectors")
    args = parser.parse_args()

    if args.list:
        dissectors = list_dissectors()
        print(f"AirTap Available Dissectors ({len(dissectors)}):")
        for d in dissectors:
            print(f"  - {d}")
        return 0

    res = install(dest_dir=args.dest, dry_run=args.dry_run)
    if res["status"] == "ok":
        prefix = "[DRY-RUN] Would install" if args.dry_run else "[+] Successfully installed"
        print(f"{prefix} {res['total_dissectors']} Wireshark Lua dissectors to: {res['target_dir']}")
        return 0
    else:
        print(f"[-] Installation failed: {res['message']}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
