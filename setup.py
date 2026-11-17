#!/usr/bin/python3
#-*- encoding: Utf-8 -*-
import os
from os.path import dirname, realpath
from setuptools import setup
from re import search, MULTILINE

SCRIPT_DIR = dirname(realpath(__file__))
README_PATH = os.path.join(SCRIPT_DIR, 'README.md')
VERSION_PATH = os.path.join(SCRIPT_DIR, 'src', '__init__.py')

with open(README_PATH, encoding='utf-8') as fd:
    long_description = fd.read()

# Read __version__ out of the package rather than importing it, so that
# building a distribution doesn't require runtime dependencies.

with open(VERSION_PATH, encoding='utf-8') as fd:
    version = search(r"^__version__\s*=\s*'([^']+)'", fd.read(), MULTILINE).group(1)

setup(name = 'airtap',
    version = version,
    description = 'AirTap is a cellular radio diagnostics and packet capture framework for 2G/3G/4G/5G basebands',
    author = 'AirTap Team',
    author_email = 'contact@telcosec.net',
    url = 'https://github.com/TelcoSec-Tools/AirTAP-Framework',
    project_urls = {
        'Documentation': 'https://github.com/TelcoSec-Tools/AirTAP-Framework#readme',
        'Source': 'https://github.com/TelcoSec-Tools/AirTAP-Framework',
        'Tracker': 'https://github.com/TelcoSec-Tools/AirTAP-Framework/issues',
        'Changelog': 'https://github.com/TelcoSec-Tools/AirTAP-Framework/blob/master/CHANGELOG.md',
    },
    long_description = long_description,
    long_description_content_type = 'text/markdown',
    entry_points = {
        'console_scripts': [
            'airtap = airtap.main:main'
        ]
    },
    license = 'GPL-3.0-only',
    license_files = ['LICENSE'],
    classifiers = [
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Telecommunications Industry',
        'Intended Audience :: Science/Research',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: 3.13',
        'Topic :: Communications :: Cellular Phone',
        'Topic :: Communications :: Ham Radio',
        'Topic :: Security',
        'Topic :: System :: Hardware :: Hardware Drivers',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS',
        'Operating System :: Microsoft :: Windows'
    ],
    python_requires = '>=3.8',
    install_requires = [
        'pyserial>=3.5',
        'pyusb>=1.2.1',
        'crcmod>=1.7',
        'pycrate>=0.7.0'
    ],
    extras_require = {
        'dev': [
            'pytest>=7.0',
            'pytest-cov>=4.0',
            'build>=1.0.0',
            'twine>=4.0.0',
            'flake8>=6.0.0'
        ]
    },
    include_package_data = True,
    packages = [
        'airtap',
        'airtap.inputs',
        'airtap.protocol',
        'airtap.modules',
        'airtap.modules.efs_shell_commands',
        'airtap.modules.wireshark_plugin'
    ],
    package_data = {
        'airtap': [
            'inputs/adb_bridge/*',
            'inputs/adb_wsl2_bridge/*',
            'inputs/external/*',
            'inputs/external/adb/*',
            'inputs/external/adb/lib64/*',
            'modules/wireshark_plugin/*.lua',
            'modules/wireshark_plugin/*.py',
            'modules/gui_assets/*'
        ]
    },
    package_dir = {
        'airtap': 'src'
    }
)
