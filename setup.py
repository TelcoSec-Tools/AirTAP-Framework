#!/usr/bin/python3
#-*- encoding: Utf-8 -*-
from os.path import dirname, realpath
from setuptools import setup

SCRIPT_DIR = dirname(realpath(__file__))
README_PATH = SCRIPT_DIR + '/README.md'

with open(README_PATH) as fd:
    long_description = fd.read()

setup(name = 'airtap',
    version = '2.0.1',
    description = 'AirTap is a tool communicating with Qualcomm-based phones and modems, allowing to capture raw 2G/3G/4G radio frames',
    author = 'AirTap Team',
    author_email = '',
    long_description = long_description,
    long_description_content_type = 'text/markdown',
    entry_points = {
        'console_scripts': [
            'airtap = airtap.main:main'
        ]
    },
    # SPDX expression rather than a "License ::" classifier, which setuptools
    # deprecated in 77.0. GPL-3.0-only (not -or-later) because neither the
    # upstream LICENSE nor any source header grants the "any later version"
    # option.
    license = 'GPL-3.0-only',
    license_files = ['LICENSE'],
    classifiers = [
        'Programming Language :: Python :: 3',
        'Topic :: Communications :: Ham Radio'
    ],
    install_requires = [
        'pyserial>=3.5',
        'pyusb>=1.2.1',
        'crcmod>=1.7',
        'pycrate>=0.7.0'
    ],
    include_package_data = True,
    package_data = {
        'airtap.inputs.adb_bridge': ['*'],
        'airtap.inputs.adb_wsl2_bridge': ['*'],
        'airtap.inputs.external': ['*'],
        'airtap.inputs.external.adb': ['*'],
        'airtap.inputs.external.adb.lib64': ['*']
    },
    packages = [
        'airtap',
        'airtap.inputs',
        'airtap.inputs.adb_bridge',
        'airtap.inputs.adb_wsl2_bridge',
        'airtap.inputs.external',
        'airtap.inputs.external.adb',
        'airtap.inputs.external.adb.lib64',
        'airtap.protocol',
        'airtap.modules',
        'airtap.modules.efs_shell_commands'
    ],
    package_dir = {
        'airtap': 'src'
    }
)
