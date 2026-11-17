#!/usr/bin/python3
#-*- encoding: Utf-8 -*-

"""
    The single source of truth for the AirTap version. setup.py reads this
    string out of the file rather than importing it, so that building a
    distribution never has to import the package (and therefore never has to
    have its dependencies installed).
"""

__version__ = '2.6.0'
