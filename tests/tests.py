#!/usr/bin/python3
#-*- encoding: Utf-8 -*-
from unittest import main, TestLoader, TextTestRunner

"""
    Doc.: https://docs.python.org/3/library/unittest.html
"""

loader = TestLoader()
runner = TextTestRunner(verbosity = 2)

import tests_usbmodem_argparser
import tests_hdlc
import tests_messages

suite = loader.loadTestsFromModule(tests_usbmodem_argparser)
suite.addTests(loader.loadTestsFromModule(tests_hdlc))
suite.addTests(loader.loadTestsFromModule(tests_messages))

runner.run(suite)