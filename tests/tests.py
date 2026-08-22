#!/usr/bin/python3
#-*- encoding: Utf-8 -*-
from unittest import TestLoader, TextTestRunner
from os.path import dirname, realpath
import sys

"""
    Run the whole test suite without pytest:

        python tests/tests.py

    Doc.: https://docs.python.org/3/library/unittest.html

    This used to import three test modules by hand, which meant a new test file
    was invisible here until someone remembered to add it - it ran 8 of the
    suite's 70 tests while reporting success. Discovery keeps it honest.

    pytest is configured (in pyproject.toml) to ignore this file, so that
    collecting the suite doesn't run it a second time through this runner.
"""

TESTS_DIR = dirname(realpath(__file__))
PROJECT_ROOT = dirname(TESTS_DIR)

# The test modules import the package as "src.<...>", which only resolves with
# the project root on sys.path. Under pytest that happens to be arranged for
# us; discovery from here has to do it explicitly.

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

if __name__ == '__main__':

    suite = TestLoader().discover(start_dir = TESTS_DIR, pattern = 'tests_*.py')

    result = TextTestRunner(verbosity = 2).run(suite)

    sys.exit(0 if result.wasSuccessful() else 1)
