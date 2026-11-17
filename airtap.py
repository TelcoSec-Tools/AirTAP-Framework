#!/usr/bin/env python3
#-*- encoding: Utf-8 -*-

import sys

from src.main import main

if __name__ == '__main__':
    # main() returns 1 on errors; propagate it so scripts and CI can tell.
    sys.exit(main())
