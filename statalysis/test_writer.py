#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!
"""
LICENSE
Copyright (C) 2014-2015 Tellectual LLC

"""

import os.path
from datetime import datetime as dt

from twisted.python import failure

import testbase as tb

import writer


class TestWriter(tb.TestCase):
    def setUp(self):
        self.rk = writer.Writer()

