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

import records


ip1 = "221.127.9.141"
ip2 = "82.132.214.244"


class TestParserRecordKeeper(tb.TestCase):
    
    def setUp(self):
        self.rk = records.ParserRecordKeeper()

    def test_isRedirect(self):
        wasRD, vhost = self.rk.isRedirect("foo.com", ip1, 200)
        self.assertFalse(wasRD)
        self.assertEqual(vhost, "foo.com")
        wasRD, vhost = self.rk.isRedirect("foo.com", ip2, 302)
        self.assertFalse(wasRD)
        self.assertEqual(vhost, "foo.com")
        for k in xrange(10):
            wasRD, vhost = self.rk.isRedirect("bar.com", ip2, 200)
            self.assertTrue(wasRD)
            self.assertEqual(vhost, "foo.com")
        wasRD, vhost = self.rk.isRedirect("bar.com", ip1, 200)
        self.assertFalse(wasRD)
        self.assertEqual(vhost, "bar.com")
