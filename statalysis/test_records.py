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
from twisted.internet import defer

from testbase import *
import records


class TestParserRecordKeeper(TestCase):
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


class TestMasterRecordKeeper(TestCase):
    def setUp(self):
        self.rk = records.MasterRecordKeeper(
            "sqlite://", warnings=True)
        self.t = self.rk.trans
        return self.rk.startup()
    
    @defer.inlineCallbacks
    def tearDown(self):
        yield self.rk.shutdown()
        
    @defer.inlineCallbacks
    def test_addRecords(self):
        N_expected = [2, 1]
        yield self.rk.addRecords(RECORDS, "access.log")
        for k, ip in enumerate([ip1, ip2]):
            N = yield self.t.hitsForIP(ip)
            self.assertEqual(N, N_expected[k])
            self.assertTrue(self.rk.ipm(ip))
            

    
