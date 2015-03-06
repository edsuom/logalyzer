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
        self.dbPath = "records.db"
        self.rk = records.MasterRecordKeeper(
            "sqlite:///{}".format(self.dbPath),
            warnings=True,
        )
        self.t = self.rk.trans
    
    @defer.inlineCallbacks
    def tearDown(self):
        for ip in (ip1, ip2):
            yield self.t.purgeIP(ip)
        yield self.rk.shutdown()
        
    @defer.inlineCallbacks
    def test_addRecords(self):
        yield self.rk.addRecords(RECORDS)
        self.failUnlessEqual(self.rk.records, RECORDS)
        N = yield self.t.hitsForIP(ip1)
        self.failUnlessEqual(N, 2)
        
            

    
