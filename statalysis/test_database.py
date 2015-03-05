#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!
"""
LICENSE
Copyright (C) 2014-2015 Tellectual LLC

"""

import os.path
from datetime import datetime as dt

from twisted.internet import defer
from twisted.python import failure

import testbase as tb

import database


dt1 = dt(2015, 2, 20, 12, 2, 49)
dt2 = dt(2015, 3, 2, 21, 17, 16)

ip1 = "171.127.9.141"
ip2 = "32.132.214.244"

RECORDS = {
    dt1: [
        {'vhost': "foo.com",
         'ip': ip1, 'http': 200, 'was_rd': False,
         'url': "/", 'ref': "-", 'ua': "-"},
        {'vhost': "foo.com",
         'ip': ip1, 'http': 200, 'was_rd': False,
         'url': "/image.png", 'ref': "-", 'ua': "-"}],
    dt2: [
        {'vhost': "bar.com",
         'ip': ip2, 'http': 404, 'was_rd': False,
         'url': "/", 'ref': "-", 'ua': "-"}],
    }

months = ["2", "2", "3"]
vhosts = ["foo.com", "foo.com", "bar.com"]
ips = [ip1, ip1, ip2]


class TestTransactor(tb.TestCase):
    def setUp(self):
        self.dbPath = "file.db"
        self.t = database.Transactor("sqlite:///{}".format(self.dbPath))

    def tearDown(self):
        return self.t.shutdown()

    def oops(self, failure):
        failure.printDetailedTraceback()
        
    def test_setEntry(self):
        def cb1(result):
            self.assertFalse(result)
            self.assertTrue(os.path.isfile(self.dbPath))
            return self.t.setEntry(
                dt1, 1, values).addCallback(cb2)

        def cb2(result):
            self.assertFalse(result)
            return self.t.setEntry(
                dt1, 1, values).addCallback(cb3)

        def cb3(result):
            self.assertFalse(result)
            values[0] = 404
            return self.t.setEntry(
                dt1, 1, values).addCallback(self.assertTrue)

        values = [
            200, False, ip1,
            1, # vhost_id
            1, # url_id
            1, # ref_id
            1, # ua_id
        ]
        return self.t.setEntry(dt1, 0, values).addCallback(cb1)

    @defer.inlineCallbacks
    def writeAllRecords(self):
        for dt, theseRecords in RECORDS.iteritems():
            for k, thisRecord in enumerate(theseRecords):
                wasConflict = yield self.t.setEntry(dt, k, thisRecord)
                self.assertFalse(wasConflict)

    def test_setMultipleEntries(self):
        return self.writeAllRecords()
    
    def test_setRecord(self):
        def cb1(null):
            return self.t.getRecord(dt1, 0).addCallback(cb2)

        def cb2(record):
            self.assertEqual(record, firstRecord)

        firstRecord = RECORDS[dt1][0]
        return self.t.setRecord(dt1, 0, firstRecord).addCallback(cb1)
