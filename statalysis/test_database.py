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


def makeEntry(http, was_rd, ip, *ids):
    result = [http, was_rd, ip]
    for thisID in ids:
        result.append(thisID)
    for k in xrange(4-len(ids)):
        result.append(1)
    return result




class TestTransactor(tb.TestCase):
    def setUp(self):
        self.dbPath = "file.db"
        self.t = database.Transactor("sqlite:///{}".format(self.dbPath))

    @defer.inlineCallbacks
    def tearDown(self):
        for ip in (ip1, ip2):
            yield self.t.purgeIP(ip)
        yield self.t.shutdown()
    
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

        values = makeEntry(200, False, ip1)
        return self.t.setEntry(dt1, 0, values).addCallback(cb1)

    def test_setRecord(self):
        def cb1(null):
            return self.t.getRecord(dt1, 0).addCallback(cb2)

        def cb2(record):
            self.assertEqual(record, firstRecord)

        firstRecord = RECORDS[dt1][0]
        return self.t.setRecord(dt1, 0, firstRecord).addCallback(cb1)

    @defer.inlineCallbacks
    def writeAllRecords(self):
        for dt, theseRecords in RECORDS.iteritems():
            for k, thisRecord in enumerate(theseRecords):
                kNew = yield self.t.setRecord(dt, k, thisRecord)
                self.assertEqual(kNew, k)

    def test_writeMultipleRecords(self):
        return self.writeAllRecords()

    @defer.inlineCallbacks
    def test_writesConflictingRecord(self):
        yield self.writeAllRecords()
        cRecord = RECORDS[dt1][0]
        # Repeat of same record yields same sequence
        kNew = yield self.t.setRecord(dt1, 0, cRecord)
        self.assertEqual(kNew, 0)
        # Change URL and get new sequence
        cRecord['url'] = "/bogus.html"
        kNew = yield self.t.setRecord(dt1, 0, cRecord)
        self.assertNotEqual(kNew, 0)
        

    
                    

