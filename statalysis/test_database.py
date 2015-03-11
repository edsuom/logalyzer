#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!
"""
LICENSE
Copyright (C) 2014-2015 Tellectual LLC

"""

import os.path

from twisted.internet import defer
from twisted.python import failure

from testbase import *

import database


ROWS = [(dt1, 0), (dt1, 1), (dt2, 0)]


def makeEntry(http, was_rd, ip, *ids):
    result = [http, was_rd, ip]
    for thisID in ids:
        result.append(thisID)
    for k in xrange(4-len(ids)):
        result.append(1)
    return result


class TestDTK(TestCase):
    def test_init(self):
        dtk = database.DTK(ROWS)
        self.assertEqual(len(dtk), 3)
        self.assertEqual(
            dtk.x,
            {2015: {
                2: {20: {12: {2:  {49: [0, 1]}}}},
                3: {2:  {21: {17: {16: [0]}}}}}}
            )

    def test_check(self):
        dtk = database.DTK()
        self.assertFalse(dtk.check(dt1, 0))
        dtk.load(ROWS)
        self.assertTrue(dtk.check(dt1, 0))
        self.assertTrue(dtk.check(dt1, 1))
        self.assertFalse(dtk.check(dt1, 2))
        self.assertTrue(dtk.check(dt2, 0))
        self.assertFalse(dtk.check(dt2, 1))

    def test_set(self):
        dtk = database.DTK()
        self.assertFalse(dtk.check(dt1, 0))
        dtk.set(dt1, 0)
        self.assertTrue(dtk.check(dt1, 0))
        self.assertFalse(dtk.check(dt1, 1))
        dtk.set(dt1, 1)
        self.assertTrue(dtk.check(dt1, 1))
        self.assertFalse(dtk.check(dt1, 2))
        

class TestTransactor(TestCase):
    def setUp(self):
        self.dbPath = "file.db"
        self.t = database.Transactor(
            "sqlite:///{}".format(self.dbPath))
    
    @defer.inlineCallbacks
    def tearDown(self):
        for ip in (ip1, ip2):
            yield self.t.purgeIP(ip)
        yield self.t.shutdown()
    
    def test_setEntry(self):
        def cb1(result):
            self.assertEqual(result, 'a')
            self.assertTrue(os.path.isfile(self.dbPath))
            return self.t.setEntry(
                dt1, 1, values).addCallback(cb2)

        def cb2(result):
            self.assertEqual(result, 'a')
            return self.t.setEntry(
                dt1, 1, values).addCallback(cb3)

        def cb3(result):
            self.assertEqual(result, 'p')
            values[0] = 404
            return self.t.setEntry(
                dt1, 1, values).addCallback(self.assertEqual, 'c')

        values = makeEntry(200, False, ip1)
        return self.t.setEntry(dt1, 0, values).addCallback(cb1)

    @defer.inlineCallbacks
    def test_setRecord(self):
        firstRecord = RECORDS[dt1][0]
        # Set once and check what we get is what we set
        result = yield self.t.setRecord(dt1, 0, firstRecord)
        self.assertEqual(result, None)
        record = yield self.t.getRecord(dt1, 0)
        self.assertEqual(record, firstRecord)
        # Set again with slight difference to confirm caching doesn't
        # raise error
        modRecord = firstRecord.copy()
        modRecord['ua'] = "Foo Browser/1.2"
        result = yield self.t.setRecord(dt1, 2, modRecord)
        self.assertEqual(result, None)
        record = yield self.t.getRecord(dt1, 2)
        self.assertEqual(record, modRecord)
    
    @defer.inlineCallbacks
    def writeAllRecords(self):
        for dt, theseRecords in RECORDS.iteritems():
            for k, thisRecord in enumerate(theseRecords):
                result = yield self.t.setRecord(dt, k, thisRecord)
                self.assertEqual(result, None)

    def test_writeMultipleRecords(self):
        return self.writeAllRecords()

    @defer.inlineCallbacks
    def test_writesConflictingRecord(self):
        yield self.writeAllRecords()
        cRecord = RECORDS[dt1][0]
        # Repeat of same record yields same sequence
        result = yield self.t.setRecord(dt1, 0, cRecord)
        self.assertEqual(result, 0)
        # Change URL and get new sequence
        cRecord['url'] = "/bogus.html"
        result = yield self.t.setRecord(dt1, 0, cRecord)
        self.assertEqual(result, 2)

    @defer.inlineCallbacks
    def test_purgeIP(self):
        yield self.writeAllRecords()
        rowsDeleted = yield self.t.purgeIP(ip1)
        self.assertEqual(rowsDeleted, 2)
        rowsDeleted = yield self.t.purgeIP(ip1)
        self.assertEqual(rowsDeleted, 0)

    @defer.inlineCallbacks
    def test_hitsForIP(self):
        N = yield self.t.hitsForIP(ip1)
        self.assertEqual(N, 0)
        yield self.writeAllRecords()
        N = yield self.t.hitsForIP(ip1)
        self.assertEqual(N, 2)
        N = yield self.t.hitsForIP(ip2)
        self.assertEqual(N, 1)

    
        
