#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!
"""
LICENSE
Copyright (C) 2014-2015 Tellectual LLC

"""

import os.path, random
from copy import copy

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
        self.assertEqual(len(dtk), 2)
        self.assertEqual(
            dtk.x,
            {2015: {
                2: {20: {12: [2]}},
                3: {2:  {21: [17]}}},
             })

    def test_check(self):
        dtk = database.DTK()
        self.assertFalse(dtk.check(dt1))
        dtk.load(ROWS)
        self.assertTrue(dtk.check(dt1))
        self.assertTrue(dtk.check(dt2))
        self.assertFalse(dtk.check(dt3))

    def test_set(self):
        dtk = database.DTK()
        self.assertFalse(dtk.check(dt1))
        dtk.set(dt1)
        self.assertTrue(dtk.check(dt1))
        self.assertFalse(dtk.check(dt2))
        dtk.set(dt3)
        self.assertTrue(dtk.check(dt3))
        self.assertFalse(dtk.check(dt2))
        

class TestTransactor(TestCase):
    def setUp(self):
        # In-memory database
        self.t = database.Transactor("sqlite://")#, echo=True)
        return self.t.preload()
    
    def tearDown(self):
        return self.t.shutdown()

    def test_pendingID(self):
        pe = self.t._pendingID
        names = ('alpha', 'bravo', 'charlie')
        values = ('delta', 'foxtrot', 'golf')
        for j, name in enumerate(names):
            for k, value in enumerate(values):
                d = defer.Deferred()
                self.assertEqual(pe(name, value), None)
                pe(name, value, d)
                self.assertEqual(pe(name, value), d)
                if j > 0:
                    self.assertNotEqual(pe(names[j-1], value), d)
                if k > 0:
                    self.assertNotEqual(pe(name, values[k-1]), d)
                pe(name, value, clear=True)
                self.assertEqual(pe(name, value), None)
    
    @defer.inlineCallbacks
    def test_setEntry(self):
        values = makeEntry(200, False, ip1)
        # Add new entry for first k
        code = yield self.t.setEntry(dt1, 0, values)
        self.assertEqual(code, 'a')
        # Add new entry for second k
        code = yield self.t.setEntry(dt1, 1, values)
        self.assertEqual(code, 'a')
        # Set duplicate entry for first k
        code = yield self.t.setEntry(dt1, 1, values)
        self.assertEqual(code, 'p')
        # Confirm conflict with changed entry having same dt-k
        values[0] = 404
        code = yield self.t.setEntry(dt1, 1, values)
        self.assertEqual(code, 'c')
        # But still no problem with original entry
        values[0] = 200
        code = yield self.t.setEntry(dt1, 1, values)
        self.assertEqual(code, 'p')

    @defer.inlineCallbacks
    def test_setNameValue(self):
        someValues = ("/", "foo", "bar-whatever", "/wasting-time forever")
        for j in xrange(3):
            for name in self.t.indexedValues:
                for k, value in enumerate(someValues):
                    # First time set...
                    ID = yield self.t.setNameValue(name, value)
                    self.assertEqual(ID, k+1)
                    # ...is same as second time
                    ID = yield self.t.setNameValue(name, value)
                    self.assertEqual(ID, k+1)
        
    @defer.inlineCallbacks
    def test_getID(self):
        def nowRun(null, name, value):
            d = self.t._getID(name, value)
            d.addCallback(gotID, value)
            return d

        def gotID(ID, value):
            IDLists[value].append(ID)

        N = 4
        self.t.cacheSetup()
        someValues = ("foo", "bar-whatever", "/wasting-time forever")
        for name in self.t.indexedValues:
            dList = []
            IDLists = {}
            for value in someValues:
                IDLists[value] = []
                for k in xrange(N):
                    randomDelay = random.randrange(0, 2)
                    d = self.t.deferToDelay(randomDelay)
                    d.addCallback(nowRun, name, value)
                    dList.append(d)
            yield defer.DeferredList(dList)
            for value in someValues:
                IDList = IDLists[value]
                self.assertEqual(len(IDList), N)
                self.assertEqual(min(IDList), max(IDList))
        
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
        cRecord = copy(RECORDS[dt1][0])
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

    @defer.inlineCallbacks
    def test_fileInfo(self):
        file1 = "access.log"
        file2 = "another/access.log"
        # Nothing at first
        x = yield self.t.fileInfo(file1)
        self.assertEqual(x, None)
        # Set and get
        yield self.t.fileInfo(file1, dt1, 1234)
        x = yield self.t.fileInfo(file1)
        self.assertEqual(x, (dt1, 1234))
        # Set differently and get
        yield self.t.fileInfo(file1, dt1, 5678)
        x = yield self.t.fileInfo(file1)
        self.assertEqual(x, (dt1, 5678))
        # Set and get a different file
        yield self.t.fileInfo(file2, dt2, 5678)
        x = yield self.t.fileInfo(file2)
        self.assertEqual(x, (dt2, 5678))
        
        
        
        
