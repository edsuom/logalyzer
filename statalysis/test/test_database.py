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


VERBOSE = True

DB_URL = 'mysql://test@localhost/test'
#DB_URL = 'sqlite://'


def makeEntry(id, http, was_rd, *ids):
    result = [id, http, was_rd]
    for thisID in ids:
        result.append(thisID)
    for k in xrange(4-len(ids)):
        result.append(1)
    return result


class TestDTK(TestCase):
    rows = [(dt1,), (dt1,), (dt2,)]

    def test_init(self):
        dtk = database.DTK(self.rows)
        self.assertEqual(len(dtk), 2)
        self.assertEqual(
            dtk.x,
            {2015: {
                2: {20: {12: {2: [49]}}},
                3: {2:  {21: {17: [16]}}}},
             })

    def test_check(self):
        dtk = database.DTK()
        self.assertFalse(dtk.check(dt1))
        dtk.load(self.rows)
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
    verbose = False
    spew = False
    
    def setUp(self):
        self.handler = TestHandler(self.isVerbose())
        logging.getLogger('asynqueue').addHandler(self.handler)
        self.t = database.Transactor(
            DB_URL, verbose=self.isVerbose(), spew=self.spew)
        return self.t.waitUntilRunning()
        
    @defer.inlineCallbacks
    def tearDown(self):
        if getattr(getattr(self, 't', None), 'running', False):
            tableNames = ['entries', 'files'] + self.t.indexedValues
            for tableName in tableNames:
                if hasattr(self.t, tableName):
                    yield self.t.sql("DROP TABLE {}".format(tableName))
            yield self.t.shutdown()

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
    def test_matchingEntry(self):
        values = makeEntry(ip1, 200, False)
        # Should be none there yet
        ID = yield self.t.matchingEntry(dt1, values)
        self.assertNone(ID)
        wi, ID1 = yield self.t.setEntry(dt1, values)
        self.assertTrue(wi)
        # Now there should be
        ID = yield self.t.matchingEntry(dt1, values)
        self.assertEqual(ID, ID1)
        # A different dt doesn't match
        ID = yield self.t.matchingEntry(dt2, values)
        self.assertNone(ID)
        # Any difference in values makes the match fail
        for k in xrange(3,7):
            newValues = copy(values)
            newValues[k] = 2
            ID = yield self.t.matchingEntry(dt1, newValues)
            self.assertNone(ID)
                
    @defer.inlineCallbacks
    def test_setEntry(self):
        # Test setup
        self.t.dtk = MockDTK(self.verbose)
        cm = self.t.dtk.callsMade
        values = makeEntry(ip1, 200, False)

        # New entry
        wi, ID1 = yield self.t.setEntry(dt1, values)
        # Was inserted
        self.assertTrue(wi)
        # Must be an integer ID
        self.assertIsInstance(ID1, (int, long))
        # DTK was set, though not checked because still dtk_pending
        self.assertEqual(cm, [['set', dt1]])
                         
        # Duplicate entry
        wi, ID2 = yield self.t.setEntry(dt1, values)
        # Not inserted
        self.assertFalse(wi)
        # Same as the other one
        self.assertEqual(ID2, ID1)
        # DTK was neither checked nor set
        self.assertEqual(len(cm), 1)

        # dtk no longer pending
        self.t.dtk.isPending(False)
        
        # Duplicate entry again
        wi, ID2 = yield self.t.setEntry(dt1, values)
        # Not inserted, same ID
        self.assertFalse(wi)
        self.assertEqual(ID2, ID1)
        # DTK was check, not set
        self.assertEqual(len(cm), 2)
        self.assertEqual(cm[-1], ['check', dt1])
        
        # New entry: different dt, same values
        wi, ID3 = yield self.t.setEntry(dt2, values)
        # Was inserted
        self.assertTrue(wi)
        # New ID
        self.assertIsInstance(ID3, (int, long))
        self.assertNotEqual(ID3, ID1)
        # DTK was checked and set
        self.assertEqual(len(cm), 4)
        self.assertEqual(cm[-2:], [['check', dt2], ['set', dt2]])
        
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
            return self.t._getID(name, value).addCallback(
                lambda ID: IDLists[value].append(ID))
        N = 4
        self.t.cacheSetup()
        someValues = ("foo", "bar-whatever", "/wasting-time forever")
        for name in self.t.indexedValues:
            dList = []
            IDLists = {}
            for value in someValues:
                IDLists[value] = []
                for k in xrange(N):
                    randomDelay = 0.5*random.random()
                    d = deferToDelay(randomDelay)
                    d.addCallback(nowRun, name, value)
                    dList.append(d)
            yield defer.DeferredList(dList)
            for value in someValues:
                IDList = IDLists[value]
                self.assertEqual(len(IDList), N)
                self.assertEqual(min(IDList), max(IDList))

    def _writeIndexedValues(self, record):
        dList = []
        for name in self.t.indexedValues:
            dList.append(self.t.setNameValue(name, record[name]))
        return defer.gatherResults(dList)
    
    @defer.inlineCallbacks                
    def test_getValuesFromIDs(self):
        record = RECORDS[dt1][0]
        IDs = yield self._writeIndexedValues(record)
        valueDict = yield self.t._getValuesFromIDs(IDs)
        for name, value in valueDict.iteritems():
            self.assertEqual(value, record[name])

    @defer.inlineCallbacks                
    def writeAllRecords(self):
        for dt, records in RECORDS.iteritems():
            for record in records:
                values = [record[x] for x in self.t.directValues]
                IDs = yield self._writeIndexedValues(record)
                values.extend(IDs)
                yield self.t.insertEntry(dt, values)
            
    @defer.inlineCallbacks                
    def test_getRecords(self):
        def checkValues(x, y):
            names = self.t.directValues + self.t.indexedValues
            for name in names:
                self.assertIn(name, x)
                self.assertEqual(x[name], y[name])
        
        # Write all records
        yield self.writeAllRecords()
        # Call, repeatedly
        for kk in xrange(5):
            records = yield self.t.getRecords(dt1)
            for k, record in enumerate(records):
                checkValues(record, RECORDS[dt1][k])
                
    @defer.inlineCallbacks
    def test_setRecord(self):
        firstRecord = RECORDS[dt1][0]
        # Set once and check what we get is what we set
        wi, ID1 = yield self.t.setRecord(dt1, firstRecord)
        # Was inserted
        self.assertTrue(wi)
        self.assertIsInstance(ID1, (int, long))
        records = yield self.t.getRecords(dt1)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0], firstRecord)
        # Set again with slight difference
        modRecord = firstRecord.copy()
        modRecord['ua'] = "Foo Browser/1.2"
        wi, ID2 = yield self.t.setRecord(dt1, modRecord)
        # Was inserted
        self.assertTrue(wi)
        self.assertIsInstance(ID2, (int, long))
        self.assertNotEqual(ID2, ID1)
        records = yield self.t.getRecords(dt1)
        self.assertEqual(len(records), 2)
        self.assertIn(firstRecord, records)
        self.assertIn(modRecord, records)
    
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
        
        
        
        
