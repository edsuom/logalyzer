#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# logalyzer:
# Parses your bloated HTTP access logs to extract the info you want
# about hits to your webserver from (hopefully) real people instead of
# just the endless hackers and bots. Stores the info in a relational
# database where you can access it using all the power of SQL.
#
# Copyright (C) 2015, 2017, 2018 by Edwin A. Suominen,
# http://edsuom.com/logalyzer
#
# See edsuom.com for API documentation as well as information about
# Ed's background and other projects, software and otherwise.
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the
# License. You may obtain a copy of the License at
# 
#   http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an "AS
# IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language
# governing permissions and limitations under the License.

import os.path, random
from copy import copy

from twisted.internet import defer
from twisted.python import failure

from asynqueue.iteration import Delay

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
            tableNames = ['entries', 'bad_ip', 'files'] + self.t.indexedValues
            for tableName in tableNames:
                if hasattr(self.t, tableName):
                    yield self.t.sql("DROP TABLE {}".format(tableName))
            yield self.t.shutdown()

    def _progress(self):
        if not hasattr(self, '_pCounter'):
            self._pCounter = 0
        self._pCounter += 1
        return self._pCounter
            
    @defer.inlineCallbacks
    def test_preload(self):
        # Write four dt-ip combos to DB
        for dt in (dt1, dt2):
            for ip in (ip1, ip2):
                values = makeEntry(ip, 200, False)
                yield self.t.insertEntry(dt, values)
        # Do the preload
        N_ip = yield self.t.preload(self._progress, 1, 1)
        # Check that progress calls were made
        self.assertGreater(self._progress(), 2)
        # Check the IP Matcher
        for ip, expected in ((ip1, True), (ip2, True), ("192.168.1.1", False)):
            self.assertEqual(self.t.ipm(ip), expected)
        # Wait for and check the DTK
        yield Delay().untilEvent(lambda: not self.t.dtk.isPending())
        for dt, expected in ((dt1, True), (dt2, True), (dt3, False)):
            self.assertEqual(self.t.dtk.check(dt), expected)
                
    @defer.inlineCallbacks
    def test_matchingEntry(self):
        # Since we're not doing preload, give the transactor an empty
        # IP Matcher
        self.t.ipm = database.IPMatcher()
        values = makeEntry(ip1, 200, False)
        # Should be none there yet
        ID = yield self.t.matchingEntry(dt1, values)
        self.assertNone(ID)
        wi = yield self.t.setEntry(dt1, values)
        self.assertTrue(wi)
        # Now there should be
        ID = yield self.t.matchingEntry(dt1, values)
        self.assertNotNone(ID)
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
        # Since we're not doing preload, give the transactor an empty
        # IP Matcher
        self.t.ipm = database.IPMatcher()

        # New entry
        wi = yield self.t.setEntry(dt1, values)
        self.t.ipm.addIP(ip1)
        # Was inserted
        self.assertTrue(wi)
        # DTK was set, though not checked because still dtk_pending
        self.assertEqual(cm, [['set', dt1]])
                         
        # Duplicate entry
        wi = yield self.t.setEntry(dt1, values)
        # Not inserted
        self.assertFalse(wi)
        # DTK was neither checked nor set
        self.assertEqual(len(cm), 1)

        # dtk no longer pending
        self.t.dtk.isPending(False)
        
        # Duplicate entry again
        wi = yield self.t.setEntry(dt1, values)
        # Not inserted, same ID
        self.assertFalse(wi)
        # DTK was check, not set
        self.assertEqual(len(cm), 2)
        self.assertEqual(cm[-1], ['check', dt1])
        
        # New entry: different dt, same values
        wi = yield self.t.setEntry(dt2, values)
        # Was inserted
        self.assertTrue(wi)
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
    def test_setNameValue_more(self):
        def nowRun(null, name, value):
            return self.t.setNameValue(name, value).addCallback(
                lambda ID: IDLists[value].append(ID))
        N = 4
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
                self.t.ipm.addIP(record['ip'])
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
        # Since we're not doing preload, give the transactor an empty
        # IP Matcher
        self.t.ipm = database.IPMatcher()
        firstRecord = RECORDS[dt1][0]
        # Set once and check what we get is what we set
        wi = yield self.t.setRecord(dt1, firstRecord)
        # Was inserted
        self.assertTrue(wi)
        records = yield self.t.getRecords(dt1)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0], firstRecord)
        # Set again with slight difference
        modRecord = firstRecord.copy()
        modRecord['ua'] = "Foo Browser/1.2"
        wi = yield self.t.setRecord(dt1, modRecord)
        # Was inserted
        self.assertTrue(wi)
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
        yield self.t.fileInfo(file1, dt1, 1234, 1000)
        x = yield self.t.fileInfo(file1)
        self.assertEqual(x, (dt1, 1234, 1000))
        # Set differently and get
        yield self.t.fileInfo(file1, dt1, 5678, 2000)
        x = yield self.t.fileInfo(file1)
        self.assertEqual(x, (dt1, 5678, 2000))
        # Set and get a different file
        yield self.t.fileInfo(file2, dt2, 5678, 2000)
        x = yield self.t.fileInfo(file2)
        self.assertEqual(x, (dt2, 5678, 2000))
        
        
        
        
