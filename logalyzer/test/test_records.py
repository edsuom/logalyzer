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

from twisted.internet import defer

from testbase import ip1, ip2, RECORDS, TestCase
import records


class TestRecordKeeper(TestCase):
    verbose = True
    
    def setUp(self):
        verbose = self.isVerbose()
        self.rk = records.RecordKeeper(
            "sqlite://", 1, [], verbose=verbose, info=verbose)
        self.t = self.rk.t
        return self.rk.startup()
    
    @defer.inlineCallbacks
    def tearDown(self):
        for tableName in ('entries',):
            if hasattr(self.t, tableName):
                yield self.t.sql("DROP TABLE {}".format(tableName))
        yield self.rk.shutdown()

    @defer.inlineCallbacks
    def test_purgeIP(self):
        # Add test records
        for dt, theseRecords in RECORDS.iteritems():
            for thisRecord in theseRecords:
                yield self.rk.addRecord(dt, thisRecord)
        # IPM before purge
        self.assertTrue(self.t.ipm(ip1))
        # Purge an IP address. In the test, we wait for the purge, but
        # not in real life.
        yield self.rk.purgeIP(ip1, False)
        # IPM after purge
        self.assertFalse(self.t.ipm(ip1), ip1)
        # Make sure it's not in the DB anymore, either
        N = yield self.t.hitsForIP(ip1)
        self.assertEqual(N, 0)
        
    @defer.inlineCallbacks
    def test_addRecord(self):
        N_expected = [2, 1]
        for dt, theseRecords in RECORDS.iteritems():
            for thisRecord in theseRecords:
                wasAdded = yield self.rk.addRecord(dt, thisRecord)
                self.assertTrue(wasAdded)
        for k, ip in enumerate([ip1, ip2]):
            N = yield self.t.hitsForIP(ip)
            self.assertEqual(N, N_expected[k])
            self.assertTrue(self.t.ipm(ip))
