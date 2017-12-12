#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!
"""
LICENSE
Copyright (C) 2014-2015 Tellectual LLC

"""

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
