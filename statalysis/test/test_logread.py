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

from testbase import RULES_BOT, moduleDir, TestCase

import logread

DB_URL = 'mysql://test@localhost/test'
#DB_URL = 'sqlite://'


class TestReader(TestCase):
    verbose = True
    
    def setUp(self):
        logFiles = [
            os.path.join(moduleDir(), 'log', 'access.log')]
        self.rules = {'BotMatcher': RULES_BOT}
        self.r = logread.Reader(
            logFiles, self.rules, DB_URL,
            cores=1, verbose=self.isVerbose(), vhost="evolvingoutofeden.com")
        self.t = self.r.rk.t

    @defer.inlineCallbacks
    def test_run(self):
        result = yield self.r.run().addErrback(self.oops)
        if isinstance(result, failure.Failure):
            result.raiseException()
        else:
            ipList = result
            self.assertIsInstance(ipList, list)
            self.assertTrue(len(ipList) > 1)
            Ne = 2
            N = yield self.t.hitsForIP("98.190.155.57")
            # Why do I get N=0?
            msg = "Expected at least {:d} records, got {:d}".format(Ne, N)
            self.assertGreater(N, Ne, msg)
            yield self.r.done()

        

            
