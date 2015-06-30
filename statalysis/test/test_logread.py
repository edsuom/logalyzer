#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!
"""
LICENSE
Copyright (C) 2014-2015 Tellectual LLC

"""

import os.path
from contextlib import contextmanager
from datetime import datetime as dt

from twisted.python import failure
from twisted.internet import defer

from testbase import *

import logread

DB_URL = 'mysql://test@localhost/test'
#DB_URL = 'sqlite://'


class TestProcessReader(TestCase):
    verbose = True

    def setUp(self):
        self.rules = {'BotMatcher': RULES_BOT}
        self.r = logread.ProcessReader({})
        self.m = self.r.m

    def uaMatcher(self, ip, ua):
        return ua.endswith('bot')

    def botMatcher(self, ip, url):
        if url.endswith(('.php', '.js')):
            return True
        return False
        
    @contextmanager
    def matcher(self, name):
        x = getattr(self.m, name)
        setattr(self.m, name, getattr(self, name))
        yield
        setattr(self.m, name, x)
        
    def test_makeRecord(self):
        def mr(*args):
            stuff = stuffBase + list(args)
            return self.r.makeRecord(stuff, alreadyParsed=True)

        # Empty line
        self.assertNone(self.r.makeRecord(""))
        # Excluded codes
        dtStuff = dt(2015, 1, 1, 12, 30)
        stuffBase = ["foo.com", ip1, dtStuff, "/"]
        self.r.exclude = [400, 404]
        for http, expectReject in (
                (200, False), (301, False), (400, True), (404, True)):
            result = mr(http, "-", "-")
            if expectReject:
                self.assertNone(result, http)
            else:
                self.assertNotNone(result, http)
        self.r.exclude = []
        for http in (200, 301, 400, 404):
            self.assertNotNone(mr(http, "-", "-"))
        stuffBase.append(200)
        # Excluded UA
        with self.matcher('uaMatcher'):
            self.assertNotNone(mr("-", "Mozilla innocent browser/1.2"))
            self.assertNone(mr("-", "I am a bot"))
        # Excluded URL
        with self.matcher('botMatcher'):
            stuffBase = stuffBase[:-2]
            tail = [200, "-", "Mozilla innocent browser/1.2"]
            # ... innocent URL
            self.assertIsInstance(mr("/", *tail), tuple)
            # ... malicious URL
            result = mr("/foo/wp-login.php", *tail)
            self.assertEqual(result, ip1)
        # Innocent record, still rejected until IP matcher cleared
        args = (
            "/index.html", 302, "http://greatsite.com/", "Awesome browser/2.3")
        result = mr(*args)
        self.assertNone(result)
        self.r.ipm.removeIP(ip1)
        result = mr(*args)
        self.assertEqual(result[0], dtStuff)
        self.assertIsInstance(result[1], dict)
        self.assertTrue(len(result[1]) > 5)

    def _checkParsing(self, fileName, N1, N2):
        yielded = {}
        filePath = fileInModuleDir(fileName)
        with self.matcher('botMatcher'):
            for stuff in self.r(filePath):
                yielded.setdefault(type(stuff), []).append(stuff)
        self.assertGreater(
            len(yielded), 0, "Nothing was parsed from {}".format(fileName))
        self.assertGreaterEqual(len(yielded[str]), N1)
        self.assertGreaterEqual(len(yielded[tuple]), N2)
        
    def test_call_oldFormat(self):
        return self._checkParsing("access.log.1", 2, 10)

    def test_call_newFormat(self):
        return self._checkParsing("access.log.2", 1, 10)


class TestReader(TestCase):
    verbose = False

    def setUp(self):
        self.rules = {'BotMatcher': RULES_BOT}
        self.r = logread.Reader(
            self.rules, DB_URL,
            cores=1, verbose=self.isVerbose())
        self.r.myDir = moduleDir()
        self.t = self.r.rk.t

    @defer.inlineCallbacks
    def tearDown(self):
        yield self.r.shutdown()
        
    def test_getMatchers(self):
        matchers = self.r.getMatchers(self.rules)
        self.assertEqual(
            matchers.keys(), ['BotMatcher'])
        import sift
        self.assertIsInstance(
            matchers['BotMatcher'], sift.BotMatcher)
    
    def test_dispatch(self):
        pass
       
    @defer.inlineCallbacks
    def test_run(self):
        ipList = yield self.r.run(["access.log.1"]).addErrback(self.oops)
        self.msg("Dispatch loop done, got {:d} bad IP addresses", len(ipList))
        self.assertIsInstance(ipList, list)
        self.assertTrue(len(ipList) > 1)
        Ne = 2
        ip = "207.216.252.13"
        N = yield self.t.hitsForIP(ip)
        msg = "Expected at least {:d} records for IP '{}', got {:d}".format(
            Ne, ip, N)
        self.assertGreaterEqual(N, Ne, msg)

        

            
