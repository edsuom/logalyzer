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
        self.rules = {'BotMatcher': RULES_BOT, 'UAMatcher': RULES_UA}
        self.r = logread.ProcessReader({})
        self.m = self.r.m

    def uaMatcher(self, ip, ua):
        if 'bot' in ua:
            return True
        if 'yandex' in ua:
            return True
        return False

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
                self.assertRecord(result, http=http)
        self.r.exclude = []
        for http in (200, 301, 400, 404):
            self.assertRecord(mr(http, "-", "-"))
        stuffBase.append(200)
        # Excluded UA
        with self.matcher('uaMatcher'):
            self.assertRecord(mr("-", "Mozilla innocent browser/1.2"))
            ignoredResult = mr("-", "I am a bot")
            self.assertIsInstance(ignoredResult[0], str)
            self.assertFalse(ignoredResult[1])
        # Excluded URL
        with self.matcher('botMatcher'):
            stuffBase = stuffBase[:-2]
            tail = [200, "-", "Mozilla innocent browser/1.2"]
            # ... innocent URL
            self.assertIsInstance(mr("/", *tail), tuple)
            # ... malicious URL
            result = mr("/foo/wp-login.php", *tail)
            self.assertEqual(list(result), [ip1, True])
        # Innocent record, still rejected until IP matcher cleared
        args = (
            "/index.html", 302, "http://greatsite.com/", "Awesome browser/2.3")
        result = mr(*args)
        self.assertNone(result)
        self.r.ipm.removeIP(ip1)
        result = mr(*args)
        self.assertRecord(result)

    def _checkParsing(self, fileName, matcher, **kw):
        yielded = {}
        filePath = fileInModuleDir(fileName)
        counts = {'ignored': 0, 'blocked': 0, 'accepted': 0}
        with self.matcher(matcher):
            for stuff in self.r(filePath):
                self.assertIsInstance(stuff, (list, tuple))
                self.assertEqual(len(stuff), 2)
                if isinstance(stuff[0], str):
                    if stuff[1]:
                        counts['blocked'] += 1
                    else:
                        counts['ignored'] += 1
                    continue
                counts['accepted'] += 1
        self.assertGreater(
            max(counts.values()), 0,
            "Nothing was parsed from {}".format(fileName))
        for name, value in kw.iteritems():
            self.assertEqual(
                counts[name], value,
                "Had {:d} counts of type '{}', not {:d}".format(
                    counts[name], name, value))
    
    def test_call_oldFormat_bot(self):
        return self._checkParsing(
            "access.log.1", 'botMatcher', accepted=63, blocked=2, ignored=1)

    def test_call_newFormat_bot(self):
        return self._checkParsing(
            "access.log.2", 'botMatcher', accepted=91, blocked=3, ignored=13)

    def test_call_oldFormat_ua(self):
        return self._checkParsing(
            "access.log.1", 'uaMatcher', accepted=260, blocked=0, ignored=6)

    def test_call_newFormat_ua(self):
        return self._checkParsing(
            "access.log.2", 'uaMatcher', accepted=80, blocked=0, ignored=34)

    

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
        rejectedIPs = yield self.r.run(["access.log.1"]).addErrback(self.oops)
        self.msg(
            "Dispatch loop done, got {:d} bad IP addresses",
            len(rejectedIPs))
        self.assertIsInstance(rejectedIPs, dict)
        for ip in rejectedIPs:
            self.assertIsInstance(ip, str)
            self.assertIsInstance(rejectedIPs[ip], bool)
        self.assertTrue(len(rejectedIPs) > 1)
        Ne = 2
        ip = "207.216.252.13"
        N = yield self.t.hitsForIP(ip)
        msg = "Expected at least {:d} records for IP '{}', got {:d}".format(
            Ne, ip, N)
        self.assertGreaterEqual(N, Ne, msg)

        

            
