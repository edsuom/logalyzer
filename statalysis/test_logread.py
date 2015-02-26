#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!
"""
LICENSE
Copyright (C) 2014-2015 Tellectual LLC

"""

import os.path
from datetime import datetime as dt

import testbase as tb

import logread


ip1 = "221.127.9.141"
ip2 = "82.132.214.244"


class TestRecordKeeper(tb.TestCase):
    
    def setUp(self):
        self.rk = logread.RecordKeeper()

    def test_isRedirect(self):
        vhost = self.rk.isRedirect("foo.com", ip1, 200)
        self.assertEqual(vhost, "foo.com")
        vhost = self.rk.isRedirect("foo.com", ip2, 302)
        self.assertEqual(vhost, "foo.com")
        for k in xrange(10):
            vhost = self.rk.isRedirect("bar.com", ip2, 200)
            self.assertEqual(vhost, "foo.com")
        vhost = self.rk.isRedirect("bar.com", ip1, 200)
        self.assertEqual(vhost, "bar.com")
        

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
              "Safari/534.30"
          ]),
        )
        for text, expected in textExpected:
            self.assertEqual(self.p.parseLine(text), expected)

    def test_makeRecord(self):
        def mr(*args):
            stuff = stuffBase + list(args)
            return self.p.makeRecord(stuff, alreadyParsed=True)

        def uaMatcher(ip, ua):
            return ua.endswith('bot')

        def botMatcher(url):
            if ".php" in url:
                return True
            return False

        # Empty line
        self.assertNone(self.p.makeRecord(""))
        # Excluded codes
        dtStuff = dt(2015, 1, 1, 12, 30)
        stuffBase = ["foo.com", ip1, dtStuff, "/"]
        self.p.exclude = [400, 404]
        for code, expectReject in (
                (200, False), (301, False), (400, True), (404, True)):
            result = mr(code, "-", "-")
            if expectReject:
                self.assertNone(result, code)
            else:
                self.assertNotNone(result, code)
        self.p.exclude = []
        for code in (200, 301, 400, 404):
            self.assertNotNone(mr(code, "-", "-"))
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
        self.r = logread.Reader(
            os.path.join(tb.moduleDir(parent=True), 'log'),
            vhost="freedomtodoubt.com")

    def test_complains(self):
        self.assertRaises(OSError, logread.Reader, 'bogusdir')
        
    def test_run(self):
        def gotRecords(records):
            self.assertIsInstance(records, dict)
            self.assertTrue(len(records) > 100)
        
        return self.r.run()
        
            
