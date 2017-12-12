#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!
"""
LICENSE
Copyright (C) 2014-2015 Tellectual LLC

"""

import os.path, random
from time import time

import ipcalc
from ipaddress import IPv4Address

import testbase as tb

import sift


class TestIPMatcher(tb.TestCase):
    ipList = (
        "134.249.51.137",
        "195.242.218.133",
        "216.137.107.220",
        "24.10.60.163",
        "134.249.76.28")

    def setUp(self):
        self.m = sift.IPMatcher(tb.RULES_IP)

    def test_someMatches(self):
        cases = (
            ("109.207.200.0",   False),
            ("118.194.247.128", True),
            ("109.206.250.240", False),
            ("134.249.49.191",  True))
        for thisIP, expectMatch in cases:
            self.assertEqual(self.m(thisIP), expectMatch, thisIP)

    def test_performance_noCache(self):
        def timeit(f, *args):
            t0 = time()
            f(*args)
            return time() - t0

        def runFromList(N, f, ipList):
            count = 0
            Nk = len(ipList)
            while count < N:
                ip = ipList[count % Nk]
                f(ip)
                count += 1
        
        # Build a matcher and plain old dict with the same shitload of
        # fake IP addresses
        ipm = sift.IPMatcher(); ipd = {}
        count = 0; N = 10000
        maxInt = 2**32 - 1
        tm = td = 0
        while count < N:
            ip = str(IPv4Address(random.randint(0, maxInt)))
            tm += timeit(ipm.addIP, ip)
            td += timeit(ipd.__setitem__, ip, False)
            count += 1
        print("\nIPM takes {:.1f}x as long as plain dict to initialize".format(
            tm/td))
        # Now add a few known IP addresses
        for ip in self.ipList:
            ipm.addIP(ip)
            ipd[ip] = False
        # Time to find hits
        tm = timeit(runFromList, 100, ipm, self.ipList)
        td = timeit(runFromList, 100, ipd.__contains__, self.ipList)
        print("\nIPM takes {:.1f}x as long to find hits".format(
            tm/td))
        

        
            

class TestNetMatcher(tb.TestCase):
    def setUp(self):
        self.m = sift.NetMatcher(tb.RULES_NET)

    def test_addedRules(self):
        cases = (
            "109.207.200.0/21",
            "109.227.64.0/18",
            "37.56.0.0/15",
            "46.185.0.0/17")
        for ipString in cases:
            thisNet = ipcalc.Network(ipString)
            self.assertIn(
                thisNet.host_first(),
                [x[0].host_first() for x in self.m.networks])

    def test_someMatches(self):
        cases = (
            ("109.207.200.0",   True),
            ("109.207.201.10",  True),
            ("109.206.250.240", False),
            ("109.227.67.33",   True))
        for thisIP, expectMatch in cases:
            self.assertEqual(self.m(thisIP), expectMatch, thisIP)
        

class ReMatcherTestMixin:
    def setUp(self):
        rules = getattr(tb, self.rulesName)
        self.m = getattr(sift, self.matcherName)(rules)
        self.table = {}

    def checkWithRandomIP(self, string, expected):
        def msg():
            maybeNo = "" if expected else "no "
            return "Expected {}match for {}: '{}'".format(
                maybeNo, ip, string)

        thisList = self.table.setdefault(expected, [])
        while len(thisList) < 10:
            thisList.append(
                ".".join([str(random.randint(0,255)) for k in xrange(4)]))
        ip = random.choice(thisList)
        if expected:
            self.assertTrue(self.m(ip, string), msg())
        else:
            self.assertFalse(self.m(ip, string), msg())
        
    def test_someMatches(self):
        # Test negatives and positives, multiple times to ensure
        # caching doesn't screw things up
        for k in xrange(10):
            for string in self.negatives:
                self.checkWithRandomIP(string, False)
            for string in self.positives:
                self.checkWithRandomIP(string, True)


class TestUAMatcher(ReMatcherTestMixin, tb.TestCase):
    rulesName = 'RULES_UA'
    matcherName = 'UAMatcher'
    negatives = (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:20.0) " +\
          "Gecko/20100101 Firefox/20.0",
        "Mozilla/5.0 (compatible; Google Desktop/5.9.1005.12335; " +\
          "http://desktop.google.com/)",
        "Mozilla/5.0 (iPad; CPU OS 6_0_1 like Mac OS X) " +\
          "AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 " +\
          "Mobile/10A523 Safari/8536.25",
        "Perfect%20Browser-iPad/7.0 CFNetwork/609 Darwin/13.0.0",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:19.0) " +\
          "Gecko/20100101 Firefox/19.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 6_0 like Mac OS X) " +\
          "AppleWebKit/536.26 (KHTML, like Gecko) Mobile/10A403 " +\
          "[FBAN/FBIOS;FBAV/5.3;FBBV/89182;FBDV/iPhone4,1;FBMD/iPhone;" +\
          "FBSN/iPhone OS;FBSV/6.0;FBSS/2; FBCR/AT&T;FBID/phone;FBLC/en_US]",
    )
    positives = (
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
        "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
        "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
        "msnbot/2.0b (+http://search.msn.com/msnbot.htm)",
        "Twitterbot/1.0",
        "Mozilla/5.0 (compatible; DotBot/1.1; " +\
          "http://www.opensiteexplorer.org/dotbot, help@moz.com)",
        "adbeat_bot",
        "Java/1.6.0_26",
    )


class TestBotMatcher(ReMatcherTestMixin, tb.TestCase):
    rulesName = 'RULES_BOT'
    matcherName = 'BotMatcher'
    negatives = (
        "/",
        "/images/",
        "/images/coolimage.jpg",
        "/favicon.ico",
        "/css/",
        "/index.html",
        "/mypagethathappenstomentionphpbutotherwiseinnocent.html",
    )
    positives = (
        "/scripts/takeover.php",
        "?../../../etc/passwd",
        "/fckeditor",
        "/fckeditor/login",
        "/stuff/account/login",
        "/stupid/scripts/whatever.cgi",
        "/wherever/anything.php?arg1=foo?arg2=bar",
        "/suomi/section-0007.html/trackback/",
        "/js/transport.js",
        "/html/section-0017.html/trackback/",
    )
        
            

        
