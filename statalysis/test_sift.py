#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!
"""
LICENSE
Copyright (C) 2014-2015 Tellectual LLC

"""

import os.path, random

import ipcalc

import testbase as tb

import sift


class TestIPMatcher(tb.TestCase):
    def setUp(self):
        self.ip = sift.IPMatcher(tb.RULES_IP)

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
                [x.host_first() for x in self.ip.networks])

    def test_someMatches(self):
        cases = (
            ("109.207.200.0",   True),
            ("109.207.201.10",  True),
            ("109.206.250.240", False),
            ("109.227.67.33",   True))
        for thisIP, expectMatch in cases:
            self.assertEqual(self.ip(thisIP), expectMatch, thisIP)
        

class TestUAMatcher(tb.TestCase):
    def setUp(self):
        self.ua = sift.UAMatcher(tb.RULES_UA)
        self.table = {}

    def checkWithRandomIP(self, uaString, expected):
        def msg():
            maybeNo = "" if expected else "no "
            return "Expected {}match for {}: '{}'".format(
                maybeNo, ip, uaString)
        
        thisList = self.table.setdefault(expected, [])
        while len(thisList) < 10:
            thisList.append(
                ".".join([str(random.randint(0,255)) for k in xrange(4)]))
        ip = random.choice(thisList)
        if expected:
            self.assertTrue(self.ua(ip, uaString), msg())
        else:
            self.assertFalse(self.ua(ip, uaString), msg())
        
    def test_someMatches(self):
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
        # Test negatives and positives, multiple times to ensure
        # caching doesn't screw things up
        for k in xrange(10):
            for uaString in negatives:
                self.checkWithRandomIP(uaString, False)
            for uaString in positives:
                self.checkWithRandomIP(uaString, True)


class TestBotMatcher(tb.TestCase):
    def setUp(self):
        self.bot = sift.BotMatcher(tb.RULES_BOT)

    def test_someMatches(self):
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
            )
        # Test negatives and positives, multiple times to ensure
        # caching doesn't screw things up
        for k in xrange(10):
            for url in negatives:
                self.assertFalse(self.bot(url))
            for url in positives:
                self.assertTrue(self.bot(url))
        
            

        
