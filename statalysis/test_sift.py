#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!
"""
LICENSE
Copyright (C) 2014-2015 Tellectual LLC

"""

import os.path

import ipcalc

import testbase as tb

import sift


class TestIPMatcher(tb.TestCase):
    def setUp(self):
        self.ip = sift.IPMatcher()
        self.rulePath = os.path.join(
            tb.moduleDir(parent=True), "lists", "russians.txt")

    def test_addRules(self):
        self.ip.addRules(self.rulePath)
        cases = (
            "109.207.200.0/21",
            "109.227.64.0/18",
            "37.59.0.0/16",
            "212.129.0.0/18")
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
        # All False until rules are loaded
        for thisIP, expectMatch in cases:
            self.assertEqual(self.ip(thisIP), False)
        # Load rules, clear cache, and try again
        self.ip.clearCache()
        self.ip.addRules(self.rulePath)
        for thisIP, expectMatch in cases:
            self.assertEqual(self.ip(thisIP), expectMatch, thisIP)
        

        

