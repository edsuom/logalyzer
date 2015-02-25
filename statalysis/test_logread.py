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


class TestParser(tb.TestCase):
    def setUp(self):
        self.p = logread.Parser({})

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
              "AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30"
          ]),
        )
        for text, expected in textExpected:
            self.assertEqual(self.p.parseLine(text), expected)


class TestReader(tb.TestCase):
    def setUp(self):
        self.r = logread.Reader(
            os.path.join(tb.moduleDir(parent=True), 'log'), {})

    def test_complains(self):
        self.assertRaises(OSError, logread.Reader, 'bogusdir')
        
    def test_run(self):
        def gotRecords(records):
            self.assertIsInstance(records, dict)
            self.assertTrue(len(records) > 100)
        
        return self.r.run("freedomtodoubt.com")
        
            
