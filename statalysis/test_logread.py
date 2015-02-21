#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!
"""
LICENSE
Copyright (C) 2014-2015 Tellectual LLC

"""

import os.path
import testbase as tb

import logread


class TestReader(tb.TestCase):
    def setUp(self):
        self.r = logread.Reader(os.path.join(tb.moduleDir(parent=True), 'log'))

    def test_readLines(self):
        lines = self.r.readLinesFromFile("access.log")
        self.assertGreater(len(lines), 100)

    def test_parseDatetimeBlock(self):
        from datetime import datetime as dt
        textExpected = (
            ("20/Feb/2015:12:02:49 +0000", dt(2015, 2, 20, 12, 2, 49)),
            ("2/Jan/2015:21:17:16 +0000", dt(2015, 1, 2, 21, 17, 16)),
            ("07/Sep/2014:06:46:34 -0400", dt(2014, 9, 7, 6, 46, 34)))
        for text, dtExpected in textExpected:
            self.assertEqual(self.r.parseDatetimeBlock(text), dtExpected)

    def test_parseLine(self):
        from datetime import datetime as dt
        textExpected = (
            ('64.233.172.98 freedomtodoubt.com - [07/Sep/2014:06:46:34 -0400] '+\
                 '"GET /ftd.css HTTP/1.1" 200 1238 "http://freedomtodoubt.com/" '+\
                 '"Mozilla/5.0 (Linux; U; Android 4.3; en-us; SPH-L710 Build/JSS15J) '+\
                 'AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30"',
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
            self.assertEqual(self.r.parseLine(text), expected)

    def test_recordator(self):
        lines = self.r.readLinesFromFile("access.log")
        for record in self.r.recordator("freedomtodoubt.com", lines):
            print record

    def test_recordator_with_code(self):
        lines = self.r.readLinesFromFile("access.log")
        for record in self.r.recordator("freedomtodoubt.com", lines, exclude=[404]):
            print record

    def test_run(self):
        records = self.r.run("freedomtodoubt.com", exclude=[404], noUA=True)
        print records
        
            
