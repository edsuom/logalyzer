#!/usr/bin/env python

"""
NAME
EzOpt test module


SYNOPSIS
python test_ezopt.py [optional_test_arg]


DESCRIPTION
This is a test module for the ezopt module.

Don't wrap/fill this line! It is a first test line, which is extremely long to test filling of the text and make sure that it looks OK as a result.

This is a second test line.


OPTIONS
--ABC
Long option ABC

-u
Short option u

-s, --speckle
Both option s

-i, --interactive N
Both option i with value N


LICENSE
Copyright (C) 2004 Edwin A. Suominen

Registered Patent Agent * Open Source Developer (Yes, both...)
Web Site: http://www.eepatents.com

This code is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License ('GPL') as published by the Free
Software Foundation; either version 2 of the License, or at your option) any
later version.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GPL for more details.

You probably have several hundred more or less identical copies of the GPL on
your system. Just type 'locate COPYING' in your shell to see a list.

"""

import unittest, sys
import ezopt

# We need to override sys.exit() to prevent bogus errors where script would
# properly exit
def dummyExit(*args):
    print "\nSCRIPT WOULD EXIT HERE WITH CODE %s" % str(args[0])
sys.exit = dummyExit


class Test_Docstring(unittest.TestCase):
    def setUp(self):
        self.ds = ezopt.Docstring()

    def test_docstring(self):
        self.failUnlessEqual(self.ds(__file__), __doc__.strip())


class Test_Opt(unittest.TestCase):
    def setUp(self):
        self.opts = ezopt.Opt(__file__, noParse=True)
        self.dashes = '-' * 40

    def test_sections(self):
        nameList = []; valueList = []
        for name, value in self.opts.sections.items():
            nameList.append(name)
            valueList.append(value)
        self.failUnlessEqual(len(nameList), 5)
        nameList.sort()
        RefNameList = ['description', 'license', 'name', 'options', 'synopsis']
        self.failUnlessEqual(nameList, RefNameList)

    def test_optParser(self):
        print "\n\nMUST DISPLAY HELP BELOW:\n%s" % self.dashes
        sys.argv = [sys.argv[0], '-h']
        self.opts.parse()

    def test_printSource(self):
        print "\n\nMUST DISPLAY SOURCE BELOW:\n%s" % self.dashes
        sys.argv = [sys.argv[0], '--source']
        self.opts.parse()

    def test_printLicense(self):
        print "\n\nMUST DISPLAY LICENSE BELOW:\n%s" % self.dashes
        sys.argv = [sys.argv[0], '--license']
        self.opts.parse()

    def test_all(self):
        def checkBadAttribute():
            print 'Here it is:', self.opts.arg1000

        sys.argv = [sys.argv[0], '-u', '-i5', 'whatever']
        self.opts.parse()
        self.failUnlessEqual(self.opts['ABC'], False)
        self.failUnlessEqual(self.opts['u'], True)
        self.failUnlessEqual(self.opts['i'], '5')
        self.failUnlessEqual(self.opts[0], 'whatever')
        self.failUnlessRaises(AttributeError, checkBadAttribute)

    def test_list(self):
        args = ['adam', 'eve', 'cain', 'abel']
        sys.argv = [sys.argv[0]] + args
        self.opts.parse()
        self.failUnlessEqual(len(self.opts), 4)
        for k, thisArg in enumerate(self.opts):
            self.failUnlessEqual(thisArg, args[k])
        self.failUnlessEqual(k, 3)

    def test_options(self):
        args = ['-i', 'adam', '-u', 'eve', 'cain', 'abel']
        optsDict = {'-i':'adam',}
        sys.argv = [sys.argv[0]] + args
        self.opts.parse()
        print self.opts[1]
        self.failUnlessEqual(len(self.opts), 3)
        self.failUnlessEqual(self.opts['i'], 'adam')
        self.failUnlessEqual(self.opts['u'], True)


if __name__ == '__main__':
    unittest.main()
