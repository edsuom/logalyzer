#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# logalyzer:
# Parses your bloated HTTP access logs to extract the info you want
# about hits from (hopefully) real people instead of just the endless
# stream of hackers and bots that passes for web traffic
# nowadays. Stores the info in a relational database where you can
# access it using all the power of SQL.
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

"""
Logfile parsing, imported by L{logread}.
"""

import re
from datetime import datetime
from collections import OrderedDict

from twisted.internet import defer


from util import *
import sift


class RedirectChecker(object):
    """
    I check for requests that follow a redirect. Call me with the IP
    address and HTTP code of each request in order.
    """
    def __init__(self):
        self.redirects = set()

    def clear(self):
        self.redirects.clear()
        
    def __call__(self, ip, http):
        """
        Checks if this vhost is the destination of a redirect from another
        one.

        Returns C{True} if the last request from this IP address
        resulted in a redirect.
        """
        if http in [301, 302]:
            self.redirects.add(ip)
            return False
        if ip in self.redirects:
            self.redirects.remove(ip)
            return True
        return False


class MatcherManager(object):
    """
    I manage a menagerie of matchers, making their magic available via
    methods.
    """
    matcherTable = (
        ('ipMatcher',    'IPMatcher'),
        ('netMatcher',   'NetMatcher'),
        ('uaMatcher',    'UAMatcher'),
        ('botMatcher',   'BotMatcher'),
        ('refMatcher',   'RefMatcher'),
        ('vhostMatcher', 'VhostMatcher'),
    )

    def __init__(self, matchers):
        for callableName, matcherName in self.matcherTable:
            f = matchers.get(matcherName, self.alwaysFalse)
            setattr(self, callableName, f)

    def alwaysFalse(self, *args):
        """
        This is the default matching method for when no suitable matcher
        was met.
        """
        return False

    
class LineParser(object):
    """ 
    I parse logfile lines to generate timestamp-keyed records. Send an
    instance of me to your processes.

    Instantiate me with a dict of matchers (ipMatcher, uaMatcher,
    and/or botMatcher). If you want to exclude any HTTP codes, list
    them with exclude.
    """
    reTwistdPrefix = rc(
        rdb("-", 4, 2, 2) +\
        "[\sT]" +\
        rdb(":", 2, 2, 2) + r'\+\d+',   # # 1111-22-33 44:55:66+0000
        r'\[(.+?)\]',                   # 7+
        r'(.+)'                         # 8+ (= CLF portion)
        )

    reCLF = rc(
        # IP Address
        r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',        # 1
        # vhost
        r'([\w\-\.]+)',                                 # 2
        # -
        r'\-',
        # [Date/time block]
        r'\[(.+?)\]',                                   # 3
        # HTTP Request, swallowing the open quote
        r'\"([A-Z]+)',                                  # 4
        # URL
        r'(\S+)',                                       # 5
        # HTTP/1.1 or whatever, ignored along with the close quote
        r'[^\s\"]+\"',
        # Code
        r'(\d{3})',                                     # 6
        # Bytes
        r'(\d+|\-)',                                    # 7
        # Referrer
        r'\"(.+?)\"',                                   # 8
        # User Agent
        r'\"(.+?)\"'                                    # 9
        )

    reDatetime = re.compile(
        # Day/Month                 # Year:Hr:Min:Sec
        r'(\d{1,2})/([^/]+)/' + rdb(":", 4, 2, 2, 2))

    months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
              'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

    def dtFactory(self, *args):
        intArgs = [int(x) for x in args]
        return datetime(*intArgs)

    def parseDatetimeBlock(self, text):
        """
        Returns a datetime object for the date & time in the supplied
        text string
        """
        match = self.reDatetime.match(text)
        if match is None:
            raise ValueError("Invalid date/time '{}'".format(text))
        day, monthName, year, hour, minute, second = match.groups()
        month = self.months.index(monthName) + 1
        return self.dtFactory(year, month, day, hour, minute, second)

    def setVhost(self, vhost):
        self.vhost = vhost.lower()
    
    def __call__(self, line):
        """
        Parses an individual logfile line and returns a list:

        [vhost, Requestor IP address, datetime, url, http, referrer, UA]

        Lowercase is forced for vhost, but nothing else.

        """
        dt = None
        match = self.reTwistdPrefix.match(line)
        if match:
            dt = self.dtFactory(*match.groups()[:6])
            line = match.group(8)
        match = self.reCLF.match(line)
        if match is None:
            return
        result = [match.group(2).lower(), match.group(1)]
        if result[0] == '-':
            # No vhost specified for this record...
            vhost = getattr(self, 'vhost', None)
            if vhost:
                # ...but we have one defined for the whole file, so
                # use that
                result[0] = vhost
        if dt is None:
            dt = self.parseDatetimeBlock(match.group(3))
        result.extend([dt, match.group(5), int(match.group(6))])
        result.extend(match.group(8, 9))
        return result
