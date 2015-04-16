#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!
"""
LICENSE
Copyright (C) 2014-2015 Tellectual LLC

"""

import re
from datetime import datetime
from collections import OrderedDict

from twisted.internet import defer


from util import *
import sift


class RedirectChecker(object):
    """
    I check for vhosts that are redirects from another one.
    """
    N_redirects = 50

    def __init__(self):
        self.redirects = OrderedDict()
        
    def __call__(self, vhost, ip, http):
        """
        Checks if this vhost is the destination of a redirect from another
        one, and replace it with the old one if so.

        Returns a 2-tuple containing a Bool that indicates if this was
        a redirect, and the vhost (the original if so).
        """
        wasRedirect = False
        if http in [301, 302]:
            # This is a redirect, so save my vhost for the inevitable
            # check from the same IP address
            self.redirects[ip] = vhost
        else:
            oldVhost = self.redirects.pop(ip, None)
            if oldVhost:
                # There was a former vhost: This is a redirect.
                wasRedirect = True
                # While we set the substitute vhost, put a replacement
                # entry back in the FIFO to ensure we can find it
                # again if checked again soon
                vhost = self.redirects[ip] = oldVhost
        # Remove oldest entry until FIFO no longer too big
        while len(self.redirects) > self.N_redirects:
            self.redirects.popitem(last=False)
        return wasRedirect, vhost


class MatcherManager(object):
    """
    I manage a menagerie of matchers, making their magic available via
    methods.
    """
    matcherTable = (
        ('ipMatcher',  'IPMatcher'),
        ('netMatcher', 'NetMatcher'),
        ('uaMatcher',  'UAMatcher'),
        ('botMatcher', 'BotMatcher'),
        ('refMatcher', 'RefMatcher'))

    def __init__(self, matchers)
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
        rdb("-", 4, 2, 2),              # 1111-22-33
        rdb(":", 2, 2, 2) + r'\+\d+',   # 44-55-66
        r'\[(.+?)\]',                   # 7+
        r'(.+)'                         # 8+ (= CLF portion)
        )

    reCLF = rc(
        # IP Address
        r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',        # 1
        # vhost
        r'([\w\-\.]+)',                                 # 2
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

    def __call__(self, line):
        """
        Parses an individual logfile line and returns a list:

        [vhost, Requestor IP address, datetime, url, http, referrer, UA]

        """
        dt = None
        match = self.reTwistdPrefix.match(line)
        if match:
            dt = self.dtFactory(*match.groups()[:6])
            if match.group(7) == '-':
                return
            line = match.group(8)
        match = self.reCLF.match(line)
        if match is None:
            return
        result = [match.group(2).lower(), match.group(1)]
        if dt is None:
            dt = self.parseDatetimeBlock(match.group(3))
        result.extend([dt, match.group(5), int(match.group(6))])
        result.extend(match.group(8, 9))
        return result
