#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!
"""
LICENSE
Copyright (C) 2014-2015 Tellectual LLC

"""

import re, os.path, array
from collections import deque

import ipcalc


class MatcherBase(object):
    """
    Build your matcher on me
    """
    def newCache(self, N=30):
        """
        Generates the FIFO queue for a new sort-of LRU cache of strings
        and returns its index, starting with 0 for the first cache.
        """
        if not hasattr(self, 'caches'):
            self.caches = []
        thisCache = deque([""], N)
        self.caches.append(thisCache)
        return len(self.caches) - 1

    def clearCache(self):
        for cache in self.caches:
            cache.clear()
    
    def checkCache(self, k, x):
        """
        Checks cache k for the string x, returning True if it's there or
        False if not.
        """
        return bool(self.caches[k].count(x))

    def setCache(self, k, x):
        """
        Appends x to cache k, which will result in it being found there if
        checked within N cache misses.

        The value least recently added (from a cache miss) will be
        popped off the other end. It isn't strictly an LRU cache,
        since a cache hit will be drowned in misses.
        """
        self.caches[k].append(x)

    def fileLinerator(self, filePath):
        fh = open(filePath, 'rb')
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            yield line
        fh.close()


class IPMatcher(MatcherBase):
    """
    I efficiently match IP addresses with rules
    """
    reRule = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/[123]{0,1}[0-9])')
    
    def __init__(self):
        self.networks = []
        # Cache for Offenders
        self.newCache()
        # Cache for innocents
        self.newCache()
        # LongInt lookup table for making it faster to add rules.
        self.netLongs = array.array('L')
        # LongInt lookup table for known and added offenders
        self.ipLongs = array.array('L')
    
    def addRules(self, filePath):
        """
        Add some rules from a text file with lines in aaa.bbb.ccc.ddd/ee notation
        """
        for line in self.fileLinerator(filePath):
            match = self.reRule.match(line)
            if match is None:
                continue
            thisNet = ipcalc.Network(match.group(0))
            # Quick check
            thisLong = thisNet.network_long()
            if thisLong in self.netLongs:
                # Same long network address, so do more thorough check
                for otherNet in self.networks:
                    if thisNet.check_collision(otherNet):
                        # Yep, redundant rule
                        break
                else:
                    # No collision, so actually NOT a redundant rule;
                    # add it. (Will this ever happen with properly
                    # defined rules?)
                    self.networks.append(thisNet)
            else:
                # New long network address, add both it and the network object
                self.netLongs.append(thisLong)
                self.networks.append(thisNet)

    def addOffender(self, ip):
        """
        Call this with an IP address (string format) to add it to my list
        of offenders.
        """
        self.ipLongs.append(long(ipcalc.IP(ip)))
                
    def __call__(self, ip):
        # Likely to be several sequential hits from offenders and
        # innocents alike
        if self.checkCache(0, ip):
            # Offender was cached
            return True
        if self.checkCache(1, ip):
            # Innocent was cached
            return False
        ipObject = ipcalc.IP(ip)
        # Check for known and added offenders
        ipLong = long(ipObject)
        if ipLong in self.ipLongs:
            return True
        # Not found (yet), go through the actual list of networks
        for net in self.networks:
            if net.has_key(ipObject):
                # Offender found
                self.setCache(0, ip)
                self.ipLongs.append(ipLong)
                return True
        self.setCache(1, ip)
        return False


class UAMatcher(MatcherBase):
    """
    I efficiently match User Agent strings with regular expressions
    """
    def __init__(self, uaFilePath):
        # Cache for Offenders
        self.newCache()
        # Cache for innocents
        self.newCache()
        reParts = []
        for line in self.fileLinerator(uaFilePath):
            reParts.append(line)
        self.reUA = re.compile(r'|'.join(reParts))
    
    def __call__(self, ip, uaString):
        # Likely to be several sequential hits from offenders and
        # innocents alike
        if self.checkCache(0, ip):
            # Offender was cached
            return True
        if self.checkCache(1, ip):
            # Innocent was cached
            return False
        if self.reUA.search(uaString):
            # Offender found
            self.setCache(0, ip)
            return True
        self.setCache(1, ip)
        return False

    
                    
            
            
            
