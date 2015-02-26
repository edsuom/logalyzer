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
    def __init__(self, rules):
        self.startup(rules)

    def reFromRules(self, rules):
        reParts = []
        for rule in rules:
            rule = rule.strip()
            if rule:
                reParts.append(rule)
        return re.compile(r'|'.join(reParts))
        
    def startup(self, rules):
        """
        Override this to process rule given as lines of text, one for each
        rule.
        """
        raise NotImplementedError("Must define a startup method")
    
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

    def clearCache(self, value=None):
        for cache in self.caches:
            if value is None:
                cache.clear()
            while cache.count(value):
                cache.remove(value)
    
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


class IPMatcher(MatcherBase):
    """
    I efficiently match IP addresses with rules
    """
    reRule = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/[123]{0,1}[0-9])')
    
    def startup(self, rules):
        self.networks = []
        # Cache for offenders
        self.newCache()
        # Cache for innocents
        self.newCache()
        # LongInt lookup table for making it faster to add rules.
        self.netLongs = array.array('L')
        # LongInt lookup table for known and added offenders
        self.ipLongs = array.array('L')
        # Add the rules
        for rule in rules:
            self.addRule(rule)
    
    def addRule(self, rule):
        """
        Add a network matching rule in aaa.bbb.ccc.ddd/ee notation
        """
        match = self.reRule.match(rule)
        if match is None:
            return
        thisNet = ipcalc.Network(match.group(0))
        # Quick check
        thisLong = thisNet.network_long()
        if thisLong in self.netLongs:
            # Same long network address, so do more thorough check
            for otherNet, null in self.networks:
                if thisNet.check_collision(otherNet):
                    # Yep, redundant rule
                    break
            else:
                # No collision, so actually NOT a redundant rule;
                # add it. (Will this ever happen with properly
                # defined rules?)
                self.networks.append([thisNet, 0])
        else:
            # New long network address, add both it and the network object
            self.netLongs.append(thisLong)
            self.networks.append([thisNet, 0])

    def addOffender(self, ip):
        """
        Call this with an IP address (string format) to add it to my list
        of offenders.
        """
        ipLong = long(ipcalc.IP(ip))
        if ipLong not in self.ipLongs:
            self.ipLongs.append(ipLong)
            self.clearCache(ip)
    
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
        # Not found (yet), go through the actual list of networks. If
        # a hit is found, the count for that network is increased and
        # the list is resorted by number of hits,
        # descending. Hopefully this will result in more efficient
        # operation as the more notorious networks get found first.
        for netAndCount in self.networks:
            if netAndCount[0].has_key(ipObject):
                # Offender found
                self.setCache(0, ip)
                self.ipLongs.append(ipLong)
                netAndCount[1] += 1
                self.networks.sort(key=lambda x: x[1], reverse=True)
                return True
        self.setCache(1, ip)
        return False


class UAMatcher(MatcherBase):
    """
    I efficiently match User Agent strings with regular expressions
    """
    def startup(self, rules):
        # Cache for Offenders
        self.newCache()
        # Cache for innocents
        self.newCache()
        self.reUA = self.reFromRules(rules)
    
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


class BotMatcher(MatcherBase):
    def startup(self, rules):
        self.reURL = self.reFromRules(rules)
    
    def __call__(self, url):
        return bool(self.reURL.search(url))


class RefMatcher(MatcherBase):
    def startup(self, rules):
        self.reReferrer = self.reFromRules(rules)
    
    def __call__(self, ref):
        return bool(self.reReferrer.search(ref))
