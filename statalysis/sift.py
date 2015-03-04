#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!
"""
LICENSE
Copyright (C) 2014-2015 Tellectual LLC

"""

import re, os.path, array


import ipcalc

import util


class MatcherBase(object):
    """
    Build your matcher on me
    """
    def __init__(self, rules):
        clean = []
        for rule in rules:
            rule = rule.strip()
            if rule:
                clean.append(rule)
        self.cm = util.CacheManager()
        self.startup(clean)

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
    


class IPMatcher(MatcherBase):
    """
    I efficiently match IP addresses to individual known
    offenders. Simple and fast, no caching.
    """
    def startup(self, rules):
        # Lookup table for hashed ip strings
        self.ipHashes = array.array('L')
        for ip in rules:
            self.addOffender(ip)
        # Prep for binary searches
        self.N = len(self.ipHashes)
        self.ipHashes = sorted(self.ipHashes)
        # Cache for offenders
        self.cm.new()
        # Cache for innocents
        self.cm.new()

    def dqToHash(self, ip):
        """
        Fast dotted-quad to guaranteed-unique long int hash, adapted from
        ipcalc.IP. This is NOT the actual long int value of the ip,
        because we don't bother reversing the order of the four dotted
        elements.
        """
        return sum(
            long(byte) << 8 * index
            for index, byte in enumerate(ip.split('.')))
            
    def addOffender(self, ip):
        """
        Call this with an IP address (string format) to add it to my list
        of offenders. As a bonus, returns the ip address in long 
        """
        ipHash = self.dqToHash(ip)
        if ipHash not in self.ipHashes:
            self.ipHashes.append(ipHash)

    def hasHash(self, ipHash):
        """
        Binary search, adapted from
        http://code.activestate.com/recipes/81188/
        """
        kMin = 0
        kMax = self.N - 1
        while True:
            if kMax < kMin:
                return False
            k = (kMin  + kMax) // 2
            if self.ipHashes[k] < ipHash:
                kMin = k + 1
            elif self.ipHashes[k] > ipHash:
                kMax = k - 1
            else:
                return True
            
    def __call__(self, ip):
        # Likely to be several sequential hits from offenders and
        # innocents alike
        if self.cm.check(0, ip):
            # Offender was cached
            return True
        if self.cm.check(1, ip):
            # Innocent was cached
            return False
        if self.hasHash(self.dqToHash(ip)):
            # Offender found
            self.cm.set(0, ip)
            return True
        # No offending IP address match
        self.cm.set(1, ip)
        return False


class NetMatcher(MatcherBase):
    """
    I efficiently match IP addresses to IP networks with rules
    """
    reRule = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/[123]{0,1}[0-9])')
    
    def startup(self, rules):
        self.networks = []
        # Cache for offenders
        self.cm.new()
        # Cache for innocents
        self.cm.new()
        # LongInt lookup table for making it faster to add rules.
        self.netLongs = array.array('L')
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
    
    def __call__(self, ip):
        # Likely to be several sequential hits from offenders and
        # innocents alike
        if self.cm.check(0, ip):
            # Offender was cached
            return True
        if self.cm.check(1, ip):
            # Innocent was cached
            return False
        ipObject = ipcalc.IP(ip)
        # Not found (yet), go through the actual list of networks. If
        # a hit is found, the count for that network is increased and
        # the list is resorted by number of hits, descending. This
        # results in more efficient operation as the more notorious
        # networks get found first.
        for netAndCount in self.networks:
            if netAndCount[0].has_key(ipObject):
                # Offender found
                self.cm.set(0, ip)
                netAndCount[1] += 1
                self.networks.sort(key=lambda x: x[1], reverse=True)
                return True
        self.cm.set(1, ip)
        return False


class ReMatcherBase(MatcherBase):
    """
    I efficiently match strings with regular expressions
    """
    def startup(self, rules):
        # Cache for Offenders only
        self.cm.new()
        self.re = self.reFromRules(rules)
    
    def __call__(self, ip, string):
        # Likely to be several sequential hits from offenders
        if self.cm.check(0, ip):
            # Offender was cached
            return True
        # Sometimes offenders start with an innocent query, so no
        # cache for innocents
        if self.re.search(string.strip()):
            # Offender found
            self.cm.set(0, ip)
            return True
        return False


class UAMatcher(ReMatcherBase):
    """
    I use parsed .ua rules to efficiently check for user-agents that
    are undesirable in logs, though they shouldn't be blocked.
    """


class BotMatcher(ReMatcherBase):
    """
    I use parsed .url rules to efficiently check for bots that are
    seen in logs doing hacker-type things, and should get blocked.
    """


class RefMatcher(ReMatcherBase):
    """
    I use parsed .ref rules to efficiently check for referrers that
    are clearly logspammer, and should get blocked.
    """

