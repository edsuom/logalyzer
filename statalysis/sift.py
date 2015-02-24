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
    N_cache = 20
    
    def fileLinerator(self, filePath):
        fh = open(filePath, 'rb')
        for line in fh:
            if line.startswith("#"):
                continue
            yield line.strip()
        fh.close()


class IPMatcher(MatcherBase):
    """
    I efficiently match IP addresses with rules
    """
    reRule = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/[123]{0,1}[0-9])')
    
    def __init__(self):
        self.networks = []
        self.longs = array.array('L')
        self.clearCache()

    def clearCache(self):
        self.cachedTrue = array.array('L')
        self.cachedFalse = deque(
            array.array('L', [0]*self.N_cache), self.N_cache)
        
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
            if thisLong in self.longs:
                # Same long network address, so do more thorough check
                for otherNet in self.networks:
                    if thisNet.check_collision(otherNet):
                        # Yep, redundant rule
                        break
                else:
                    # No collisions, so actually not a redundant rule; add it
                    # (Will this ever happen with properly defined rules?)
                    self.networks.append(thisNet)
            else:
                # New long network address, add both it and the network object
                self.longs.append(thisLong)
                self.networks.append(thisNet)

    def __call__(self, ip):
        net = ipcalc.Network(ip)
        netLong = net.network_long()
        # Likely to be many multiple hits from offenders, much faster
        # to check for previously matched long
        if netLong in self.cachedTrue:
            return True
        # Also expect repeated checks of regular IPs, though temporally limited
        if self.cachedFalse.count(netLong):
            return False
        # Not found (yet), go through the actual list of networks
        for other in self.networks:
            if net.check_collision(other):
                self.cachedTrue.append(netLong)
                return True
        self.cachedFalse.append(netLong)
        return False


class UAMatcher(MatcherBase):
    """
    I efficiently match User Agent strings with regular expressions
    """
    def __init__(self, uaFilePath):
        self.lastUA, self.lastResult = "", False
        self.reParts = []
        for line in self.fileLinerator(filePath):
            self.reParts.append(line)
            
    def __call__(self, uaString):
        # Compiled RE should be fast enough that only the most
        # rudimentary caching makes sense
        if uaString == self.lastUA:
            return self.lastResult
        self.lastUA = uaString
        if not hasattr(self, 'reUA'):
            self.reUA = re.compile(r'|'.join(self.reParts))
        self.lastResult = bool(self.reUA.search(uaString))
        return self.lastResult
    
                    
            
            
            
