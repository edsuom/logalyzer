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


class IPMatcher(object):
    """
    I efficiently match IP addresses with rules
    """
    N_cache = 20
    
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
        fh = open(filePath, 'rb')
        for line in fh:
            if line.startswith("#"):
                continue
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
        fh.close()

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


    
        
            
            
            
