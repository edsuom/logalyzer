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
Filtering of HTTP logs as they are read.
"""

import re, os.path, array

import ipcalc

import util


class IPMatcher(object):
    """
    I efficiently match IP addresses. Simple and fast.

    Construct me with a list of IP addresses in dotted-quad format,
    and add any further ones with L{addIP}.

    """
    reDottedQuad = re.compile(r'[0-9]{,3}\.[0-9]{,3}\.[0-9]{,3}\.[0-9]{,3}')
    
    def __init__(self, rules=[]):
        self.ipSet = set()
        for rule in rules:
            rule = rule.strip()
            if rule:
                self.addIP(rule)

    def __len__(self):
        return len(self.ipSet)
        
    def addIP(self, ip):
        """
        Call this with an IP address (string format) to add it to my list
        if it's not already there.
        """
        if self.reDottedQuad.match(ip):
            self.ipSet.add(ip)

    def removeIP(self, ip):
        """
        Call this with an IP address (string format) to remove it from my
        list if it's there.
        """
        self.ipSet.discard(ip)
            
    def __call__(self, ip):
        return ip in self.ipSet
        

class MatcherBase(object):
    """
    Build your matcher on me
    """
    def __init__(self, rules=[]):
        clean = []
        for rule in rules:
            rule = rule.strip()
            if rule:
                clean.append(rule)
        self.cm = util.CacheManager()
        self.startup(clean)

    def reFromRules(self, rules):
        if not rules:
            # Messes up GUI
            #print "WARNING: Empty rules for {}".format(self)
            return
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
        if self.re and self.re.search(string.strip()):
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
    are clearly logspammers, and should get blocked.
    """


class VhostMatcher(ReMatcherBase):
    """
    I use parsed .vhost rules to efficiently check for referrers that
    are requesting clearly inappropriate vhosts , and should get
    blocked.
    """

