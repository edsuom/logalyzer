#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!
"""
LICENSE
Copyright (C) 2014-2015 Tellectual LLC

"""

import re, os.path, array

import ipcalc


class IPMatcher(object):
    reRule = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/[123]{0,1}[0-9])')
    
    def __init__(self, fileDir):
        self.fileDir = fileDir
        self.networks = []
        self.longs = array.array('L')

    def addRules(self, fileName):
        """
        Add some rules from a text file with lines in aaa.bbb.ccc.ddd/ee notation
        """
        fh = open(os.path.join(self.fileDir, fileName), 'rb')
        for line in fh:
            if line.startswith("#"):
                continue
            match = self.reRule.match(line)
            if match is None:
                continue
            thisNet = ipcalc.Network(match.group(0))
            thisLong = thisNet.network_long()
            if thisLong in self.longs:
                continue
            self.longs.append(thisLong)
            self.networks.append(thisNet)
        fh.close()

    def __call__(self, ip):
        net = ipcalc.Network(ip)
        #import pdb; pdb.set_trace()
        #if net.network_long() not in self.longs:
        #    # Quick check
        #    return False
        for other in self.networks:
            if net.check_collision(other):
                return True
        return False


    
        
            
            
            
