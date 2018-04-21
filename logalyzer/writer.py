#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!

"""
LICENSE
Copyright (C) 2015 Tellectual LLC
"""

from util import Base


class IPWriter(Base):
    """
    I write IP addresses to files.
    """
    def ipToLong(self, ip):
        """
        Converts a dotted-quad IP address string to a long int. Adapted
        from ipcalc.IP
        """
        q = ip.split('.')
        q.reverse()
        if len(q) > 4:
            raise ValueError(
                '%s: IPv4 address invalid: more than 4 bytes' % dq)
        for x in q:
            if not 0 <= int(x) <= 255:
                raise ValueError(
                    '%s: IPv4 address has invalid byte value' % dq)
        while len(q) < 4:
            q.insert(1, '0')
        return sum(long(byte) << 8 * index for index, byte in enumerate(q))
    
    def writeIPs(self, rejectedIPs, filePath):
        """
        Writes the blocked IPs in the supplied dict of ip addresses, in
        numerical order, to the specified filePath.
        """
        ipList = sorted(rejectedIPs.keys(), key=self.ipToLong)
        with open(filePath, 'w') as fh:
            for ip in ipList:
                if rejectedIPs[ip]:
                    fh.write(ip + '\n')
