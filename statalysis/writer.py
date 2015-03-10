#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!

"""
LICENSE
Copyright (C) 2015 Tellectual LLC
"""

import csv, marshal

from twisted.internet import defer, task

import database
from util import Base


class Writer(Base):
    """
    I write stuff to files in various formats.
    """
    csvDelimiter = '\t'

    dateHeadings = [
        "Year", "Mo", "Day", "Hr", "Min"]
    fields = (
        ('vhost', "Virtual Host"),
        ('ip',    "IP Address"),
        ('http',  "HTTP"),
        ('url',   "URL Requested"),
        ('ref',   "Referrer"),
        ('ua',    "User Agent"),
    )
    
    def __init__(self, *filePaths, **kw):
        self.dList = []
        self.writeTypes = {}
        for filePath in filePaths:
            thisType = filePath.split('.')[-1].upper()
            self.writeTypes[thisType] = filePath
        self.verbose = kw.get('printRecords', False)
        self.gui = kw.get('gui', None)
    
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
    
    def writeIPs(self, ipList, filePath):
        """
        Writes the supplied list of ip addresses, in numerical order and
        with no repeats, to the specified filePath.
        """
        ipLast = None
        fh = open(filePath, 'w')
        for ip in sorted(ipList, key=self.ipToLong):
            if ip != ipLast:
                fh.write(ip + '\n')
                ipLast = ip
        fh.close()

    def headings(self):
        headingNames = [x[1] for x in self.fields]
        return self.dateHeadings + headingNames
        
    def makeRow(self, record):
        row = [record[x[0]] for x in self.fields]
        if record['was_rd']:
            row[0] += "*"
        return row
    
    def recordator(self, records):
        """
        Flattens the supplied records dict of lists into a single
        list. Each item in the list is a row list with the fields of
        the record.

        With each new date/time, my attribute I{rowBase} is
        updated. See my C{dateHeadings} for what the elements of that
        list are.

        Yields each row list in turn, which you should prefix with the
        current value of I{rowBase}.

        """
        keys = sorted(records.keys())
        for dt in keys:
            self.msgHeading(self.dtFormat(dt))
            theseRecords = records[dt]
            for k, thisRecord in enumerate(theseRecords):
                self.msgBody("{:3d}: {}", k, thisRecord)
                yield dt, k, thisRecord
    
    def _setupCSV(self, filePath):
        fh = open(filePath, 'wb')
        self._cw = csv.writer(fh, delimiter=self.csvDelimiter)
        self._cw.writerow(self.headings())
        # Do NOT call this, just return the shutterdowner callable
        return fh.close
    
    def _writeCSV(self, dt, k, record):
        rowBase = [dt.year, dt.month, dt.day, dt.hour, dt.minute]
        self._cw.writerow(rowBase + self.makeRow(record))

    def _setupPYO(self, filePath):
        self._fhPYO = open(filePath, 'wb')
        return self._fhPYO.close
    
    def _writePYO(self, dt, k, record):
        marshal.dump([self.dtFormat(dt), k, record], self._fhPYO)
            
    def write(self, records):
        """
        Writes records to all desired formats, returning a deferred that
        fires when the writing is done.

        Each _writeXXX method is run cooperatively with the twisted
        reactor. The methods can return deferreds or not.
        """
        def runWriters():
            for dt, k, thisRecord in self.recordator(records):
                for thisWriter in writers:
                    yield thisWriter(dt, k, thisRecord)

        def setupDone(null):
            # Now write them records!
            d = task.Cooperator().coiterate(runWriters())
            d.addCallbacks(doneWriting, self.oops)
            return d

        @defer.deferredGenerator
        def doneWriting(null):
            for shutterDowner in sdList:
                yield defer.waitForDeferred(
                    defer.maybeDeferred(shutterDowner))

        dList = []
        sdList = []
        writers = []
        # Prepare my writers
        for writeType, filePath in self.writeTypes.iteritems():
            thisSetterUpper = getattr(self, "_setup{}".format(writeType))
            thisWriter = getattr(self, "_write{}".format(writeType))
            writers.append(thisWriter)
            d = defer.maybeDeferred(thisSetterUpper, filePath)
            d.addCallbacks(sdList.append, self.oops)
            dList.append(d)
        return defer.DeferredList(dList).addCallbacks(setupDone, self.oops)
