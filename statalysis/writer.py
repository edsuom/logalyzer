#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!

"""
NAME
statalysis: Analyzes web server log files


SYNOPSIS
sa [--vhost somehost.com]
   [-p] [-e, --exclude http1,http2,...]
   [-d, --ruledir <directory of rule files>]
     [-i, --ip  [xX]|rule1,rule2,...]
     [-n, --net [xX]|rule1,rule2,...]
     [-u, --ua  [xX]|rule1,rule2,...]
     [-b, --bot [xX]|rule1,rule2,...]
     [-r, --ref [xX]|rule1,rule2,...]
   [--omit] [-y, --secondary]
   [-s, --save <file to save purged IPs>]
   [-v, --verbose]
<file> <file...>


DESCRIPTION

Analyzes log files in the directory where outFile is to go, producing
one or more output <files> (except if -c option set).

The format of the output files is determined by their extension:

.csv: Comma-separated (actually tabs) values, one row for each record
.db:  SQLite database of records saved as sAsync persistent dictionary


Specify particular ip, net, ua, bot, or ref rules in the rules
directory with a comma-separated list after the -i, -n, -u, -b, or -r
option. Use x or X to skip all such rules. Omit the option to use all
pertinent rules in the rules directory.

All records from IP addresses with bot behavior will be purged.

WARNING: If any of your bot-detecting rules that purge IP addresses
(bot, ref) match innocent search engines, e.g., with a url match to
'/robots.txt', don't use the saved list (--save) to block access to
your web server!


OPTIONS

--vhost vhost
A particular virtual host of interest

-p, --print
Print records after loading

-e, --exclude exclude
Exclude HTTP code(s) (comma separated list, no spaces)

-d, --ruledir ruledir
Directory for .net, .ua, and .url file(s) containing IP, user-agent,
and url exclusion rules

-i, --ip rules
Rules corresponding to .ip files in ruledir containing IP addresses
aaa.bbb.ccc.ddd notation

-n, --net rules
Rules corresponding to .net files in ruledir containing IP network
exclusion rules in aaa.bbb.ccc.ddd/ee notation

-u, --ua rules
Rules corresponding to .ua files containing regular expressions (case
sensitive) that match User-Agent strings to exclude

-b, --bot rules
Rules corresponding to .url files containing regular expressions (case
sensitive) that match url strings indicating a malicious bot

-r, --referrer rules
Rules corresponding to .ref files containing regular expressions (case
sensitive) that match referrer strings indicating a malicious bot

--omit
Omit the user-agent string from the records

-y, --secondary
Ignore secondary files (css, webfonts, images)

-s, --save file
File in which to save a list of the purged (or consolidated) IP
addresses, in ascending numerical order with repeats omitted.

-c, --consolidate
Just consolidate IP addresses in the <file> with those in the ip rules
(-i), saving that to the file specified with -s. Ignores logfiles and
net, ua, bot, and ref rules, and doesn't generate any csv file

--cores N
The number of CPU cores (really, python processes) to run in parallel

-v, --verbose
Run verbosely


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
            self.msg("\n{}", self.dtFormat(dt), "-")
            theseRecords = records[dt]
            for k, thisRecord in enumerate(theseRecords):
                self.msg("{:3d}: {}", k, thisRecord)
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
