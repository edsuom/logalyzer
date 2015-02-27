#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!

"""
NAME
statalysis: Analyzes web server log files


SYNOPSIS
sa [--vhost somehost.com]
   [-p] [-e, --exclude code1,code2,...]
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

import csv

from twisted.internet import defer, threads

from util import Base


class Writer(Base):
    """
    I write stuff to files in various formats.
    """
    csvDelimiter = '\t'

    dateHeadings = ["Year", "Mo", "Day", "Hr", "Min"]
    headings = {
        'vhost': "Virtual Host",
        'ip':    "IP Address",
        'code':  "HTTP",
        'url':   "URL Requested",
        'ref':   "Referrer",
        'ua':    "User Agent",
        }
    
    def __init__(self, *filePaths, **kw):
        self.dList = []
        self.writeTypes = {}
        for filePath in filePaths:
            thisType = filePath.split('.')[-1].upper()
            self.writeTypes[thisType] = filePath
        self.printRecords = kw.get('printRecords', False)
    
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

    def makeRow(self, x):
        row = []
        if 'vhost' in self.fields:
            row.append(x['vhost'])
        for field in ('ip', 'code', 'url', 'ref'):
            row.append(x[field])
        if 'ua' in self.fields:
            row.append(x['ua'])
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
        self.fields = records[keys[0]][0].keys()
        for dt in keys:
            self.rowBase = [dt.year, dt.month, dt.day, dt.hour, dt.minute]
            if self.printRecords:
                print "\n{:4d}-{:02d}-{:02d}, {:02d}:{:02d}".format(*rowBase)
            theseRecords = records[dt]
            for thisRecord in theseRecords:
                if self.printRecords:
                    itemList = [
                        "{}: {}".format(x, y)
                        for x, y in thisRecord.iteritems()]
                    print ", ".join(itemList)
                yield self.makeRow(theseRecords)

    def _setupCSV(self, filePath):
        fh = open(csvFilePath, 'wb')
        self._cw = csv.writer(fh, delimiter=self.csvDelimiter)
        self._cw.writerow(self.dateHeadings + self.makeRow(self.headings))
        return fh.close  # Do NOT call this, just return the shutterdowner
                
    def _writeCSV(self, row):
        return threads.deferToThread(
            self._cw.writerow, self.rowBase + row)
    
    @defer.deferredGenerator
    def write(self, records):
        """
        Writes records to all desired formats, returning a deferred that
        fires when the writing is done.
        """
        def doneWriting(null):
            
        sdList = []
        writers = []
        # Prepare my writers
        for writeType, filePath in self.writeTypes.iteritems():
            thisSetterUpper = getattr(self, "_setup{}".format(writeType))
            fhList.append(thisSetterUpper(filePath))
            thisWriter = getattr(self, "_write{}".format(writeType))
            writers.append(thisWriter)
        # Write them records!
        for row in self.recordator(records):
            dList = [thisWriter(row) for thisWriter in writers]
            wfd = defer.waitForDeferred(defer.DeferredList(dList))
            yield wfd
        # Done writing, shut everything down
        for shutterDowner in sdList:
            shutterDowner()
