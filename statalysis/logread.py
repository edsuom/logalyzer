#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!
"""
LICENSE
Copyright (C) 2014-2015 Tellectual LLC

"""

import re, os, os.path, gzip
from datetime import datetime

from twisted.internet import defer, reactor

#from asynqueue import ThreadQueue


def rdb(sep, *args):
    """
    Builds a regular expression for separated digits.
    """
    parts = []
    for numDigits in args:
        parts.append(r'(\d{{{:d}}})'.format(numDigits))
    return sep.join(parts)

def rc(*parts):
    """
    Compiles a regular expression from whitespace-separated parts.
    """
    rexp = r'\s+'.join(parts) + r'\s*$'
    return re.compile(rexp)



class Compiler(object):
    """
    I compile logfile records into a single big mass, chronologically
    sorted.
    """
    def __init__(self, verbose=False):
        self.dtLast = None
        self.records = {}
        self.verbose = verbose

    def addRecord(self, record):
        dt = record[0]
        rest = record[1:]
        if dt in self.records:
            thoseRecords = self.records[dt]
            if rest not in thoseRecords:
                thoseRecords.append(rest)
            # Otherwise, its a duplicate record
        else:
            # First record with this timestamp
            self.records[dt] = [rest]

    def printDatetime(self, dt):
        pass
        #if self.verbose:
        #    print "\n{}".format(dt.isoformat(' '))

    def printRecord(self, record):
        pass
        #if self.verbose:
        #    print "{:15s}  {}".format(record[0], record[1][:50])

    def getRecords(self):
        """
        Returns my records in chronological order.
        """
        records = self.records
        keys = records.keys()
        keys.sort()
        result = []
        for key in keys:
            theseRecords = records[key]
            for thisRecord in theseRecords:
                result.append(thisRecord)
        return result


class ProcessQueue(object):
    def __init__(self, N):
        from multiprocessing import Pool
        self.pool = Pool(processes=N)

    def call(self, func, *args, **kw):
        d = defer.Deferred()
        self.pool.apply_async(func, args, kw, d.callback)
        return d


class BogusQueue(object):
    def call(self, func, *args, **kw):
        result = func(*args, **kw)
        return defer.succeed(result)


class Reader(object):
    """
    I read and parse web server log files
    """
    cores = 3
    verbose = True

    reTwistdPrefix = rc(
        rdb("-", 4, 2, 2),              # 1111-22-33
        rdb(":", 2, 2, 2) + r'\+\d+',   # 44-55-66
        r'\[(.+?)\]',                   # 7+
        r'(.+)'                         # 8+ (= CLF portion)
        )

    reCLF = rc(
        # IP Address
        r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',        # 1
        # vhost
        r'([\w\-\.]+)',                                 # 2
        r'\-',
        # [Date/time block]
        r'\[(.+?)\]',                                   # 3
        # HTTP Request, swallowing the open quote
        r'\"([A-Z]+)',                                  # 4
        # URL
        r'(\S+)',                                       # 5
        # HTTP/1.1 or whatever, ignored along with the close quote
        r'[^\s\"]+\"',
        # Code
        r'(\d{3})',                                     # 6
        # Bytes
        r'(\d+|\-)',                                    # 7
        # Referrer
        r'\"(.+?)\"',                                   # 8
        # User Agent
        r'\"(.+?)\"'                                    # 9
        )

    reDatetime = re.compile(
        # Day/Month/Year
        r'(\d{1,2})/([^/]+)/'    +\
            rdb(":", 4, 2, 2, 2)
        )

    months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
              'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

    def __init__(self, logDir, exclude=[], noUA=False):
        if not os.path.isdir(logDir):
            raise OSError("Directory '{}' not found".format(logDir))
        self.dirPath = logDir
        self.exclude, self.noUA = exclude, noUA
        self.compiler = Compiler(self.verbose)
        #self.q = ProcessQueue(self.cores)
        self.q = BogusQueue()

    def msg(self, line):
        if self.verbose:
            print "\n{}".format(line)

    def oops(self, failure):
        failure.raiseException()
        reactor.stop()
    
    def pathInDir(self, fileName):
        """
        Returns the absolute path of a file in my project directory
        """
        if os.path.split(fileName)[0]:
            raise ValueError(
                "Path '{}' specified, use file name only".format(fileName))
        return os.path.abspath(os.path.join(self.dirPath, fileName))

    def file(self, fileName, isFullPath=False):
        """
        Opens a file (possibly a compressed one), returning a file
        object.
        """
        if not isFullPath:
            fileName = self.pathInDir(fileName)
        if fileName.endswith('.gz'):
            fh = gzip.open(fileName, 'rb')
        else:
            fh = open(fileName, mode="r")
        return fh

    def dtFactory(self, *args):
        intArgs = [int(x) for x in args]
        return datetime(*intArgs)

    def parseDatetimeBlock(self, text):
        """
        Returns a datetime object for the date & time in the supplied
        text string
        """
        match = self.reDatetime.match(text)
        if match is None:
            raise ValueError("Invalid date/time '{}'".format(text))
        day, monthName, year, hour, minute, second = match.groups()
        month = self.months.index(monthName) + 1
        return self.dtFactory(year, month, day, hour, minute, second)

    def parseLine(self, line):
        """
        Parses an individual logfile line and returns a list:

        [vhost, Requestor IP address, datetime, url, code, referrer, UA]

        """
        dt = None
        match = self.reTwistdPrefix.match(line)
        if match:
            dt = self.dtFactory(*match.groups()[:6])
            if match.group(7) == '-':
                self.msg(match.group(8))
                return
            line = match.group(8)
        match = self.reCLF.match(line)
        if match is None:
            self.msg(line)
            return
        result = list(match.group(2, 1))
        if dt is None:
            dt = self.parseDatetimeBlock(match.group(3))
        result.extend([dt, match.group(5), int(match.group(6))])
        result.extend(match.group(8, 9))
        return result

    def makeRecord(self, line, vhost=None):
        """
        Supply a mess of logfile lines and this method will iterate
        over the parsed results for the specified vhost to generate a
        list for each valid line:

        [dt, Requestor IP address, url, UA, code]

        If noUA is set True, no UA will be included in the list.

        If one or more HTTP codes are supplied with the exclude
        keyword, then the code will be omitted and lines with those
        codes will be ignored.

        """
        stuff = self.parseLine(line)
        if stuff is None:
            # Bogus line
            return
        thisVhost, ip, dt, url, code, ref, ua = stuff
        if vhost is None:
            record = [thisVhost, dt, ip, url]
        elif thisVhost != vhost:
            record = [dt, ip, url]
        else:
            # Excluded vhost
            return
        if self.noUA is False:
            record.append(ua)
        if self.exclude:
            if code in self.exclude:
                # Excluded code
                return
        else:
            record.append(code)
        self.compiler.addRecord(record)

    def run(self, vhost=None):
        """
        """
        def makeRecords(fileName):
            print fileName
            fh = self.file(fileName)
            for line in fh:
                self.makeRecord(line, vhost)
            fh.close()

        def allDone(null):
            return self.compiler.getRecords()

        dList = []
        records = []
        for fileName in os.listdir(self.dirPath):
            if 'access.log' not in fileName:
                continue
            dList.append(self.q.call(makeRecords, fileName))
        return defer.DeferredList(dList).addCallbacks(allDone, self.oops)

        
            
