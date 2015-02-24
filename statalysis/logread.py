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

from asynqueue import *

import sift


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


class RecordKeeper(object):
    """
    I keep timestamp-keyed log records.
    """
    secondsInDay = 24 * 60 * 60
    secondsInHour = 60 * 60

    def __init__(self):
        self.records = {}
        self.newKeys = []

    def seconds(self, dt):
        return self.secondsInDay * dt.toordinal() +\
            self.secondsInHour * dt.hour +\
            60 * dt.minute +\
            dt.second

    def add(self, dt, record):
        #sec = self.seconds(dt)
        if dt in self.records:
            thoseRecords = self.records[dt]
            if record in thoseRecords:
                # Duplicate record, ignore
                return
            thoseRecords.append(record)
        else:
            # First record with this timestamp
            self.records[dt] = [record]
        # Record was added, include it in the next get
        self.newKeys.append(dt)

    def clear(self):
        self.newKeys = []

    def get(self):
        """
        Returns the records added since the last clearing
        """
        newRecords = {}
        for key in self.newKeys:
            newRecords[key] = self.records[key]
        return newRecords


class Parser(object):
    """
    I parse logfile lines to generate timestamp-keyed records
    """
    verbose = False
    
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

    def __init__(self, exclude, noUA, ipMatcher=None):
        self.exclude, self.noUA = exclude, noUA
        if ipMatcher is not None:
            self.ipMatcher = ipMatcher
        self.rk = RecordKeeper()

    def ipMatcher(self, ip):
        """
        Never matches any IP address if no ipMatcher supplied.
        """
        return False
        
    def msg(self, line):
        if self.verbose:
            print "\n{}".format(line)
    
    def file(self, filePath):
        """
        Opens a file (possibly a compressed one), returning a file
        object.
        """
        if filePath.endswith('.gz'):
            fh = gzip.open(filePath, 'rb')
        else:
            fh = open(filePath, mode="r")
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
            record = [thisVhost, ip, url]
        elif thisVhost == vhost:
            record = [ip, url]
        else:
            # Excluded vhost
            return
        if self.noUA is False:
            record.append(ua)
        if self.exclude:
            if code in self.exclude:
                # Excluded code
                return
        if self.ipMatcher(ip):
            # Excluded IP address (check last because time-consuming)
            return
        record.append(code)
        return dt, record

    def __call__(self, fileName, vhost):
        """
        The public interface to all the parsing.
        """
        self.rk.clear()
        fh = self.file(fileName)
        for line in fh:
            stuff = self.makeRecord(line, vhost)
            if stuff:
                self.rk.add(*stuff)
        fh.close()
        return self.rk.get()

    
class Reader(object):
    """
    I read and parse web server log files
    """
    cores = 3 # Leave one for the main process and GUI responsiveness
    verbose = True

    def __init__(
            self, logDir,
            exclude=[], noUA=False, ruleFiles=[], verbose=False):
        #----------------------------------------------------------------------
        if not os.path.isdir(logDir):
            raise OSError("Directory '{}' not found".format(logDir))
        self.dirPath = logDir
        self.records = {}
        if ruleFiles:
            ipMatcher = sift.IPMatcher()
            for filePath in ruleFiles:
                ipMatcher.addRules(filePath)
        else:
            ipMatcher = None
        parser = Parser(exclude, noUA, ipMatcher)
        #self.q = BogusQueue()
        self.q = ProcessQueue(self.cores, parser=parser)
        if verbose:
            self.verbose = True
        
    def msg(self, text):
        if self.verbose:
            print text

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
        
    def addUniqueRecords(self, records):
        for key, theseRecords in records.iteritems():
            thoseRecords = self.records.setdefault(key, [])
            for thisRecord in theseRecords:
                if thisRecord not in thoseRecords:
                    thoseRecords.append(thisRecord)

    def run(self, vhost=None):
        """
        Runs everything in twisted fashion. Why? Because I'm a glutton for
        punishment.
        """
        def gotSomeRecords(records, fileName):
            self.msg(" {}: {:d} records".format(fileName, len(records)))
            self.addUniqueRecords(records)

        def allDone(null):
            return self.q.shutdown().addBoth(lambda _ : self.records)
        
        dList = []
        for fileName in os.listdir(self.dirPath):
            if 'access.log' not in fileName:
                continue
            self.msg(fileName)
            d = self.q.call(
                'parser', self.pathInDir(fileName), vhost)
            d.addCallback(gotSomeRecords, fileName)
            d.addErrback(self.oops)
            dList.append(d)
        return defer.DeferredList(dList).addCallbacks(allDone, self.oops)

        
            
