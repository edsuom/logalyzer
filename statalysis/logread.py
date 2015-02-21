#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!
"""
LICENSE
Copyright (C) 2014-2015 Tellectual LLC

"""

import re, os, os.path, gzip
from datetime import datetime


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


class Reader(object):
    """
    I read and parse web server log files
    """
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

    def __init__(self, logDir):
        if not os.path.isdir(logDir):
            raise OSError("Directory '{}' not found".format(logDir))
        self.dirPath = logDir
        self.dtLast = None

    def msg(self, line):
        if self.verbose:
            print "\n{}".format(line)

    def printRecord(self, dt, record):
        if not self.verbose:
            return
        if dt != self.dtLast:
            self.dtLast = dt
            print "\n{}".format(dt.isoformat(' '))
        print "{:15s}  {}".format(record[0], record[1][:50])
    
    def pathInDir(self, fileName):
        """
        Returns the absolute path of a file in my project directory
        """
        if os.path.split(fileName)[0]:
            raise ValueError(
                "Path '{}' specified, use file name only".format(fileName))
        return os.path.abspath(os.path.join(self.dirPath, fileName))

    def readLinesFromFile(self, fileName, isFullPath=False):
        if not isFullPath:
            fileName = self.pathInDir(fileName)
        if fileName.endswith('.gz'):
            fh = gzip.open(fileName, 'rb')
        else:
            fh = open(fileName, mode="r")
        # Read the file a line at a time
        outLines = []
        for line in fh:
            outLines.append(line.rstrip('\n\r'))
        fh.close()
        return outLines

    def dt(self, *args):
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
        return self.dt(year, month, day, hour, minute, second)

    def parseLine(self, line):
        """
        Parses an individual logfile line and returns a list:

        [vhost, Requestor IP address, datetime, url, code, referrer, UA]

        """
        dt = None
        match = self.reTwistdPrefix.match(line)
        if match:
            dt = self.dt(*match.groups()[:6])
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

    def recordator(self, vhost, lines, exclude=[], noUA=False):
        """
        Supply a mess of logfile lines and this method will iterate
        over the parsed results for the specified vhost in
        chronological order. Each iteration yields a list:

        [dt, Requestor IP address, url, UA, code]

        If noUA is set True, no UA will be included in the list.

        If one or more HTTP codes are supplied with the exclude
        keyword, then the code will be omitted and lines with those
        codes will be ignored.

        """
        for line in lines:
            stuff = self.parseLine(line)
            if stuff is None:
                continue
            thisVhost, ip, dt, url, code, ref, ua = stuff
            if thisVhost != vhost:
                continue
            thisRecord = [dt, ip, url]
            if noUA is False:
                thisRecord.append(ua)
            if exclude:
                if code in exclude:
                    continue
            else:
                thisRecord.append(code)
            yield thisRecord

    def logerator(self, records):
        """
        Supply a mess of records that each begin with a datetime
        object and this method will iterate over the UNIQUE remainder
        of each record in chronological order.

        Only unique entries will be yielded.

        """
        data = {}
        for stuff in records:
            dt = stuff[0]
            thisRecord = stuff[1:]
            thoseRecords = data.setdefault(dt, [])
            if thisRecord in thoseRecords:
                continue
            self.printRecord(dt, thisRecord)
            thoseRecords.append(thisRecord)
        keys = data.keys()
        keys.sort()
        for key in keys:
            theseRecords = data[key]
            for thisRecord in theseRecords:
                yield thisRecord

    def run(self, vhost, exclude=[], noUA=False):
        records = []
        for fileName in os.listdir(self.dirPath):
            if 'access.log' not in fileName:
                continue
            self.msg("Reading '{}'...".format(fileName))
            lines = self.readLinesFromFile(fileName)
            for thisRecord in self.recordator(vhost, lines, exclude, noUA):
                records.append(thisRecord)
        return list(self.logerator(records))
        



            
        
        

       
    


