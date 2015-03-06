#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!
"""
LICENSE
Copyright (C) 2014-2015 Tellectual LLC

"""

import re, gzip
from datetime import datetime

from twisted.internet import defer, reactor

from asynqueue import ProcessQueue

from util import *
import sift

    
class Parser(Base):
    """ 
    I parse logfile lines to generate timestamp-keyed records. Send an
    instance of me to your processes.

    Instantiate me with a dict of matchers (ipMatcher, uaMatcher,
    and/or botMatcher). If you want to exclude any HTTP codes, list
    them with exclude.
    """
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
        # Day/Month                 # Year:Hr:Min:Sec
        r'(\d{1,2})/([^/]+)/' + rdb(":", 4, 2, 2, 2))

    reSecondary = re.compile(
        r'(\.(jpg|jpeg|png|gif|css|ico|woff|ttf|svg|eot\??))' +\
        r'|(robots\.txt|sitemap\.xml|googlecea.+\.html)$')

    months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
              'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

    matcherTable = (
        ('ipMatcher',  'IPMatcher'),
        ('netMatcher', 'NetMatcher'),
        ('uaMatcher',  'UAMatcher'),
        ('botMatcher', 'BotMatcher'),
        ('refMatcher', 'RefMatcher'))

    def __init__(
            self, matchers,
            vhost=None, exclude=[], ignoreSecondary=False,
            verbose=False):
        #----------------------------------------------------------------------
        for callableName, matcherName in self.matcherTable:
            if matcherName in matchers:
                setattr(self, callableName, matchers[matcherName])
        from records import ParserRecordKeeper
        self.rk = ParserRecordKeeper()
        self.vhost = vhost
        self.exclude = exclude
        self.ignoreSecondary = ignoreSecondary
        self.verbose = verbose

    def ipMatcher(self, ip):
        """
        Never matches any IP address if no ipMatcher supplied.
        """
        return False

    def netMatcher(self, ip):
        """
        Never matches any IP address if no netMatcher supplied.
        """
        return False

    def uaMatcher(self, ip, uaString):
        """
        Never matches any UA string if no uaMatcher supplied.
        """
        return False

    def botMatcher(self, ip, url):
        """
        Never matches any url if no botMatcher supplied.
        """
        return False

    def refMatcher(self, ip, url):
        """
        Never matches any referrer string if no refMatcher supplied.
        """
        return False
    
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

        [vhost, Requestor IP address, datetime, url, http, referrer, UA]

        """
        dt = None
        match = self.reTwistdPrefix.match(line)
        if match:
            dt = self.dtFactory(*match.groups()[:6])
            if match.group(7) == '-':
                return
            line = match.group(8)
        match = self.reCLF.match(line)
        if match is None:
            return
        result = [match.group(2).lower(), match.group(1)]
        if dt is None:
            dt = self.parseDatetimeBlock(match.group(3))
        result.extend([dt, match.group(5), int(match.group(6))])
        result.extend(match.group(8, 9))
        return result

    def makeRecord(self, line, alreadyParsed=False):
        """
        This is where most of the processing time gets spent.

        Supply a mess of logfile lines and this method will iterate over
        the parsed results for the specified vhost (or all vhosts, if
        none was specified in my constructor) to generate a datetime
        object and dict for each valid line. The dict contains the
        following entries:

        http:   HTTP code
        vhost:  Virtual host requested
        was_rd: C{True} if there was a redirect to this URL
        ip:     Requestor IP address
        url:    Requested url
        ref:    Referrer
        ua:     The requestor's User-Agent string.

        The dict entry was_rd indictates if the vhost listed was the
        original vhost requested before a redirect. In that case the
        redirect-destination vhost isn't used, though it may be the
        same.

        If my ignoreSecondary attribute is set and this is a secondary
        file (css or image), it is ignored with no further checks.

        If one or more HTTP codes are supplied in my exclude
        attribute, then lines with those codes will be ignored.
        """
        stuff = line if alreadyParsed else self.parseLine(line)
        if stuff is None:
            # Bogus line
            return
        vhost, ip, dt, url, http, ref, ua = stuff
        # First and fastest of all is checking for known bad guys
        if ip in self.rk.ipList or self.ipMatcher(ip):
            return
        # Now check for secondary file, if we are ignoring those
        if self.ignoreSecondary and self.reSecondary.search(url):
            return
        # Then do some relatively easy exclusion checks, starting with
        # botMatcher and refMatcher so we can harvest the most bot IP
        # addresses (useful if -i option set)
        if self.botMatcher(ip, url) or self.refMatcher(ip, ref):
            if self.rk.purgeIP(ip):
                self.msg(line)
            return
        if self.exclude:
            if http in self.exclude:
                # Excluded code
                return
        if self.uaMatcher(ip, ua):
            # Excluded UA string
            return
        # OK, this is an approved record ... unless the vhost is
        # excluded, and unless there is an IP address match
        record = {
            'http': http,
            'ip': ip, 'url': url, 'ref': ref, 'ua': ua }
        record['was_rd'], record['vhost'] = self.rk.isRedirect(vhost, ip, http)
        if self.vhost and self.vhost != record['vhost']:
            # Excluded vhost, so bail right now
            return
        # The last and by FAR the most time-consuming check is for
        # excluded networks. Only done if all other checks have
        # passed.
        if self.netMatcher(ip):
            return
        return dt, record
    
    def __call__(self, fileName):
        """
        The public interface to parse a logfile. My processes call this
        via the queue.
        """
        self.rk.clear()
        fh = self.file(fileName)
        for line in fh:
            # This next line is where most of the processing time is spent
            try:
                stuff = self.makeRecord(line)
            except:
                import sys, traceback
                eType, eValue = sys.exc_info()[:2]
                print "\nERROR {}: '{}'\n when parsing logfile '{}':\n{}\n".format(
                    eType.__name__, eValue, fileName, line)
                traceback.print_tb(sys.exc_info()[2])
                return
            if stuff:
                self.rk.addRecordToRecords(*stuff)
        fh.close()
        return self.rk.getNewStuff()

    
class Reader(Base):
    """
    I read and parse web server log files
    """
    def __init__(
            self, logDir, dbURL=None,
            rules={}, vhost=None, exclude=[], ignoreSecondary=False,
            cores=None, verbose=False, warnings=False):
        #----------------------------------------------------------------------
        self.myDir = logDir
        from records import MasterRecordKeeper
        self.rk = MasterRecordKeeper(dbURL, warnings=warnings)
        matchers = {}
        for matcherName, ruleList in rules.iteritems():
            thisMatcher = getattr(sift, matcherName)(ruleList)
            matchers[matcherName] = thisMatcher
        parser = Parser(
            matchers, vhost, exclude, ignoreSecondary, verbose)
        #self.q = BogusQueue(parser=parser)
        if cores is None:
            import multiprocessing as mp
            cores = mp.cpu_count() - 1
        else:
            cores = int(cores)
        self.q = ProcessQueue(cores, parser=parser)
        reactor.addSystemEventTrigger('before', 'shutdown', self.shutdown)
        if verbose:
            self.verbose = True

    def shutdown(self):
        dList = [self.q.shutdown(), self.rk.shutdown()]
        return defer.DeferredList(dList)
            
    def run(self):
        """
        Runs everything via the process queue (multiprocessing!),
        returning a reference to my main-process recordkeeper with all
        the results in it.
        """
        @defer.inlineCallbacks
        def gotSomeResults(results, fileName):
            if results is None:
                reactor.stop()
            else:
                ipList, records = results
                self.msg("\n{}: {:d} purged IPs, {:d} records".format(
                    fileName, len(ipList), len(records)))
                for ip in ipList:
                    yield self.rk.purgeIP(ip)
                yield self.rk.addRecords(records)

        def allDone(null):
            reactor.stop()
            return self.rk.getStuff()
        
        dList = []
        for fileName in self.filesInDir():
            if 'access.log' not in fileName:
                continue
            d = self.q.call(
                'parser', self.pathInDir(fileName))
            d.addCallback(gotSomeResults, fileName)
            d.addErrback(self.oops)
            dList.append(d)
        return defer.DeferredList(dList).addCallbacks(allDone, self.oops)
    
