#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!
"""
LICENSE
Copyright (C) 2014-2015 Tellectual LLC

"""

import re, gzip
from datetime import datetime
from collections import OrderedDict

from twisted.internet import defer, reactor

from asynqueue import *

from util import *
import sift


class RecordKeeper(object):
    """
    I keep timestamp-keyed log records in a dict.
    """
    N_redirects = 50
    secondsInDay = 24 * 60 * 60
    secondsInHour = 60 * 60

    def __init__(self):
        self.ipList = []
        self.records = {}
        self.redirects = OrderedDict()
        
    def isRedirect(self, vhost, ip, http):
        """
        Checks if this vhost is the destination of a redirect from another
        one, and replace it with the old one if so.
        """
        wasRedirect = False
        if http in [301, 302]:
            # This is a redirect, so save my vhost for the inevitable
            # check from the same IP address
            self.redirects[ip] = vhost
        else:
            oldVhost = self.redirects.pop(ip, None)
            if oldVhost:
                # There was a former vhost: This is a redirect.
                wasRedirect = True
                # While we set the substitute vhost, put a replacement
                # entry back in the FIFO to ensure we can find it
                # again if checked again soon
                vhost = self.redirects[ip] = oldVhost
        # Remove oldest entry until FIFO no longer too big
        while len(self.redirects) > self.N_redirects:
            self.redirects.popitem(last=False)
        return wasRedirect, vhost

    def _purgeFromRecords(self, ip):
        def purgeList():
            while True:
                ipList = [x['ip'] for x in recordList]
                if ip not in ipList:
                    return
                del recordList[ipList.index(ip)]
                
        removedKeys = []
        for key, recordList in self.records.iteritems():
            for record in recordList:
                if record['ip'] == ip:
                    # Oops, we have to cleanse this record list of at
                    # least one tainted record
                    purgeList()
                    break
            if not recordList:
                # The whole list was removed, so we will remove the key
                removedKeys.append(key)
        # Remove keys
        for key in removedKeys:
            self.records.pop(key, None)
    
    def purgeIP(self, ip):
        """
        Purges my records of entries from the supplied IP address and
        appends the IP to a list to be returned when I'm done so that
        other instances can purge their records of it, too.

        Any further adds from this IP are ignored.

        Returns True if this IP was purged (not seen before), False if
        not.

        If I am running with database persistence, returns a deferred
        that fires with the value when the database has been updated
        instead of the value itself.
        """
        if ip in self.ipList:
            # Already purged
            return False
        self._purgeFromRecords(ip)
        # Add the IP
        self.ipList.append(ip)
        return True

    def addRecordToRecords(self, dt, record):
        if record['ip'] in self.ipList:
            # Purged IP, ignore
            return
        if dt in self.records:
            thoseRecords = self.records[dt]
            if record in thoseRecords:
                # Duplicate record, ignore
                return
            thoseRecords.append(record)
        else:
            # First record with this timestamp
            self.records[dt] = [record]
        # If we are keeping track of records since the last get,
        # append this as a new datetime key for the next get.
        if hasattr(self, 'newKeys'):
            self.newKeys.append(dt)
        
    def clear(self):
        self.newKeys = []

    def getRecords(self):
        """
        Returns a list of purged IP addresses and the records added since
        the last clearing
        """
        newRecords = {}
        for key in self.newKeys:
            if key in self.records:
                # Not purged and new, so get it
                newRecords[key] = self.records[key]
        return self.ipList, newRecords


class MasterRecordKeeper(RecordKeeper, Base):
    """
    I am the master record keeper that gets fed info from the
    subprocesses. I operate with deferreds; supply a database URL to
    my constructor and I will do the recordkeeping persistently via
    that database, too.
    """
    def __init__(self, dbURL=None):
        super(MasterRecordKeeper, self).__init__()
        if dbURL is None:
            self.trans = None
        else:
            self.trans = database.Transactor(dbURL)

    def shutdown(self):
        if self.trans is None:
            return defer.succeed(None)
        return self.trans.shutdown()
        
    def _purgeFromDB(self, ip):
        def donePurging(N):
            if N > 0:
                self.msg("Purged DB of {:d} entries for IP {}", N, ip)
        
        if self.trans is None:
            return defer.succeed(0)
        # Deleting unwanted entries is a low-priority activity
        # compared to everything else
        return self.trans.purgeIP(
            ip, niceness=10).addCallbacks(donePurging, self.oops)
    
    def purgeIP(self, ip):
        """
        Purges my records (and database, if any) of entries from the
        supplied IP address and appends the IP to a list to be
        returned when I'm done so that a master list of purged IP
        addresses can be provided.

        Any further adds from this IP are ignored.
        """
        if ip in self.ipList:
            # Already purged
            return
        # Database purge (happens asynchronously)
        d = self._purgeFromDB(ip)
        self._purgeFromRecords(ip)
        # Add the IP to our purged list
        self.ipList.append(ip)
        # Return the deferred for the (eventual) database purge
        return d

    def addRecordToDB(self, dt, k, record):
        """
        """
        # TODO
    
    @defer.inlineCallbacks
    def addRecords(self, records):
        for dt, theseRecords in records.iteritems():
            for k, thisRecord in enumerate(theseRecords):
                self.addRecordToRecords(dt, thisRecord)
                yield self.addRecordToDB(dt, k, thisRecord)
    
    def getRecords(self):
        """
        Returns a list of purged IP addresses and all my records.
        """
        return self.ipList, self.records

                
    
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
        # Day/Month/Year
        r'(\d{1,2})/([^/]+)/'    +\
            rdb(":", 4, 2, 2, 2)
        )

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
        self.rk = RecordKeeper()
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
        result = list(match.group(2, 1))
        if dt is None:
            dt = self.parseDatetimeBlock(match.group(3))
        result.extend([dt, match.group(5), int(match.group(6))])
        result.extend(match.group(8, 9))
        return result

    def makeRecord(self, line, alreadyParsed=False):
        """
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
            stuff = self.makeRecord(line)
            if stuff:
                self.rk.addRecordToRecords(*stuff)
        fh.close()
        return self.rk.getRecords()

    
class Reader(Base):
    """
    I read and parse web server log files
    """
    def __init__(
            self, logDir, dbURL=None,
            rules={}, vhost=None, exclude=[],
            ignoreSecondary=False, cores=None, verbose=False):
        #----------------------------------------------------------------------
        self.myDir = logDir
        self.rk = MasterRecordKeeper(dbURL)
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
            ipList, records = results
            self.msg(" {}: {:d} purged IPs, {:d} records".format(
                fileName, len(ipList), len(records)))
            for ip in ipList:
                yield self.rk.purgeIP(ip)
            yield self.rk.addRecords(records)

        def allDone(null):
            reactor.stop()
            return self.rk.get()
        
        dList = []
        for fileName in self.filesInDir():
            if 'access.log' not in fileName:
                continue
            self.msg(fileName)
            d = self.q.call(
                'parser', self.pathInDir(fileName))
            d.addCallback(gotSomeResults, fileName)
            d.addErrback(self.oops)
            dList.append(d)
        return defer.DeferredList(dList).addCallbacks(allDone, self.oops)

        
            
