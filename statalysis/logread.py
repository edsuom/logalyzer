#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!
"""
LICENSE
Copyright (C) 2014-2015 Tellectual LLC

Lots of lists. At 20th file result, 15406 lists:

hd[0].byvia
----------------------
13k [0]
642 [1]
406 [2]
 18 [3]
  8 [4]
  6 [5]
  6 [5]

Pretty clear these are k values from dt-k

"""

import os, re, gzip
from copy import copy
from datetime import datetime

from zope.interface import implements
from twisted.internet import defer, reactor
from twisted.internet.interfaces import IConsumer

import asynqueue

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
            wasPurged = self.rk.purgeIP(ip)
            if wasPurged:
                self.msgBody(line)
            return ip
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

    def processator(self, fileName):
        """
        Processes the specified logfile, yielding nasty IP addresses as
        they are identified and purging them from my records.
        """
        fh = self.file(fileName)
        for line in fh:
            try:
                # This next line is where most of the processing time is spent
                stuff = self.makeRecord(line)
            except Exception, e:
                import traceback
                eType, eValue = e[:2]
                self.msgHeading(
                    "ERROR {}: '{}'\n when parsing logfile '{}':\n{}\n",
                    eType.__name__, eValue, fileName, line)
                traceback.print_tb(e[2])
                fh.close()
                break
            if isinstance(stuff, (tuple)):
                self.rk.addRecordToRecords(*stuff)
            elif stuff:
                # This line had a newly purged IP address
                yield stuff
        fh.close()
    
    def __call__(self, fileName):
        """
        The public interface to parse a logfile. My processes call this
        via the queue to iterate first over IP addresses being purged
        and then records added as a result of parsing. The caller must
        differentiate between strings (purged IP addresses) and tuples
        (datetime, record).

        A later optimization may avoid the need for my recordkeeper to
        store the records, in which case it will just yield them
        without storing them, unpredicatably interspersed with nasty
        IP addresses, and let the caller do all the purging. So don't
        put any stock in when you get what iterated.
        """
        self.rk.clear()
        for ip in self.processator(fileName):
            yield ip
        for dt, theseRecords in self.rk():
            for thisRecord in theseRecords:
                yield dt, thisRecord

    
class Reader(Base):
    """
    I read and parse web server log files
    """
    timeout = 60*10 # Ten minutes per file
    
    def __init__(
            self, logFiles, dbURL, cores=None,
            verbose=False, info=False, warnings=False, gui=None):
        #----------------------------------------------------------------------
        self.fileNames = logFiles
        from records import MasterRecordKeeper
        self.rk = MasterRecordKeeper(dbURL, warnings=warnings, gui=gui)
        self.t = self.rk.trans
        self.cores = cores
        self.info = info
        self.verbose = verbose
        self.gui = gui
        self.isRunning = False

    def getMatchers(self, rules):
        result = {}
        for matcherName, ruleList in rules.iteritems():
            thisMatcher = getattr(sift, matcherName)(ruleList)
            result[matcherName] = thisMatcher
        return result

    def getQueue(self, thread=False):
        if thread or (self.cores is not None and int(self.cores) == 0):
            return asynqueue.ThreadQueue()
        if self.cores is None:
            cores = asynqueue.ProcessQueue.cores()
        else:
            cores = int(self.cores)
        return ProcessQueue(cores)
    
    @defer.inlineCallbacks
    def done(self):
        """
        Call this to shut everything down.
        """
        if self.isRunning:
            self.dShutdown = defer.Deferred
            yield self.dShutdown
        self.isRunning = False
        self.msgHeading("Shutting down reader...")
        yield self.pq.shutdown()
        self.msgBody("Process queue shut down")
        yield self.rk.shutdown()
        self.msgBody("Master recordkeeper shut down")
        if self.linger():
            yield self.deferToDelay(10)
            
    def run(self, rules, vhost=None, exclude=[], ignoreSecondary=False):
        """
        Runs everything via the process queue (multiprocessing!),
        returning a reference to a list of all IP addresses purged
        during the run.
        """
        def gotSomeResults(result, fileName, dtFile):
            # DEBUG memory leak
            # -------------------------------
            self.N_iter += 1
            h1 = hp.heap()
            print h1
            print h1.byrcs
            objgraph.show_growth(limit=10)
            if self.N_iter > 20:
                import pdb
                pdb.set_trace()
            # -------------------------------
            # The records are never getting freed from memory
            # It seems like each "thisRecord" is getting stored somewhere

            # (Pdb) h1[0].referents[0].byvia
            # Partition of a set of 56174 objects. Total size = 5505272 bytes.
            #  Index  Count   %     Size   % Cumulative  % Referred Via:
            #      0  13720  24  2011976  37   2011976  37 "['ua']"
            #      1   6862  12  1434064  26   3446040  63 "['ref']"
            #      2  12667  23   796272  14   4242312  77 "['vhost']"
            #      3  14062  25   778960  14   5021272  91 "['ip']"
            #      4   8621  15   473112   9   5494384 100 "['url']"
            #      5     24   0     1176   0   5495560 100 '.keys()[0]'
            #      6     24   0     1008   0   5496568 100 '.keys()[1]'
            #      7     21   0     1008   0   5497576 100 '.keys()[3]'
            #      8     21   0     1008   0   5498584 100 '.keys()[6]'
            #      9     21   0      840   0   5499424 100 '.keys()[2]'

            ipList, records = result
            N_records = self.rk.len(records)
            self.fileStatus(
                fileName, "{:d} purges, {:d} records",
                len(ipList), N_records)
            # NOTE: Using this instead of the real dq.put stops the
            #memory leak, along with all functionality.
            #dq.put((dtFile, None, fileName))
            dq.put((dtFile, result, fileName))

        def dispatch(fileName):
            def gotInfo(result):
                if result:
                    self.msgBody("DB datetime: {}", result[0], ID=ID)
                    if result[0] == dtFile:
                        self.fileStatus(fileName, "{:d} records", result[1])
                        dq.put((None, None, fileName))
                        return
                else:
                    self.msgBody("No DB entry", ID=ID)
                self.fileStatus(fileName, "Parsing...")
                # AsynQueue needs some work before timeout can be used
                d = self.pq.call(
                    parser, filePath, timeout=self.timeout)
                d.addCallback(gotSomeResults, fileName, dtFile)
                d.addErrback(self.oops, "Parsing of '{}'", fileName)
                return d

            ID = self.msgHeading("Checking for '{}' update", fileName)
            filePath = self.pathInDir(fileName)
            dtFile = datetime.fromtimestamp(os.stat(filePath).st_mtime)
            self.msgBody("File datetime: {}", dtFile, ID=ID)
            # TODO: WHY is the bottom line not working????
            #return gotInfo(None)
            # Now it seems to be, after changes to fileInfo
            return self.t.fileInfo(
                fileName).addCallbacks(gotInfo, self.oops)

        @defer.inlineCallbacks
        def resultsLoop(*args):
            while self.isRunning and filesLeft:
                dtFile, stuff, fileName = yield dq.get()
                filesLeft.remove(fileName)
                if stuff is None:
                    # Non-parsed file, reflected already in DB
                    continue
                ipList, records = stuff
                self.fileStatus(fileName, "Purging & adding...")
                dList = []
                for ip in ipList:
                    d = self.rk.purgeIP(ip)
                    d.addCallback(lambda _ : self.fileStatus(fileName))
                    d.addErrback(
                        self.oops,
                        "Trying to purge IP {} while processing '{}'",
                        ip, fileName)
                    dList.append(d)
                N_total = self.rk.len(records)
                N_added = yield self.rk.addRecords(
                    records, fileName).addErrback(
                        self.oops,
                        "Trying to add records for {}", fileName)
                self.fileStatus(
                    fileName,
                    "Added {:d} of {:d} records", N_added, N_total)
                # Write the files entry into the DB only now that its
                # records have been accounted for
                dList.append(self.t.fileInfo(
                    fileName, dtFile, N_total, niceness=15))
                # Only now, after the records have all been added, do
                # we wait for the low-priority IP purging and DB write
                yield defer.DeferredList(dList)
            # Wait for any file writes and closes, too
            yield defer.DeferredList(dWriteList)
            result = self.rk.getIPs()
            if hasattr(self, 'dShutdown'):
                self.dShutdown.callback(result)
            defer.returnValue(result)


        # DEBUG memory leak
        # -------------------------------
        self.N_iter = 0
        import objgraph
        objgraph.show_growth(limit=10)
        from guppy import hpy
        hp = hpy()
        hp.setrelheap()
        # -------------------------------

        self.isRunning = True
        dWriteList = []
        dq = defer.DeferredQueue()
        filesLeft = copy(self.fileNames)
        parser = Parser(
            self.getMatchers(rules),
            vhost, exclude, ignoreSecondary, verbose=self.info)
        self.pq = self.getQueue()
        # The files are all dispatched at once
        for fileName in self.fileNames:
            # References to the deferreds are stored in the process
            # queue, and we wait for their results. No need to keep
            # references returned from dispatch calls.
            dispatch(fileName)
        return self.rk.startup().addCallback(resultsLoop, self.oops)    
