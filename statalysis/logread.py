#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!
"""
LICENSE
Copyright (C) 2014-2015 Tellectual LLC

"""

import os, re, gzip
from copy import copy
from datetime import datetime
from collections import OrderedDict

from zope.interface import implements
from twisted.internet import defer
from twisted.internet.interfaces import IConsumer

import asynqueue

import parse
from util import *


class ProcessReader(object):
    """
    Subordinate Python processes use their own instances of me to read
    logfiles.
    """
    reSecondary = re.compile(
        r'(\.(jpg|jpeg|png|gif|css|ico|woff|ttf|svg|eot\??))' +\
        r'|(robots\.txt|sitemap\.xml|googlecea.+\.html)$')

    def __init__(self, matchers, **kw):
        for name, default in (
                ('vhost', None), ('exclude', []), ('ignoreSecondary', False)):
            value = kw.get(name, default)
            setattr(name, value)
        self.p = parse.LineParser()
        self.m = parse.MatcherManager(matchers)
        self.rc = parse.RedirectChecker()
        self.ipm = sift.IPMatcher()

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

    def makeRecord(self, line):
        """
        This is where most of the processing time gets spent.

        Given one line of a logfile, returns one of the following
        three types:

        * A C{None} object if the logfile line was rejected.

        * A string containing the dotted-quad form of an IP address
          whose behavior not only caused the line to be rejected but
          also all other lines from that IP address

        * A 2-tuple containing a datetime object and a dict describing
          the record for the logfile valid line. The dict contains the
          following entries:

            ip:     Requestor IP address
            http:   HTTP code
            vhost:  Virtual host requested
            was_rd: C{True} if there was a redirect to this URL
            url:    Requested url
            ref:    Referrer
            ua:     The requestor's User-Agent string.

        The dict entry 'was_rd' indictates if the vhost listed was the
        original vhost requested before a redirect. In that case the
        redirect-destination vhost isn't used, though it may be the
        same.

        If my I{ignoreSecondary} attribute is set and this is a
        secondary file (css or image), it is ignored with no further
        checks.

        If one or more HTTP codes are supplied in my I{exclude}
        attribute, then lines with those codes will be ignored.
        """
        stuff = self.p(line)
        if stuff is None:
            # Bogus line
            return
        vhost, ip, dt, url, http, ref, ua = stuff
        # First and fastest of all is checking for known bad guys. We
        # check our dedicated purged-IP matcher and then an IP matcher
        # for 'ip' rules, if any.
        if self.ipm(ip) or self.m.ipMatcher(ip):
            return
        # Now check for secondary file, if we are ignoring those
        if self.ignoreSecondary and self.reSecondary.search(url):
            return
        # Then do some relatively easy exclusion checks, starting with
        # botMatcher and refMatcher so we can harvest the most bot IP
        # addresses (useful if -i option set)
        if self.m.botMatcher(ip, url) or self.m.refMatcher(ip, ref):
            # Misbehaving IP
            self.ipm.addIP(ip)
            return ip
        if self.exclude:
            if http in self.exclude:
                # Excluded code
                return
        if self.m.uaMatcher(ip, ua):
            # Excluded UA string
            return
        # OK, this is an approved record ... unless the vhost is
        # excluded, and unless there is an IP address match
        record = {
            'ip': ip, 'http': http,
            'url': url, 'ref': ref, 'ua': ua }
        record['was_rd'], record['vhost'] = self.rc(vhost, ip, http)
        if self.vhost and self.vhost != record['vhost']:
            # Excluded vhost, so bail right now
            return
        # The last and by FAR the most time-consuming check is for
        # excluded networks. Only done if all other checks have
        # passed.
        if self.m.netMatcher(ip):
            return
        return dt, record

    def ignoreIPs(self, IPs):
        """
        The supervising process may call this with a list of IP addresses
        to be rejected as I continue parsing.
        """
        for IP in IPs:
            self.ipm.addIP(ip, ignoreCache=True)
        
    def __call__(self, fileName):
        """
        The public interface to parse a logfile. My processes call this
        via the queue to iterate over misbehaving IP addresses and
        parsed dt-record combinations. The two types iterated are
        strings (misbehaving IP addresses) and 2-tuples (datetime,
        record). Either type may be yielded at any time, and the
        caller must know what to do with them.
        """
        with self.file(fileName) as fh:
            for line in fh:
                # This next line is where most of the processing time
                # is spent
                stuff = self.makeRecord(line)
                if stuff:
                    yield stuff
    
    
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
            return self.t.fileInfo(fileName).addCallbacks(gotInfo, self.oops)

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
            result = self.rk.getIPs()
            if hasattr(self, 'dShutdown'):
                self.dShutdown.callback(result)
            defer.returnValue(result)

        self.isRunning = True
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
