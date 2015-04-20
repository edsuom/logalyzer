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
from twisted.internet import defer, reactor
from twisted.internet.interfaces import IConsumer

import asynqueue

import sift, parse
from util import Base


class KWParse:
    """
    Subclass me, define a list of name-default keyword options via the
    'keyWords' class attribute, and call this method in your
    constructor.
    """
    def parseKW(self, kw):
        for name, default in self.keyWords:
            value = kw.get(name, default)
            setattr(self, name, value)


class ProcessReader(KWParse):
    """
    Subordinate Python processes use their own instances of me to read
    logfiles.
    """
    reSecondary = re.compile(
        r'(\.(jpg|jpeg|png|gif|css|ico|woff|ttf|svg|eot\??))' +\
        r'|(robots\.txt|sitemap\.xml|googlecea.+\.html)$')

    keyWords = (
        ('vhost', None), ('exclude', []), ('ignoreSecondary', False))

    def __init__(self, matchers, **kw):
        self.parseKW(kw)
        self.isRunning = False
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

    def makeRecord(self, line, alreadyParsed=False):
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
        stuff = line if alreadyParsed else self.p(line)
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
            self.ipm.addIP(ip)
            
    def __call__(self, fileName):
        """
        The public interface to parse a logfile. My processes call this
        via the queue to iterate over misbehaving IP addresses and
        parsed dt-record combinations. The two types iterated are
        strings (misbehaving IP addresses) and 2-tuples (datetime,
        record). Either type may be yielded at any time, and the
        caller must know what to do with them.
        """
        self.isRunning = True
        with self.file(fileName) as fh:
            for line in fh:
                if not self.isRunning:
                    break
                # This next line is where most of the processing time
                # is spent
                stuff = self.makeRecord(line)
                if stuff:
                    yield stuff

    
class Reader(KWParse, Base):
    """
    I read and parse web server log files
    """
    # Maximum number of logfiles to process concurrently
    N = 6
    
    keyWords = (
        ('cores', None),
        ('vhost', None), ('exclude', []), ('ignoreSecondary', False),
        ('verbose', False), ('info', False), ('warnings', False),
        ('gui', None))
    
    def __init__(self, logFiles, rules, dbURL, **kw):
        self.parseKW(kw)
        self.consumers = []
        self.fileNames = logFiles
        # Three connections for each concurrent parsing of a logfile:
        # one for each transaction, two for the iterations that may be
        # done during that transaction.
        N_pool = 3*max([1, 2*self.N_processes])
        from records import RecordKeeper
        self.rk = RecordKeeper(
            dbURL, N_pool,
            verbose=self.verbose, info=self.info, echo=self.warnings,
            gui=self.gui)
        self.pr = ProcessReader(
            self.getMatchers(rules),
            vhost=self.vhost, exclude=self.exclude,
            ignoreSecondary=self.ignoreSecondary)
        # A lock for getting shutdown done right
        self.lock = asynqueue.DeferredLock()
        self.lock.addStopper(self.rk.shutdown)
        reactor.addSystemEventTrigger(
            'before', 'shutdown', self.shutdown)

    def getMatchers(self, rules):
        result = {}
        for matcherName, ruleList in rules.iteritems():
            thisMatcher = getattr(sift, matcherName)(ruleList)
            result[matcherName] = thisMatcher
        return result

    @property
    def N_processes(self):
        if self.cores is None:
            cores = asynqueue.ProcessQueue.cores()
        else:
            cores = int(self.cores)
        return min([self.N, cores])
        
    def getQueue(self, thread=False):
        if thread or (self.N_processes == 0):
            q = asynqueue.ThreadQueue()
        else:
            q = asynqueue.ProcessQueue(self.N_processes)
        self.lock.addStopper(q.shutdown)
        return q
    
    def shutdown(self):
        """
        Call this to shut everything down.
        """
        self.msgHeading("Shutting down...")
        for consumer in self.consumers:
            consumer.stopProduction()
        return self.lock.stop()

    @defer.inlineCallbacks
    def run(self, updateOnly=False):
        """
        Runs everything via the process queue (multiprocessing!),
        returning a reference to a list of all IP addresses purged
        during the run.
        """
        def dispatch(fileName):
            def gotInfo(result):
                if result:
                    dt, N = result
                    self.msgBody("DB datetime: {}", dt, ID=ID)
                    if dt == dtFile:
                        self.fileStatus(
                            fileName, "Already loaded, {:d} records", N)
                        return
                    self.fileStatus(fileName, "File was updated, reloading")
                else:
                    self.fileStatus(fileName, "New file")
                return load()

            def load():
                self.msgBody("Dispatching file for loading", ID=ID)
                # Get a ProcessConsumer for this file
                consumer = self.rk.consumerFactory(fileName)
                self.consumers.append(consumer)
                # Call the ProcessReader on one of my subordinate
                # processes to have it feed the consumer with
                # misbehaving IP addresses and filtered records
                return self.pq.call(
                    self.pr, filePath, consumer=consumer).addCallback(
                        self.consumers.remove)

            filePath = self.pathInDir(fileName)
            ID = self.msgHeading("Logfile {}...", fileName)
            if updateOnly:
                dtFile = datetime.fromtimestamp(os.stat(filePath).st_mtime)
                self.msgBody("File datetime: {}", dtFile, ID=ID)
                return self.rk.fileInfo(fileName).addCallbacks(gotInfo, self.oops)
            return load()

        dList = []
        self.lock.acquire()
        self.pq = self.getQueue()
        # We have at most two files being parsed concurrently for each
        # worker servicing my process queue
        ds = defer.DeferredSemaphore(min([self.N, 2*len(self.pq)]))
        # "Wait" for everything to start up
        yield self.rk.startup()
        # Dispatch files as permitted by the semaphore
        for fileName in self.fileNames:
            # "Wait" for the number of concurrent parsings to fall
            # back to the limit
            yield ds.acquire()
            # References to the deferreds from dispatch calls are
            # stored in the process queue, and we wait for their
            # results.
            d = dispatch(fileName)
            d.addCallback(lambda _: ds.release())
            dList.append(d)
        
        yield defer.DeferredList(dList)
        self.lock.release()
        ipList = self.rk.getNewIPs()
        self.msgBody(
            "Identified {:d} misbehaving IP addresses", len(ipList))
        defer.returnValue(ipList)
