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
        with self.file(fileName) as fh:
            for line in fh:
                # This next line is where most of the processing time
                # is spent
                stuff = self.makeRecord(line)
                if stuff:
                    yield stuff

    
class Reader(KWParse, Base):
    """
    I read and parse web server log files
    """
    keyWords = (
        ('cores', None),
        ('vhost', None), ('exclude', []), ('ignoreSecondary', False),
        ('verbose', False), ('info', False), ('warnings', False),
        ('gui', None))
    
    def __init__(self, logFiles, rules, dbURL, **kw):
        self.parseKW(kw)
        self.fileNames = logFiles
        from records import RecordKeeper
        self.rk = RecordKeeper(
            dbURL,
            verbose=self.verbose, info=self.info, echo=self.warnings,
            gui=self.gui)
        self.pr = ProcessReader(
            self.getMatchers(rules),
            vhost=self.vhost, exclude=self.exclude,
            ignoreSecondary=self.ignoreSecondary)
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
        return asynqueue.ProcessQueue(cores)
    
    @defer.inlineCallbacks
    def done(self):
        """
        Call this to shut everything down.
        """
        if self.isRunning:
            self.dShutdown = defer.Deferred()
            yield self.dShutdown
        self.isRunning = False
        self.msgHeading("Shutting down reader...")
        yield self.pq.shutdown()
        self.msgBody("Process queue shut down")
        yield self.rk.shutdown()
        self.msgBody("Master recordkeeper shut down")
        if self.linger():
            yield self.deferToDelay(10)
            
    def run(self):
        """
        Runs everything via the process queue (multiprocessing!),
        returning a reference to a list of all IP addresses purged
        during the run.
        """
        def dispatch(fileName):
            def gotInfo(result):
                if result:
                    self.msgBody("DB datetime: {}", result[0], ID=ID)
                    if result[0] == dtFile:
                        self.fileStatus(
                            fileName,
                            "Already loaded, {:d} records", result[1])
                        return
                    self.fileStatus(fileName, "File was updated, reloading")
                else:
                    self.fileStatus(fileName, "New file")
                self.msgBody("Dispatching file for loading", ID=ID)
                # Get a ProcessConsumer for this file
                consumer = self.rk.consumerFactory(fileName)
                # Call the ProcessReader on one of my subordinate
                # processes to have it feed the consumer with
                # misbehaving IP addresses and filtered records
                return self.pq.call(self.pr, filePath, consumer=consumer)

            ID = self.msgHeading("Checking for '{}' update", fileName)
            filePath = self.pathInDir(fileName)
            dtFile = datetime.fromtimestamp(os.stat(filePath).st_mtime)
            self.msgBody("File datetime: {}", dtFile, ID=ID)
            return self.rk.fileInfo(fileName).addCallbacks(gotInfo, self.oops)

        def done(null):
            if hasattr(self, 'dShutdown'):
                self.dShutdown.callback(None)
            ipList = self.rk.getNewIPs()
            self.msgOrphan(
                "Done. Identified {:d} misbehaving IP addresses", len(ipList))
            return ipList

        self.isRunning = True
        filesLeft = copy(self.fileNames)
        self.pq = self.getQueue()
        # The files are all dispatched at once
        dList = []
        for fileName in self.fileNames:
            # References to the deferreds are stored in the process
            # queue, and we wait for their results. No need to keep
            # references returned from dispatch calls.
            dList.append(dispatch(fileName))
        return self.rk.startup().addCallback(
            lambda _: defer.DeferredList(dList)).addCallbacks(done, self.oops)
