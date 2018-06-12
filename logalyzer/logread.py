#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# logalyzer:
# Parses your bloated HTTP access logs to extract the info you want
# about hits from (hopefully) real people instead of just the endless
# stream of hackers and bots that passes for web traffic
# nowadays. Stores the info in a relational database where you can
# access it using all the power of SQL.
#
# Copyright (C) 2015, 2017, 2018 by Edwin A. Suominen,
# http://edsuom.com/logalyzer
#
# See edsuom.com for API documentation as well as information about
# Ed's background and other projects, software and otherwise.
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the
# License. You may obtain a copy of the License at
# 
#   http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an "AS
# IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language
# governing permissions and limitations under the License.

"""
HTTP logfile reading and parsing.
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
from records import RecordKeeper


# PROFILING
from util import profile


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
    benignBotURLs = ("/robots.txt",)
    
    reSecondary = re.compile(
        r'(\.(jpg|jpeg|png|gif|css|ico|woff|ttf|svg|eot\??))' +\
        r'|(robots\.txt|sitemap\.xml|googlecea.+\.html)$')

    keyWords = (('exclude', []), ('ignoreSecondary', False))

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
        three types of result:

          - For a bogus or ignored logfile line where there's no IP
            address parsed or other entries from an IP address that was
            parsed aren't to be affected, C{None}.
          
          - For a rejected logfile line, a 2-tuple with (1) a string
            containing the dotted-quad form of an IP address whose
            behavior or source caused the line to be rejected from
            inclusion in logfile analysis, followed by (2) C{False} if
            we are only interested in ignoring its logfile entries, or
            C{True} if the IP address's behavior was so egregious as to
            be blocked from further web access as well as being ignored
            from logfile analysis.
          
          - For an accepted logfile line, a 2-tuple containing (1) a
            datetime object and (2) a dict describing the record for the
            logfile valid line. The dict contains the following
            entries::
          
              ip:     Requestor IP address
              http:   HTTP code
              vhost:  Virtual host requested
              was_rd: TRUE if there was a redirect to this URL
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
        # First and fastest of all is checking for IP addresses
        # already identified as being blocked. If this is a blocked IP
        # address, there's no need to pay any further attention to
        # anything from it
        if self.ipm(ip):
            return
        # Now (also very fast), check for specified IP addresses to
        # ignore but not block
        if self.m.ipMatcher(ip):
            return ip, False
        # Now check for secondary file, if we are ignoring those
        if self.ignoreSecondary and self.reSecondary.search(url):
            return
        # Then do some relatively easy exclusion checks, starting with
        # botMatcher and refMatcher so we can harvest the most blocked
        # IP addresses
        if self.m.botMatcher(ip, url) or self.m.refMatcher(ip, ref):
            # Misbehaving IP
            self.ipm.addIP(ip)
            return ip, True
        if self.exclude:
            if http in self.exclude:
                # Excluded code
                return
        if self.m.uaMatcher(ip, ua):
            # Excluded UA string. We may ignore but never block based
            # just on UA, even if it's a bot.
            return ip, False
        # OK, this is an approved record ... unless the requested
        # vhost is bogus or there is an IP address match
        record = {
            'ip': ip, 'http': http,
            'url': url, 'ref': ref, 'ua': ua }
        record['was_rd'] = self.rc(ip, http)
        if self.m.vhostMatcher(ip, vhost):
            # Excluded vhost, consider this IP misbehaving also, and block
            self.ipm.addIP(ip)
            return ip, True
        record['vhost'] = vhost
        # If the request got this far but asked for a URL indicating a benign bot,
        # ignore but don't block
        if url in self.benignBotURLs:
            return ip, False
        # The last and by FAR the most time-consuming check is for
        # excluded networks to ignore (but not block). Only done if
        # all other checks have passed. Use your .net rules to avoid
        # getting bogged down with logfile analysis of requests from
        # places where you just KNOW it's not an actual person
        # browsing your site.
        if self.m.netMatcher(ip):
            return ip, False
        return dt, record

    def ignoreIPs(self, ipList):
        """
        The supervising process may call this with a list of IP addresses
        to be summarily rejected as I continue parsing.
        """
        for ip in ipList:
            self.ipm.addIP(ip)
            
    def __call__(self, filePath):
        """
        The public interface to parse a logfile. My processes call this
        via the queue to iterate over misbehaving IP addresses and
        parsed dt-record combinations. The two types iterated are
        strings (misbehaving IP addresses) and 2-tuples (datetime,
        record). Either type may be yielded at any time, and the
        caller must know what to do with them.

        If the logfile does not specify a virtual host in CLF column
        #2, you can specify a vhost for the entire file on the first
        line. It can be prefixed with a comment symbol ("#" or ";" if
        you wish).
        """
        # Redirect checking is only valid within an individual logfile
        self.rc.clear()
        firstLine = True
        self.isRunning = True
        with self.file(filePath) as fh:
            for line in fh:
                #print line
                if firstLine:
                    firstLine = False
                    # Check first non-blank line for possible vhost
                    # definition
                    line = line.strip()
                    if not line:
                        continue
                    match = re.match(r'^[#;]*\s*([\S]+\.[\S]+)$', line)
                    if match:
                        # This was indeed a vhost definition
                        self.p.setVhost(match.group(1))
                        continue
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
        ('exclude', []), ('ignoreSecondary', False), ('blockedIPs', []),
        ('verbose', False), ('info', False), ('warnings', False),
        ('gui', None), ('updateOnly', False))
    
    def __init__(self, rules, dbURL, **kw):
        self.parseKW(kw)
        self.consumers = []
        # Three connections for each concurrent parsing of a logfile:
        # one for each transaction, two for the iterations that may be
        # done during that transaction.
        N_pool = 3*max([1, 2*self.N_processes])
        self.rk = RecordKeeper(
            dbURL, N_pool, self.blockedIPs,
            verbose=self.verbose, info=self.info, echo=self.warnings,
            gui=self.gui)
        self.pr = ProcessReader(
            self.getMatchers(rules),
            exclude=self.exclude,
            ignoreSecondary=self.ignoreSecondary)
        # A lock for getting shutdown done right
        self.lock = asynqueue.DeferredLock()

    def isRunning(self):
        if hasattr(self, '_shutdownFlag'):
            return False
        if hasattr(self, 'pq'):
            return self.pq.isRunning()
        return False
    
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
        return q

    @defer.inlineCallbacks
    def shutdown(self):
        """
        Call this to shut everything down.
        """
        if hasattr(self, '_shutdownFlag'):
            self.msgWarning("Ignoring repeated call to reader shutdown")
        else:
            # Signal dispatch loop to quit
            self._shutdownFlag = None
            ID = self.msgHeading("Reader shutting down...")
            # "Wait" for lock
            yield self.lock.acquireAndRelease()
            self.msgBody("Dispatch loop finished", ID=ID)
            # Delete my consumers and "wait" for them to stop their
            # producers
            dList = []
            while self.consumers:
                dList.append(self.consumers.pop(0).stopProduction(ID))
            if dList:
                yield defer.DeferredList(dList)
                self.msgBody(
                    "Stopped {:d} active consumers", len(dList), ID=ID)
            else:
                self.msgBody("No consumers active", ID=ID)
            # "Wait" for recordkeeper to shut down
            if hasattr(self, 'rk'):
                yield self.rk.shutdown()
                del self.rk
                self.msgBody("Record keeper shut down", ID=ID)
            # "Wait" for process queue to shut down
            if hasattr(self, 'pq'):
                yield self.pq.shutdown()
                del self.pq
                self.msgBody("Process queue stopped", ID=ID)
            self.msgBody("All done", ID=ID)

    #@profile
    def _dispatch(self, fileName):
        """
        Called by L{run} to dispatch parsing jobs to CPU cores.
        """
        def gotInfo(result):
            if result:
                dt, size, N = result
                self.msgBody(
                    "Last parsed with {:d} bytes, timestamp '{}'",
                    size, dt, ID=ID)
                if [dt, size] == fileInfo:
                    self.fileStatus(
                        fileName, "Loaded, {:d} records", N)
                    return
                self.fileStatus(fileName, "Updated, reloading")
            else:
                self.fileStatus(fileName, "New file")
            return load()

        def done(null, consumer):
            N = consumer.N_parsed
            self.consumers.remove(consumer)
            self.msgBody("Parsed {:d} records from {}", N, fileName, ID=ID)
            # Update file info for this log file
            d1 = self.rk.fileInfo(fileName, fileInfo[0], fileInfo[1], N)
            # Advise all ProcessReaders of newly identified IP
            # addresses that are being blocked so that they can skip
            # over any log entries from them.
            ipList = self.rk.getNewBlockedIPs()
            d2 = self.pq.update(self.pr.ignoreIPs, ipList)
            # The delay involved with updating the workers and
            # updating the database can be concurrent.
            return defer.DeferredList([d1, d2])
        
        def load():
            self.msgBody("Dispatching file for loading", ID=ID)
            # Get a ProcessConsumer for this file
            consumer = self.rk.consumerFactory(fileName)
            self.consumers.append(consumer)
            # Call the ProcessReader on one of my subordinate
            # processes to have it feed the consumer with
            # misbehaving IP addresses and filtered records
            return self.pq.call(
                self.pr,
                filePath,
                consumer=consumer).addCallback(done, consumer)

        filePath = self.pathInDir(fileName)
        ID = self.msgHeading("Logfile {}...", fileName)
        stat = os.stat(filePath)
        fileInfo = [int(getattr(stat, x)) for x in ('st_mtime', 'st_size')]
        fileInfo[0] = datetime.fromtimestamp(fileInfo[0])
        if self.updateOnly:
            self.msgBody(
                "File size {:d} bytes, timestamp '{}'",
                fileInfo[1], fileInfo[0], ID=ID)
            return self.rk.fileInfo(
                fileName).addCallbacks(gotInfo, self.oops)
        return load()

    @defer.inlineCallbacks
    def run(self, fileNames):
        """
        Runs everything via the process queue (multiprocessing!),
        returning a reference to a list of all IP addresses purged
        during the run.
        """
        dList = []
        self.lock.acquire()
        self.pq = self.getQueue()
        ID = self.msgHeading(
            "Dispatching {:d} parsing jobs", len(fileNames))
        # We have at most two files being parsed concurrently for each
        # worker servicing my process queue
        ds = defer.DeferredSemaphore(min([self.N, 2*len(self.pq)]))
        # "Wait" for everything to start up
        yield self.rk.startup()
        
        # Dispatch files as permitted by the semaphore
        for fileName in fileNames:
            if not self.isRunning():
                break
            # "Wait" for the number of concurrent parsings to fall
            # back to the limit
            yield ds.acquire()
            # If not running, break out of the loop
            if not self.isRunning():
                break
            # References to the deferreds from dispatch calls are
            # stored in the process queue, and we wait for their
            # results.
            d = self._dispatch(fileName)
            d.addCallback(lambda _: ds.release())
            dList.append(d)
        self.msgBody(
            "Done dispatching, awaiting {:d} last results",
            ds.limit-ds.tokens, ID=ID)
        yield defer.DeferredList(dList)
        self.msgBody(
            "Rejected {:d} IP addresses, of which {:d} were blocked",
            len(self.rk.rejectedIPs), sum(self.rk.rejectedIPs.values()), ID=ID)
        # Can now shut down, regularly or due to interruption
        self.lock.release()
        # Fire result deferred with list of bad IPs
        defer.returnValue(self.rk.rejectedIPs)


