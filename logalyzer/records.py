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
All the recordkeeping is done here, with help from L{database}.
"""

from zope.interface import implements
from twisted.internet import defer
from twisted.internet.interfaces import IConsumer

from asynqueue.util import DeferredTracker

from util import Base
from sift import IPMatcher
import database


class ProcessConsumer(Base):
    """
    I consume bad IP addresses and good records from a logfile parsing
    process.
    """
    implements(IConsumer)

    msgInterval = 10000
    stopInterval = 100000
    
    def __init__(self, rk, fileName, msgID=None, verbose=False, gui=None):
        self.N_parsed = 0
        self.N_added = 0
        self.rk = rk
        self.fileName = fileName
        self.msgID = msgID
        self.verbose = verbose
        self.gui = gui
        self.dt = DeferredTracker()
        self.N_backLog = 0
    
    def registerProducer(self, producer, streaming):
        if hasattr(self, 'producer'):
            raise RuntimeError()
        if not streaming:
            raise TypeError("I only work with push producers")
        self.producer = producer
        producer.registerConsumer(self)
        if self.verbose:
            self.msgHeading("Producer {} registered", repr(producer))
        if self.msgID:
            self.rk.msgBody(
                "Process now loading file {}", self.fileName, ID=self.msgID)
        self.dProducer = defer.Deferred()
        self.dt.put(self.dProducer)
    
    def unregisterProducer(self):
        if not hasattr(self, 'producer'):
            return
        del self.producer
        if self.verbose:
            self.msgBody(
                "Added {:d} of {:d} records from producer",
                self.N_added, self.N_parsed)
        if hasattr(self, 'rk'):
            if self.msgID:
                self.rk.msgBody(
                    "Added {:d} of {:d} records",
                    self.N_added, self.N_parsed, ID=self.msgID)
            self.rk.fileStatus(
                self.fileName, "Done: {:d}/{:d}", self.N_added, self.N_parsed)
            del self.rk
        if hasattr(self, 'gui'):
            # Does this help the GUI-only memory leak? Dunno. Doesn't hurt.
            del self.gui
        self.dProducer.callback(None)

    def write(self, data):
        def done(wasAdded):
            self.N_backLog -= 1
            if self.N_backLog < 10 and hasattr(self, 'producer'):
                self.producer.resumeProducing()
            if hasattr(self, 'rk'):
                self.N_parsed += 1
                if wasAdded:
                    self.N_added += 1
                return
                # This next little bit causes a huge memory leak, only
                # in GUI mode. A high price to pay to watch a spinner
                # symbol, so it's avoided with the 'return' above.
                if not self.N_parsed % 10:
                    self.rk.fileProgress(self.fileName)
                if self.msgID and not self.N_added % 100:
                    self.rk.msgProgress(self.msgID)

        if not hasattr(self, 'rk'):
            return
        if isinstance(data[0], str):
            # No need to pause producer for a mere IP address
            d = self.rk.purgeIP(*data)
            # With both disabled, usage was file; VM=316MB, RM=111MB
            # No worse with this enabled
        else:
            # Writing records can take a while, so pause the producer
            # until it's done if there's a backlog. That keeps my DB
            # transaction queue's memory usage from ballooning with
            # too many pending records.
            self.N_backLog += 1
            if self.N_backLog > 10:
                self.producer.pauseProducing()
            # Major memory leak was caused by the callback, in GUI
            # mode: It added a little over 5,000 bytes per record
            # parsed to the memory usage.
            d = self.rk.addRecord(*data).addCallbacks(done, self.oops)
        self.dt.put(d)

    def stopProduction(self, ID=None):
        del self.rk
        if hasattr(self, 'producer'):
            self.msgBody(
                "Interrupting producer {} after {:d}/{:d} records",
                repr(self.producer), self.N_added, self.N_parsed, ID=ID)
            self.producer.stopProducing()
        return self.dt.deferToAll()
            
                
class RecordKeeper(Base):
    """
    I am the master record keeper that gets fed info from the
    subprocesses. I operate with deferreds; supply a database URL to
    my constructor so I can do the recordkeeping persistently via that
    database.

    Call my L{startup} method right away and then my transactions can
    make use of L{DTK} and {sift.IPMatcher} instances via I{dtk} and
    I{ipm} attributes to avoid database activity.

    """
    progressUpdateInterval = 1000
    
    def __init__(
            self, dbURL, N_pool, blockedIPs,
            verbose=False, info=False, echo=False, gui=None):
        # ---------------------------------------------------------------------
        self.rejectedIPs = dict.fromkeys(blockedIPs, True)
        self.verbose = verbose
        self.info = info
        self.gui = gui
        self.t = database.Transactor(
            dbURL, pool_size=N_pool, verbose=echo, echo=echo)
        self.dt = DeferredTracker()
        # There will be no repeated checks of the same IP in my usage
        # of the IP matcher, so the cache would only slow things down
        self.ipm = IPMatcher()

    def startup(self):
        """
        Returns a deferred that fires when my DB transactor is running and
        my transactor has preloaded its IPMatcher.

        Shows progress loading IP addresses, one update per 1000 loaded.
        """
        def progress():
            self.msgProgress(ID, self.progressUpdateInterval)
        
        def done(N_ip):
            self.msgBody(
                "DB has records from {:d} IP addresses", N_ip, ID=ID)

        ID = self.msgHeading("Preloading IP info from DB")
        return self.t.callWhenRunning(
            self.t.preload,
            progressCall=progress, N_batch=100,
            N_progress=self.progressUpdateInterval).addCallbacks(
                done, self.oops)
        
    def shutdown(self):
        return self.dt.deferToAll().addCallbacks(lambda _: self.t.shutdown())

    def getNewBlockedIPs(self):
        """
        Returns a list of those rejected IP addresses that are to be
        blocked and were identified since the last call to this method.
        """
        ipList = []
        for ip in self.rejectedIPs:
            if self.rejectedIPs[ip] and not self.ipm(ip):
                self.ipm.addIP(ip)
                ipList.append(ip)
        return ipList
    
    def consumerFactory(self, fileName, msgID=None):
        """
        Constructs and returns a reference to a new L{ProcessConsumer}
        that obtains nasty IP addresses and new records from a process
        parsing a particular logfile.
        """
        return ProcessConsumer(
            self, fileName, msgID=msgID, verbose=self.info, gui=self.gui)
    
    def fileInfo(self, *args):
        """
        See L{database.Transactor.fileInfo}
        """
        return self.t.fileInfo(*args)
        
    def purgeIP(self, ip, block):
        """
        Purges my records (and database, if any) of entries from the
        supplied IP address and appends the IP to a list to be
        returned when I'm done so that a master list of purged IP
        addresses can be provided. Any further adds from this IP are
        ignored.
        
        @return: A C{Deferred} that fires when the database has been
          updated, or immediately if no database transaction is
          needed.
        
        """
        def donePurging(N):
            if N: self.msgProgress(self.purgeMsgID, N)

        if not hasattr(self, 'purgeMsgID'):
            self.purgeMsgID = self.msgHeading("Purging IP addresses")
        if ip in self.rejectedIPs:
            # This IP address was already purged during this session
            if block and not self.rejectedIPs[ip]:
                # but not as a blocked IP, and this time it's been bad
                # enough for a block, so change its status
                self.rejectedIPs[ip] = True
            # Don't even bother going to the queue
            return defer.succeed(None)
        # Add to this session's purge (and ignore) list and update the
        # DB accordingly
        self.rejectedIPs[ip] = block
        d = self.t.purgeIP(ip, niceness=15)
        d.addCallbacks(donePurging, self.oops)
        self.dt.put(d)
        return d

    def addRecord(self, dt, record):
        """
        Adds the supplied record to the database for the specified
        datetime, if it's not already there.

        Note: Multiple identical HTTP queries occurring during the
        same second will be viewed as a single one. That shouldn't be
        an issue.
        
        Returns a deferred that fires with a Bool indicating if a new
        entry was added to the database.
        """
        if record['ip'] in self.rejectedIPs:
            return defer.succeed(False)
        d = self.t.setRecord(dt, record)
        d.addErrback(self.oops)
        self.dt.put(d)
        return d


