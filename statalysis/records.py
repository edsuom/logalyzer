#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!
"""
LICENSE
Copyright (C) 2014-2015 Tellectual LLC

"""

from zope.interface import implements
from twisted.internet import defer
from twisted.internet.interfaces import IConsumer

from asynqueue.util import DeferredTracker

from util import Base
import database


class ProcessConsumer(Base):
    """
    I consume bad IP addresses and good records from a logfile parsing
    process.
    """
    implements(IConsumer)

    msgInterval = 1000
    stopInterval = 5000
    
    def __init__(
            self, recordKeeper, fileName, msgID=None, verbose=False, gui=None):
        self.N_parsed = 0
        self.N_added = 0
        self.rk = recordKeeper
        self.fileName = fileName
        self.msgID = msgID
        self.verbose = verbose
        self.gui = gui
    
    def registerProducer(self, producer, streaming):
        if hasattr(self, 'producer'):
            raise RuntimeError()
        if not streaming:
            raise TypeError("I only work with push producers")
        self.producer = producer
        producer.registerConsumer(self)
        self.msgHeading("Producer {} registered", repr(producer))
        if self.msgID:
            self.rk.msgBody(
                "Process now loading file {}", self.fileName, ID=self.msgID)
    
    def unregisterProducer(self):
        del self.producer
        self.msgBody(
            "Added {:d} of {:d} records from producer", self.N_added, self.N_parsed)
        if hasattr(self, 'rk'):
            if self.msgID:
                self.rk.msgBody(
                    "Added {:d} of {:d} records",
                    self.N_added, self.N_parsed, ID=self.msgID)
            self.rk.fileStatus(
                self.fileName, "Done: {:d}/{:d}", self.N_added, self.N_parsed)

    def write(self, x):
        def done(result):
            if hasattr(self, 'producer'):
                self.producer.resumeProducing()
            if hasattr(self, 'rk'):
                self.N_parsed += 1
                if result[0]:
                    self.N_added += 1
                if not self.N_parsed % 10:
                    self.rk.fileProgress(self.fileName)
                if self.msgID and not self.N_added % 100:
                    self.rk.msgProgress(self.msgID)

        if not hasattr(self, 'rk'):
            return
        if isinstance(x, str):
            # No need to pause producer for a mere IP address

            # DEBUG: Disabled to avoid need for lengthy preload while
            # memory leak debugging
            #self.rk.purgeIP(x)
            pass
            # With both disabled, usage was VM=316MB, RM=111MB
            # No worse with this enabled
        else:
            # Writing records can take long enough to pause the
            # producer until it's done. That keeps my DB transaction
            # queue's memory usage from ballooning with a backlog of
            # pending records.
            dt, record = x
            # DEBUG: Major memory leak here
            self.producer.pauseProducing()
            self.cleak(self.rk.addRecord, dt, record).addCallbacks(done, self.oops)
            #self.rk.addRecord(dt, record).addCallbacks(done, self.oops)

    def stopProduction(self):
        del self.rk
        if hasattr(self, 'producer'):
            self.producer.stopProducing()
            
                
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
    def __init__(
            self, dbURL, N_pool,
            verbose=False, info=False, echo=False, gui=None):
        # ---------------------------------------------------------------------
        # List of IP addresses purged during this session
        self.ipList = []
        self.dt = DeferredTracker()
        self.t = database.Transactor(
            dbURL, pool_size=N_pool, verbose=echo, echo=echo)
        self.verbose = verbose
        self.info = info
        self.gui = gui

    def startup(self):
        def done(ipm):
            self.ipm = ipm
            self.msgBody("{:d} IP addresses", len(ipm), ID=ID)
        ID = self.msgHeading("Preloading IP Matcher from DB")
        # DEBUG
        d = self.t.waitUntilRunning()
        #d = self.t.callWhenRunning(
        #    self.t.preload).addCallbacks(done, self.oops)
        return self.dt.put(d)
        
    def shutdown(self):
        return self.dt.deferToAll().addCallback(lambda _: self.t.shutdown())

    def fileInfo(self, *args):
        """
        See L{database.Transactor.fileInfo}
        """
        return self.t.fileInfo(*args)
        
    def purgeIP(self, ip):
        """
        Purges my records (and database, if any) of entries from the
        supplied IP address and appends the IP to a list to be
        returned when I'm done so that a master list of purged IP
        addresses can be provided. Any further adds from this IP are
        ignored.

        If the database is to be updated, adds the deferred from that
        transaction to my DeferredTracker. Returns the deferred, too,
        but you can ignore it.

        """
        def donePurging(N):
            self.msgBody(
                "Purged {:d} DB entries for IP {}",
                N, ip, ID=ID)

        if ip in self.ipList:
            # This IP address was already purged during this session
            return
        # Add to this session's purge (and ignore) list
        self.ipList.append(ip)
        if not self.ipm(ip):
            # This IP address isn't in the database; nothing to purge.
            return
        # The in-database IP matcher says it's in the database so it
        # needs to be removed...
        self.ipm.removeIP(ip)
        # ...though the actual DB transaction is very low priority
        # because our IP matcher was just updated
        ID = self.msgHeading("Purging IP address {}", ip)
        d = self.t.purgeIP(ip, niceness=15)
        d.addCallbacks(donePurging, self.oops)
        return self.dt.put(d)

    def addRecord(self, dt, record):
        """
        Adds the supplied record to the database for the specified
        datetime, if it's not already there.

        Note: Multiple identical HTTP queries occurring during the
        same second will be viewed as a single one. That shouldn't be
        an issue.
        
        Adds the deferred from the DB transaction to my
        DeferredTracker and returns it. It will fire with a 2-tuple: A
        Bool indicating if a new entry was added, and the integer ID
        of the new or existing entry, see
        L{database.Transactor.setRecord}.

        """
        # DEBUG
        #self.ipm.addIP(record['ip'])
        d = self.t.setRecord(dt, record)
        d.addErrback(self.oops)
        return self.dt.put(d)

    def consumerFactory(self, fileName, msgID=None):
        """
        Constructs and returns a reference to a new L{ProcessConsumer}
        that obtains nasty IP addresses and new records from a process
        parsing a particular logfile.
        """
        return ProcessConsumer(
            self, fileName, msgID=msgID, verbose=self.verbose, gui=self.gui)
        #verbose=self.info)
    
    def getNewIPs(self):
        """
        Returns a list of purged IP addresses that have been added since
        the last time this method was called.

        """
        if not hasattr(self, 'ipList_index'):
            self.ipList_index = 0
        result = self.ipList[self.ipList_index:]
        self.ipList_index = len(self.ipList) - 1
        return result


