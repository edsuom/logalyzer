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
        self.dProducer = defer.Deferred()
        self.dt.put(self.dProducer)
    
    def unregisterProducer(self):
        if not hasattr(self, 'producer'):
            return
        del self.producer
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
            if hasattr(self, 'producer'):
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
        if isinstance(data, str):
            # No need to pause producer for a mere IP address
            d = self.rk.purgeIP(data)
            # With both disabled, usage was file; VM=316MB, RM=111MB
            # No worse with this enabled
        else:
            # Writing records can take long enough to pause the
            # producer until it's done. That keeps my DB transaction
            # queue's memory usage from ballooning with a backlog of
            # pending records.
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
                "Stopping producer {} after {:d}/{:d} records",
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
    def __init__(
            self, dbURL, N_pool,
            verbose=False, info=False, echo=False, gui=None):
        # ---------------------------------------------------------------------
        self.t = database.Transactor(
            dbURL, pool_size=N_pool, verbose=echo, echo=echo)
        self.verbose = verbose
        self.info = info
        self.gui = gui

    def startup(self):
        """
        Returns a deferred that fires when my DB transactor is running and
        I've preloaded my IPMatcher and list of bad IP
        addresses. Fires with the bad-ip list.
        """
        def done(stuff):
            self.ipm, self.ipList = stuff
            self.msgBody(
                "DB has records from {:d} IP addresses and warns "+\
                "of {:d} known bad ones",
                len(self.ipm), len(self.ipList), ID=ID)
            return self.ipList
        ID = self.msgHeading("Preloading IP info from DB")
        return self.t.callWhenRunning(
            self.t.preload).addCallbacks(done, self.oops)
        
    def shutdown(self):
        return self.t.shutdown()

    def consumerFactory(self, fileName, msgID=None):
        """
        Constructs and returns a reference to a new L{ProcessConsumer}
        that obtains nasty IP addresses and new records from a process
        parsing a particular logfile.
        """
        return ProcessConsumer(
            self, fileName, msgID=msgID, verbose=self.verbose, gui=self.gui)
    
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

        Returns a deferred that fires when the database has been
        updated, or immediately if no database transaction is needed.
        """
        def donePurging(N):
            self.msgBody(
                "Purged {:d} DB entries for IP {}", N, ip, ID=ID)

        if ip in self.ipList:
            # This IP address was already purged during this session
            return defer.succeed(None)
        # Add to this session's purge (and ignore) list
        self.ipList.append(ip)
        if not self.ipm(ip):
            # This IP address isn't in the database; nothing to purge.
            return defer.succeed(None)
        # The in-database IP matcher says it's in the database so it
        # needs to be removed...
        self.ipm.removeIP(ip)
        # ...though the actual DB transaction is very low priority
        # because our IP matcher was just updated
        ID = self.msgHeading("Purging IP address {}", ip)
        return self.t.purgeIP(
            ip, niceness=15).addCallbacks(donePurging, self.oops)

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
        ip = record['ip']
        if ip in self.ipList:
            # Ignore this, it's from a purged IP address
            return defer.succeed(False)
        self.ipm.addIP(ip)
        return self.t.setRecord(dt, record).addErrback(self.oops)

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


