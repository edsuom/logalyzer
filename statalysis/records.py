#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!
"""
LICENSE
Copyright (C) 2014-2015 Tellectual LLC

"""

from twisted.internet import defer

from asynqueue.util import DeferredTracker

from util import Base
import database


class ProcessConsumer(Base):
    implements(IConsumer)
    
    def __init__(self, recordKeeper, fileName, verbose=False):
        self.rk = recordKeeper
        self.fileName = fileName
        self.verbose = verbose
        self.producer = None
    
    def registerProducer(self, producer, streaming):
        if self.producer:
            raise RuntimeError()
        if not streaming:
            raise TypeError("I only work with push producers")
        producer.registerConsumer(self)
        self.msg("Producer {} registered", repr(producer))
    
    def unregisterProducer(self):
        self.producer = None
        self.msg("Producer unregistered")

    def write(self, data):
        self.producer.pauseProducing()
        if isinstance(data, str):
            self.rk.purgeIP
            
        self.msg("Data received, len: {:d}", len(data))

                
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
    def __init__(self, dbURL, warnings=False, echo=False, gui=None):
        # List of IP addresses purged during this session
        self.ipList = []
        self.dt = DeferredTracker()
        self.t = database.Transactor(dbURL, verbose=echo, echo=echo)
        self.verbose = warnings
        self.gui = gui

    def startup(self):
        def done(ipm):
            self.ipm = ipm
            self.msgBody("{:d} IP addresses", len(ipm), ID=ID)
        ID = self.msgHeading("Preloading IP Matcher from DB")
        return self.t.preload().addCallbacks(done, self.oops)
        
    def shutdown(self):
        return self.dt.deferToAll().addCallback(lambda _: self.t.shutdown())

    def len(self, records):
        N = 0
        for theseRecords in records.itervalues():
            N += len(theseRecords)
        return N

    def purgeIP(self, ip):
        """
        Purges my records (and database, if any) of entries from the
        supplied IP address and appends the IP to a list to be
        returned when I'm done so that a master list of purged IP
        addresses can be provided. Any further adds from this IP are
        ignored.

        If the database is to be updated, adds the deferred from that
        transaction to my DeferredTracker. Returns nothing.
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
        dt.put(d)

    def addRecord(self, dt, record, fileName=None):
        """
        Adds the supplied record to the database for the specified
        datetime, if it's not already there.

        Note: Multiple identical HTTP queries occurring during the
        same second will be viewed as a single one. That shouldn't be
        an issue.

        Call from within a particular logfile context to update a file
        progress indicator as each record is added.
        
        Adds the deferred from the DB transaction to my
        DeferredTracker. Returns nothing.

        """
        def done(result):
            if result[0]:
                self.fileProgress(fileName)

        self.ipm.addIP(record['ip'])
        d = self.t.setRecord(dt, k, record)
        if fileName:
            d.addCallback(done)
        d.addErrback(self.oops)
        self.dt.put(d)
        return d

    def consumerFactory(self, fileName):
        """
        Constructs and returns a reference to a new L{ProcessConsumer}
        that obtains nasty IP addresses and new records from a process
        parsing a particular logfile.
        """
        pc = ProcessConsumer(self, fileName, self.verbose)
        

        
    def startAddingRecords(self, fileName):
        N = 0
        N_records = self.len(records)
        count = 0
        ID = self.msgHeading(
            "Adding {:d} records for '{}'", N_records, fileName)
        for dt, theseRecords in records.iteritems():
            for k, thisRecord in enumerate(theseRecords):
                d = self.addRecord(dt, k, thisRecord)
                d.addErrback(
                    self.oops,
                    "addRecords(<{:d} records>, {}", N_records, fileName)

                inc = yield d
                N += inc
                count += 1
                if not count % 10:
                    self.msgProgress(ID)
        defer.returnValue(N)
    
    def getIPs(self):
        """
        Returns a list of purged IP addresses
        """
        return self.ipList


