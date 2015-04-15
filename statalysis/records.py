#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!
"""
LICENSE
Copyright (C) 2014-2015 Tellectual LLC

"""

from collections import OrderedDict

from twisted.internet import defer, threads


from util import Base
from sift import IPMatcher
import database


class ParserRecordKeeper(object):
    """
    I keep timestamp-keyed log records in a dict for instances of
    L{Parser} running in subordinate processes.

    I only keep my records in memory, via my I{records} dict.

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
        for key in self.records.keys():
            recordList = self.records.get(key, [])
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
        appends the IP to a list of IP addresses I ignore in future.

        Returns True if this IP was purged (not seen before), False if
        not.
        """
        if ip in self.ipList:
            # Already purged
            return False
        self._purgeFromRecords(ip)
        # Add the IP
        self.ipList.append(ip)
        return True

    def addRecordToRecords(self, dt, record):
        """
        Adds the supplied record to my records for the specified datetime.
        """
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
        """
        Clears my list of new keys so that only records added (with
        L{addRecordToRecords}) from this point on are included in the
        next call to L{getRecords}.
        """
        self.newKeys = []

    def __call__(self):
        """
        Iterates over my records added since the last call to L{clear}.
        """
        for key in self.newKeys:
            if key in self.records:
                # Not purged and new, so get it
                yield self.records.pop(key)


class ParserConsumer(Base):
    implements(IConsumer)
    
    def __init__(self, masterRecordKeeper, verbose=False):
        self.rk = masterRecordKeeper
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
        if isinstance(data, tuple):
            
        self.msg("Data received, len: {:d}", len(data))

                
class MasterRecordKeeper(Base):
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
        self.ipList = []
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
        return self.t.shutdown()

    def len(self, records):
        N = 0
        for theseRecords in records.itervalues():
            N += len(theseRecords)
        return N

    def consumerFactory(self):
        """
        Constructs and returns a reference to a new L{ParserConsumer} that
        reports nasty IP addresses and new records back to me.
        """
        return ParserConsumer(self, self.verbose)
        
    def purgeIP(self, ip):
        """
        Purges my records (and database, if any) of entries from the
        supplied IP address and appends the IP to a list to be
        returned when I'm done so that a master list of purged IP
        addresses can be provided. Any further adds from this IP are
        ignored.

        Returns a deferred that fires when the records and any
        database have been updated.

        Overrides L{ParserRecordKeeper.purgeIP}.
        """
        def donePurging(N):
            self.msgBody(
                "Purged {:d} DB entries for IP {}",
                N, ip, ID=ID)

        if self.ipp(ip):
            return defer.succeed(None)
        # Add the IP to our purged IP matcher and list
        self.ipp.addIP(ip)
        self.ipList.append(ip)
        if not self.ipm(ip):
            return defer.succeed(None)
        # The in-database IP matcher says it's in the database...
        self.ipm.removeIP(ip)
        # ...so it needs to be removed, though the actual DB
        # transaction is very low priority because our IP matcher
        # was just updated
        ID = self.msgHeading("Purging IP address {}", ip)
        return self.t.purgeIP(
            ip, niceness=10).addCallbacks(donePurging, self.oops)

    def addRecord(self, dt, record):
        """
        Called to add the supplied record to the database for the
        specified datetime-sequence combination dt-k, if it's not
        already there.

        # TODO: No k in call

        Returns 1 if a new entry was written, 0 if not. Use that
        result to increment a counter.
        """
        def done(result):
            if result is None:
                return 1
            if result != k:
                self.msgWarning(
                    "Conflicting record in DB: " +\
                    "Timestamp {}, was at k={:d}, written as k={:d}",
                    str(dt), k, result)
                return 1
            return 0

        self.ipm.addIP(record['ip'])
        return self.t.setRecord(
            dt, k, record).addCallbacks(done, self.oops)

    @defer.inlineCallbacks
    def addRecords(self, records, fileName):
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
                self.fileProgress(fileName)
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
