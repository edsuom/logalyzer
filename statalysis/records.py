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
        appends the IP to a list to be returned when I'm done so that
        other instances can purge their records of it, too.

        Any further adds from this IP are ignored.

        Returns True if this IP was purged (not seen before), False if
        not.

        If I am running with database persistence, returns a deferred
        that fires with the value when the database has been updated
        instead of the value itself.
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

    def getNewStuff(self):
        """
        Returns a list of purged IP addresses and the records added since
        the last clearing
        """
        newRecords = {}
        for key in self.newKeys:
            if key in self.records:
                # Not purged and new, so get it
                newRecords[key] = self.records[key]
        return self.ipList, newRecords


class MasterRecordKeeper(ParserRecordKeeper, Base):
    """
    I am the master record keeper that gets fed info from the
    subprocesses. I operate with deferreds; supply a database URL to
    my constructor and I will do the recordkeeping persistently via
    that database, too.
    """
    progressChars = "xo+XO"

    def __init__(self, dbURL=None, warnings=False, echo=False):
        super(MasterRecordKeeper, self).__init__()
        if dbURL is None:
            self.trans = None
        else:
            self.trans = database.Transactor(dbURL, echo=echo)
            self.verbose = warnings
        self.pk = 0
    
    def shutdown(self):
        if self.trans is None:
            return defer.succeed(None)
        self.msg("Shutting down master recordkeeper...")
        return self.trans.shutdown().addCallback(
            lambda _ : self.msg("  ...shutdown complete"))
    
    def _purgeFromDB(self, ip):
        def donePurging(N):
            if N > 0:
                self.msg("Purged DB of {:d} entries for IP {}", N, ip)
        
        if self.trans is None:
            return defer.succeed(0)
        # Deleting unwanted entries is a low-priority activity
        # compared to everything else
        return self.trans.purgeIP(
            ip, niceness=10).addCallbacks(donePurging, self.oops)
    
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
        if ip in self.ipList:
            # Already purged
            return defer.succeed(None)
        dList = [self._purgeFromDB(ip).addErrback(self.oops)]
        dList.append(
            threads.deferToThread(
                self._purgeFromRecords, ip).addErrback(self.oops))
        # Add the IP to our purged list
        self.ipList.append(ip)
        # Return the deferred for the record and (possible) database
        # purge
        return defer.DeferredList(dList)

    def _addRecordToDB(self, dt, k, record):
        """
        Adds the supplied record to my database (if I'm running one) for
        the specified datetime-sequence combination dt-k.
        """
        def done(kNew):
            if kNew != k:
                self.msg(
                    "\nWARNING: Conflicting record in DB: " +\
                    "Timestamp {}, was at k={:d}, written as k={:d}",
                    str(dt), k, kNew, "-")
        
        return self.trans.setRecord(
            dt, k, record).addCallbacks(done, self.oops)

    @defer.inlineCallbacks
    def addRecords(self, records):
        def progressChar():
            pc = self.progressChars[self.pk]
            self.pk = (self.pk + 1) % len(self.progressChars)
            return pc

        N = 0
        pc = progressChar()
        self.msg("\nAdding '{}' records:", pc)
        for dt, theseRecords in records.iteritems():
            for k, thisRecord in enumerate(theseRecords):
                self.addRecordToRecords(dt, thisRecord)
                if self.trans:
                    yield self._addRecordToDB(
                        dt, k, thisRecord).addErrback(self.oops)
                    if self.verbose:
                        print pc,
                        N += 1
        self.msg("\nAdded {:d} '{}' Records", N, pc, "-")
    
    def getStuff(self):
        """
        Returns a list of purged IP addresses and all my records.
        """
        return self.ipList, self.records
