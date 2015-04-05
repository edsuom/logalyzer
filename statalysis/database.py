#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!

"""
LICENSE
Copyright (C) 2015 Tellectual LLC
"""

from twisted.internet import defer

from sasync.database import transact, SA, AccessBroker

import util
from sift import IPMatcher


class DTK(object):
    """
    I maintain a CPU-efficient but somewhat memory expensive lookup
    tree for datetime objects.

    The item value at each leaf node is an integer indicating how many
    records are in the database for that exact-to-the-second datetime.
    """
    units = ['year', 'month', 'day', 'hour', 'minute', 'second']

    def __init__(self, rows=[]):
        self.N = 0
        self.x = {}
        self.load(rows)

    def __len__(self):
        return self.N

    def load(self, rows):
        """
        Load a list of datetime objects or rows whose first element is
        a datetime object.
        """
        for dt in rows:
            if isinstance(dt, (list, tuple)):
                dt = dt[0]
            self.set(dt)

    def _uniterator(self, dt):
        """
        Iterates over values for each time unit of the supplied
        datetime object, yielding an integer number of positions to
        the last time unit and the value for that time unit.

        TODO: Account for new k info
        """
        N = len(self.units)
        for k, unitName in enumerate(self.units):
            yield N-k-1, getattr(dt, unitName)

    def check(self, dt):
        """
        Check the specified datetime object, returning the number of
        database records for it if it's in my lookup tree, zero if
        it's not.

        TODO: Implement this change
        """
        stuff = self.x
        for p, unitVal in self._uniterator(dt):
            if unitVal not in stuff:
                return False
            if p > 0:
                stuff = stuff[unitVal]
        return True

    def set(self, dt):
        """
        Sets an entry in my lookup tree for the specified datetime
        object.

        TODO: Account for new k info
        """
        stuff = self.x
        for p, unitVal in self._uniterator(dt):
            if p > 1:
                stuff = stuff.setdefault(unitVal, {})
            elif p == 1:
                stuff = stuff.setdefault(unitVal, [])
            elif unitVal not in stuff:
                stuff.append(unitVal)
                self.N += 1


class Transactor(AccessBroker, util.Base):
    """
    I handle transactions for an efficient database of logfile
    entries.

    """
    valueLength = 255
    directValues = ['http', 'was_rd', 'ip']
    indexedValues = ['vhost', 'url', 'ref', 'ua']
    colNames = directValues +\
               ["id_{}".format(x) for x in indexedValues]

    def cacheSetup(self):
        """
        Sets up caches for values written to the indexed value tables
        """
        # We use huge caches because DB access is so slow
        self.cm = util.CacheManager(200)
        self.cachedValues = {}
        for name in self.indexedValues:
            self.cm.new(name)
            self.cachedValues[name] = {}

    def _pendingID(self, name, value, d=None, clear=False):
        if not hasattr(self, '_pendingIDs'):
            self._pendingIDs = {}
        if name not in self._pendingIDs:
            self._pendingIDs[name] = {}
        if clear:
            self._pendingIDs[name].pop(value, None)
        elif d is None:
            return self._pendingIDs[name].get(value, None)
        self._pendingIDs[name][value] = d
    
    @defer.inlineCallbacks
    def startup(self):
        yield self.table(
            'entries',
            SA.Column(
                'dt', SA.DateTime,
                primary_key=True),
            SA.Column(
                'k', SA.SmallInteger,
                primary_key=True,
                autoincrement=False),
            SA.Column('http', SA.SmallInteger, nullable=False),
            SA.Column('was_rd', SA.Boolean, nullable=False),
            SA.Column('ip', SA.String(15), nullable=False),
            
            SA.Column('id_vhost', SA.Integer, nullable=False),
            SA.Column('id_url', SA.Integer, nullable=False),
            SA.Column('id_ref', SA.Integer),
            SA.Column('id_ua', SA.Integer),
        )
        for name in self.indexedValues:
            yield self.table(
                name,
                SA.Column('id', SA.Integer, primary_key=True),
                SA.Column('value', SA.String(self.valueLength)),
            )
        yield self.table(
            'files',
            SA.Column(
                'name', SA.String(self.valueLength), primary_key=True),
            SA.Column('dt', SA.DateTime),
            SA.Column('records', SA.Integer),
        )
        self.pendingID = {}

    @transact
    def preload(self):
        """
        Loads DTK and IPMatcher objects from database (can take a while,
        but do it while waiting for the first result from the log
        reader processes).
        """
        self.dtk = DTK()
        ipm = IPMatcher()
        col = self.entries.c
        with self.selex(col.dt, col.k, col.ip) as sh:
            rows = sh().fetchmany()
            while rows:
                for row in rows:
                    self.dtk.set(row[0])
                    ipm.addIP(row[2], ignoreCache=True)
        # All of that setup was done inside the loop. Now let the
        # resultproxy close and return a reference to our fully setup
        # DTK and IPMatcher objects. It might seem dangerous to share
        # the DTK object outside the thread, but it shall only be read
        # outside, and modified only inside the thread.
        return self.dtk, ipm

    @transact
    def getEntry(self, dt, k):
        """
        Returns all of the columns after dt, k for one unique dt-k
        combination in the entries table.
        """
        col = self.entries.c
        if not self.s('s_entry'):
            cList = [getattr(col, x) for x in self.colNames]
            self.s(
                cList,
                SA.and_(col.dt == SA.bindparam('dt'),
                        col.k == SA.bindparam('k')))
        self.rp = self.s().execute(dt=dt, k=k)
        return self.rp.first()

    @transact
    def insertEntry(self, dt, k, values):
        """
        Inserts a DB entry for the specified dt-k combination, using the
        supplied dict values.

        You must ensure that the dt-k combination is not already in
        the DB and that there is one value for each name defined in
        I{colNames}.

        Returns C{True} if the entry was inserted, C{False} if not.

        """
        kw = {'dt': dt, 'k': k}
        N = [len(x) for x in (self.colNames, values)]
        if N[0] > N[1]:
            self.msgWarning("Need {:d} values entries, only got {:d}", *N)
            return False
        for kk, name in enumerate(self.colNames):
            kw[name] = values[kk]
        self.rp = self.entries.insert().execute(**kw)
        return self.rp.is_insert
    
    @defer.inlineCallbacks
    def setEntry(self, dt, k, values):
        """
        Adds a new entry to the database for the specified
        datetime-sequence combination dt-k. See my colNames attribute
        for the six values you need to supply.

        Returns a deferred that fires with one of three status values:

        p: Present: Matching dt-k entry present with identical values,
           nothing added.
        c: Conflict: Matching dt-k entry found, but with differing
           values, you need to add another one with a different k.
        a: Added: No matching dt-k entry found, so one was added.
        f: Failed to insert for some reason.

        """
        def checkExisting(rowValues):
            for kk, value in enumerate(rowValues):
                if value != values[kk]:
                    return 'c'
            return 'p'

        # Check the lookup tree first
        pleaseInsert = True
        kInDTK = self.dtk.check(dt)
        if kInDTK >= k:
            # There appears to be at least a dt entry already...
            row = yield self.getEntry(dt, k)
            if row:
                # ... yes, and also for this k; we won't be inserting
                # anything for this dt-k combination
                pleaseInsert = False
                # But let's check the existing row and return a 'c' if
                # there's a conflict, or a 'p' if not.
                code = yield checkExisting(row)
            # ... no, we must have purget it or it's for a different k.
        if pleaseInsert:
            # Insert new entry
            wasInserted = yield self.insertEntry(dt, k, values)
            if wasInserted:
                code = 'a'
                if kInDTK < k:
                    self.dtk.set(dt)
            else:
                code = 'f'
        defer.returnValue(code)
    
    @transact
    def setNameValue(self, name, value):
        """
        Get the unique ID for this value in the named table, adding a new
        entry for it there if necessary.
        """
        table = getattr(self, name)
        if not self.s("s_{}".format(name)):
            self.s([table.c.id], table.c.value == SA.bindparam('value'))
        self.rp = self.s().execute(value=value)
        row = self.rp.first()
        if row:
            ID = row[0]
        else:
            rp = table.insert().execute(value=value)
            ID = rp.lastrowid
        return ID

    @transact
    def getMaxSequence(self, dt):
        # Memory leak here? Might produce a lot of those [0] lists I'm seeing.
        if not self.s('max_sequence'):
            c = self.entries.c
            self.s([SA.func.max(c.k)], c.dt == SA.bindparam('dt'))
        self.rp = self.s().execute(dt=dt)
        k = self.rp.first()[0]
        return k

    def _getID(self, name, value):
        """
        Returns a deferred to the unique ID for the named value in the
        supplied record dict, looked up from the appropriate
        indexed-value table if it's not in my cache for that name.
        
        Runs asynchronously; don't call from a transact method.
        """
        def done(ID):
            # The order of the following two lines might be important
            # if all transactions didn't run in a single thread. But
            # they do.
            valueDict[value] = ID
            self._pendingID(name, value, clear=True)
            return ID

        valueDict = self.cachedValues[name]
        # Truncate any overly long values now, before they cause any
        # complications in the DB check or insertion
        value = value[:self.valueLength]
        if self.cm.check(name, value) and value in valueDict:
            # Cached ID
            return defer.succeed(valueDict[value])
        # Get ID from DB for value, at high priority
        dID = self._pendingID(name, value)
        if dID is None:
            discardedValue = self.cm.set(name, value)
            if discardedValue in valueDict:
                # This is important! Otherwise ALL values accumulate
                # in memory, which can get HUGE!
                del valueDict[discardedValue]
            # No pending DB fetches now, so do one in its own 
            # high-priority transaction
            d = self.setNameValue(name, value, niceness=-15)
            self._pendingID(name, value, d)
            d.addCallback(done)
        else:
            d = defer.Deferred()
            d.addCallback(lambda _ : valueDict[value])
            dID.chainDeferred(d)
        d.addErrback(
            self.oops, "Getting ID for '{}' value '{}'", name, value)
        return d

    @defer.inlineCallbacks
    def setRecord(self, dt, k, record, isRetry=False):
        """
        Adds all needed database entries for the supplied record at
        the specified datetime-sequence combination dt-k.

        Returns a deferred that fires with

        - C{None} if a new database entry was written,

        - a new value of k if there was a conflict with an existing
          dt-k combination and the new value had to be obtained

        - the old k value if there was the same exact entry (no
          conflict), or

        - C{False} if the DB operation failed even after a retry.

        A conflict exists when there is already an entry for the
        specified dt-k combination that matches values than the ones
        in your supplied record.

        """
        if not hasattr(self, 'cm'):
            self.cacheSetup()
        # Build list of values and indexed-value IDs
        dList = []
        values = [record[x] for x in ('http', 'was_rd', 'ip')]
        for name in self.indexedValues:
            dList.append(self._getID(name, record[name]))
        IDs = yield defer.gatherResults(dList)
        values.extend(IDs)
        # Set the entry in its own transaction (which includes
        # checking for existing ID/value entries)
        # TODO: Occasionally hangs at this next line!!!
        success = False
        code = yield self.setEntry(dt, k, values)
        if code == 'p':
            # Entry was already present
            result = k
            success = True
        if code == 'c':
            # Conflict with existing dt-k combination having different
            # values; need to get a new sequence number for this entry
            maxSequence = yield self.getMaxSequence(dt)
            k = maxSequence + 1
            code = yield self.setEntry(dt, k, values)
            if code == 'c':
                self.msgWarning(
                    "Couldn't add record for {} even with new " +\
                    "sequence number {:d}", dt, k)
            result = k
        elif code == 'a':
            # New entry was added
            result = None
            success = True
        if not success:
            # Must have failed...
            if isRetry:
                # ...and this is a retry, so give up
                result = False
                self.msgError(
                    "Failed to set record for <{}> - {:d}:\n{}",
                    dt, k, record)
            else:
                # ...retry once
                self.msgWarning("Retrying...")
                result = yield self.setRecord(dt, k, record, isRetry=True)
        defer.returnValue(result)

    @transact
    def getValuesFromIDs(self, IDs):
        """
        Call with a list of IDs, one for each of my I{indexedValues}, and
        returns a dict with the name:value items.
        """
        result = {}
        for k, ID in enumerate(IDs):
            name = self.indexedValues[k]
            cols = getattr(getattr(self, name), 'c')
            with self.selex(cols.value) as sh:
                sh.where(cols.id == ID)
                result[name] = sh().first()[0]
        return result
        
    @defer.inlineCallbacks
    def getRecord(self, dt, k):
        """
        Returns a (deferred) dict containing the record for the specified
        datetime-sequence combination dt-k.
        """
        result = {}
        row = yield self.getEntry(dt, k)
        row = list(row)
        for j, name in enumerate(self.directValues):
            result[name] = row[j]
        valueDict = yield self.getValuesFromIDs(row[3:])
        result.update(valueDict)
        defer.returnValue(result)

    @transact
    def purgeIP(self, ip):
        """
        Purges the database of entries with the specified IP address,
        returning the (deferred) number of rows that were matched and
        presumably deleted.
        """
        with self.selex(self.entries.delete) as sh:
            sh.where(self.entries.c.ip == ip)
            result = sh().rowcount
        return result

    @transact
    def hitsForIP(self, ip):
        """
        Returns the number of entries for the specified IP address
        """
        cols = self.entries.c
        with self.selex(SA.func.count(cols.http)) as sh:
            sh.where(cols.ip == ip)
            result = sh().first()[0]
        return result

    @transact
    def fileInfo(self, fileName, *args):
        """
        With just fileName, returns the datetime and number of records for
        the file, if one was processed previously and its results
        fully reflected in the DB, or C{None}

        With two additional arguments of a datetime object and an
        integer number of records, updates or inserts an entry for the
        file to indicate that it has been processed and its results
        are fully reflected in the DB.
        """
        cols = self.files.c
        if args:
            # The transact decorator is smart enough to avoid multiple
            # wrapping with a recursive call.
            if self.fileInfo(fileName):
                self.files.update(
                    cols.name == fileName).execute(
                        dt=args[0], records=args[1])
            else:
                self.files.insert().execute(
                    name=fileName, dt=args[0], records=args[1])
            return
        if not self.s("file_info"):
            self.s(
                [cols.dt, cols.records],
                cols.name == SA.bindparam('name'))
        self.rp = self.s().execute(name=fileName)
        return self.rp.first()

    @transact
    def deleteFileInfo(self, fileName):
        """
        Probably don't need this except for testing
        """
        self.files.delete(self.files.c.name == fileName).delete()
    
        
        

                
                
            
