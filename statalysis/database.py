#!/usr/bin/python
# -*- coding: utf-8 -*-
# UTF-8. That’s cool!

"""
LICENSE
Copyright (C) 2015 Tellectual LLC
"""

from zope.interface import implements
from twisted.internet import defer
from twisted.internet.interfaces import IConsumer

from sasync.database import transact, SA, AccessBroker

import util
from sift import IPMatcher


class DTK(object):
    """
    I maintain a CPU-efficient but somewhat memory expensive lookup
    tree for datetime objects.
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
        """
        N = len(self.units)
        for k, unitName in enumerate(self.units):
            yield N-k-1, getattr(dt, unitName)

    def check(self, dt):
        """
        Check the specified datetime object, returning C{True} if it's
        in my lookup tree.
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


class PreloadConsumer(object):
    """
    I consume single-item query results, doing the specified f-args-kw
    for each.
    """
    implements(IConsumer)

    def __init__(self, f, **kw):
        self.f = f
        self.kw = kw
    
    def registerProducer(self, producer, streaming):
        pass
    def unregisterProducer(self):
        pass
        
    def write(self, row):
        """
        All I care about is having rows written, 
        """
        self.f(row[0], **kw)
                

class Transactor(AccessBroker, util.Base):
    """
    I handle transactions for an efficient database of logfile
    entries.
    """
    valueLength = 255
    directValues = ['ip', 'http', 'was_rd']
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
        # Primary key is an auto-incrementing index, which can be used
        # to find out the order in which requests were made within a
        # single second.
        yield self.table(
            'entries',
            SA.Column('id', SA.SmallInteger,
                      primary_key=True, autoincrement=True),
            SA.Column('dt', SA.DateTime, nullable=False),
            SA.Column('ip', SA.String(15), nullable=False),
            SA.Column('http', SA.SmallInteger, nullable=False),
            SA.Column('was_rd', SA.Boolean, nullable=False),
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
        self.dtk = DTK()
        self.dtk_pending = None
        self.ipm = IPMatcher()
        self.ipm_pending = None

    def preload(self):
        """
        Loads my DTK and IPMatcher objects from the database, returning a
        deferred that fires when the two DB queries are done and loading is
        underway for both.

        You can use the DTK and IPMatcher objects via I{dtk} and I{ipm} in
        the meantime; doing so will save you more and more time as the
        entries load from the database.
        """
        def noLongerPending(null, objName):
            delattr(self, "{}_pending".format(objName))
        
        def run():
            dList = []
            col = self.entries.c
            for objName, colName, fn, kw in (
                    ('dtk', 'dt', 'set', {}),
                    ('ipm', 'ip', 'addIP', {'ignoreCache':True})):
                obj = getattr(self, objName)
                f = getattr(obj, fn)
                consumer = PreloadConsumer(f, **kw)
                s = self.select([getattr(col, colName)], distinct=True)
                # This deferred will get fired when the query has run
                dSelectExecuted = defer.Deferred()
                # When done iterating, remove the pending flag for this object
                self.selectorator(s, consumer, dSelectExecuted).addCallback(
                    noLongerPending, objName)
                dList.append(dSelectExecuted)
            return defer.DeferredList(dList)
        return self.callWhenRunning(run)
    
    @transact
    def getEntries(self, dt):
        """
        Returns all of the columns after dt for one datetime second of
        entries.
        """
        col = self.entries.c
        if not self.s('s_entry'):
            cList = [getattr(col, x) for x in self.colNames]
            self.s(cList, col.dt == SA.bindparam('dt'))
        return self.s().execute(dt=dt)

    @transact
    def insertEntry(self, dt, values):
        """
        Inserts a DB entry for the specified datetime, using the supplied
        dict values.

        You must ensure that there is one value for each name
        defined in I{colNames}.
        
        """
        kw = {'dt': dt}
        N = [len(x) for x in (self.colNames, values)]
        if N[0] > N[1]:
            self.msgWarning("Need {:d} values entries, only got {:d}", *N)
            return
        for k, name in enumerate(self.colNames):
            kw[name] = values[k]
        self.entries.insert().execute(**kw)

    @defer.inlineCallbacks
    def _isEntryAlreadyThere(self, dt):
        dr = yield self.getEntries(dt)
        # TODO: Cache hashes of value combinations for recent dt
        for d in dr:
            theseValues = yield d
            if matchingValues(theseValues, values):
                # Yep, one was found, no new entry will be needed
                dr.stop()
                result = True
                break
        else:
            result = False
        defer.returnValue(result)
        
    @defer.inlineCallbacks
    def setEntry(self, dt, values):
        """
        Adds a new entry to the database for the specified datetime
        dt. See my colNames attribute for the six values you need to
        supply.

        Returns a deferred that fires with C{True} if a new entry was
        added, or C{False} if one was already present and no new one
        was needed.
        """
        def matchingValues(x, y):
            for k, value in enumerate(x):
                if value != y[k]:
                    return False
            return True

        # Check the lookup tree first
        if self.dtk.check(dt):
            # There is at least one entry for this dt, so check for an
            # existing entry with identical values
            alreadyThere = yield self._isEntryAlreadyThere(dt)
        else:
            # No lookup tree entry (yet), so set one
            self.dtk.set(dt)
            if hasattr(self, 'dtk_pending'):
                # The lookup tree is still loading, so we can't be
                # sure there isn't a DB entry already
                alreadyThere = yield self._isEntryAlreadyThere(dt)
            else:
                # The lookup tree is fully up to date, so its word is
                # authoritative: There's no matching entry in the DB
                alreadyThere = False
        # Will we be inserting a new entry?
        pleaseInsert = not alreadyThere
        if pleaseInsert:
            # Yes, do it now
            yield self.insertEntry(dt, values)
        defer.returnValue(pleaseInsert)
    
    @transact
    def setNameValue(self, name, value):
        """
        Get the unique ID for this value in the named table, adding a new
        entry for it there if necessary.
        """
        table = getattr(self, name)
        if not self.s("s_{}".format(name)):
            self.s([table.c.id], table.c.value == SA.bindparam('value'))
        row = self.s().execute(value=value).first()
        if row:
            ID = row[0]
        else:
            rp = table.insert().execute(value=value)
            ID = rp.lastrowid
        return ID

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

    def setRecord(self, dt, record):
        """
        Adds all needed database entries for the supplied record at the
        specified datetime, returning a deferred that fires C{True} if
        a new entry was added or C{False} if there already was a
        matching one.
        """
        def gotIDs(IDs):
            values.extend(IDs)
            return self.setEntry(dt, values)
            
        if not hasattr(self, 'cm'):
            self.cacheSetup()
        # Build list of values and indexed-value IDs
        values = [record[x] for x in self.directValues]
        dList = [
            self._getID(name, record[name])
            for name in self.indexedValues]
        return defer.gatherResults(dList).addCallback(gotIDs)

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
        return self.s().execute(name=fileName).first()

    @transact
    def deleteFileInfo(self, fileName):
        """
        Probably don't need this except for testing
        """
        self.files.delete(self.files.c.name == fileName).delete()
    
        
        

                
                
            
